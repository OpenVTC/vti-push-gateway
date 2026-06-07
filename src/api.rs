//! The gateway's `push/*` control plane: a transport-agnostic dispatch **core**
//! ([`dispatch_push`]) plus the HTTPS transport adapter.
//!
//! - `push/register/0.1`  — device → opaque handle (token held by gateway).
//! - `push/provision/0.1` — controller VTA → set the handle's trigger allowlist.
//! - `push/wake/0.1`      — trigger → contentless wake, allowlist-gated.
//!
//! [`dispatch_push`] takes an already-authenticated `sender` + a parsed
//! `TrustTask` and returns the response **document** (a `…#response` or a
//! `trust-task-error`). Each transport adapter authenticates/unpacks, calls the
//! core, and delivers the document in its own idiom — `POST /trust-tasks`
//! (HTTPS, did-signed) here; the DIDComm adapter (added next, the *preferred*
//! transport) will call the same core with the authcrypt sender. The core is a
//! function, not a worker task: request/response transports just `await`/call
//! it (see the architecture note — no dedicated worker, which would bottleneck).

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::Rng;
use serde::Serialize;
use serde_json::{json, Value};
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;

use crate::auth::{self, HEADER_DID, HEADER_SIG};
use crate::sender::{self, PushSender, SendOutcome};
use crate::store::{ProvisionOutcome, Store, WakeAuthz};
use crate::types::{ProvisionRequest, RegisterRequest, WakePayload, WakeRequest};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub senders: Arc<Vec<Box<dyn PushSender>>>,
    /// This gateway's externally-reachable address, echoed into issued handles.
    pub gateway_addr: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/trust-tasks", post(trust_tasks))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

fn new_id() -> String {
    format!("urn:uuid:{}", Uuid::new_v4())
}

/// Issue a fresh opaque handle (32 bytes of CSPRNG, base58btc).
fn new_handle() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    bs58::encode(b).into_string()
}

// ─── Response-document builders (transport-agnostic) ──────────────────────

/// Serialize a `…#response` success document for this request.
fn success_value<R: Serialize>(doc: &TrustTask<Value>, payload: R) -> Value {
    serde_json::to_value(doc.respond_with(new_id(), payload)).unwrap_or_else(|e| {
        reject_value(
            doc,
            RejectReason::TaskFailed {
                reason: format!("response encode: {e}"),
                details: None,
            },
        )
    })
}

/// Serialize a `trust-task-error` document for this request.
fn reject_value(doc: &TrustTask<Value>, reason: RejectReason) -> Value {
    serde_json::to_value(doc.reject_with(new_id(), reason)).unwrap_or(Value::Null)
}

/// Parse `doc.payload` into the typed body, or return a `malformed_request`
/// error document.
fn parse<T: serde::de::DeserializeOwned>(doc: &TrustTask<Value>) -> Result<T, Value> {
    serde_json::from_value(doc.payload.clone()).map_err(|e| {
        reject_value(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("payload: {e}"),
            },
        )
    })
}

// ─── The transport-agnostic dispatch core ─────────────────────────────────

/// Perform a `push/*` operation and return the response document. `sender` is
/// the authenticated caller DID (`None` if the transport authenticated no one —
/// allowed for `push/register`). Shared by every transport adapter.
pub(crate) async fn dispatch_push(
    state: &AppState,
    sender: Option<String>,
    doc: &TrustTask<Value>,
) -> Value {
    let uri = &doc.type_uri;
    match (uri.slug(), uri.major(), uri.minor()) {
        // `push/register` accepts both 0.1 and 0.2. The payload schemas are
        // field-identical — 0.2 is the Trust-Tasks lowerCamelCase migration, a
        // version-string bump for this no-enum payload — and `respond_with`
        // mirrors the request version into the `#response`. See issue #7.
        ("push/register", 0, 1 | 2) => handle_register(state, doc).await,
        ("push/provision", 0, 1) => handle_provision(state, sender, doc).await,
        ("push/wake", 0, 1) => handle_wake(state, sender, doc).await,
        _ => reject_value(
            doc,
            RejectReason::UnsupportedType {
                type_uri: uri.to_string(),
            },
        ),
    }
}

/// `push/register` — unauthenticated by design (the handle is opaque and useless
/// until its VTA provisions a trigger allowlist).
async fn handle_register(state: &AppState, doc: &TrustTask<Value>) -> Value {
    let req: RegisterRequest = match parse(doc) {
        Ok(r) => r,
        Err(v) => return v,
    };
    if sender::select(&state.senders, &req.registration).is_none() {
        return reject_value(
            doc,
            RejectReason::TaskFailed {
                reason: "no sender configured for this platform".into(),
                details: None,
            },
        );
    }
    let handle = new_handle();
    state
        .store
        .insert(handle.clone(), req.registration, req.controller_vta_did);
    success_value(
        doc,
        json!({ "wakeHandle": { "gateway": state.gateway_addr, "handle": handle } }),
    )
}

/// `push/provision` — only the handle's controller VTA may set its allowlist.
async fn handle_provision(
    state: &AppState,
    sender: Option<String>,
    doc: &TrustTask<Value>,
) -> Value {
    let Some(caller) = sender else {
        return reject_value(doc, RejectReason::ProofRequired);
    };
    let req: ProvisionRequest = match parse(doc) {
        Ok(r) => r,
        Err(v) => return v,
    };
    let triggers = req.policy.allowed_triggers.clone();
    match state.store.provision(&req.handle, &caller, req.policy) {
        ProvisionOutcome::Ok => success_value(
            doc,
            json!({ "handle": req.handle, "policy": { "allowedTriggers": triggers } }),
        ),
        ProvisionOutcome::UnknownHandle => reject_value(
            doc,
            RejectReason::TaskFailed {
                reason: "unknown handle".into(),
                details: None,
            },
        ),
        ProvisionOutcome::NotController => reject_value(
            doc,
            RejectReason::PermissionDenied {
                reason: "caller is not this handle's controller VTA".into(),
            },
        ),
    }
}

/// `push/wake` — fire the contentless doorbell iff the trigger is allowlisted.
async fn handle_wake(state: &AppState, sender: Option<String>, doc: &TrustTask<Value>) -> Value {
    let Some(trigger) = sender else {
        return reject_value(doc, RejectReason::ProofRequired);
    };
    let req: WakeRequest = match parse(doc) {
        Ok(r) => r,
        Err(v) => return v,
    };
    let registration = match state.store.authorize_wake(&req.handle, &trigger) {
        WakeAuthz::Allowed(reg) => reg,
        WakeAuthz::UnknownHandle => {
            return reject_value(
                doc,
                RejectReason::TaskFailed {
                    reason: "unknown handle".into(),
                    details: None,
                },
            );
        }
        WakeAuthz::NotAllowed => {
            return reject_value(
                doc,
                RejectReason::PermissionDenied {
                    reason: "trigger DID is not on this handle's allowlist".into(),
                },
            );
        }
    };
    let Some(s) = sender::select(&state.senders, &registration) else {
        return reject_value(
            doc,
            RejectReason::TaskFailed {
                reason: "no sender for this handle's platform".into(),
                details: None,
            },
        );
    };
    let payload = WakePayload {
        v: req.v,
        mediator: req.mediator,
        count: req.count,
        urgency: req.urgency,
    };
    match s.send(&registration, &payload).await {
        SendOutcome::Delivered => success_value(doc, json!({ "status": "delivered" })),
        SendOutcome::TransientFailure => reject_value(
            doc,
            RejectReason::TaskFailed {
                reason: "transient push-service failure; message remains queued".into(),
                details: None,
            },
        ),
        SendOutcome::PermanentlyUnregistered => {
            // Binding §3.2: drop the dead token; report it in-band.
            state.store.remove(&req.handle);
            success_value(doc, json!({ "status": "token-unregistered" }))
        }
    }
}

// ─── HTTPS transport adapter ───────────────────────────────────────────────

/// Authenticate the request if it is did-signed: verify the signature over the
/// raw body and return the caller DID. Absent headers → `Ok(None)` (anonymous,
/// allowed for `push/register`). A present-but-invalid signature → `Err(401)`.
// The `Err` is a ready-to-return HTTP `Response` (short-circuit), so its size is
// intentional — this isn't a hot-path value moved around.
#[allow(clippy::result_large_err)]
fn authenticate(headers: &HeaderMap, body: &Bytes) -> Result<Option<String>, Response> {
    let did = headers.get(HEADER_DID).and_then(|v| v.to_str().ok());
    let sig = headers.get(HEADER_SIG).and_then(|v| v.to_str().ok());
    match (did, sig) {
        (Some(d), Some(s)) => match auth::verify_signed(d, s, body) {
            Ok(()) => Ok(Some(d.to_string())),
            Err(e) => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "auth_failed", "message": e.to_string() })),
            )
                .into_response()),
        },
        _ => Ok(None),
    }
}

/// Serialize a response document as an HTTP 200 JSON body — the in-band Trust
/// Task envelope carries the outcome (success or `trust-task-error`).
fn http_doc(value: Value) -> Response {
    match serde_json::to_vec(&value) {
        Ok(b) => (StatusCode::OK, [(CONTENT_TYPE, "application/json")], b).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "encode", "message": e.to_string() })),
        )
            .into_response(),
    }
}

async fn trust_tasks(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let doc: TrustTask<Value> = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_body", "message": e.to_string() })),
            )
                .into_response();
        }
    };
    let sender = match authenticate(&headers, &body) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    http_doc(dispatch_push(&state, sender, &doc).await)
}
