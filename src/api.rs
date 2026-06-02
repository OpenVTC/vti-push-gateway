//! The gateway's `push/*` Trust-Task dispatcher (HTTPS binding).
//!
//! `POST /trust-tasks` accepts a [`TrustTask`] document and dispatches by type
//! URI to the push control plane:
//!
//! - `push/register/0.1`  — device → opaque handle (token held by gateway).
//! - `push/provision/0.1` — controller VTA → set the handle's trigger allowlist.
//! - `push/wake/0.1`      — trigger → contentless wake, allowlist-gated.
//!
//! The envelope (`TrustTask` + `respond_with`/`reject_with` + `RejectReason`)
//! is the canonical `trust_tasks_rs` form, so the same documents ride the
//! DIDComm binding (added next — the *preferred* transport) without per-
//! transport auth code. Over HTTPS the caller authenticates by signing the raw
//! body with its `did:key` (the [`crate::auth`] `X-TT-Did`/`X-TT-Signature`
//! scheme); that authenticated DID is the sender used for authorization.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use serde::Serialize;
use serde_json::{json, Value};
use trust_tasks_rs::{RejectReason, TrustTask};
use uuid::Uuid;

use crate::auth::{self, HEADER_DID, HEADER_SIG};
use crate::sender::{self, PushSender, SendOutcome};
use crate::store::{ProvisionOutcome, Store, WakeAuthz};
use crate::types::{ProvisionRequest, RegisterRequest, WakePayload, WakeRequest};

const PUSH_REGISTER: &str = "https://trusttasks.org/spec/push/register/0.1";
const PUSH_PROVISION: &str = "https://trusttasks.org/spec/push/provision/0.1";
const PUSH_WAKE: &str = "https://trusttasks.org/spec/push/wake/0.1";

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
    rand::rngs::OsRng.fill_bytes(&mut b);
    bs58::encode(b).into_string()
}

/// Serialize a response document (success `TrustTask` or `trust-task-error`) as
/// an HTTP 200 JSON body — the in-band Trust Task envelope carries the outcome.
fn doc_response<T: Serialize>(doc: &T) -> Response {
    match serde_json::to_vec(doc) {
        Ok(b) => (StatusCode::OK, [(CONTENT_TYPE, "application/json")], b).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "encode", "message": e.to_string() })),
        )
            .into_response(),
    }
}

fn reject(doc: &TrustTask<Value>, reason: RejectReason) -> Response {
    doc_response(&doc.reject_with(new_id(), reason))
}

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

    match doc.type_uri.to_string().as_str() {
        PUSH_REGISTER => handle_register(&state, &doc),
        PUSH_PROVISION => handle_provision(&state, sender, &doc),
        PUSH_WAKE => handle_wake(&state, sender, &doc),
        other => reject(
            &doc,
            RejectReason::UnsupportedType {
                type_uri: other.to_string(),
            },
        ),
    }
}

#[allow(clippy::result_large_err)] // Err is a ready-to-return Response (short-circuit).
fn parse<T: serde::de::DeserializeOwned>(doc: &TrustTask<Value>) -> Result<T, Response> {
    serde_json::from_value(doc.payload.clone()).map_err(|e| {
        reject(
            doc,
            RejectReason::MalformedRequest {
                reason: format!("payload: {e}"),
            },
        )
    })
}

/// `push/register` — unauthenticated by design (the handle is opaque and useless
/// until its VTA provisions a trigger allowlist).
fn handle_register(state: &AppState, doc: &TrustTask<Value>) -> Response {
    let req: RegisterRequest = match parse(doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if sender::select(&state.senders, &req.registration).is_none() {
        return reject(
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
    doc_response(&doc.respond_with(
        new_id(),
        json!({ "wakeHandle": { "gateway": state.gateway_addr, "handle": handle } }),
    ))
}

/// `push/provision` — only the handle's controller VTA may set its allowlist.
fn handle_provision(state: &AppState, sender: Option<String>, doc: &TrustTask<Value>) -> Response {
    let Some(caller) = sender else {
        return reject(doc, RejectReason::ProofRequired);
    };
    let req: ProvisionRequest = match parse(doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let triggers = req.policy.allowed_triggers.clone();
    match state.store.provision(&req.handle, &caller, req.policy) {
        ProvisionOutcome::Ok => doc_response(&doc.respond_with(
            new_id(),
            json!({ "handle": req.handle, "policy": { "allowedTriggers": triggers } }),
        )),
        ProvisionOutcome::UnknownHandle => reject(
            doc,
            RejectReason::TaskFailed {
                reason: "unknown handle".into(),
                details: None,
            },
        ),
        ProvisionOutcome::NotController => reject(
            doc,
            RejectReason::PermissionDenied {
                reason: "caller is not this handle's controller VTA".into(),
            },
        ),
    }
}

/// `push/wake` — fire the contentless doorbell iff the trigger is allowlisted.
fn handle_wake(state: &AppState, sender: Option<String>, doc: &TrustTask<Value>) -> Response {
    let Some(trigger) = sender else {
        return reject(doc, RejectReason::ProofRequired);
    };
    let req: WakeRequest = match parse(doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let registration = match state.store.authorize_wake(&req.handle, &trigger) {
        WakeAuthz::Allowed(reg) => reg,
        WakeAuthz::UnknownHandle => {
            return reject(
                doc,
                RejectReason::TaskFailed {
                    reason: "unknown handle".into(),
                    details: None,
                },
            );
        }
        WakeAuthz::NotAllowed => {
            return reject(
                doc,
                RejectReason::PermissionDenied {
                    reason: "trigger DID is not on this handle's allowlist".into(),
                },
            );
        }
    };
    let Some(s) = sender::select(&state.senders, &registration) else {
        return reject(
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
    match s.send(&registration, &payload) {
        SendOutcome::Delivered => {
            doc_response(&doc.respond_with(new_id(), json!({ "status": "delivered" })))
        }
        SendOutcome::TransientFailure => reject(
            doc,
            RejectReason::TaskFailed {
                reason: "transient push-service failure; message remains queued".into(),
                details: None,
            },
        ),
        SendOutcome::PermanentlyUnregistered => {
            // Binding §3.2: drop the dead token; report it in-band.
            state.store.remove(&req.handle);
            doc_response(&doc.respond_with(new_id(), json!({ "status": "token-unregistered" })))
        }
    }
}
