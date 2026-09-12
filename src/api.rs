//! The gateway's `push/*` control plane: a transport-agnostic dispatch **core**
//! ([`dispatch_push`]) plus the HTTPS transport adapter.
//!
//! - `push/register/0.2`  — device → opaque handle (token held by gateway).
//! - `push/provision/0.2` — controller VTA → set the handle's trigger allowlist.
//! - `push/wake/0.2`      — trigger → contentless wake, allowlist-gated.
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
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, StatusCode,
    },
    middleware::{self, Next},
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
use crate::egress::EgressPolicy;
use crate::metrics::Metrics;
use crate::sender::{self, PushSender, SendOutcome};
use crate::store::{ProvisionOutcome, Store, WakeAuthz};
use crate::types::{ProvisionRequest, RegisterRequest, WakePayload, WakeRequest};

/// Largest accepted `POST /trust-tasks` body. Real `push/*` documents are well
/// under 2 KiB; larger bodies get `413 Payload Too Large`.
pub const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;

/// Upper bound on one push send in the wake path, independent of any
/// per-sender client timeout.
pub const WAKE_SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// Env var setting the address the management (metrics) listener binds to.
pub const ENV_METRICS_BIND: &str = "GATEWAY_METRICS_BIND";
/// Default management bind address — loopback, so counters are not public.
pub const DEFAULT_METRICS_BIND: &str = "127.0.0.1:9300";
/// Env var setting a bearer token the metrics listener requires.
pub const ENV_METRICS_TOKEN: &str = "GATEWAY_METRICS_TOKEN";

/// The single reason returned when a `push/*` payload does not deserialise.
///
/// Deliberately fixed: the caller learns that its document did not match the
/// schema, and the serde detail (which names fields and types, and echoes back
/// parts of the input) goes to a `debug!` log instead. The schema itself is
/// public, so this is hygiene rather than a vulnerability — see the PR.
const SCHEMA_MISMATCH: &str = "payload does not match the push/* 0.2 schema";

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub senders: Arc<Vec<Box<dyn PushSender>>>,
    /// This gateway's externally-reachable address, echoed into issued handles.
    pub gateway_addr: String,
    /// Operation counters scraped at `GET /metrics`.
    pub metrics: Arc<Metrics>,
    /// What registrations may point push delivery at.
    pub egress: Arc<EgressPolicy>,
}

/// The **public** router: the `push/*` Trust-Task endpoint and a liveness probe.
///
/// `/metrics` is deliberately absent — see [`metrics_router`].
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/trust-tasks", post(trust_tasks))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

/// The **management** router, served on its own listener ([`ENV_METRICS_BIND`],
/// loopback by default).
///
/// The counters name handle, provision and wake volumes and their failure
/// outcomes. That is operational intelligence about a push fleet, and it shared a
/// listener with the public API — so anything fronting the gateway (an nginx
/// vhost proxying `location /` wholesale, as the vti-setup template does) exposed
/// it to the internet. Separating the listener means the deployment cannot leak
/// it by accident; the optional [`ENV_METRICS_TOKEN`] bearer token is for when
/// the management port must be reachable off-host.
pub fn metrics_router(state: AppState, token: Option<String>) -> Router {
    let mut router = Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(|| async { "ok" }));
    if let Some(expected) = token {
        let expected: Arc<str> = expected.into();
        router = router.layer(middleware::from_fn(move |req, next| {
            require_bearer(expected.clone(), req, next)
        }));
    }
    router
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

/// Gate the management router on a bearer token.
async fn require_bearer(expected: Arc<str>, req: Request, next: Next) -> Response {
    let presented = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(got) if constant_time_eq(got.as_bytes(), expected.as_bytes()) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(CONTENT_TYPE, "text/plain; charset=utf-8")],
            "metrics require a bearer token\n",
        )
            .into_response(),
    }
}

/// Compare two byte strings without an early exit on the first difference, so
/// the response time does not reveal a correct prefix of the token.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `GET /metrics` — Prometheus text exposition of the operation counters.
async fn metrics(State(state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
        .into_response()
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

/// A `malformed_request` error document with a fixed, caller-safe reason.
fn malformed(doc: &TrustTask<Value>, reason: &str) -> Value {
    reject_value(
        doc,
        RejectReason::MalformedRequest {
            reason: reason.to_string(),
        },
    )
}

/// Parse `doc.payload` into the typed body, or return a `malformed_request`
/// error document carrying the fixed [`SCHEMA_MISMATCH`] reason.
fn parse<T: serde::de::DeserializeOwned>(doc: &TrustTask<Value>) -> Result<T, Value> {
    serde_json::from_value(doc.payload.clone()).map_err(|e| {
        tracing::debug!(error = %e, type_uri = %doc.type_uri, "push/* payload failed to parse");
        malformed(doc, SCHEMA_MISMATCH)
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
        // The gateway speaks `push/*` 0.2 only — a clean cutover aligned with
        // the registry's latest versions (issue #20; pre-production, so the
        // 0.1 forms, including `push/register/0.1`'s former dual-accept leg
        // from issue #7, are dropped rather than dual-accepted). 0.1→0.2 was
        // the Trust-Tasks lowerCamelCase migration: request payloads are
        // field-identical; `push/wake`'s response `status` enum became
        // `tokenUnregistered`. `respond_with` mirrors the request version
        // into the `#response`.
        ("push/register", 0, 2) => handle_register(state, doc).await,
        ("push/provision", 0, 2) => handle_provision(state, sender, doc).await,
        ("push/wake", 0, 2) => handle_wake(state, sender, doc).await,
        _ => reject_value(
            doc,
            RejectReason::UnsupportedType {
                type_uri: uri.to_string(),
            },
        ),
    }
}

/// `push/register` — unauthenticated by design (the handle is opaque and useless
/// until its VTA provisions a trigger allowlist). The registration is validated
/// (field bounds, Web Push endpoint policy, APNs topic policy) before anything
/// is stored.
async fn handle_register(state: &AppState, doc: &TrustTask<Value>) -> Value {
    let req: RegisterRequest = match parse(doc) {
        Ok(r) => r,
        Err(v) => return v,
    };
    if let Err(reason) = req.validate(&state.egress) {
        return malformed(doc, reason);
    }
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
    state.metrics.inc_register();
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
    let mut req: ProvisionRequest = match parse(doc) {
        Ok(r) => r,
        Err(v) => return v,
    };
    // Bound and normalise the controller-supplied allowlist before it is stored
    // or echoed back.
    if let Err(reason) = req.policy.validate_and_normalize() {
        return malformed(doc, reason);
    }
    let triggers = req.policy.allowed_triggers.clone();
    match state.store.provision(&req.handle, &caller, req.policy) {
        ProvisionOutcome::Ok => {
            state.metrics.inc_provision_ok();
            success_value(
                doc,
                json!({ "handle": req.handle, "policy": { "allowedTriggers": triggers } }),
            )
        }
        ProvisionOutcome::UnknownHandle => {
            state.metrics.inc_provision_unknown_handle();
            reject_value(
                doc,
                RejectReason::TaskFailed {
                    reason: "unknown handle".into(),
                    details: None,
                },
            )
        }
        ProvisionOutcome::NotController => {
            state.metrics.inc_provision_not_controller();
            reject_value(
                doc,
                RejectReason::PermissionDenied {
                    reason: "caller is not this handle's controller VTA".into(),
                },
            )
        }
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
    if let Err(reason) = req.validate() {
        return malformed(doc, reason);
    }
    let registration = match state.store.authorize_wake(&req.handle, &trigger) {
        WakeAuthz::Allowed(reg) => reg,
        WakeAuthz::UnknownHandle => {
            state.metrics.inc_wake_unknown_handle();
            return reject_value(
                doc,
                RejectReason::TaskFailed {
                    reason: "unknown handle".into(),
                    details: None,
                },
            );
        }
        WakeAuthz::NotAllowed => {
            state.metrics.inc_wake_not_allowed();
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
    // Bound the send even if a sender's own client has no timeout.
    let outcome =
        match tokio::time::timeout(WAKE_SEND_TIMEOUT, s.send(&registration, &payload)).await {
            Ok(outcome) => outcome,
            Err(_) => {
                tracing::warn!(
                    platform = registration.platform(),
                    "push send exceeded the wake timeout"
                );
                SendOutcome::TransientFailure
            }
        };
    match outcome {
        SendOutcome::Delivered => {
            state.metrics.inc_wake_delivered();
            success_value(doc, json!({ "status": "delivered" }))
        }
        SendOutcome::TransientFailure => {
            state.metrics.inc_wake_transient_failure();
            reject_value(
                doc,
                RejectReason::TaskFailed {
                    reason: "transient push-service failure; message remains queued".into(),
                    details: None,
                },
            )
        }
        SendOutcome::PermanentlyUnregistered => {
            // Binding §3.2: drop the dead token; report it in-band.
            // (`tokenUnregistered` is the 0.2 spelling of the status enum.)
            state.store.remove(&req.handle);
            state.metrics.inc_wake_token_unregistered();
            success_value(doc, json!({ "status": "tokenUnregistered" }))
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
            // Same reasoning as `parse`: a fixed reason out, the detail to logs.
            tracing::debug!(error = %e, "request body is not a Trust Task document");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_body",
                    "message": "body is not a Trust Task document",
                })),
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
