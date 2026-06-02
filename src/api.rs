//! REST handlers — the gateway transport of the push binding.
//!
//! - `POST /v1/register`  (device, unauthenticated) → issue an opaque handle.
//! - `POST /v1/provision` (controller VTA, did-signed) → set a handle's allowlist.
//! - `POST /v1/wake`      (trigger, did-signed) → contentless wake if allowed.
//!
//! `provision` and `wake` authenticate by verifying an Ed25519 signature over
//! the raw request body against the caller's `did:key` ([`crate::auth`]).

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use rand::RngCore;

use crate::auth::{self, HEADER_DID, HEADER_SIG};
use crate::sender::{self, PushSender, SendOutcome};
use crate::store::{ProvisionOutcome, Store, WakeAuthz};
use crate::types::{
    ProvisionRequest, RegisterRequest, RegisterResponse, WakeHandle, WakePayload, WakeRequest,
};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub senders: Arc<Vec<Box<dyn PushSender>>>,
    /// This gateway's externally-reachable address, echoed into issued handles.
    pub gateway_addr: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/register", post(register))
        .route("/v1/provision", post(provision))
        .route("/v1/wake", post(wake))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(state)
}

/// A handler error that renders as a small JSON body. Kept small (so it's a
/// cheap `Result` `Err`) and converted to a `Response` only at the edge.
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.code, "message": self.message })),
        )
            .into_response()
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "invalid_body", e.to_string()))
}

/// Authenticate a did-signed request: verify the signature over the raw body and
/// return the caller's DID.
fn authenticate(headers: &HeaderMap, body: &Bytes) -> Result<String, ApiError> {
    let did = headers
        .get(HEADER_DID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "missing_did",
                "X-TT-Did header required",
            )
        })?;
    let sig = headers
        .get(HEADER_SIG)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "missing_signature",
                "X-TT-Signature header required",
            )
        })?;
    auth::verify_signed(did, sig, body)
        .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, "auth_failed", e.to_string()))?;
    Ok(did.to_string())
}

/// Issue a fresh opaque handle (32 bytes of CSPRNG, base58btc).
fn new_handle() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    bs58::encode(b).into_string()
}

async fn register(State(state): State<AppState>, body: Bytes) -> Result<Response, ApiError> {
    let req: RegisterRequest = parse_json(&body)?;
    // Reject a registration whose platform no sender handles, rather than
    // silently dropping wakes later (binding §8).
    if sender::select(&state.senders, &req.registration).is_none() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_platform",
            "no sender configured for this platform",
        ));
    }
    let handle = new_handle();
    state
        .store
        .insert(handle.clone(), req.registration, req.controller_vta_did);
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            wake_handle: WakeHandle {
                gateway: state.gateway_addr.clone(),
                handle,
            },
        }),
    )
        .into_response())
}

async fn provision(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let caller = authenticate(&headers, &body)?;
    let req: ProvisionRequest = parse_json(&body)?;
    match state.store.provision(&req.handle, &caller, req.policy) {
        ProvisionOutcome::Ok => Ok(StatusCode::NO_CONTENT.into_response()),
        ProvisionOutcome::UnknownHandle => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "unknown_handle",
            "no such handle",
        )),
        ProvisionOutcome::NotController => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "not_controller",
            "caller is not this handle's controller VTA",
        )),
    }
}

async fn wake(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let trigger = authenticate(&headers, &body)?;
    let req: WakeRequest = parse_json(&body)?;
    let registration = match state.store.authorize_wake(&req.handle, &trigger) {
        WakeAuthz::Allowed(reg) => reg,
        WakeAuthz::UnknownHandle => {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "unknown_handle",
                "no such handle",
            ))
        }
        WakeAuthz::NotAllowed => {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "not_allowed",
                "trigger DID is not on this handle's allowlist",
            ))
        }
    };

    let Some(s) = sender::select(&state.senders, &registration) else {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_platform",
            "no sender for this handle's platform",
        ));
    };
    let payload = WakePayload {
        v: req.v,
        mediator: req.mediator,
        count: req.count,
        urgency: req.urgency,
    };
    match s.send(&registration, &payload) {
        SendOutcome::Delivered => Ok(StatusCode::ACCEPTED.into_response()),
        SendOutcome::TransientFailure => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "push_failed",
            "transient push-service failure; message remains queued",
        )),
        SendOutcome::PermanentlyUnregistered => {
            // Binding §3.2: drop the dead token; the message stays queued for
            // the consumer's next voluntary pickup.
            state.store.remove(&req.handle);
            Err(ApiError::new(
                StatusCode::GONE,
                "token_dead",
                "push token permanently unregistered; handle dropped",
            ))
        }
    }
}
