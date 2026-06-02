//! The gateway's DIDComm transport — the **preferred** transport.
//!
//! Built on `affinidi-messaging-didcomm-service` (the same crate `vta-service`
//! uses), which does the server-side work — connect to the mediator, receive,
//! **unpack + authenticate the authcrypt sender** — and routes each message to
//! a handler. The gateway provides its provisioned `did:webvh` identity secrets
//! (a [`TDKProfile`]) and a [`Router`] mapping the `push/*` type URIs to a
//! handler that calls the shared [`dispatch_push`] core.
//!
//! Authentication is intrinsic: the unpacked [`Message`]'s `from` is the
//! cryptographically-authenticated sender — no `X-TT-Did` header, no hand-rolled
//! verification (contrast the HTTPS adapter). The reply is packed back to the
//! sender by the service.

use affinidi_messaging_didcomm_service::{
    handler_fn, ignore_handler, trust_ping_handler, DIDCommResponse, DIDCommService,
    DIDCommServiceConfig, DIDCommServiceError, Extension, HandlerContext, ListenerConfig,
    RestartPolicy, RetryConfig, Router, MESSAGE_PICKUP_STATUS_TYPE, TRUST_PING_TYPE,
};
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use trust_tasks_rs::TrustTask;

use crate::api::{dispatch_push, AppState, PUSH_PROVISION, PUSH_REGISTER, PUSH_WAKE};
use crate::identity::GatewayIdentity;

/// DIDComm message type wrapping a Trust Task document (the DIDComm binding's
/// envelope). The request body and the reply both carry a Trust Task doc here.
const TRUST_TASK_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// Handler for every `push/*` type — the crate has already unpacked the message
/// and authenticated the sender (`message.from`). The inner Trust Task doc rides
/// in `message.body`. Calls the shared [`dispatch_push`] core; the service packs
/// the returned response document back to the sender.
async fn handle_push(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let doc: TrustTask<Value> = match serde_json::from_value(message.body.clone()) {
        Ok(d) => d,
        Err(e) => {
            // Not a Trust Task envelope — nothing to respond to meaningfully.
            tracing::warn!(error = %e, from = ?message.from, "push/* body is not a Trust Task document");
            return Ok(None);
        }
    };
    // `message.from` is the authcrypt-authenticated sender (None for anoncrypt).
    let response = dispatch_push(&state, message.from.clone(), &doc);
    Ok(Some(DIDCommResponse::new(
        TRUST_TASK_ENVELOPE_TYPE,
        response,
    )))
}

/// Build the `push/*` router (+ trust-ping and a no-op for pickup-status).
fn build_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .route(PUSH_REGISTER, handler_fn(handle_push))?
        .route(PUSH_PROVISION, handler_fn(handle_push))?
        .route(PUSH_WAKE, handler_fn(handle_push))
}

/// Start the gateway's DIDComm listener: connect to the mediator as the
/// provisioned `did:webvh` identity and route inbound `push/*` to the shared
/// dispatch core. Returns the running service (cancel `shutdown` to stop it).
pub async fn start(
    identity: &GatewayIdentity,
    state: AppState,
    shutdown: CancellationToken,
) -> Result<DIDCommService, String> {
    let secrets = identity.secrets()?;
    let profile = TDKProfile::new(
        "push-gateway",
        &identity.did,
        Some(&identity.mediator),
        secrets,
    );
    let config = DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: "push-gateway".into(),
            profile,
            restart_policy: RestartPolicy::Always {
                backoff: RetryConfig {
                    initial_delay_secs: 5,
                    max_delay_secs: 60,
                },
            },
            ..Default::default()
        }],
    };
    let router = build_router(state).map_err(|e| format!("build router: {e}"))?;
    DIDCommService::start(config, router, shutdown)
        .await
        .map_err(|e| format!("DIDComm service start: {e}"))
}
