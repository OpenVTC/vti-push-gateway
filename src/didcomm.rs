//! The gateway's DIDComm transport adapter, and the mediator listener it shares
//! with TSP.
//!
//! Built on `affinidi-messaging-didcomm-service` (the same crate `vta-service`
//! uses), which does the server-side work — connect to the mediator, receive,
//! unpack — and routes each message to a handler. The gateway provides its
//! provisioned `did:webvh` identity secrets (a [`TDKProfile`]) and a [`Router`]
//! that — like the VTA — routes the single Trust Task envelope type to a handler
//! passing the document to [`intake::receive`], the intake every transport
//! shares, which authenticates it by its own proof and dispatches on the
//! `push/*` `type` inside the body.
//!
//! This adapter adds nothing to authorisation: the envelope's `from` is handed
//! to the intake only as the transport's claim about its sender, which must
//! agree with the proven issuer and never stands in for it (see
//! [`crate::intake`]). The reply is packed back to the envelope sender by the
//! service.
//!
//! The same listener carries TSP: the mediator allows one websocket per DID, so
//! the service multiplexes both protocols off it ([`Protocols::BOTH`]) and hands
//! TSP messages to [`crate::tsp::TspIntake`], which feeds the same intake.
//!
//! [`start`] hands the listener `state`'s durable TSP relationship store
//! ([`crate::relationships`]), when one was built, so a peer's relationship
//! survives a gateway restart instead of being wiped and forcing a re-invite.

use affinidi_messaging_didcomm_service::{
    handler_fn, ignore_handler, trust_ping_handler, DIDCommResponse, DIDCommService,
    DIDCommServiceConfig, DIDCommServiceError, Extension, HandlerContext, ListenerConfig,
    Protocols, RestartPolicy, RetryConfig, Router, MESSAGE_PICKUP_STATUS_TYPE, TRUST_PING_TYPE,
};

use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use tokio_util::sync::CancellationToken;

use crate::api::AppState;
use crate::identity::GatewayIdentity;
use crate::intake;
use crate::resolver::ResolverTuning;
use crate::tsp::TspIntake;

/// DIDComm message type wrapping a Trust Task document (the DIDComm binding's
/// envelope). The request body and the reply both carry a Trust Task doc here.
const TRUST_TASK_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// Handler for every `push/*` type. The inner Trust Task doc rides in
/// `message.body`; [`intake::receive`] authenticates it by its proof and
/// dispatches it, and the service packs the returned response document back
/// to the sender.
async fn handle_push(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<AppState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    Ok(
        intake::receive(&state, message.from.as_deref(), &message.body)
            .await
            .map(|response| DIDCommResponse::new(TRUST_TASK_ENVELOPE_TYPE, response)),
    )
}

/// Build the router. Like the VTA, **one** DIDComm message type
/// (`TRUST_TASK_ENVELOPE_TYPE`) carries every `push/*` `TrustTask<P>` in its
/// body; `handle_push` → [`intake::receive`] routes on the Trust Task `type`
/// inside the body. (Plus trust-ping and a no-op for pickup-status.)
fn build_router(state: AppState) -> Result<Router, DIDCommServiceError> {
    Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .route(TRUST_TASK_ENVELOPE_TYPE, handler_fn(handle_push))
}

/// Start the gateway's mediator listener: connect to the mediator as the
/// provisioned `did:webvh` identity and hand inbound `push/*` — over DIDComm
/// and over TSP, on the one socket — to the shared intake. Returns the running
/// service (cancel `shutdown` to stop it).
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
    // Tuned DID resolver (cache + timeout) for did:webvh sender/recipient
    // resolution; replaces the listener's implicit `TDKConfig::headless()`.
    let tuning = ResolverTuning::from_env();
    tracing::info!(resolver = %tuning.summary(), "DIDComm DID-resolver tuning");
    let tdk_config = tuning.tdk_config()?;
    // Durable across a restart when the gateway was built with one
    // (`GATEWAY_RELATIONSHIPS_FILE`); otherwise the listener falls back to the
    // SDK's ephemeral in-memory default, which forgets every relationship on
    // restart and forces each peer to re-invite before its next message is
    // admitted (the §7.2.2 gate drops it otherwise).
    let relationship_store = state
        .tsp_relationships
        .clone()
        .map(|store| store as std::sync::Arc<dyn affinidi_tdk::messaging::RelationshipStore>);
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
            tdk_config: Some(tdk_config),
            protocols: Protocols::BOTH,
            relationship_store,
            ..Default::default()
        }],
    };
    let router = build_router(state.clone()).map_err(|e| format!("build router: {e}"))?;
    DIDCommService::start_with_tsp(config, router, TspIntake::new(state), shutdown)
        .await
        .map_err(|e| format!("messaging service start: {e}"))
}
