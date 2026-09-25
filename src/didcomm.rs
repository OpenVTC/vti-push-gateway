//! The gateway's DIDComm transport — the **preferred** transport.
//!
//! Built on `affinidi-messaging-didcomm-service` (the same crate `vta-service`
//! uses), which does the server-side work — connect to the mediator, receive,
//! unpack — and routes each message to a handler. The gateway provides its
//! provisioned `did:webvh` identity secrets (a [`TDKProfile`]) and a [`Router`]
//! that — like the VTA — routes the single Trust Task envelope type to a handler
//! calling the shared [`dispatch_push`] core, which dispatches on the `push/*`
//! `type` inside the body.
//!
//! ## Who the caller is
//!
//! The DIDComm envelope's `from` does **not** authorise anything here. A
//! `push/provision` or `push/wake` is authenticated by the Data Integrity proof
//! on the Trust Task document itself ([`crate::proof`]), exactly as the HTTPS
//! adapter authenticates by a signature over the body: the caller is the
//! document's `issuer`, and only once the proof binds that issuer to one of its
//! own `authentication` keys (VTI-KEY-106). A document without a proof reaches the core as
//! anonymous, so `push/register` (anonymous by design) still works and
//! `push/provision` / `push/wake` are refused with `proofRequired`.
//!
//! An `authentication` proof carries no challenge, so the document itself is
//! what binds it to one delivery (VTI-KEY-107): it must name this gateway as
//! `recipient`, carry an `issuedAt` inside the acceptance window
//! ([`acceptance_window`], VTI-OPS-024), and an `id` not already accepted
//! (VTI-OPS-026, the shared [`AppState::replay`] record). A second delivery of
//! an accepted document is answered with the first response and not executed
//! again; a different document under an accepted `id` gets `idConflict`.
//!
//! When the envelope does name a sender, it has to agree with the proven
//! issuer — a mismatch is refused as an identity mismatch rather than resolved
//! in either party's favour — and a document addressed to another `recipient`
//! is refused as `wrongRecipient`. The reply is packed back to the envelope
//! sender by the service.

use affinidi_messaging_didcomm_service::{
    handler_fn, ignore_handler, trust_ping_handler, DIDCommResponse, DIDCommService,
    DIDCommServiceConfig, DIDCommServiceError, Extension, HandlerContext, ListenerConfig,
    RestartPolicy, RetryConfig, Router, MESSAGE_PICKUP_STATUS_TYPE, TRUST_PING_TYPE,
};
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use trust_tasks_rs::{
    document_digest, ConsistencyError, FreshnessPolicy, RejectReason, ReplayGuard, ReplayVerdict,
    TrustTask,
};

use crate::api::{dispatch_push, reject_value, AppState};
use crate::identity::GatewayIdentity;
use crate::proof::{ProofError, ProofVerifier};
use crate::resolver::ResolverTuning;

/// DIDComm message type wrapping a Trust Task document (the DIDComm binding's
/// envelope). The request body and the reply both carry a Trust Task doc here.
const TRUST_TASK_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// Everything the DIDComm handler needs: the shared dispatch state, the proof
/// verifier, and the gateway's own DID (to check a document's `recipient`).
#[derive(Clone)]
pub struct DidcommState {
    pub app: AppState,
    pub proofs: ProofVerifier,
    pub gateway_did: String,
}

/// Establish who sent a `push/*` document received over DIDComm.
///
/// Returns the proven issuer DID, `Ok(None)` for a document with no proof (an
/// anonymous caller — acceptable for `push/register` only, which the core
/// enforces), or the refusal to send back. `envelope_from` is the DIDComm
/// `from`; it is compared against the proven issuer but never trusted in its
/// place.
pub async fn authenticate(
    proofs: &ProofVerifier,
    gateway_did: &str,
    envelope_from: Option<&str>,
    body: &Value,
) -> Result<Option<String>, RejectReason> {
    if let Some(recipient) = body.get("recipient").and_then(Value::as_str) {
        if recipient != gateway_did {
            return Err(RejectReason::WrongRecipient {
                in_band: recipient.to_string(),
                expected: gateway_did.to_string(),
            });
        }
    }
    let issuer = match proofs.verify_issuer(body).await {
        Ok(issuer) => issuer,
        Err(ProofError::Missing) => return Ok(None),
        Err(ProofError::Invalid(reason)) => return Err(RejectReason::ProofInvalid { reason }),
    };
    // VTI-KEY-107: an `authentication` proof has no challenge, so the document
    // must say whom it is for (checked above when present — required here).
    if body.get("recipient").and_then(Value::as_str).is_none() {
        return Err(RejectReason::MalformedRequest {
            reason: "a document authenticated by its proof must name its recipient".into(),
        });
    }
    if let Some(from) = envelope_from {
        let from_did = from.split('#').next().unwrap_or(from);
        if from_did != issuer {
            return Err(RejectReason::IdentityMismatch(
                ConsistencyError::IssuerMismatch {
                    in_band: issuer,
                    transport: from_did.to_string(),
                },
            ));
        }
    }
    Ok(Some(issuer))
}

/// The acceptance window for an authenticated document's time of issue
/// (VTI-OPS-024): `issuedAt` is required, may be at most
/// [`trust_tasks_rs::DEFAULT_MAX_AGE`] (5 min) old and no more than
/// [`trust_tasks_rs::DEFAULT_SKEW`] (60 s) in the future. The replay record
/// is kept for exactly this window, so the two cannot drift apart.
pub fn acceptance_window() -> FreshnessPolicy {
    FreshnessPolicy::consequential()
}

/// Admit an authenticated document once (VTI-OPS-024 / VTI-OPS-026).
///
/// `Ok(Some(response))` is a duplicate delivery of a document already
/// executed, answered with what the first execution returned — it is not run
/// again. `Ok(None)` means the document is fresh and has been claimed.
async fn admit_once(
    state: &AppState,
    doc: &TrustTask<Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Value>, RejectReason> {
    let policy = acceptance_window();
    doc.validate_freshness(now, &policy)?;
    if doc.id.is_empty() {
        return Err(RejectReason::MalformedRequest {
            reason: "document carries no identifier".into(),
        });
    }
    let digest = document_digest(doc).map_err(|_| RejectReason::MalformedRequest {
        reason: "document cannot be canonicalised".into(),
    })?;
    // Retained until the document leaves the window — a producer-supplied
    // `expiresAt` cannot stretch it (`issuedAt` is required by the policy).
    let window_end = doc
        .issued_at
        .zip(policy.max_age)
        .map(|(issued, age)| issued + age + policy.skew);
    let retain_until = match (policy.record_expiry(doc, now), window_end) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    match state
        .replay
        .claim(&doc.id, &digest, retain_until, now)
        .await
    {
        Ok(ReplayVerdict::Fresh) => Ok(None),
        Ok(ReplayVerdict::Duplicate {
            prior_response: Some(prior),
            ..
        }) => Ok(Some(prior)),
        Ok(ReplayVerdict::Duplicate { .. }) => Err(RejectReason::TaskFailed {
            reason: "this document has already been accepted".into(),
            details: None,
        }),
        Ok(ReplayVerdict::Conflict) => Err(RejectReason::IdConflict),
        Ok(_) => Err(RejectReason::IdConflict),
        // Fail closed: without the record a duplicate cannot be ruled out.
        Err(e) => {
            tracing::error!(error = %e, "replay record unavailable; refusing");
            Err(RejectReason::TaskFailed {
                reason: "replay record unavailable; retry later".into(),
                details: None,
            })
        }
    }
}

/// Handle one Trust Task envelope body: authenticate it, dispatch it, and return
/// the response document — or `None` when the body is not a Trust Task document
/// at all and there is nothing meaningful to answer.
pub async fn handle_envelope(
    state: &DidcommState,
    envelope_from: Option<&str>,
    body: &Value,
) -> Option<Value> {
    let doc: TrustTask<Value> = match serde_json::from_value(body.clone()) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, from = ?envelope_from, "push/* body is not a Trust Task document");
            return None;
        }
    };
    let refuse = |reason: RejectReason| {
        tracing::warn!(from = ?envelope_from, %reason, "refusing push/* document");
        Some(reject_value(&doc, reason))
    };
    let sender = match authenticate(&state.proofs, &state.gateway_did, envelope_from, body).await {
        Ok(sender) => sender,
        Err(reason) => return refuse(reason),
    };
    if sender.is_none() {
        // Anonymous: only `push/register` can succeed, and it is idempotent in
        // effect (a fresh opaque handle, bounded by the registry caps).
        return Some(dispatch_push(&state.app, None, &doc).await);
    }
    match admit_once(&state.app, &doc, chrono::Utc::now()).await {
        Ok(None) => {}
        Ok(Some(prior)) => return Some(prior),
        Err(reason) => return refuse(reason),
    }
    let response = dispatch_push(&state.app, sender, &doc).await;
    if let Err(e) = state
        .app
        .replay
        .record_response(&doc.id, Some(&response))
        .await
    {
        tracing::warn!(error = %e, "could not record the response for duplicate delivery");
    }
    Some(response)
}

/// Handler for every `push/*` type. The inner Trust Task doc rides in
/// `message.body`; [`handle_envelope`] authenticates it by its proof and calls
/// the shared [`dispatch_push`] core, and the service packs the returned
/// response document back to the sender.
async fn handle_push(
    _ctx: HandlerContext,
    message: Message,
    Extension(state): Extension<DidcommState>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    Ok(
        handle_envelope(&state, message.from.as_deref(), &message.body)
            .await
            .map(|response| DIDCommResponse::new(TRUST_TASK_ENVELOPE_TYPE, response)),
    )
}

/// Build the router. Like the VTA, **one** DIDComm message type
/// (`TRUST_TASK_ENVELOPE_TYPE`) carries every `push/*` `TrustTask<P>` in its
/// body; `handle_push` → `dispatch_push` routes on the Trust Task `type` inside
/// the body. (Plus trust-ping and a no-op for pickup-status.)
fn build_router(state: DidcommState) -> Result<Router, DIDCommServiceError> {
    Router::new()
        .extension(state)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .route(TRUST_TASK_ENVELOPE_TYPE, handler_fn(handle_push))
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
    // Tuned DID resolver (cache + timeout) for did:webvh sender/recipient
    // resolution; replaces the listener's implicit `TDKConfig::headless()`.
    let tuning = ResolverTuning::from_env();
    tracing::info!(resolver = %tuning.summary(), "DIDComm DID-resolver tuning");
    let tdk_config = tuning.tdk_config()?;
    // A separate resolver for proof verification, under the same tuning and
    // host policy: the DIDs it resolves are named by inbound documents.
    let proof_resolver = DIDCacheClient::new(tuning.did_cache_config())
        .await
        .map_err(|e| format!("build proof DID resolver: {e}"))?;
    let state = DidcommState {
        app: state,
        proofs: ProofVerifier::new(Arc::new(proof_resolver)),
        gateway_did: identity.did.clone(),
    };
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
            ..Default::default()
        }],
    };
    let router = build_router(state).map_err(|e| format!("build router: {e}"))?;
    DIDCommService::start(config, router, shutdown)
        .await
        .map_err(|e| format!("DIDComm service start: {e}"))
}
