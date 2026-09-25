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
//! ([`acceptance_window`], VTI-OPS-024) and not past its `expiresAt`, and an
//! `id` the same issuer has not already had accepted (VTI-OPS-026, the shared
//! [`AppState::replay`] record, keyed by (issuer, id)). The record is claimed
//! only **after** the caller is rate-limited and authorised for the handle, so
//! a refused caller leaves nothing in it. A second delivery of an accepted
//! document is answered with the first response and not executed again; a
//! different document under the same issuer's accepted `id` gets `idConflict`;
//! a transient push failure releases the claim so a retry is attempted.
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
    document_digest, ConsistencyError, DocumentDigest, FreshnessPolicy, RejectReason, TrustTask,
};

use crate::api::{dispatch_push, dispatch_push_once, reject_value, AdmitOnce, AppState};
use crate::identity::GatewayIdentity;
use crate::proof::{ProofError, ProofVerifier};
use crate::replay::{Admission, ReplayRecord};
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

/// Margin added to the replay record's retention past the last instant the
/// window accepts a document, so acceptance and record expiry never meet at
/// the same instant and leave a moment in which a replay is both fresh and
/// forgotten.
const RETENTION_MARGIN: chrono::TimeDelta = chrono::TimeDelta::seconds(1);

/// Check an authenticated document's time bounds and identifier
/// (VTI-OPS-024, VTI-KEY-107) and work out how long its replay record must be
/// kept. Nothing is claimed here — that happens only once the caller is
/// authorised ([`DocumentOnce`]).
fn check_window(
    doc: &TrustTask<Value>,
    gateway_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(DocumentDigest, Option<chrono::DateTime<chrono::Utc>>), RejectReason> {
    let policy = acceptance_window();
    doc.validate_freshness(now, &policy)?;
    // `validate_freshness` does not look at `expiresAt` once `issuedAt` is
    // present; `validate_basic` refuses `expiresAt <= now` (and re-checks the
    // recipient).
    doc.validate_basic(now, gateway_did)?;
    if doc.id.is_empty() {
        return Err(RejectReason::MalformedRequest {
            reason: "document carries no identifier".into(),
        });
    }
    let digest = document_digest(doc).map_err(|_| RejectReason::MalformedRequest {
        reason: "document cannot be canonicalised".into(),
    })?;
    // Retained until the last instant the window still accepts the document,
    // plus a margin. That instant is `issuedAt + max_age + skew` — the same
    // bound `validate_freshness` applies — or `expiresAt` when that is sooner.
    // (`record_expiry` alone would stop at `issuedAt + max_age`, `skew` short
    // of acceptance, which is a replay gap.) `issuedAt` is required by the
    // policy, so a producer's `expiresAt` can shorten this but never stretch it.
    let accept_until = doc
        .issued_at
        .zip(policy.max_age)
        .map(|(issued, age)| issued + age + policy.skew);
    let retain_until = match (accept_until, doc.expires_at) {
        (Some(a), Some(e)) => Some(a.min(e)),
        (a, e) => a.or(e),
    }
    .map(|t| t + RETENTION_MARGIN);
    Ok((digest, retain_until))
}

/// The once-only admission of one authenticated document, run by the dispatch
/// core after the caller is rate-limited and authorised (see
/// [`crate::api::AdmitOnce`]). The record is keyed by (issuer, id).
struct DocumentOnce<'a> {
    replay: &'a ReplayRecord,
    id: &'a str,
    digest: DocumentDigest,
    retain_until: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
}

#[async_trait::async_trait]
impl AdmitOnce for DocumentOnce<'_> {
    async fn admit(&self, issuer: &str, handle: &str) -> Result<Admission, RejectReason> {
        self.replay
            .claim(
                issuer,
                handle,
                self.id,
                &self.digest,
                self.retain_until,
                self.now,
            )
            .await
    }
    async fn complete(&self, issuer: &str, handle: &str, response: Option<&Value>) {
        self.replay
            .complete(issuer, handle, self.id, &self.digest, response)
            .await;
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
    let now = chrono::Utc::now();
    let (digest, retain_until) = match check_window(&doc, &state.gateway_did, now) {
        Ok(v) => v,
        Err(reason) => return refuse(reason),
    };
    let once = DocumentOnce {
        replay: &state.app.replay,
        id: &doc.id,
        digest,
        retain_until,
        now,
    };
    Some(dispatch_push_once(&state.app, sender, &doc, Some(&once)).await)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(extra: Value) -> TrustTask<Value> {
        let mut d = serde_json::json!({
            "id": "urn:uuid:w", "type": "https://trusttasks.org/spec/push/wake/0.2",
            "recipient": "did:web:gw.example", "payload": {}
        });
        d.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(d).unwrap()
    }

    /// The record outlives the last instant the window accepts the document,
    /// so there is no instant at which a replay is both fresh and forgotten.
    #[test]
    fn retention_ends_after_acceptance_does() {
        let now = chrono::Utc::now();
        let issued = now - chrono::TimeDelta::seconds(10);
        let d = doc(serde_json::json!({ "issuedAt": issued.to_rfc3339() }));
        let (_, until) = check_window(&d, "did:web:gw.example", now).unwrap();
        let p = acceptance_window();
        let last_accepted = issued + p.max_age.unwrap() + p.skew;
        assert_eq!(until, Some(last_accepted + RETENTION_MARGIN));
        // A producer's `expiresAt` shortens it, still with the margin.
        let exp = now + chrono::TimeDelta::seconds(5);
        let d = doc(
            serde_json::json!({ "issuedAt": issued.to_rfc3339(), "expiresAt": exp.to_rfc3339() }),
        );
        let (_, until) = check_window(&d, "did:web:gw.example", now).unwrap();
        assert_eq!(until, Some(exp + RETENTION_MARGIN));
    }

    #[test]
    fn an_expired_document_fails_the_window() {
        let now = chrono::Utc::now();
        let d = doc(serde_json::json!({
            "issuedAt": (now - chrono::TimeDelta::seconds(30)).to_rfc3339(),
            "expiresAt": (now - chrono::TimeDelta::seconds(20)).to_rfc3339(),
        }));
        assert!(matches!(
            check_window(&d, "did:web:gw.example", now),
            Err(RejectReason::Expired { .. })
        ));
    }
}
