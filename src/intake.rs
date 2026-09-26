//! Where every transport hands the gateway a `push/*` Trust Task document.
//!
//! Every remote operation here is a Trust Task, and a Trust Task is
//! authorised by what the document proves, not by the transport that carried
//! it. So each transport adapter — HTTPS (`POST /trust-tasks`, [`crate::api`])
//! and DIDComm ([`crate::didcomm`]) — does only its own unpacking and then
//! calls [`receive`]; the authentication, freshness and replay rules below are
//! the same whichever transport a document arrived on. A new transport (TSP)
//! is another caller of [`receive`], nothing more.
//!
//! ## Who the caller is
//!
//! A `push/provision` or `push/wake` is authenticated by the Data Integrity
//! proof on the document itself ([`crate::proof`]): the caller is the
//! document's `issuer`, and only once the proof binds that issuer to one of
//! its own `authentication` keys (VTI-KEY-106). A transport's own claim about
//! its sender — a DIDComm envelope's `from` — authorises nothing; when there is
//! one it must agree with the proven issuer, and a mismatch is refused as an
//! identity mismatch rather than resolved in either party's favour. A document
//! without a proof is anonymous, so `push/register` (anonymous by design) still
//! works and `push/provision` / `push/wake` are refused with `proofRequired`.
//!
//! ## One delivery, once
//!
//! An `authentication` proof carries no challenge, so the document itself is
//! what binds it to one delivery (VTI-KEY-107): it must name this gateway's DID
//! as `recipient`, carry an `issuedAt` inside the acceptance window
//! ([`acceptance_window`], VTI-OPS-024) and not be past its `expiresAt`, and
//! carry an `id` the same issuer has not already had accepted (VTI-OPS-026,
//! the shared [`AppState::replay`] record, keyed by (proven issuer, id)). The
//! record is claimed only **after** the caller is rate-limited and authorised
//! for the handle, so a refused caller leaves nothing in it, and it refuses
//! rather than evicts when full, so it fails closed. A second delivery of an
//! accepted document — over the same transport or another — is answered with
//! the first response and not executed again; a different document under the
//! same issuer's accepted `id` gets `idConflict`; a transient push failure
//! releases the claim so a retry is attempted.
//!
//! A gateway without a DID (no `GATEWAY_IDENTITY_FILE`) can be named as no
//! document's recipient, so it accepts no authenticated document: it serves
//! `push/register` only.

use serde_json::Value;
use trust_tasks_rs::{
    document_digest, ConsistencyError, DocumentDigest, FreshnessPolicy, RejectReason, TrustTask,
};

use crate::api::{dispatch_push, dispatch_push_once, reject_value, AdmitOnce, AppState};
use crate::proof::ProofError;
use crate::replay::{Admission, ReplayRecord};

/// Establish who issued a `push/*` document.
///
/// Returns the proven issuer DID, `Ok(None)` for a document with no proof (an
/// anonymous caller — acceptable for `push/register` only, which the core
/// enforces), or the refusal to send back. `transport_sender` is whatever the
/// transport claims about its sender (a DIDComm envelope's `from`); it is
/// compared against the proven issuer but never trusted in its place.
pub async fn authenticate(
    state: &AppState,
    transport_sender: Option<&str>,
    body: &Value,
) -> Result<Option<String>, RejectReason> {
    let gateway_did = state.gateway_did.as_deref();
    if let Some(recipient) = body.get("recipient").and_then(Value::as_str) {
        if Some(recipient) != gateway_did {
            return Err(RejectReason::WrongRecipient {
                in_band: recipient.to_string(),
                expected: gateway_did.unwrap_or(&state.gateway_addr).to_string(),
            });
        }
    }
    let issuer = match state.proofs.verify_issuer(body).await {
        Ok(issuer) => issuer,
        Err(ProofError::Missing) => return Ok(None),
        Err(ProofError::Invalid(reason)) => return Err(RejectReason::ProofInvalid { reason }),
    };
    if gateway_did.is_none() {
        return Err(RejectReason::TaskFailed {
            reason: "this gateway has no DID, so it accepts no authenticated document".into(),
            details: None,
        });
    }
    // VTI-KEY-107: an `authentication` proof has no challenge, so the document
    // must say whom it is for (checked above when present — required here).
    if body.get("recipient").and_then(Value::as_str).is_none() {
        return Err(RejectReason::MalformedRequest {
            reason: "a document authenticated by its proof must name its recipient".into(),
        });
    }
    if let Some(from) = transport_sender {
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

/// Receive one `push/*` Trust Task document from any transport: authenticate
/// it, dispatch it, and return the response document — or `None` when `body`
/// is not a Trust Task document at all and there is nothing to answer.
///
/// `transport_sender` is the transport's own claim about its sender, if it
/// makes one (see [`authenticate`]); HTTPS makes none.
pub async fn receive(
    state: &AppState,
    transport_sender: Option<&str>,
    body: &Value,
) -> Option<Value> {
    let doc: TrustTask<Value> = match serde_json::from_value(body.clone()) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, from = ?transport_sender, "push/* body is not a Trust Task document");
            return None;
        }
    };
    Some(receive_document(state, transport_sender, body, &doc).await)
}

/// [`receive`] for a body the transport has already parsed as `doc`. `body` is
/// the document exactly as received: the proof is verified over it, unknown
/// members included.
pub async fn receive_document(
    state: &AppState,
    transport_sender: Option<&str>,
    body: &Value,
    doc: &TrustTask<Value>,
) -> Value {
    let refuse = |reason: RejectReason| {
        tracing::warn!(from = ?transport_sender, %reason, "refusing push/* document");
        reject_value(doc, reason)
    };
    let sender = match authenticate(state, transport_sender, body).await {
        Ok(sender) => sender,
        Err(reason) => return refuse(reason),
    };
    let (Some(_), Some(gateway_did)) = (&sender, state.gateway_did.as_deref()) else {
        // Anonymous: only `push/register` can succeed, and it is idempotent in
        // effect (a fresh opaque handle, bounded by the registry caps).
        return dispatch_push(state, None, doc).await;
    };
    let now = chrono::Utc::now();
    let (digest, retain_until) = match check_window(doc, gateway_did, now) {
        Ok(v) => v,
        Err(reason) => return refuse(reason),
    };
    let once = DocumentOnce {
        replay: &state.replay,
        id: &doc.id,
        digest,
        retain_until,
        now,
    };
    dispatch_push_once(state, sender, doc, Some(&once)).await
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

    #[test]
    fn a_document_without_a_time_of_issue_fails_the_window() {
        let d = doc(serde_json::json!({}));
        assert!(check_window(&d, "did:web:gw.example", chrono::Utc::now()).is_err());
    }
}
