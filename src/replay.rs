//! The record of accepted document identifiers (VTI-OPS-026).
//!
//! Keyed by **(issuer, id)** and partitioned per issuer: every issuer has its
//! own bounded record, so no issuer can evict another's entries or occupy an
//! identifier another issuer will use. Records are only ever created for a
//! caller that has already been authorised for the operation (see
//! `didcomm::handle_envelope`), so an unauthorised party creates none.
//!
//! When a bound is reached the record **refuses** new documents rather than
//! evicting live entries — eviction would make the evicted documents
//! replayable. Both bounds sit above what the per-DID rate limit lets one issuer
//! produce inside the acceptance window.
//!
//! In memory and per process: a restart forgets it, which the acceptance
//! window makes safe (anything forgotten is by then too old to accept).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde_json::Value;
use trust_tasks_rs::{
    DocumentDigest, InMemoryReplayGuard, RejectReason, ReplayGuard, ReplayVerdict,
};

/// Default bound on one issuer's retained records — above the default per-DID
/// rate (20/s, burst 60) sustained for the whole acceptance window (~6 min).
pub const DEFAULT_PER_ISSUER: usize = 8_192;
/// Default bound on records across all issuers.
pub const DEFAULT_TOTAL: usize = 65_536;

/// What the record says about a document offered for execution.
#[derive(Debug, Clone, PartialEq)]
pub enum Admission {
    /// Not seen before; now claimed. Execute, then [`ReplayRecord::complete`].
    Fresh,
    /// Already executed; answer with this response and do not execute again.
    Answered(Value),
}

pub struct ReplayRecord {
    per_issuer: usize,
    total: usize,
    issuers: Mutex<HashMap<String, Arc<InMemoryReplayGuard>>>,
}

impl Default for ReplayRecord {
    fn default() -> Self {
        Self::new(DEFAULT_PER_ISSUER, DEFAULT_TOTAL)
    }
}

fn busy() -> RejectReason {
    RejectReason::TaskFailed {
        reason: "too many documents accepted in the current window; retry later".into(),
        details: None,
    }
}

impl ReplayRecord {
    /// A record retaining at most `per_issuer` entries per issuer and `total`
    /// overall. Both must be non-zero.
    pub fn new(per_issuer: usize, total: usize) -> Self {
        assert!(
            per_issuer > 0 && total > 0,
            "replay record bounds must be non-zero"
        );
        Self {
            per_issuer,
            total,
            issuers: Mutex::new(HashMap::new()),
        }
    }

    /// The issuer's partition, after checking both bounds.
    fn partition(
        &self,
        issuer: &str,
        now: DateTime<Utc>,
    ) -> Result<Arc<InMemoryReplayGuard>, RejectReason> {
        let mut map = self.issuers.lock().expect("replay record mutex");
        let mut total = 0;
        map.retain(|_, g| {
            g.purge_expired(now);
            total += g.len();
            !g.is_empty()
        });
        let guard = map
            .entry(issuer.to_string())
            // Capacity one above the bound, so the guard itself never evicts:
            // the bound is enforced here, by refusing.
            .or_insert_with(|| Arc::new(InMemoryReplayGuard::new(self.per_issuer + 1)))
            .clone();
        if guard.len() >= self.per_issuer || total >= self.total {
            return Err(busy());
        }
        Ok(guard)
    }

    /// Claim `(issuer, id)`. Call only for a caller already authorised.
    pub async fn claim(
        &self,
        issuer: &str,
        id: &str,
        digest: &DocumentDigest,
        retain_until: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Admission, RejectReason> {
        let guard = self.partition(issuer, now)?;
        match guard.claim(id, digest, retain_until, now).await {
            Ok(ReplayVerdict::Fresh) => Ok(Admission::Fresh),
            Ok(ReplayVerdict::Duplicate {
                prior_response: Some(prior),
                ..
            }) => Ok(Admission::Answered(prior)),
            // In flight, or completed without a recorded response.
            Ok(ReplayVerdict::Duplicate { .. }) => Err(RejectReason::TaskFailed {
                reason: "this document has already been accepted".into(),
                details: None,
            }),
            Ok(_) => Err(RejectReason::IdConflict),
            // Fail closed: without the record a duplicate cannot be ruled out.
            Err(e) => {
                tracing::error!(error = %e, "replay record unavailable; refusing");
                Err(busy())
            }
        }
    }

    /// Close out a claim: keep `response` for a later duplicate, or — with
    /// `None` — release the claim so the same document can be attempted again
    /// (the effect did not happen, e.g. a transient push failure).
    pub async fn complete(
        &self,
        issuer: &str,
        id: &str,
        digest: &DocumentDigest,
        response: Option<&Value>,
    ) {
        let guard = self
            .issuers
            .lock()
            .expect("replay record mutex")
            .get(issuer)
            .cloned();
        let Some(guard) = guard else { return };
        let result = match response {
            Some(r) => guard.record_response(id, Some(r)).await,
            None => guard.release(id, digest).await,
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, "could not close out a replay record entry");
        }
    }

    /// Entries currently retained for `issuer` (tests and metrics).
    pub fn len_for(&self, issuer: &str) -> usize {
        self.issuers
            .lock()
            .expect("replay record mutex")
            .get(issuer)
            .map_or(0, |g| g.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::{document_digest, TrustTask};

    fn digest(id: &str) -> DocumentDigest {
        let doc: TrustTask<Value> = serde_json::from_value(serde_json::json!({
            "id": id, "type": "https://trusttasks.org/spec/push/wake/0.2", "payload": {}
        }))
        .unwrap();
        document_digest(&doc).unwrap()
    }

    #[tokio::test]
    async fn keyed_by_issuer_and_id() {
        let r = ReplayRecord::default();
        let now = Utc::now();
        let until = Some(now + chrono::TimeDelta::minutes(5));
        assert_eq!(
            r.claim("did:a", "x", &digest("x"), until, now).await,
            Ok(Admission::Fresh)
        );
        // The same id from another issuer is a different document.
        assert_eq!(
            r.claim("did:b", "x", &digest("x2"), until, now).await,
            Ok(Admission::Fresh)
        );
    }

    #[tokio::test]
    async fn a_full_partition_refuses_instead_of_evicting() {
        let r = ReplayRecord::new(2, 100);
        let now = Utc::now();
        let until = Some(now + chrono::TimeDelta::minutes(5));
        for id in ["1", "2"] {
            assert_eq!(
                r.claim("did:a", id, &digest(id), until, now).await,
                Ok(Admission::Fresh)
            );
        }
        assert!(r
            .claim("did:a", "3", &digest("3"), until, now)
            .await
            .is_err());
        assert_eq!(r.len_for("did:a"), 2, "nothing was evicted");
        // Another issuer is unaffected.
        assert_eq!(
            r.claim("did:b", "1", &digest("1"), until, now).await,
            Ok(Admission::Fresh)
        );
    }

    #[tokio::test]
    async fn a_released_claim_can_be_attempted_again() {
        let r = ReplayRecord::default();
        let now = Utc::now();
        let until = Some(now + chrono::TimeDelta::minutes(5));
        let d = digest("x");
        assert_eq!(
            r.claim("did:a", "x", &d, until, now).await,
            Ok(Admission::Fresh)
        );
        r.complete("did:a", "x", &d, None).await;
        assert_eq!(
            r.claim("did:a", "x", &d, until, now).await,
            Ok(Admission::Fresh)
        );
    }
}
