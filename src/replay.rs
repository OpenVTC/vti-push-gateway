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
//! replayable. Three budgets, so no one party can spend everyone's:
//!
//! - **per issuer** ([`DEFAULT_PER_ISSUER`]);
//! - **per handle** ([`DEFAULT_PER_HANDLE`]) — what one handle's controller and
//!   triggers may hold between them, whichever DIDs they use;
//! - **overall, shared fairly**: once the soft bound ([`DEFAULT_TOTAL`]) is
//!   reached, an issuer is admitted only while it holds fewer than its fair
//!   share (`soft bound / issuers holding records`). Anonymous registration
//!   lets anyone become the controller of a handle naming a DID of their own,
//!   so authorised issuers are not scarce; this is what stops a set of them
//!   filling the record and locking everyone else out. A hard bound of twice
//!   the soft bound caps memory.
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
/// Default soft bound on records across all issuers (see the module docs).
pub const DEFAULT_TOTAL: usize = 65_536;
/// Default bound on records charged to one handle within the window.
pub const DEFAULT_PER_HANDLE: usize = 512;

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
    per_handle: usize,
    total: usize,
    inner: Mutex<Inner>,
}

/// One record charged to a handle: (issuer, id, retained until).
type HandleCharge = (String, String, Option<DateTime<Utc>>);

#[derive(Default)]
struct Inner {
    issuers: HashMap<String, Arc<InMemoryReplayGuard>>,
    /// Per handle: the (issuer, id) of each record charged to it, with the
    /// record's retention, so the budget frees as records expire.
    handles: HashMap<String, Vec<HandleCharge>>,
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
        Self::with_per_handle(per_issuer, DEFAULT_PER_HANDLE, total)
    }

    /// As [`Self::new`], with an explicit per-handle bound.
    pub fn with_per_handle(per_issuer: usize, per_handle: usize, total: usize) -> Self {
        assert!(
            per_issuer > 0 && per_handle > 0 && total > 0,
            "replay record bounds must be non-zero"
        );
        Self {
            per_issuer,
            per_handle,
            total,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The issuer's partition, after checking every budget.
    fn partition(
        &self,
        issuer: &str,
        handle: &str,
        now: DateTime<Utc>,
    ) -> Result<Arc<InMemoryReplayGuard>, RejectReason> {
        let mut inner = self.inner.lock().expect("replay record mutex");
        let mut total = 0;
        inner.issuers.retain(|_, g| {
            g.purge_expired(now);
            total += g.len();
            !g.is_empty()
        });
        inner.handles.retain(|_, v| {
            v.retain(|(_, _, until)| until.is_none_or(|t| t > now));
            !v.is_empty()
        });
        if inner.handles.get(handle).map_or(0, Vec::len) >= self.per_handle {
            return Err(busy());
        }
        let active = inner.issuers.len() + usize::from(!inner.issuers.contains_key(issuer));
        let guard = inner
            .issuers
            .entry(issuer.to_string())
            // Capacity one above the bound, so the guard itself never evicts:
            // the bound is enforced here, by refusing.
            .or_insert_with(|| Arc::new(InMemoryReplayGuard::new(self.per_issuer + 1)))
            .clone();
        let held = guard.len();
        let fair_share = (self.total / active.max(1)).max(1);
        if held >= self.per_issuer
            || total >= self.total.saturating_mul(2)
            || (total >= self.total && held >= fair_share)
        {
            return Err(busy());
        }
        Ok(guard)
    }

    fn charge(&self, handle: &str, issuer: &str, id: &str, until: Option<DateTime<Utc>>) {
        let mut inner = self.inner.lock().expect("replay record mutex");
        inner.handles.entry(handle.to_string()).or_default().push((
            issuer.to_string(),
            id.to_string(),
            until,
        ));
    }

    fn uncharge(&self, handle: &str, issuer: &str, id: &str) {
        let mut inner = self.inner.lock().expect("replay record mutex");
        if let Some(v) = inner.handles.get_mut(handle) {
            v.retain(|(i, d, _)| !(i == issuer && d == id));
        }
    }

    /// Claim `(issuer, id)`. Call only for a caller already authorised.
    /// The record is charged to `handle`'s budget as well as the issuer's.
    pub async fn claim(
        &self,
        issuer: &str,
        handle: &str,
        id: &str,
        digest: &DocumentDigest,
        retain_until: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Admission, RejectReason> {
        let guard = self.partition(issuer, handle, now)?;
        match guard.claim(id, digest, retain_until, now).await {
            Ok(ReplayVerdict::Fresh) => {
                self.charge(handle, issuer, id, retain_until);
                Ok(Admission::Fresh)
            }
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
        handle: &str,
        id: &str,
        digest: &DocumentDigest,
        response: Option<&Value>,
    ) {
        if response.is_none() {
            self.uncharge(handle, issuer, id);
        }
        let guard = self
            .inner
            .lock()
            .expect("replay record mutex")
            .issuers
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
        self.inner
            .lock()
            .expect("replay record mutex")
            .issuers
            .get(issuer)
            .map_or(0, |g| g.len())
    }

    /// Records currently charged to `handle` (tests and metrics).
    pub fn len_for_handle(&self, handle: &str) -> usize {
        self.inner
            .lock()
            .expect("replay record mutex")
            .handles
            .get(handle)
            .map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn a_handle_budget_is_shared_by_every_issuer_on_it() {
        let r = ReplayRecord::with_per_handle(100, 3, 1_000);
        let now = Utc::now();
        let until = Some(now + chrono::TimeDelta::minutes(5));
        for (i, issuer) in ["did:a", "did:b", "did:c"].into_iter().enumerate() {
            let id = i.to_string();
            assert_eq!(
                r.claim(issuer, "h", &id, &digest(&id), until, now).await,
                Ok(Admission::Fresh)
            );
        }
        assert!(r
            .claim("did:d", "h", "9", &digest("9"), until, now)
            .await
            .is_err());
        // Another handle is unaffected, and a released claim frees its slot.
        assert_eq!(
            r.claim("did:d", "h2", "9", &digest("9"), until, now).await,
            Ok(Admission::Fresh)
        );
        r.complete("did:a", "h", "0", &digest("0"), None).await;
        assert_eq!(r.len_for_handle("h"), 2);
    }

    #[tokio::test]
    async fn at_the_soft_bound_only_issuers_over_their_share_are_refused() {
        let r = ReplayRecord::with_per_handle(1_000, 1_000, 10);
        let now = Utc::now();
        let until = Some(now + chrono::TimeDelta::minutes(5));
        for i in 0..10 {
            let id = i.to_string();
            assert_eq!(
                r.claim("did:flood", &id, &id, &digest(&id), until, now)
                    .await,
                Ok(Admission::Fresh)
            );
        }
        // Full: the flooder, far over its share, is refused ...
        assert!(r
            .claim("did:flood", "x", "x", &digest("x"), until, now)
            .await
            .is_err());
        // ... and a newcomer, under its share, is admitted.
        assert_eq!(
            r.claim("did:new", "y", "y", &digest("y"), until, now).await,
            Ok(Admission::Fresh)
        );
    }

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
            r.claim("did:a", "h", "x", &digest("x"), until, now).await,
            Ok(Admission::Fresh)
        );
        // The same id from another issuer is a different document.
        assert_eq!(
            r.claim("did:b", "h", "x", &digest("x2"), until, now).await,
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
                r.claim("did:a", id, id, &digest(id), until, now).await,
                Ok(Admission::Fresh)
            );
        }
        assert!(r
            .claim("did:a", "3", "3", &digest("3"), until, now)
            .await
            .is_err());
        assert_eq!(r.len_for("did:a"), 2, "nothing was evicted");
        // Another issuer is unaffected.
        assert_eq!(
            r.claim("did:b", "1", "1", &digest("1"), until, now).await,
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
            r.claim("did:a", "h", "x", &d, until, now).await,
            Ok(Admission::Fresh)
        );
        r.complete("did:a", "h", "x", &d, None).await;
        assert_eq!(
            r.claim("did:a", "h", "x", &d, until, now).await,
            Ok(Admission::Fresh)
        );
    }
}
