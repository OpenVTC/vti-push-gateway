//! Durable storage for the gateway's TSP relationship state.
//!
//! A TSP peer opens a relationship with an invite before it sends application
//! messages ([`crate::tsp`]), and the SDK's §7.2.2 gate silently drops every
//! application frame from a VID the gateway holds no relationship with. The
//! SDK's default [`RelationshipStore`](affinidi_tdk::messaging::RelationshipStore)
//! is in-memory and wiped on restart, so a restarted gateway forgot every peer
//! and dropped its traffic until each re-invited — this module is what fixes
//! that (mirrors `vti_common::relationship_store` in
//! `verifiable-trust-infrastructure`, adapted to the gateway's own on-disk
//! storage rather than its keyspace store, which the gateway does not have).
//!
//! [`RelationshipFileKv`] is a
//! [`RelationshipKv`](affinidi_tdk::messaging::RelationshipKv) over the same
//! JSON-snapshot mechanism [`crate::store::Store`] uses for the push registry:
//! in-memory map, debounced background flush, owner-only atomic writes via
//! [`crate::secretfile::write_owner_only_atomic`]. The SDK's
//! `PersistentRelationshipStore` layers the per-facet key encoding and
//! defaults on top, so this module only has to be the three-method byte store.
//! That one wrapper type persists every facet the trait keeps — relationship
//! state, thread digests, reply path and learned peer capability (including the
//! peer's mediator DID) — because they all go through the same `get`/`put`
//! calls here; there is no separate capability store to forget.
//!
//! **The snapshot holds no bearer secrets** (unlike the push registry's), but a
//! TSP peer opens a relationship with an unauthenticated invite, so the snapshot
//! is still written owner-only: nothing but the gateway's own TSP handling has
//! any business reading or writing it, and a world-readable copy would let
//! another local user watch (and spoof the shape of) this gateway's peer
//! relationships.
//!
//! ## Bounding growth
//!
//! `push/register` already has caps and a TTL sweep because it is anonymous;
//! the TSP relationship gate is reachable the same way (any peer that can speak
//! TSP to this gateway's mediator can send an invite, no `push/*` proof
//! required). Rather than a second, independent cap, this reuses the SDK's own
//! answer to the same problem (design note `tsp-relationship-recovery.md`,
//! D5/D6): [`maintenance_loop`] runs a periodic idle-eviction sweep
//! (`EvictionPolicy`, 7-day default) over every stored relationship, so an
//! invite that is never followed up and never answered again ages out rather
//! than accumulating forever. [`crate::tsp`] stamps activity (`touch`) on every
//! inbound frame it admits, so a live relationship never goes idle and only an
//! abandoned one is swept.
//!
//! The gateway only ever **accepts** inbound invites and replies within the
//! same socket session ([`crate::tsp::TspIntake`]); it never calls
//! `ATM::send_to` or forms an outbound relationship of its own, so it never
//! needs to route a message cross-mediator. The learned peer-mediator mapping
//! is still persisted (see above) in case that changes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use affinidi_tdk::messaging::errors::ATMError;
use affinidi_tdk::messaging::{EvictionPolicy, PersistentRelationshipStore, RelationshipKv};
use base64::Engine;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// The concrete durable relationship store the gateway builds — the type the
/// maintenance loop needs (`evict_idle` / `established_relationships` are on
/// `PersistentRelationshipStore`, not the `RelationshipStore` trait the
/// DIDComm/TSP listener is handed).
pub type GatewayRelationshipStore = PersistentRelationshipStore<SharedRelationshipKv>;

/// A cheaply-cloned handle to a [`RelationshipFileKv`] — a local newtype
/// around `Arc<RelationshipFileKv>` rather than the bare `Arc`, because the
/// orphan rules forbid implementing the SDK's (foreign) `RelationshipKv` for
/// `Arc` (foreign) of anything, `Arc` not being a fundamental type.
///
/// Letting the backend be a shared handle rather than an owned
/// `RelationshipFileKv` (which `PersistentRelationshipStore` would otherwise
/// hold exclusively) is what lets the caller keep a second handle to it
/// ([`Self::file_store`]) to spawn [`RelationshipFileKv::flush_loop`]
/// independently of the store wrapper.
#[derive(Clone)]
pub struct SharedRelationshipKv(Arc<RelationshipFileKv>);

impl SharedRelationshipKv {
    /// A second, owned handle to the underlying file store — for spawning
    /// [`RelationshipFileKv::flush_loop`] independently of the
    /// `PersistentRelationshipStore` that otherwise holds this exclusively.
    pub fn file_store(&self) -> Arc<RelationshipFileKv> {
        self.0.clone()
    }

    /// Write the snapshot now if anything changed since the last write — see
    /// [`RelationshipFileKv::flush`].
    pub fn flush(&self) -> bool {
        self.0.flush()
    }
}

/// A `RelationshipKv` backed by an in-memory map, **optionally** durable via a
/// JSON snapshot file — the same shape as [`crate::store::Store`].
///
/// Keys and values are opaque bytes the SDK constructs; this stores them
/// verbatim and knows nothing about the facets (state, digests, reply path,
/// capability) they encode.
pub struct RelationshipFileKv {
    map: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    /// JSON snapshot path; `None` = in-memory only (no durability).
    path: Option<PathBuf>,
    /// Set by every mutation, cleared by a snapshot write.
    dirty: AtomicBool,
    /// Snapshot writes performed, for tests.
    writes: AtomicU64,
}

/// On-disk snapshot shape: raw byte keys/values aren't valid JSON object keys,
/// so both are base64-encoded. Opaque to everything but this module.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Snapshot(HashMap<String, String>);

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

impl RelationshipFileKv {
    /// In-memory only (no persistence) — relationships are lost on restart,
    /// same as the SDK's own default.
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            path: None,
            dirty: AtomicBool::new(false),
            writes: AtomicU64::new(0),
        }
    }

    /// Open a **durable** store backed by the JSON snapshot at `path`. Loads
    /// the existing snapshot if present; a missing file starts empty; an
    /// unparseable file is logged and started empty (rather than refusing to
    /// boot — peers just re-invite).
    ///
    /// A snapshot left group- or world-readable by an older build is tightened
    /// to 0600 here, before it is read.
    pub fn open(path: PathBuf) -> Self {
        crate::secretfile::tighten_to_owner_only(&path);
        let map = match std::fs::read_to_string(&path) {
            Ok(s) => match serde_json::from_str::<Snapshot>(&s) {
                Ok(snap) => snap
                    .0
                    .iter()
                    .filter_map(|(k, v)| Some((unb64(k)?, unb64(v)?)))
                    .collect(),
                Err(e) => {
                    tracing::error!(error = %e, path = %path.display(),
                        "TSP relationship snapshot is unparseable; starting empty");
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(), // missing → fresh
        };
        tracing::info!(entries = map.len(), path = %path.display(),
            "TSP relationship store loaded from snapshot");
        Self {
            map: RwLock::new(map),
            path: Some(path),
            dirty: AtomicBool::new(false),
            writes: AtomicU64::new(0),
        }
    }

    /// Snapshot writes performed so far (tests).
    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    /// Write the snapshot if anything changed since the last write. Safe to
    /// call from anywhere; a no-op in memory.
    pub fn flush(&self) -> bool {
        let Some(path) = self.path.as_ref() else {
            self.dirty.store(false, Ordering::Release);
            return false;
        };
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return false;
        }
        let json = {
            let map = self.map.read().unwrap();
            let snap = Snapshot(
                map.iter()
                    .map(|(k, v)| (b64(k), b64(v)))
                    .collect::<HashMap<_, _>>(),
            );
            match serde_json::to_vec(&snap) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!(error = %e, "serialize TSP relationship snapshot");
                    return false;
                }
            }
        };
        match crate::secretfile::write_owner_only_atomic(path, &json) {
            Ok(()) => {
                self.writes.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                self.dirty.store(true, Ordering::Release);
                tracing::warn!(error = %e, path = %path.display(),
                    "persist TSP relationship snapshot (in-memory state updated; change not durable)");
                false
            }
        }
    }

    /// Background flusher: write the snapshot at most once per `every`.
    pub async fn flush_loop(self: Arc<Self>, every: Duration, shutdown: CancellationToken) {
        let mut ticker = tokio::time::interval(every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => { self.flush(); }
                _ = shutdown.cancelled() => {
                    self.flush();
                    return;
                }
            }
        }
    }
}

impl Default for RelationshipFileKv {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RelationshipFileKv {
    /// A dropped store flushes any pending change, so a shutdown (or a test
    /// that drops and reopens) does not lose the last mutations.
    fn drop(&mut self) {
        self.flush();
    }
}

#[async_trait::async_trait]
impl RelationshipKv for SharedRelationshipKv {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ATMError> {
        Ok(self.0.map.read().unwrap().get(key).cloned())
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), ATMError> {
        self.0
            .map
            .write()
            .unwrap()
            .insert(key.to_vec(), value.to_vec());
        self.0.mark_dirty();
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), ATMError> {
        let removed = self.0.map.write().unwrap().remove(key).is_some();
        if removed {
            self.0.mark_dirty();
        }
        Ok(())
    }

    async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ATMError> {
        Ok(self
            .0
            .map
            .read()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

/// Build the gateway's durable relationship store: a JSON snapshot at `path`
/// when given, in-memory otherwise (relationships are then lost on restart,
/// same as the SDK's default, with a warning the caller is expected to log).
pub fn build_relationship_store(path: Option<PathBuf>) -> Arc<GatewayRelationshipStore> {
    let kv = match path {
        Some(p) => RelationshipFileKv::open(p),
        None => RelationshipFileKv::new(),
    };
    Arc::new(PersistentRelationshipStore::new(SharedRelationshipKv(
        Arc::new(kv),
    )))
}

/// How often the idle-eviction sweep runs (matches
/// `vti_common::relationship_store`'s interval).
const SWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Background maintenance for the durable TSP relationship store (design note
/// `tsp-relationship-recovery.md`, D6/D9): logs how many relationships
/// survived a restart, then periodically evicts ones idle past
/// [`EvictionPolicy::default`] (7 days).
///
/// Spawn this once at gateway startup — it holds the store and does not depend
/// on the mediator socket, so it must not be tied to the mediator-connect path
/// (which can retry independently of this).
pub async fn maintenance_loop(store: Arc<GatewayRelationshipStore>, shutdown: CancellationToken) {
    match store.established_relationships().await {
        Ok(established) => info!(
            count = established.len(),
            "TSP relationships restored from the durable store"
        ),
        Err(e) => warn!(error = %e, "could not enumerate restored TSP relationships"),
    }

    let policy = EvictionPolicy::default();
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let Some(now_ms) = unix_millis() else { continue };
                match store.evict_idle(now_ms, &policy).await {
                    Ok(evicted) if !evicted.is_empty() => {
                        info!(count = evicted.len(), "evicted idle TSP relationships")
                    }
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "TSP relationship eviction sweep failed"),
                }
            }
            _ = shutdown.cancelled() => return,
        }
    }
}

pub(crate) fn unix_millis() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::messaging::RelationshipStore;
    use affinidi_tdk::tsp::RelationshipState;

    fn tmp_path() -> PathBuf {
        let dir = std::env::temp_dir();
        dir.join(format!(
            "vti-push-gateway-relationships-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    /// A relationship formed, then the store reopened over the same file (a
    /// new instance, as a gateway restart would build) — the state is still
    /// `Bidirectional` and still admits an application payload. This is the
    /// failure the SDK's §7.2.2 gate otherwise causes: an in-memory store wiped
    /// by a restart would drop every peer's traffic until it re-invited.
    #[tokio::test]
    async fn relationship_survives_a_restart_and_admits_a_payload() {
        let path = tmp_path();
        {
            let store = build_relationship_store(Some(path.clone()));
            store
                .set(
                    "did:example:us",
                    "did:example:peer",
                    RelationshipState::Bidirectional,
                )
                .await
                .unwrap();
            store.backend().flush();
        }
        // A fresh store instance over the same on-disk snapshot — what a
        // restarted process builds.
        let store = build_relationship_store(Some(path.clone()));
        let state = store
            .get("did:example:us", "did:example:peer")
            .await
            .unwrap();
        assert_eq!(state, RelationshipState::Bidirectional);
        assert!(
            state.admits_application_message(),
            "a restored Bidirectional relationship must still admit application traffic"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Without a path, nothing survives a rebuild — matches the SDK's own
    /// ephemeral default and documents the in-memory fallback.
    #[tokio::test]
    async fn without_a_path_nothing_persists() {
        let store = build_relationship_store(None);
        store
            .set(
                "did:example:us",
                "did:example:peer",
                RelationshipState::Bidirectional,
            )
            .await
            .unwrap();
        drop(store);
        let store = build_relationship_store(None);
        assert_eq!(
            store
                .get("did:example:us", "did:example:peer")
                .await
                .unwrap(),
            RelationshipState::None
        );
    }

    /// A snapshot written group-readable by an older build is tightened to
    /// 0600 on open.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_loose_snapshot_is_tightened_on_open() {
        use std::os::unix::fs::PermissionsExt;

        let path = tmp_path();
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _store = build_relationship_store(Some(path.clone()));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }
}
