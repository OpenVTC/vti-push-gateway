//! Gateway state: opaque handle → device push token (never disclosed to
//! triggers or the VTA) + the controller VTA + the VTA-provisioned trigger
//! allowlist.
//!
//! In-memory by default; **optionally durable** via a JSON snapshot file
//! ([`Store::open`]): the map is loaded on boot and rewritten by a background
//! flusher. Persistence is best-effort — a write failure is logged but never
//! fails the in-flight request (a device can always re-register). Suited to the
//! gateway's small registry; an embedded DB would be over-built here.
//!
//! **The snapshot is a secret file.** It holds raw APNs/FCM device tokens and
//! Web Push endpoints with their `p256dh`/`auth` subscription secrets. Those are
//! bearer credentials: whoever reads them can wake those devices, and — because
//! `push/register` is anonymous — can re-register them under a controller DID of
//! their own choosing. So the snapshot is written through a private temporary
//! file (mode 0600, unpredictable name, `O_EXCL`), flushed with `sync_all`, then
//! renamed into place; and a snapshot found readable beyond its owner is
//! tightened when it is opened.
//!
//! ## Why this file is more than a `HashMap`
//!
//! `push/register` is anonymous, so everything here is reachable by an
//! unauthenticated caller and the map is the thing a flood grows. Three
//! properties keep that bounded:
//!
//! - **Unprovisioned handles expire.** A freshly registered handle is inert
//!   until its VTA provisions a trigger, so a handle whose allowlist is still
//!   empty after [`StoreLimits::unprovisioned_ttl_secs`] is junk and is swept.
//!   This is the root-cause fix: anonymous growth becomes bounded churn rather
//!   than a monotonic leak.
//! - **Caps.** A total handle ceiling, and a per-push-token ceiling so one device
//!   token (or one stolen one) cannot occupy the registry on its own. The
//!   per-token count is maintained as an index rather than recomputed, so the
//!   check stays O(1) under exactly the flood it exists to stop.
//! - **Writes are debounced.** Every mutation used to reserialise the whole map
//!   under the write lock, which made the snapshot cost O(n) per anonymous
//!   request. Mutations now set a dirty flag and a background flusher writes at
//!   most once per interval, keeping temp-file + fsync + rename.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::egress::EgressPolicy;
use crate::secretfile;
use crate::types::{is_bounded_did, PushRegistration, WakeTriggerPolicy};

/// Unix seconds, or 0 if the clock is before the epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Everything the gateway holds for one registered push channel.
#[derive(Serialize, Deserialize)]
pub struct HandleRecord {
    /// The raw platform push token. Never returned to triggers or the VTA; sent
    /// only to the platform push service, and written in cleartext to the
    /// owner-only snapshot file when persistence is enabled.
    pub registration: PushRegistration,
    /// The DID of the VTA allowed to provision this handle's allowlist.
    pub controller_vta_did: String,
    /// DIDs allowed to trigger a wake. Empty until the VTA provisions it, so a
    /// freshly-registered handle wakes no one until its VTA opts triggers in.
    pub allowed_triggers: Vec<String>,
    /// Unix seconds when the handle was issued, for the unprovisioned sweep.
    ///
    /// `#[serde(default)]` keeps snapshots written before this field existed
    /// loadable. Those records read as `created_at = 0`, so a legacy handle that
    /// was never provisioned is swept on the first pass — which is the intended
    /// outcome, not a quirk: it is exactly the junk the sweep is for. A legacy
    /// handle that *was* provisioned has a non-empty allowlist and survives.
    #[serde(default)]
    pub created_at: u64,
}

/// Bounds on the registry. Anonymous callers can reach every one of these.
#[derive(Debug, Clone, Copy)]
pub struct StoreLimits {
    /// Total live handles before `register` is refused.
    pub max_handles: usize,
    /// Live handles sharing one push token / Web Push endpoint.
    pub max_per_token: usize,
    /// How long a handle may stay unprovisioned before it is swept.
    pub unprovisioned_ttl_secs: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_handles: 100_000,
            max_per_token: 4,
            unprovisioned_ttl_secs: 24 * 60 * 60,
        }
    }
}

/// Why a registration was not stored. Both map to a caller-safe message.
#[derive(Debug, PartialEq, Eq)]
pub enum InsertError {
    /// The registry is full ([`StoreLimits::max_handles`]).
    AtCapacity,
    /// This push token already has [`StoreLimits::max_per_token`] live handles.
    TooManyForToken,
}

impl InsertError {
    /// A reason safe to return to an anonymous caller.
    pub fn reason(&self) -> &'static str {
        match self {
            InsertError::AtCapacity => "gateway at capacity",
            InsertError::TooManyForToken => "too many handles for this push token",
        }
    }
}

/// The guarded state: the handle map plus the per-token index, under one lock so
/// they cannot drift apart.
#[derive(Default)]
struct State {
    handles: HashMap<String, HandleRecord>,
    /// Digest of a push token/endpoint → the handles registered against it.
    by_token: HashMap<String, Vec<String>>,
}

impl State {
    /// Add a record and index it. Callers check the caps first.
    fn add(&mut self, handle: String, record: HandleRecord) {
        let digest = token_digest(&record.registration);
        self.by_token
            .entry(digest)
            .or_default()
            .push(handle.clone());
        self.handles.insert(handle, record);
    }

    /// Remove a handle and de-index it.
    fn drop_handle(&mut self, handle: &str) -> bool {
        let Some(record) = self.handles.remove(handle) else {
            return false;
        };
        let digest = token_digest(&record.registration);
        if let Some(list) = self.by_token.get_mut(&digest) {
            list.retain(|h| h != handle);
            if list.is_empty() {
                self.by_token.remove(&digest);
            }
        }
        true
    }

    /// Rebuild `by_token` from `handles` — used after loading a snapshot.
    fn reindex(&mut self) {
        self.by_token.clear();
        for (handle, record) in &self.handles {
            self.by_token
                .entry(token_digest(&record.registration))
                .or_default()
                .push(handle.clone());
        }
    }
}

/// An opaque, stable key for "the same push destination".
///
/// A digest rather than the token itself: this is only ever compared, so there is
/// no reason to keep a second copy of a bearer credential in another map (and in
/// the keys of one, where it is easy to log by accident). SHA-256 truncated to
/// 128 bits — collision resistance well beyond what a counting index needs.
fn token_digest(registration: &PushRegistration) -> String {
    use base64::Engine;

    let material = match registration {
        PushRegistration::Apns { token, .. } => format!("apns:{token}"),
        PushRegistration::Fcm { token } => format!("fcm:{token}"),
        // The endpoint *is* the destination for Web Push; the keys only encrypt.
        PushRegistration::Webpush { endpoint, .. } => format!("webpush:{endpoint}"),
    };
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, material.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest.as_ref()[..16])
}

pub struct Store {
    state: RwLock<State>,
    /// JSON snapshot path; `None` = in-memory only (no durability).
    path: Option<PathBuf>,
    limits: StoreLimits,
    /// Set by every mutation, cleared by a snapshot write.
    dirty: AtomicBool,
    /// Snapshot writes performed. Lets a test assert the debounce actually
    /// collapses writes instead of trusting the timer.
    writes: AtomicU64,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
            path: None,
            limits: StoreLimits::default(),
            dirty: AtomicBool::new(false),
            writes: AtomicU64::new(0),
        }
    }
}

/// Outcome of a provision attempt — distinguishes "no such handle" from "caller
/// is not this handle's controller VTA" so the API can return the right status.
pub enum ProvisionOutcome {
    Ok,
    UnknownHandle,
    NotController,
}

/// Outcome of resolving a wake request against the allowlist.
pub enum WakeAuthz {
    /// Allowed — carries a clone of the token to push to.
    Allowed(PushRegistration),
    UnknownHandle,
    /// The trigger DID is not on this handle's allowlist.
    NotAllowed,
}

impl Store {
    /// In-memory store (no persistence), default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// In-memory store with explicit limits.
    ///
    /// Spelled out rather than `..Self::default()`: `Store` implements [`Drop`]
    /// (to flush a pending snapshot on shutdown), and struct-update syntax would
    /// have to move the other fields out of a `Drop` type, which Rust forbids.
    pub fn with_limits(limits: StoreLimits) -> Self {
        Self {
            state: RwLock::new(State::default()),
            path: None,
            limits,
            dirty: AtomicBool::new(false),
            writes: AtomicU64::new(0),
        }
    }

    /// Open a **durable** store backed by the JSON snapshot at `path`. Loads the
    /// existing snapshot if present; a missing file starts empty; an unparseable
    /// file is logged and started empty (rather than refusing to boot — devices
    /// re-register).
    ///
    /// Records that fail current registration validation under `policy` (e.g.
    /// stored before endpoint validation existed) are dropped with a warning;
    /// the next snapshot write removes them from disk.
    ///
    /// A snapshot left group- or world-readable by an older build (which wrote it
    /// at the umask default) is tightened to 0600 here, with a warning. The
    /// warning matters as much as the fix: the tokens in it have already been
    /// readable, so they should be treated as exposed and the devices
    /// re-registered.
    pub fn open(path: PathBuf, policy: &EgressPolicy) -> Self {
        Self::open_with_limits(path, policy, StoreLimits::default())
    }

    /// [`Store::open`] with explicit limits.
    ///
    /// The tightening happens here rather than in [`Store::open`] so that every
    /// durable open gets it, and before the snapshot is read.
    pub fn open_with_limits(path: PathBuf, policy: &EgressPolicy, limits: StoreLimits) -> Self {
        secretfile::tighten_to_owner_only(&path);
        let mut handles: HashMap<String, HandleRecord> = match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                tracing::error!(error = %e, path = %path.display(),
                    "gateway store snapshot is unparseable; starting empty");
                HashMap::new()
            }),
            Err(_) => HashMap::new(), // missing → fresh
        };
        handles.retain(|_, rec| {
            let verdict = rec.registration.validate(policy).and_then(|()| {
                if is_bounded_did(&rec.controller_vta_did) {
                    Ok(())
                } else {
                    Err("controllerVtaDid must be a DID of at most 512 bytes")
                }
            });
            match verdict {
                Ok(()) => true,
                Err(reason) => {
                    tracing::warn!(
                        platform = rec.registration.platform(),
                        reason,
                        "dropping stored handle that fails registration validation"
                    );
                    false
                }
            }
        });
        // A snapshot over the cap is loaded rather than truncated: dropping live
        // devices' handles because a limit was lowered would be worse than being
        // temporarily over it. The cap then refuses new registrations until the
        // sweep brings the count down.
        if handles.len() > limits.max_handles {
            tracing::warn!(
                handles = handles.len(),
                max_handles = limits.max_handles,
                "snapshot holds more handles than the configured cap; \
                 registrations are refused until it drains"
            );
        }
        tracing::info!(handles = handles.len(), path = %path.display(),
            "gateway store loaded from snapshot");
        let mut state = State {
            handles,
            by_token: HashMap::new(),
        };
        state.reindex();
        Self {
            state: RwLock::new(state),
            path: Some(path),
            limits,
            dirty: AtomicBool::new(false),
            writes: AtomicU64::new(0),
        }
    }

    /// The configured limits.
    pub fn limits(&self) -> StoreLimits {
        self.limits
    }

    /// Live handle count.
    pub fn len(&self) -> usize {
        self.state.read().unwrap().handles.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot writes performed so far.
    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    /// Mark the map as changed; the background flusher picks it up.
    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    /// Write the snapshot if anything changed since the last write. Returns
    /// whether a write happened. Safe to call from anywhere; no-op in memory.
    pub fn flush(&self) -> bool {
        if self.path.is_none() {
            // Nothing to write, but don't leave the flag set forever.
            self.dirty.store(false, Ordering::Release);
            return false;
        }
        // Claim the work: if another flush already took it, don't write twice.
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return false;
        }
        let path = self.path.as_ref().expect("checked above");
        let json = {
            let state = self.state.read().unwrap();
            match serde_json::to_vec(&state.handles) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!(error = %e, "serialize gateway store snapshot");
                    return false;
                }
            }
        };
        match write_snapshot(path, &json) {
            Ok(()) => {
                self.writes.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                // Put the flag back so the next tick retries.
                self.dirty.store(true, Ordering::Release);
                tracing::warn!(error = %e, path = %path.display(),
                    "persist gateway store snapshot (in-memory state updated; change not durable)");
                false
            }
        }
    }

    /// Record a freshly-issued handle, subject to the caps. Allowlist starts
    /// empty (the VTA opts triggers in via `provision`).
    pub fn insert(
        &self,
        handle: String,
        registration: PushRegistration,
        controller_vta_did: String,
    ) -> Result<(), InsertError> {
        self.insert_at(handle, registration, controller_vta_did, now_secs())
    }

    /// [`Store::insert`] with an explicit creation time, for tests and for the
    /// sweep's benefit.
    pub fn insert_at(
        &self,
        handle: String,
        registration: PushRegistration,
        controller_vta_did: String,
        created_at: u64,
    ) -> Result<(), InsertError> {
        let mut state = self.state.write().unwrap();
        if state.handles.len() >= self.limits.max_handles {
            return Err(InsertError::AtCapacity);
        }
        let digest = token_digest(&registration);
        if state
            .by_token
            .get(&digest)
            .is_some_and(|l| l.len() >= self.limits.max_per_token)
        {
            return Err(InsertError::TooManyForToken);
        }
        state.add(
            handle,
            HandleRecord {
                registration,
                controller_vta_did,
                allowed_triggers: Vec::new(),
                created_at,
            },
        );
        drop(state);
        self.mark_dirty();
        Ok(())
    }

    /// Set a handle's allowlist — only the handle's controller VTA may do so.
    pub fn provision(
        &self,
        handle: &str,
        caller_did: &str,
        policy: WakeTriggerPolicy,
    ) -> ProvisionOutcome {
        let mut state = self.state.write().unwrap();
        let outcome = match state.handles.get_mut(handle) {
            None => ProvisionOutcome::UnknownHandle,
            Some(rec) if rec.controller_vta_did != caller_did => ProvisionOutcome::NotController,
            Some(rec) => {
                rec.allowed_triggers = policy.allowed_triggers;
                ProvisionOutcome::Ok
            }
        };
        drop(state);
        if matches!(outcome, ProvisionOutcome::Ok) {
            self.mark_dirty();
        }
        outcome
    }

    /// Whether `caller_did` is `handle`'s controller VTA — the authorisation
    /// half of [`Self::provision`], without applying anything. `Ok` when it is.
    pub fn check_controller(&self, handle: &str, caller_did: &str) -> ProvisionOutcome {
        let state = self.state.read().unwrap();
        match state.handles.get(handle) {
            None => ProvisionOutcome::UnknownHandle,
            Some(rec) if rec.controller_vta_did != caller_did => ProvisionOutcome::NotController,
            Some(_) => ProvisionOutcome::Ok,
        }
    }

    /// Resolve a wake: the trigger DID must be on the handle's allowlist.
    pub fn authorize_wake(&self, handle: &str, trigger_did: &str) -> WakeAuthz {
        let state = self.state.read().unwrap();
        match state.handles.get(handle) {
            None => WakeAuthz::UnknownHandle,
            Some(rec) if rec.allowed_triggers.iter().any(|d| d == trigger_did) => {
                WakeAuthz::Allowed(rec.registration.clone())
            }
            Some(_) => WakeAuthz::NotAllowed,
        }
    }

    /// Drop a handle whose token the push service reported permanently
    /// unregistered (binding §3.2 dead-token rule).
    pub fn remove(&self, handle: &str) {
        let mut state = self.state.write().unwrap();
        let removed = state.drop_handle(handle);
        drop(state);
        if removed {
            self.mark_dirty();
        }
    }

    /// Remove handles that are still unprovisioned `ttl_secs` after they were
    /// issued. Returns how many were dropped.
    ///
    /// Only ever removes handles with an **empty** allowlist: a provisioned
    /// handle is in real use and is never swept, however old it is.
    pub fn sweep_unprovisioned(&self, ttl_secs: u64, now: u64) -> usize {
        let mut state = self.state.write().unwrap();
        let stale: Vec<String> = state
            .handles
            .iter()
            .filter(|(_, rec)| {
                rec.allowed_triggers.is_empty() && now.saturating_sub(rec.created_at) >= ttl_secs
            })
            .map(|(h, _)| h.clone())
            .collect();
        for handle in &stale {
            state.drop_handle(handle);
        }
        let dropped = stale.len();
        drop(state);
        if dropped > 0 {
            self.mark_dirty();
            tracing::info!(
                dropped,
                ttl_secs,
                "swept handles that were never provisioned"
            );
        }
        dropped
    }

    /// Background sweeper: drop never-provisioned handles every `every`.
    pub async fn sweep_loop(self: Arc<Self>, every: Duration, shutdown: CancellationToken) {
        let ttl = self.limits.unprovisioned_ttl_secs;
        let mut ticker = tokio::time::interval(every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => { self.sweep_unprovisioned(ttl, now_secs()); }
                _ = shutdown.cancelled() => return,
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
                    // Last write on the way out, so a clean shutdown is durable.
                    self.flush();
                    return;
                }
            }
        }
    }
}

impl Drop for Store {
    /// A dropped store flushes any pending change, so a shutdown (or a test that
    /// drops and reopens) does not lose the last mutations.
    fn drop(&mut self) {
        self.flush();
    }
}

/// Write the snapshot to `path` atomically, owner-only, and durably.
///
/// The temporary file comes from `tempfile::NamedTempFile::new_in`, which creates
/// it with `O_EXCL` under an unpredictable name at mode 0600. The previous
/// `path.with_extension("json.tmp")` + `std::fs::write` had neither property: the
/// temp name was entirely predictable, so anything that could create a file in
/// the store's directory could pre-plant a symlink there and have the gateway
/// write every device token wherever it pointed; and the file landed at the
/// umask default, typically 0644. `sync_all` before `persist` means the rename
/// cannot publish a truncated snapshot after a crash.
fn write_snapshot(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;

    // `new_in` needs a directory, and a bare filename's parent is empty.
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("create temp snapshot in {}: {e}", dir.display()))?;
    tmp.write_all(bytes)
        .map_err(|e| format!("write temp snapshot: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("sync temp snapshot: {e}"))?;
    // `persist` renames over `path`, so the snapshot inherits the temp file's
    // 0600 rather than whatever the old file had.
    tmp.persist(path)
        .map_err(|e| format!("rename temp snapshot into place: {}", e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WebPushKeys;

    /// A syntactically valid APNs registration: the two-character hex `pair`
    /// repeated into a 64-character device token.
    fn apns(pair: &str) -> PushRegistration {
        PushRegistration::Apns {
            token: pair.repeat(32),
            topic: "org.openvtc.vta.agent".to_string(),
            environment: None,
        }
    }

    /// A distinct APNs registration per index, for cap tests.
    fn apns_n(n: usize) -> PushRegistration {
        PushRegistration::Apns {
            token: format!("{n:064x}"),
            topic: "org.openvtc.vta.agent".to_string(),
            environment: None,
        }
    }

    fn open(path: PathBuf) -> Store {
        Store::open(path, &EgressPolicy::default())
    }

    /// The controller DID `provision_self` acts as. Handles it provisions must
    /// have been inserted under this DID.
    const CONTROLLER: &str = "did:web:vta.example";

    fn provision_self(store: &Store, handle: &str) {
        let outcome = store.provision(
            handle,
            CONTROLLER,
            WakeTriggerPolicy {
                allowed_triggers: vec!["did:key:zT".into()],
            },
        );
        // Asserted so a controller-DID mismatch fails here, naming the cause,
        // rather than surfacing as a confusing count three assertions later.
        assert!(
            matches!(outcome, ProvisionOutcome::Ok),
            "provision_self: {handle} must be registered under {CONTROLLER}"
        );
    }

    /// Records written before registration validation existed are dropped on
    /// open; valid records survive.
    #[test]
    fn open_drops_records_that_fail_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");
        let keys = WebPushKeys {
            p256dh:
                "BHTHkS5TN8hSA9_AzgRusH55jqrZjomGJ42mYrmFNIKH1cc0JnR6ZzwjcWQljvhdjlapl3nOtq2P6e9IMjMoWrY"
                    .into(),
            auth: "-8GwtL6MnCVPpyjEYoad2A".into(),
        };
        {
            // `insert` does not validate, so it can write legacy-shaped records.
            let store = open(path.clone());
            let legacy = [
                (
                    "ok-webpush",
                    PushRegistration::Webpush {
                        endpoint: "https://fcm.googleapis.com/fcm/send/x".into(),
                        keys: keys.clone(),
                    },
                ),
                ("ok-apns", apns("ab")),
                (
                    "bad-loopback",
                    PushRegistration::Webpush {
                        endpoint: "http://127.0.0.1:9099/x".into(),
                        keys: keys.clone(),
                    },
                ),
                (
                    "bad-keys",
                    PushRegistration::Webpush {
                        endpoint: "https://fcm.googleapis.com/fcm/send/y".into(),
                        keys: WebPushKeys {
                            p256dh: "k".into(),
                            auth: "a".into(),
                        },
                    },
                ),
                (
                    "bad-apns-token",
                    PushRegistration::Apns {
                        token: "../x".into(),
                        topic: "org.openvtc.vta.agent".into(),
                        environment: None,
                    },
                ),
            ];
            for (h, reg) in legacy {
                store
                    .insert(h.into(), reg, "did:web:vta.example".into())
                    .unwrap();
                provision_self(&store, h);
            }
        }

        let reopened = open(path);
        for h in ["ok-webpush", "ok-apns"] {
            assert!(
                matches!(
                    reopened.authorize_wake(h, "did:key:zT"),
                    WakeAuthz::Allowed(_)
                ),
                "{h} should survive reopen"
            );
        }
        for h in ["bad-loopback", "bad-keys", "bad-apns-token"] {
            assert!(
                matches!(
                    reopened.authorize_wake(h, "did:key:zT"),
                    WakeAuthz::UnknownHandle
                ),
                "{h} should be dropped on reopen"
            );
        }
    }

    /// A durable store reloads its handles, allowlists, and tokens after a
    /// "restart" (drop + reopen the same snapshot), and a removed handle stays
    /// gone. The drop is what flushes.
    #[test]
    fn snapshot_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");

        {
            let store = open(path.clone());
            store
                .insert("h1".into(), apns("a1"), "did:web:vta.example".into())
                .unwrap();
            store
                .insert("h2".into(), apns("b2"), "did:web:vta.example".into())
                .unwrap();
            store.provision(
                "h1",
                "did:web:vta.example",
                WakeTriggerPolicy {
                    allowed_triggers: vec!["did:key:zTrigger".into()],
                },
            );
            store.remove("h2");
        } // drop → flush → "restart"

        let reopened = open(path);
        // h1 persisted with its token + provisioned allowlist.
        match reopened.authorize_wake("h1", "did:key:zTrigger") {
            WakeAuthz::Allowed(PushRegistration::Apns { token, .. }) => {
                assert_eq!(token, "a1".repeat(32))
            }
            _ => panic!("h1 should be allowed for the provisioned trigger after reopen"),
        }
        // A non-allowlisted trigger is still rejected.
        assert!(matches!(
            reopened.authorize_wake("h1", "did:key:zStranger"),
            WakeAuthz::NotAllowed
        ));
        // h2 was removed before the restart → gone.
        assert!(matches!(
            reopened.authorize_wake("h2", "did:key:zTrigger"),
            WakeAuthz::UnknownHandle
        ));
    }

    /// A missing snapshot file starts empty (fresh gateway), not an error.
    #[test]
    fn missing_snapshot_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path().join("does-not-exist.json"));
        assert!(matches!(
            store.authorize_wake("h1", "did:key:zTrigger"),
            WakeAuthz::UnknownHandle
        ));
    }

    /// An existing world-readable snapshot (written by a pre-fix build) is
    /// tightened when the store is opened, and its contents still load.
    #[test]
    #[cfg(unix)]
    fn open_tightens_a_world_readable_snapshot() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");
        {
            let store = open(path.clone());
            store
                .insert("h1".into(), apns("a1"), "did:web:vta.example".into())
                .unwrap();
            store.provision(
                "h1",
                "did:web:vta.example",
                WakeTriggerPolicy {
                    allowed_triggers: vec!["did:key:zT".into()],
                },
            );
        }
        // Simulate the pre-fix umask-default snapshot.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let reopened = open(path.clone());
        assert_eq!(
            std::fs::metadata(&path).unwrap().mode() & 0o777,
            0o600,
            "open must tighten a group/world-readable snapshot"
        );
        assert!(
            matches!(
                reopened.authorize_wake("h1", "did:key:zT"),
                WakeAuthz::Allowed(_)
            ),
            "tightening must not disturb the contents"
        );
    }

    /// A symlink pre-planted at the old, predictable temp path is not followed:
    /// the tokens go to the snapshot, never through the attacker's link.
    #[test]
    #[cfg(unix)]
    fn predictable_temp_path_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");

        // The pre-fix code wrote exactly here.
        let planted = path.with_extension("json.tmp");
        let sentinel = dir.path().join("sentinel");
        std::fs::write(&sentinel, b"untouched").unwrap();
        std::os::unix::fs::symlink(&sentinel, &planted).unwrap();

        let store = open(path.clone());
        store
            .insert("h1".into(), apns("a1"), "did:web:vta.example".into())
            .unwrap();
        // Nothing reaches disk until a flush now that writes are debounced.
        assert!(store.flush(), "the registration is written");

        // The sentinel is unchanged: nothing was written through the symlink.
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
        // The planted link is still just a dangling-free symlink, not a snapshot.
        assert!(std::fs::symlink_metadata(&planted)
            .unwrap()
            .file_type()
            .is_symlink());
        // And the real snapshot has the token.
        let snapshot = std::fs::read_to_string(&path).unwrap();
        assert!(snapshot.contains(&"a1".repeat(32)), "{snapshot}");
    }

    /// An in-memory store (no path) works and writes no file.
    #[test]
    fn in_memory_store_persists_nothing() {
        let store = Store::new();
        store
            .insert("h1".into(), apns("c3"), "did:web:vta.example".into())
            .unwrap();
        provision_self(&store, "h1");
        assert!(matches!(
            store.authorize_wake("h1", "did:key:zT"),
            WakeAuthz::Allowed(_)
        ));
        assert_eq!(store.writes(), 0, "in-memory store must not write");
    }

    /// A snapshot written before `created_at` existed still loads, and its
    /// unprovisioned records are swept on the first pass while provisioned ones
    /// survive.
    #[test]
    fn legacy_snapshot_without_created_at_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");
        // Hand-written in the pre-`created_at` shape.
        let legacy = serde_json::json!({
            "old-provisioned": {
                "registration": { "platform": "apns", "token": "ab".repeat(32),
                                  "topic": "org.openvtc.vta.agent" },
                "controller_vta_did": "did:web:vta.example",
                "allowed_triggers": ["did:key:zT"],
            },
            "old-unprovisioned": {
                "registration": { "platform": "apns", "token": "cd".repeat(32),
                                  "topic": "org.openvtc.vta.agent" },
                "controller_vta_did": "did:web:vta.example",
                "allowed_triggers": [],
            },
        });
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let store = open(path);
        assert_eq!(store.len(), 2, "both legacy records load");
        // created_at defaulted to 0 → the unprovisioned one is already stale.
        assert_eq!(store.sweep_unprovisioned(86_400, now_secs()), 1);
        assert!(matches!(
            store.authorize_wake("old-provisioned", "did:key:zT"),
            WakeAuthz::Allowed(_)
        ));
        assert!(matches!(
            store.authorize_wake("old-unprovisioned", "did:key:zT"),
            WakeAuthz::UnknownHandle
        ));
    }

    /// An unprovisioned handle disappears once the TTL has passed; a provisioned
    /// one is never swept, however old.
    #[test]
    fn sweep_drops_only_stale_unprovisioned_handles() {
        let store = Store::new();
        let ttl = 86_400;
        let t0 = 1_000_000;

        store
            .insert_at("fresh".into(), apns_n(1), CONTROLLER.into(), t0)
            .unwrap();
        store
            .insert_at("stale".into(), apns_n(2), CONTROLLER.into(), t0)
            .unwrap();
        store
            .insert_at("provisioned".into(), apns_n(3), CONTROLLER.into(), t0)
            .unwrap();
        provision_self(&store, "provisioned");

        // Just before the TTL: nothing is stale.
        assert_eq!(store.sweep_unprovisioned(ttl, t0 + ttl - 1), 0);
        assert_eq!(store.len(), 3);

        // At the TTL: both unprovisioned handles go, the provisioned one stays.
        assert_eq!(store.sweep_unprovisioned(ttl, t0 + ttl), 2);
        assert_eq!(store.len(), 1);
        assert!(matches!(
            store.authorize_wake("provisioned", "did:key:zT"),
            WakeAuthz::Allowed(_)
        ));
    }

    /// The sweeper task runs on its interval under a paused clock.
    #[tokio::test(start_paused = true)]
    async fn sweep_loop_runs_on_its_interval() {
        let store = Arc::new(Store::with_limits(StoreLimits {
            unprovisioned_ttl_secs: 1,
            ..StoreLimits::default()
        }));
        // created_at 0 → stale against any wall-clock now.
        store
            .insert_at("stale".into(), apns_n(1), "did:web:vta".into(), 0)
            .unwrap();
        assert_eq!(store.len(), 1);

        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(
            store
                .clone()
                .sweep_loop(Duration::from_secs(60), shutdown.clone()),
        );

        // The first tick of `interval` fires immediately; advance past a second.
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert_eq!(store.len(), 0, "the sweeper dropped the stale handle");

        shutdown.cancel();
        handle.await.unwrap();
    }

    /// The total cap refuses the handle that would exceed it, and says why.
    #[test]
    fn max_handles_refuses_the_eleventh() {
        let store = Store::with_limits(StoreLimits {
            max_handles: 10,
            ..StoreLimits::default()
        });
        for i in 0..10 {
            store
                .insert(format!("h{i}"), apns_n(i), "did:web:vta".into())
                .expect("within the cap");
        }
        assert_eq!(
            store.insert("h10".into(), apns_n(10), "did:web:vta".into()),
            Err(InsertError::AtCapacity)
        );
        assert_eq!(store.len(), 10, "the refused handle was not stored");

        // Freeing one lets a registration through again.
        store.remove("h0");
        store
            .insert("h10".into(), apns_n(10), "did:web:vta".into())
            .expect("space was freed");
    }

    /// One push token cannot occupy the registry: the per-token cap counts live
    /// handles sharing a destination, and frees up as they are removed.
    #[test]
    fn per_token_cap_limits_one_destination() {
        let store = Store::with_limits(StoreLimits {
            max_per_token: 2,
            ..StoreLimits::default()
        });
        let same = || apns("aa");

        store
            .insert("a".into(), same(), "did:web:vta".into())
            .unwrap();
        store
            .insert("b".into(), same(), "did:web:vta".into())
            .unwrap();
        assert_eq!(
            store.insert("c".into(), same(), "did:web:vta".into()),
            Err(InsertError::TooManyForToken)
        );
        // A different token is unaffected.
        store
            .insert("d".into(), apns("bb"), "did:web:vta".into())
            .unwrap();
        // Removing one frees a slot.
        store.remove("a");
        store
            .insert("c".into(), same(), "did:web:vta".into())
            .unwrap();
        assert_eq!(store.len(), 3);
    }

    /// A Web Push registration is keyed by its endpoint, so the same
    /// subscription re-registered with fresh keys still counts as one
    /// destination.
    #[test]
    fn per_token_cap_keys_webpush_on_the_endpoint() {
        let store = Store::with_limits(StoreLimits {
            max_per_token: 1,
            ..StoreLimits::default()
        });
        let sub = |auth: &str| {
            PushRegistration::Webpush {
            endpoint: "https://fcm.googleapis.com/fcm/send/same".into(),
            keys: WebPushKeys {
                p256dh: "BHTHkS5TN8hSA9_AzgRusH55jqrZjomGJ42mYrmFNIKH1cc0JnR6ZzwjcWQljvhdjlapl3nOtq2P6e9IMjMoWrY".into(),
                auth: auth.into(),
            },
        }
        };
        store
            .insert(
                "a".into(),
                sub("-8GwtL6MnCVPpyjEYoad2A"),
                "did:web:vta".into(),
            )
            .unwrap();
        assert_eq!(
            store.insert(
                "b".into(),
                sub("differentauthvalue00"),
                "did:web:vta".into()
            ),
            Err(InsertError::TooManyForToken),
            "the endpoint is the destination; new keys do not buy a new slot"
        );
    }

    /// 1,000 inserts cause no snapshot write on their own, and one flush after
    /// them writes exactly once — the debounce, rather than an O(n) rewrite per
    /// anonymous request.
    #[test]
    fn inserts_are_debounced_into_few_snapshot_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");
        let store = open(path.clone());

        for i in 0..1_000 {
            store
                .insert(format!("h{i}"), apns_n(i), "did:web:vta.example".into())
                .unwrap();
        }
        assert_eq!(
            store.writes(),
            0,
            "mutations must not write the snapshot themselves"
        );

        assert!(store.flush(), "the pending change is written");
        assert_eq!(store.writes(), 1);
        // Nothing changed since → no second write.
        assert!(!store.flush());
        assert_eq!(store.writes(), 1, "a clean store does not rewrite");

        // And the single write holds all 1,000 handles.
        let reopened = open(path);
        assert_eq!(reopened.len(), 1_000);
    }

    /// The snapshot holds bearer push credentials, so it must be owner-only —
    /// both when freshly created and after a rewrite.
    #[test]
    #[cfg(unix)]
    fn snapshot_is_owner_only() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");
        let store = open(path.clone());
        store
            .insert("h1".into(), apns("a1"), "did:web:vta.example".into())
            .unwrap();
        assert!(store.flush(), "the pending registration is written");
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "fresh snapshot must be 0600, was {mode:04o}");

        // A rewrite keeps it owner-only (the rename brings the temp file's mode).
        store
            .insert("h2".into(), apns("b2"), "did:web:vta.example".into())
            .unwrap();
        assert!(store.flush(), "the second registration is written");
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "rewritten snapshot must stay 0600");
    }

    /// The snapshot's mode across the whole lifecycle, for every way an older
    /// build could have left it loose — not only the 0644 that a umask of 022
    /// happens to produce, which is all `open_tightens_a_world_readable_snapshot`
    /// covers.
    ///
    /// `05_plaintext_store_snapshot.json` is the PoC's copy of this file: raw
    /// APNs device tokens and Web Push subscription secrets in cleartext. Those
    /// are bearer credentials and `push/register` is anonymous, so the file mode
    /// is what stands between them and every other account on the host. The
    /// lifecycle is: a loose file on disk → `open` tightens it → the records
    /// still load → a mutation rewrites it → it is still owner-only. A fix that
    /// tightened on open but let the rewrite path reintroduce the umask default
    /// would pass the existing gates and fail this one.
    #[test]
    #[cfg(unix)]
    fn every_loose_snapshot_mode_is_tightened_for_the_whole_lifecycle() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let token = "a1".repeat(32);
        for loose in [0o604, 0o620, 0o640, 0o644, 0o660, 0o664, 0o666, 0o777] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("gateway-store.json");
            {
                let store = open(path.clone());
                store
                    .insert("h1".into(), apns("a1"), CONTROLLER.into())
                    .unwrap();
                provision_self(&store, "h1");
            } // drop → flush

            // Stand in for the pre-fix write, which landed at the umask default.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(loose)).unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().mode() & 0o777,
                loose,
                "the fixture itself must start loose"
            );

            let reopened = open(path.clone());
            assert_eq!(
                std::fs::metadata(&path).unwrap().mode() & 0o777,
                0o600,
                "open must tighten a snapshot left at {loose:04o}"
            );
            // The tokens really are in there in cleartext, so the mode is
            // protecting something rather than guarding an empty file.
            assert!(
                std::fs::read_to_string(&path).unwrap().contains(&token),
                "the snapshot holds the raw token, so it is a secret file"
            );
            assert!(
                matches!(
                    reopened.authorize_wake("h1", "did:key:zT"),
                    WakeAuthz::Allowed(_)
                ),
                "tightening {loose:04o} must not disturb the contents"
            );

            // And the rewrite that follows the next mutation stays owner-only.
            reopened
                .insert("h2".into(), apns("b2"), CONTROLLER.into())
                .unwrap();
            assert!(reopened.flush(), "the second registration is written");
            assert_eq!(
                std::fs::metadata(&path).unwrap().mode() & 0o777,
                0o600,
                "the rewrite after tightening {loose:04o} must stay 0600"
            );
        }
    }
}
