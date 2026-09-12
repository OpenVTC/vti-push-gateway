//! Gateway state: opaque handle → device push token (never disclosed to
//! triggers or the VTA) + the controller VTA + the VTA-provisioned trigger
//! allowlist.
//!
//! In-memory by default; **optionally durable** via a JSON snapshot file
//! (`Store::open`): the map is loaded on boot and atomically rewritten after
//! every mutation, so handles/tokens survive a restart. Persistence is
//! best-effort — a write failure is logged but never fails the in-flight request
//! (a device can always re-register). Suited to the gateway's small, low-write
//! registry; an embedded DB would be over-built here.
//!
//! **The snapshot is a secret file.** It holds raw APNs/FCM device tokens and
//! Web Push endpoints with their `p256dh`/`auth` subscription secrets. Those are
//! bearer credentials: whoever reads them can wake those devices, and — because
//! `push/register` is anonymous — can re-register them under a controller DID of
//! their own choosing. So the snapshot is written through a private temporary
//! file (mode 0600, unpredictable name, `O_EXCL`), flushed with `sync_all`, then
//! renamed into place; and a snapshot found readable beyond its owner is
//! tightened when it is opened.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::egress::EgressPolicy;
use crate::secretfile;
use crate::types::{is_bounded_did, PushRegistration, WakeTriggerPolicy};

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
}

#[derive(Default)]
pub struct Store {
    handles: RwLock<HashMap<String, HandleRecord>>,
    /// JSON snapshot path; `None` = in-memory only (no durability).
    path: Option<PathBuf>,
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
    /// In-memory store (no persistence).
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a **durable** store backed by the JSON snapshot at `path`. Loads the
    /// existing snapshot if present; a missing file starts empty; an unparseable
    /// file is logged and started empty (rather than refusing to boot — devices
    /// re-register). Subsequent mutations rewrite the snapshot.
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
        tracing::info!(handles = handles.len(), path = %path.display(),
            "gateway store loaded from snapshot");
        Self {
            handles: RwLock::new(handles),
            path: Some(path),
        }
    }

    /// Serialize + atomically rewrite the snapshot. Called while holding the
    /// write lock so the persisted snapshot matches the just-applied mutation.
    /// No-op when in-memory; best-effort otherwise.
    fn persist_locked(&self, handles: &HashMap<String, HandleRecord>) {
        let Some(path) = &self.path else {
            return;
        };
        let json = match serde_json::to_vec(handles) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "serialize gateway store snapshot");
                return;
            }
        };
        if let Err(e) = write_snapshot(path, &json) {
            tracing::warn!(error = %e, path = %path.display(),
                "persist gateway store snapshot (in-memory state updated; change not durable)");
        }
    }

    /// Record a freshly-issued handle. Allowlist starts empty (the VTA opts
    /// triggers in via `provision`).
    pub fn insert(
        &self,
        handle: String,
        registration: PushRegistration,
        controller_vta_did: String,
    ) {
        let mut handles = self.handles.write().unwrap();
        handles.insert(
            handle,
            HandleRecord {
                registration,
                controller_vta_did,
                allowed_triggers: Vec::new(),
            },
        );
        self.persist_locked(&handles);
    }

    /// Set a handle's allowlist — only the handle's controller VTA may do so.
    pub fn provision(
        &self,
        handle: &str,
        caller_did: &str,
        policy: WakeTriggerPolicy,
    ) -> ProvisionOutcome {
        let mut handles = self.handles.write().unwrap();
        let outcome = match handles.get_mut(handle) {
            None => ProvisionOutcome::UnknownHandle,
            Some(rec) if rec.controller_vta_did != caller_did => ProvisionOutcome::NotController,
            Some(rec) => {
                rec.allowed_triggers = policy.allowed_triggers;
                ProvisionOutcome::Ok
            }
        };
        if matches!(outcome, ProvisionOutcome::Ok) {
            self.persist_locked(&handles);
        }
        outcome
    }

    /// Resolve a wake: the trigger DID must be on the handle's allowlist.
    pub fn authorize_wake(&self, handle: &str, trigger_did: &str) -> WakeAuthz {
        let handles = self.handles.read().unwrap();
        match handles.get(handle) {
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
        let mut handles = self.handles.write().unwrap();
        if handles.remove(handle).is_some() {
            self.persist_locked(&handles);
        }
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

    fn open(path: PathBuf) -> Store {
        Store::open(path, &EgressPolicy::default())
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
                store.insert(h.into(), reg, "did:web:vta.example".into());
                store.provision(
                    h,
                    "did:web:vta.example",
                    WakeTriggerPolicy {
                        allowed_triggers: vec!["did:key:zT".into()],
                    },
                );
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
    /// gone.
    #[test]
    fn snapshot_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");

        {
            let store = open(path.clone());
            store.insert("h1".into(), apns("a1"), "did:web:vta.example".into());
            store.insert("h2".into(), apns("b2"), "did:web:vta.example".into());
            store.provision(
                "h1",
                "did:web:vta.example",
                WakeTriggerPolicy {
                    allowed_triggers: vec!["did:key:zTrigger".into()],
                },
            );
            store.remove("h2");
        } // drop → "restart"

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

    /// The snapshot holds bearer push credentials, so it must be owner-only —
    /// both when freshly created and after a rewrite.
    #[test]
    #[cfg(unix)]
    fn snapshot_is_owner_only() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");
        let store = open(path.clone());

        store.insert("h1".into(), apns("a1"), "did:web:vta.example".into());
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "fresh snapshot must be 0600, was {mode:04o}");

        // A rewrite keeps it owner-only (the rename brings the temp file's mode).
        store.insert("h2".into(), apns("b2"), "did:web:vta.example".into());
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "rewritten snapshot must stay 0600");
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
            store.insert("h1".into(), apns("a1"), "did:web:vta.example".into());
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
        store.insert("h1".into(), apns("a1"), "did:web:vta.example".into());

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
        store.insert("h1".into(), apns("c3"), "did:web:vta.example".into());
        store.provision(
            "h1",
            "did:web:vta.example",
            WakeTriggerPolicy {
                allowed_triggers: vec!["did:key:zT".into()],
            },
        );
        assert!(matches!(
            store.authorize_wake("h1", "did:key:zT"),
            WakeAuthz::Allowed(_)
        ));
    }
}
