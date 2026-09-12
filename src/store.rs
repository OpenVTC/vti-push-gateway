//! Gateway state: opaque handle → device push token (never disclosed to
//! triggers or the VTA) + the controller VTA + the VTA-provisioned trigger
//! allowlist.
//!
//! In-memory by default; **optionally durable** via a JSON snapshot file
//! (`Store::open`): the map is loaded on boot and atomically rewritten after
//! every mutation (temp file + rename), so handles/tokens survive a restart.
//! Persistence is best-effort — a write failure is logged but never fails the
//! in-flight request (a device can always re-register). Suited to the gateway's
//! small, low-write registry; an embedded DB would be over-built here.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::egress::EgressPolicy;
use crate::types::{is_bounded_did, PushRegistration, WakeTriggerPolicy};

/// Everything the gateway holds for one registered push channel.
#[derive(Serialize, Deserialize)]
pub struct HandleRecord {
    /// The raw platform push token. Never returned to triggers or the VTA; sent
    /// only to the platform push service, and written in cleartext to the
    /// snapshot file when persistence is enabled.
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
    pub fn open(path: PathBuf, policy: &EgressPolicy) -> Self {
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

    /// Serialize + atomically rewrite the snapshot (temp file + rename). Called
    /// while holding the write lock so the persisted snapshot matches the
    /// just-applied mutation. No-op when in-memory; best-effort otherwise.
    fn persist_locked(&self, handles: &HashMap<String, HandleRecord>) {
        let Some(path) = &self.path else {
            return;
        };
        let json = match serde_json::to_string(handles) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "serialize gateway store snapshot");
                return;
            }
        };
        let tmp = path.with_extension("json.tmp");
        if let Err(e) =
            std::fs::write(&tmp, json.as_bytes()).and_then(|()| std::fs::rename(&tmp, path))
        {
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
