//! In-memory gateway state.
//!
//! Maps an opaque handle to the device's push token (held here and nowhere
//! else) plus the controller VTA and the VTA-provisioned trigger allowlist.
//! In-memory for the scaffold; a persistent backend (the token must survive
//! restarts) is a follow-up.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::types::{PushRegistration, WakeTriggerPolicy};

/// Everything the gateway holds for one registered push channel.
pub struct HandleRecord {
    /// The raw platform push token — never leaves the gateway.
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a freshly-issued handle. Allowlist starts empty (the VTA opts
    /// triggers in via `provision`).
    pub fn insert(
        &self,
        handle: String,
        registration: PushRegistration,
        controller_vta_did: String,
    ) {
        self.handles.write().unwrap().insert(
            handle,
            HandleRecord {
                registration,
                controller_vta_did,
                allowed_triggers: Vec::new(),
            },
        );
    }

    /// Set a handle's allowlist — only the handle's controller VTA may do so.
    pub fn provision(
        &self,
        handle: &str,
        caller_did: &str,
        policy: WakeTriggerPolicy,
    ) -> ProvisionOutcome {
        let mut handles = self.handles.write().unwrap();
        match handles.get_mut(handle) {
            None => ProvisionOutcome::UnknownHandle,
            Some(rec) if rec.controller_vta_did != caller_did => ProvisionOutcome::NotController,
            Some(rec) => {
                rec.allowed_triggers = policy.allowed_triggers;
                ProvisionOutcome::Ok
            }
        }
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
        self.handles.write().unwrap().remove(handle);
    }
}
