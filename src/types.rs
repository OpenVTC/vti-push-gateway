//! Payload bodies for the gateway's `push/*` Trust Tasks.
//!
//! These mirror the `push/register|provision|wake` payload schemas
//! (<https://trusttasks.org/spec/push/*>) — the *envelope* is the canonical
//! `trust_tasks_rs::TrustTask`, and these are the typed bodies the dispatcher
//! deserialises out of `doc.payload`. Platform-token specifics live here in the
//! gateway by design (a trigger/VTA never names a platform).

use serde::{Deserialize, Serialize};

/// A device's platform push channel — the token the gateway holds in exchange
/// for an opaque handle. Tagged union over `platform`. The raw token never
/// leaves the gateway. Mirrors `device/_shared` `PushRegistration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "lowercase")]
pub enum PushRegistration {
    Apns {
        token: String,
        topic: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        environment: Option<ApnsEnvironment>,
    },
    Fcm {
        token: String,
    },
    Webpush {
        endpoint: String,
        keys: WebPushKeys,
    },
}

impl PushRegistration {
    /// The abstract platform kind, for logging. Never reveals the token.
    pub fn platform(&self) -> &'static str {
        match self {
            PushRegistration::Apns { .. } => "apns",
            PushRegistration::Fcm { .. } => "fcm",
            PushRegistration::Webpush { .. } => "webpush",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApnsEnvironment {
    Sandbox,
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebPushKeys {
    pub p256dh: String,
    pub auth: String,
}

/// `push/register/0.1` payload — register a token, name the controller VTA.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub registration: PushRegistration,
    pub controller_vta_did: String,
}

/// VTA-owned allowlist of the DIDs permitted to trigger a wake for a handle.
/// Mirrors `device/_shared` `WakeTriggerPolicy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeTriggerPolicy {
    #[serde(default)]
    pub allowed_triggers: Vec<String>,
}

/// `push/provision/0.1` payload — set a handle's allowlist.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub handle: String,
    pub policy: WakeTriggerPolicy,
}

/// `push/wake/0.1` payload — contentless wake request. Carries only the binding
/// §2 hint fields; never task content.
#[derive(Debug, Clone, Deserialize)]
pub struct WakeRequest {
    pub handle: String,
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mediator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urgency: Option<Urgency>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Urgency {
    Interactive,
    Background,
}

/// The contentless doorbell delivered to the device (binding §2). Carries no
/// Trust Task content, no handle, no task type.
#[derive(Debug, Clone, Serialize)]
pub struct WakePayload {
    pub v: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urgency: Option<Urgency>,
}
