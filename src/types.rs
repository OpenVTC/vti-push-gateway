//! Wire types for the push gateway's REST surface.
//!
//! These mirror the shapes in the push wake-up binding
//! (<https://trusttasks.org/binding/push/0.1>) and the `device/_shared`
//! `WakeHandle` / `WakeTriggerPolicy` definitions. The gateway owns its own
//! DTOs rather than depending on `trust-tasks-rs` — the REST contract is the
//! spec, not a shared Rust type, and platform-token specifics live here in the
//! gateway by design (a trigger or VTA never names a platform).

use serde::{Deserialize, Serialize};

/// A device's platform push channel — the token the gateway holds in exchange
/// for an opaque handle. Tagged union over `platform`. The raw token never
/// leaves the gateway. Mirrors `device/_shared` `PushRegistration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "lowercase")]
pub enum PushRegistration {
    Apns {
        /// APNs device token (hex string from Apple Push Notification service).
        token: String,
        /// APNs topic — typically the app bundle id.
        topic: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        environment: Option<ApnsEnvironment>,
    },
    Fcm {
        /// Firebase Cloud Messaging registration token.
        token: String,
    },
    Webpush {
        /// RFC 8030 Web Push subscription endpoint.
        endpoint: String,
        /// RFC 8291 encryption keys (p256dh + auth).
        keys: WebPushKeys,
    },
}

impl PushRegistration {
    /// The abstract platform kind, for the device-facing `pushPlatform` hint and
    /// logging. Never reveals the token.
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
    /// base64url-encoded P-256 ECDH public key.
    pub p256dh: String,
    /// base64url-encoded auth secret.
    pub auth: String,
}

/// `POST /v1/register` request — a device registers its push token and names the
/// VTA that will own its trigger allowlist.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub registration: PushRegistration,
    /// The DID of the VTA permitted to provision this handle's allowlist
    /// (`device/set-wake` is conveyed to this VTA, which then provisions here).
    pub controller_vta_did: String,
}

/// An opaque, gateway-issued reference to a device's push channel. Mirrors
/// `device/_shared` `WakeHandle`. The `handle` reveals no platform token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WakeHandle {
    /// This gateway's address (https URL or DID) — where triggers send wakes.
    pub gateway: String,
    /// Opaque gateway-issued identifier for the device's push channel.
    pub handle: String,
}

/// `POST /v1/register` response.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterResponse {
    pub wake_handle: WakeHandle,
}

/// VTA-owned allowlist of the DIDs permitted to trigger a wake for a handle.
/// Mirrors `device/_shared` `WakeTriggerPolicy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WakeTriggerPolicy {
    /// DIDs authorized to trigger a wake for this handle. Empty = no party may
    /// wake the device.
    #[serde(default)]
    pub allowed_triggers: Vec<String>,
}

/// `POST /v1/provision` request — the controller VTA sets a handle's allowlist.
/// Authenticated as the controller VTA's DID (see [`crate::auth`]).
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub handle: String,
    pub policy: WakeTriggerPolicy,
}

/// `POST /v1/wake` request — a trigger (mediator or VTA) asks the gateway to send
/// a contentless wake. Authenticated as the trigger's DID. Carries only the
/// binding §2 contentless hint fields — never task content.
#[derive(Debug, Clone, Deserialize)]
pub struct WakeRequest {
    pub handle: String,
    /// Binding wire version — the integer `1`.
    pub v: u8,
    /// The mediator holding the queued messages, so a multi-mediator consumer
    /// knows which to drain. Echoed into the push payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mediator: Option<String>,
    /// Approximate queued-message count (advisory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    /// `interactive` | `background` urgency hint.
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
