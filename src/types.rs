//! Payload bodies for the gateway's `push/*` Trust Tasks.
//!
//! These mirror the `push/register|provision|wake` payload schemas
//! (<https://trusttasks.org/spec/push/*>) — the *envelope* is the canonical
//! `trust_tasks_rs::TrustTask`, and these are the typed bodies the dispatcher
//! deserialises out of `doc.payload`. Platform-token specifics live here in the
//! gateway by design (a trigger/VTA never names a platform).

use serde::{Deserialize, Serialize};

use crate::egress::EgressPolicy;

/// Upper bound on a DID named in a request (`controllerVtaDid`, `mediator`).
pub const MAX_DID_LEN: usize = 512;
/// Upper bound on a handle's `allowedTriggers` list. A handle's triggers are its
/// VTA, its mediator, and a little room to spare — 32 is far above any real
/// policy and bounds both the stored record and the per-wake scan.
pub const MAX_ALLOWED_TRIGGERS: usize = 32;
/// APNs device tokens are hex; accepted length range in characters.
pub const APNS_TOKEN_LEN: std::ops::RangeInclusive<usize> = 64..=200;
/// Upper bound on an APNs topic (bundle id), in bytes.
pub const MAX_APNS_TOPIC_LEN: usize = 255;
/// Upper bound on an FCM registration token, in bytes.
pub const MAX_FCM_TOKEN_LEN: usize = 4096;
/// base64url of a 65-byte uncompressed P-256 point: 87 chars, 88 if padded.
const MAX_P256DH_B64_LEN: usize = 88;
/// base64url of the 16-byte Web Push auth secret: 22 chars, 24 if padded.
const MAX_AUTH_B64_LEN: usize = 24;

/// Whether `token` is shaped like an APNs device token (64–200 hex chars). It
/// is interpolated into the APNs request path, so nothing else is acceptable.
pub fn is_valid_apns_token(token: &str) -> bool {
    APNS_TOKEN_LEN.contains(&token.len()) && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `did` looks like a DID and is within [`MAX_DID_LEN`].
pub fn is_bounded_did(did: &str) -> bool {
    did.len() > "did:".len() && did.len() <= MAX_DID_LEN && did.starts_with("did:")
}

/// A device's platform push channel — the token the gateway holds in exchange
/// for an opaque handle. Tagged union over `platform`. Triggers and the VTA only
/// ever see the handle; the raw token is sent only to the platform push service
/// (and persisted in the store snapshot when one is configured). Mirrors
/// `device/_shared` `PushRegistration`.
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

    /// Check the registration's fields against their bounds and the gateway's
    /// egress policy. The error is a generic, caller-safe reason.
    pub fn validate(&self, policy: &EgressPolicy) -> Result<(), &'static str> {
        match self {
            PushRegistration::Apns { token, topic, .. } => {
                if !is_valid_apns_token(token) {
                    return Err("apns token must be 64-200 hexadecimal characters");
                }
                let topic_ok = !topic.is_empty()
                    && topic.len() <= MAX_APNS_TOPIC_LEN
                    && topic
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
                if !topic_ok {
                    return Err("apns topic must be 1-255 characters of [A-Za-z0-9._-]");
                }
                if !policy.apns_topic_allowed(topic) {
                    return Err("apns topic is not accepted by this gateway");
                }
            }
            PushRegistration::Fcm { token } => {
                let ok = !token.is_empty()
                    && token.len() <= MAX_FCM_TOKEN_LEN
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-'));
                if !ok {
                    return Err("fcm token must be 1-4096 characters of [A-Za-z0-9_:-]");
                }
            }
            PushRegistration::Webpush { endpoint, keys } => {
                if let Err(e) = policy.validate_webpush_endpoint(endpoint) {
                    tracing::debug!(error = %e, "webpush endpoint refused by egress policy");
                    return Err("webpush endpoint is not an accepted push service URL");
                }
                keys.validate()?;
            }
        }
        Ok(())
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

impl WebPushKeys {
    /// `p256dh` must be a base64url 65-byte uncompressed P-256 point and `auth`
    /// a base64url 16-byte secret (RFC 8291) — the same decode the Web Push
    /// sender performs.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.p256dh.len() > MAX_P256DH_B64_LEN || self.auth.len() > MAX_AUTH_B64_LEN {
            return Err("webpush keys have the wrong length");
        }
        crate::sender::decode_webpush_keys(self).map(|_| ())
    }
}

/// `push/register/0.2` payload — register a token, name the controller VTA.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub registration: PushRegistration,
    pub controller_vta_did: String,
}

impl RegisterRequest {
    /// Field bounds + egress policy for a registration.
    pub fn validate(&self, policy: &EgressPolicy) -> Result<(), &'static str> {
        self.registration.validate(policy)?;
        if !is_bounded_did(&self.controller_vta_did) {
            return Err("controllerVtaDid must be a DID of at most 512 bytes");
        }
        Ok(())
    }
}

/// VTA-owned allowlist of the DIDs permitted to trigger a wake for a handle.
/// Mirrors `device/_shared` `WakeTriggerPolicy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeTriggerPolicy {
    #[serde(default)]
    pub allowed_triggers: Vec<String>,
}

impl WakeTriggerPolicy {
    /// Bound the allowlist and drop duplicates, in place.
    ///
    /// The list is controller-supplied, stored verbatim, echoed back in the
    /// response, and linearly scanned on every wake. Capping it at
    /// [`MAX_ALLOWED_TRIGGERS`] makes that scan irrelevant and stops a
    /// controller from growing one handle's record without bound; requiring each
    /// entry to be a DID within [`MAX_DID_LEN`] keeps junk out of the snapshot.
    /// Duplicates are removed rather than rejected — a repeated trigger is
    /// harmless intent, just wasteful to store.
    ///
    /// Order is preserved: the allowlist is echoed back to the controller, and
    /// re-ordering it would make the response look like a different policy than
    /// the one submitted.
    pub fn validate_and_normalize(&mut self) -> Result<(), &'static str> {
        if self.allowed_triggers.len() > MAX_ALLOWED_TRIGGERS {
            return Err("allowedTriggers must list at most 32 DIDs");
        }
        if !self.allowed_triggers.iter().all(|d| is_bounded_did(d)) {
            return Err("each allowedTriggers entry must be a DID of at most 512 bytes");
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.allowed_triggers.len());
        let mut deduped = Vec::with_capacity(self.allowed_triggers.len());
        for did in &self.allowed_triggers {
            if !seen.contains(&did.as_str()) {
                seen.push(did);
                deduped.push(did.clone());
            }
        }
        self.allowed_triggers = deduped;
        Ok(())
    }
}

/// `push/provision/0.2` payload — set a handle's allowlist.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionRequest {
    pub handle: String,
    pub policy: WakeTriggerPolicy,
}

/// `push/wake/0.2` payload — contentless wake request. Carries only the binding
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

impl WakeRequest {
    /// Field bounds for a wake (the `mediator` hint is forwarded to the device).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self
            .mediator
            .as_ref()
            .is_some_and(|m| m.len() > MAX_DID_LEN)
        {
            return Err("mediator must be at most 512 bytes");
        }
        Ok(())
    }
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
