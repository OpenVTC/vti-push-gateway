//! Platform push senders.
//!
//! One async trait, pluggable per platform:
//! - [`WebPushSender`] — real Web Push (VAPID), self-hostable (no Apple/Google
//!   account). Handles `webpush`.
//! - [`EchoSender`] — dev: logs the wake, delivers nothing. Handles every
//!   platform, so it's the fallback (apns/fcm, or webpush with no VAPID key).
//!
//! APNs/FCM senders drop in behind the same trait once credentials exist.

use async_trait::async_trait;
use web_push::{
    ContentEncoding, IsahcWebPushClient, SubscriptionInfo, VapidSignatureBuilder, WebPushClient,
    WebPushError, WebPushMessageBuilder,
};

use crate::types::{PushRegistration, WakePayload};

/// Result of a push send. `PermanentlyUnregistered` triggers the binding §3.2
/// dead-token rule (the gateway drops the handle).
#[derive(Debug, PartialEq, Eq)]
pub enum SendOutcome {
    Delivered,
    PermanentlyUnregistered,
    TransientFailure,
}

/// Sends a contentless wake to a platform push service. Implementations MUST
/// forward only the [`WakePayload`] fields — never task content.
///
/// `send` is **async** — real delivery (Web Push, APNs, FCM) is an HTTP call.
#[async_trait]
pub trait PushSender: Send + Sync {
    /// Whether this sender handles the given registration's platform.
    fn handles(&self, registration: &PushRegistration) -> bool;
    /// Deliver the contentless wake to the registration's token.
    async fn send(&self, registration: &PushRegistration, payload: &WakePayload) -> SendOutcome;
}

/// Dev sender: logs the wake and reports `Delivered`. Lets the gateway be tested
/// end-to-end with no platform credentials. NOT for production wakes.
pub struct EchoSender;

#[async_trait]
impl PushSender for EchoSender {
    fn handles(&self, _registration: &PushRegistration) -> bool {
        true
    }

    async fn send(&self, registration: &PushRegistration, payload: &WakePayload) -> SendOutcome {
        tracing::info!(
            platform = registration.platform(),
            mediator = payload.mediator.as_deref().unwrap_or("-"),
            count = payload.count.unwrap_or(0),
            "echo-sender: contentless wake (dev; no real push sent)"
        );
        SendOutcome::Delivered
    }
}

/// Real Web Push (RFC 8030 + RFC 8291 encryption + RFC 8292 VAPID auth) sender.
/// Self-hostable — the VAPID keypair is the gateway's own (no Apple/Google
/// account). Delivers the contentless [`WakePayload`] (encrypted) to the
/// subscription endpoint; the device's service worker wakes and drains its
/// mediator. Handles only `webpush` registrations.
pub struct WebPushSender {
    vapid_pem: Vec<u8>,
    /// VAPID `sub` claim — an operator contact (`mailto:` / https URL).
    subject: String,
    client: IsahcWebPushClient,
}

impl WebPushSender {
    /// Build a sender from the gateway's VAPID **private** key (PEM) and a
    /// contact subject. The matching public key is what subscribers register as
    /// their `applicationServerKey`.
    pub fn new(vapid_pem: Vec<u8>, subject: String) -> Result<Self, String> {
        let client = IsahcWebPushClient::new().map_err(|e| format!("web push client init: {e}"))?;
        Ok(Self {
            vapid_pem,
            subject,
            client,
        })
    }
}

#[async_trait]
impl PushSender for WebPushSender {
    fn handles(&self, registration: &PushRegistration) -> bool {
        matches!(registration, PushRegistration::Webpush { .. })
    }

    async fn send(&self, registration: &PushRegistration, payload: &WakePayload) -> SendOutcome {
        let PushRegistration::Webpush { endpoint, keys } = registration else {
            return SendOutcome::TransientFailure; // not ours (select() shouldn't route here)
        };
        let subscription =
            SubscriptionInfo::new(endpoint.clone(), keys.p256dh.clone(), keys.auth.clone());

        let signature = {
            let mut builder = match VapidSignatureBuilder::from_pem(
                std::io::Cursor::new(&self.vapid_pem),
                &subscription,
            ) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "VAPID signature builder failed");
                    return SendOutcome::TransientFailure;
                }
            };
            builder.add_claim("sub", self.subject.as_str());
            match builder.build() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "VAPID signature build failed");
                    return SendOutcome::TransientFailure;
                }
            }
        };

        // The encrypted payload is the contentless doorbell (binding §2) — only
        // the WakePayload hint fields, never task content.
        let body = serde_json::to_vec(payload).unwrap_or_default();
        let mut builder = WebPushMessageBuilder::new(&subscription);
        builder.set_payload(ContentEncoding::Aes128Gcm, &body);
        builder.set_vapid_signature(signature);
        let message = match builder.build() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "web push message build failed");
                return SendOutcome::TransientFailure;
            }
        };

        match self.client.send(message).await {
            Ok(()) => SendOutcome::Delivered,
            // 404/410 — the subscription is gone; drop the handle (binding §3.2).
            Err(WebPushError::EndpointNotValid | WebPushError::EndpointNotFound) => {
                SendOutcome::PermanentlyUnregistered
            }
            Err(e) => {
                tracing::warn!(error = %e, "web push send failed");
                SendOutcome::TransientFailure
            }
        }
    }
}

/// Pick the first sender that handles the registration's platform.
pub fn select<'a>(
    senders: &'a [Box<dyn PushSender>],
    registration: &PushRegistration,
) -> Option<&'a dyn PushSender> {
    senders
        .iter()
        .map(|b| b.as_ref())
        .find(|s| s.handles(registration))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WebPushKeys;

    fn webpush() -> PushRegistration {
        PushRegistration::Webpush {
            endpoint: "https://push.example/x".into(),
            keys: WebPushKeys {
                p256dh: "k".into(),
                auth: "a".into(),
            },
        }
    }

    fn apns() -> PushRegistration {
        PushRegistration::Apns {
            token: "t".into(),
            topic: "org.x".into(),
            environment: None,
        }
    }

    #[test]
    fn webpush_sender_handles_only_webpush() {
        let s = WebPushSender::new(b"dummy".to_vec(), "mailto:x@y".into()).unwrap();
        assert!(s.handles(&webpush()));
        assert!(!s.handles(&apns()));
    }

    #[test]
    fn select_prefers_webpush_then_falls_back_to_echo() {
        let senders: Vec<Box<dyn PushSender>> = vec![
            Box::new(WebPushSender::new(b"dummy".to_vec(), "mailto:x@y".into()).unwrap()),
            Box::new(EchoSender),
        ];
        // webpush is handled (by the WebPushSender, first in order)…
        assert!(select(&senders, &webpush()).is_some());
        // …and apns falls through to the echo sender (only it handles apns here).
        let s = select(&senders, &apns()).expect("echo handles apns");
        assert!(s.handles(&apns()));
    }
}
