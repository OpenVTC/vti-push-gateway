//! Platform push senders.
//!
//! One trait, pluggable per platform. The scaffold ships [`EchoSender`] (logs
//! the wake and reports delivered) so the whole flow — register → provision →
//! wake → push — is exercisable end-to-end without any Apple/Google account.
//! Web Push (VAPID, self-hostable) lands next; APNs/FCM drop in behind the same
//! trait once credentials exist.

use async_trait::async_trait;

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
