//! Platform push senders.
//!
//! One async trait, pluggable per platform:
//! - [`WebPushSender`] — real Web Push (VAPID), self-hostable (no Apple/Google
//!   account). Handles `webpush`.
//! - [`EchoSender`] — dev: logs the wake, delivers nothing. Handles every
//!   platform, so it's the fallback (apns/fcm, or webpush with no VAPID key).
//!
//! APNs/FCM senders drop in behind the same trait once credentials exist.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use http::{header::AUTHORIZATION, HeaderValue, Uri};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use web_push_native::{Auth, WebPushBuilder};

use crate::types::{PushRegistration, WakePayload};

/// base64url, no padding — the encoding used throughout Web Push / VAPID.
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a base64url subscription field, tolerating optional padding.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim().trim_end_matches('='))
        .ok()
}

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
///
/// Encryption (aes128gcm, RFC 8291) is done by `web-push-native`; VAPID auth
/// (ES256 JWT, RFC 8292) is signed here with `p256` so the `rsa` crate stays
/// out of the tree (see Cargo.toml).
pub struct WebPushSender {
    /// VAPID application-server signing key (P-256).
    signing_key: SigningKey,
    /// `k=` parameter of the VAPID header: the uncompressed public key,
    /// base64url — precomputed once since it never changes.
    vapid_public: String,
    /// VAPID `sub` claim — an operator contact (`mailto:` / https URL).
    subject: String,
    client: reqwest::Client,
}

/// VAPID JWTs are valid for 12 hours (RFC 8292 caps `exp` at 24h).
const VAPID_TOKEN_TTL_SECS: u64 = 12 * 60 * 60;

impl WebPushSender {
    /// Build a sender from the gateway's VAPID **private** key (PEM — PKCS#8 or
    /// SEC1) and a contact subject. The matching public key is what subscribers
    /// register as their `applicationServerKey`.
    pub fn new(vapid_pem: Vec<u8>, subject: String) -> Result<Self, String> {
        let pem =
            std::str::from_utf8(&vapid_pem).map_err(|e| format!("VAPID PEM not utf-8: {e}"))?;
        let secret = SecretKey::from_pkcs8_pem(pem)
            .or_else(|_| SecretKey::from_sec1_pem(pem))
            .map_err(|e| format!("parse VAPID key (expected P-256 PKCS#8/SEC1 PEM): {e}"))?;
        let signing_key = SigningKey::from(&secret);
        let vapid_public = b64url(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| format!("web push client init: {e}"))?;
        Ok(Self {
            signing_key,
            vapid_public,
            subject,
            client,
        })
    }

    /// Build the `Authorization: vapid t=<JWT>, k=<pubkey>` header value for a
    /// request to `endpoint` (RFC 8292 §3, aes128gcm single-header form). The
    /// JWT `aud` is the endpoint's origin.
    fn vapid_authorization(&self, endpoint: &Uri) -> Option<String> {
        let aud = format!("{}://{}", endpoint.scheme_str()?, endpoint.authority()?);
        let exp =
            SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() + VAPID_TOKEN_TTL_SECS;
        // Fixed ES256 header; claims per RFC 8292 §2.
        let header = b64url(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = b64url(
            &serde_json::to_vec(&serde_json::json!({
                "aud": aud,
                "exp": exp,
                "sub": self.subject,
            }))
            .ok()?,
        );
        let signing_input = format!("{header}.{claims}");
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", b64url(&sig.to_bytes()));
        Some(format!("vapid t={jwt}, k={}", self.vapid_public))
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
        let Ok(uri) = endpoint.parse::<Uri>() else {
            tracing::warn!("web push endpoint is not a valid URI");
            return SendOutcome::TransientFailure;
        };
        let (Some(p256dh), Some(auth)) = (b64url_decode(&keys.p256dh), b64url_decode(&keys.auth))
        else {
            tracing::warn!("web push subscription keys are not valid base64url");
            return SendOutcome::TransientFailure;
        };
        let Ok(ua_public) = p256::PublicKey::from_sec1_bytes(&p256dh) else {
            tracing::warn!("web push p256dh is not a valid P-256 point");
            return SendOutcome::TransientFailure;
        };
        if auth.len() != 16 {
            tracing::warn!(len = auth.len(), "web push auth secret must be 16 bytes");
            return SendOutcome::TransientFailure;
        }
        let ua_auth = Auth::clone_from_slice(&auth);

        // The encrypted payload is the contentless doorbell (binding §2) — only
        // the WakePayload hint fields, never task content.
        let body = serde_json::to_vec(payload).unwrap_or_default();
        let mut request = match WebPushBuilder::new(uri.clone(), ua_public, ua_auth).build(body) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "web push payload encryption failed");
                return SendOutcome::TransientFailure;
            }
        };

        let Some(vapid) = self
            .vapid_authorization(&uri)
            .and_then(|v| HeaderValue::from_str(&v).ok())
        else {
            tracing::warn!("VAPID authorization header build failed");
            return SendOutcome::TransientFailure;
        };
        request.headers_mut().insert(AUTHORIZATION, vapid);

        let req = match reqwest::Request::try_from(request) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "web push request conversion failed");
                return SendOutcome::TransientFailure;
            }
        };
        match self.client.execute(req).await {
            Ok(resp) if resp.status().is_success() => SendOutcome::Delivered,
            // 404/410 — the subscription is gone; drop the handle (binding §3.2).
            Ok(resp)
                if resp.status() == reqwest::StatusCode::NOT_FOUND
                    || resp.status() == reqwest::StatusCode::GONE =>
            {
                SendOutcome::PermanentlyUnregistered
            }
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "web push service rejected the wake");
                SendOutcome::TransientFailure
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

    /// A throwaway P-256 VAPID private key (PKCS#8 PEM) for constructing a
    /// `WebPushSender` in tests. Not used to sign anything verified here.
    const TEST_VAPID_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2pdM+9XyrmPA1+sL
9K8uXhDnVeQFWU1W/RfE1gjUJGShRANCAAR8vr5b/wAxEuOEKrNJBLH/74t9t7DM
IEi5IEIIVCOOhTviiI9vnxIg8awULr5vD3yBD1uHnzlkoCihDa7mzLS+
-----END PRIVATE KEY-----";

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
        let s = WebPushSender::new(TEST_VAPID_PEM.to_vec(), "mailto:x@y".into()).unwrap();
        assert!(s.handles(&webpush()));
        assert!(!s.handles(&apns()));
    }

    /// The hand-rolled VAPID JWT (RFC 8292) must be well-formed: three
    /// base64url parts, an ES256 header, claims bound to the endpoint origin,
    /// and a signature that verifies under the application-server key.
    #[test]
    fn vapid_authorization_is_a_valid_es256_jwt() {
        use p256::ecdsa::signature::Verifier;

        let sender = WebPushSender::new(TEST_VAPID_PEM.to_vec(), "mailto:ops@gw".into()).unwrap();
        let endpoint: Uri = "https://push.example.com/sub/abc?x=1".parse().unwrap();
        let header = sender.vapid_authorization(&endpoint).unwrap();

        // `vapid t=<jwt>, k=<pubkey>`
        let rest = header.strip_prefix("vapid t=").expect("vapid scheme");
        let (jwt, k) = rest.split_once(", k=").expect("t and k params");
        assert_eq!(k, sender.vapid_public, "k= is the application-server key");

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT is header.claims.signature");

        let hdr: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[0]).unwrap()).unwrap();
        assert_eq!(hdr["alg"], "ES256");
        assert_eq!(hdr["typ"], "JWT");

        let claims: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            claims["aud"], "https://push.example.com",
            "aud is the origin"
        );
        assert_eq!(claims["sub"], "mailto:ops@gw");
        assert!(claims["exp"].is_u64(), "exp present");

        // The signature verifies under the sender's own public key.
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&b64url_decode(parts[2]).unwrap()).unwrap();
        sender
            .signing_key
            .verifying_key()
            .verify(signing_input.as_bytes(), &sig)
            .expect("VAPID signature verifies");
    }

    #[test]
    fn select_prefers_webpush_then_falls_back_to_echo() {
        let senders: Vec<Box<dyn PushSender>> = vec![
            Box::new(WebPushSender::new(TEST_VAPID_PEM.to_vec(), "mailto:x@y".into()).unwrap()),
            Box::new(EchoSender),
        ];
        // webpush is handled (by the WebPushSender, first in order)…
        assert!(select(&senders, &webpush()).is_some());
        // …and apns falls through to the echo sender (only it handles apns here).
        let s = select(&senders, &apns()).expect("echo handles apns");
        assert!(s.handles(&apns()));
    }
}
