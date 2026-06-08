//! Platform push senders.
//!
//! One async trait, pluggable per platform:
//! - [`WebPushSender`] — real Web Push (VAPID), self-hostable (no Apple/Google
//!   account). Handles `webpush`.
//! - [`ApnsSender`] — real APNs (Apple Push Notification service) via the
//!   provider-token (JWT) API. Handles `apns`. Needs the app publisher's APNs
//!   auth key (`.p8`) + key id + team id.
//! - [`FcmSender`] — real FCM (Firebase Cloud Messaging) via the HTTP v1 API.
//!   Handles `fcm`. Needs a Google service-account JSON; the OAuth2 assertion is
//!   signed RS256 with `aws-lc-rs` (no `rsa` crate).
//! - [`EchoSender`] — dev: logs the wake, delivers nothing. Handles every
//!   platform, so it's the fallback (any platform with no credentials).

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Uri,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use web_push_native::{Auth, WebPushBuilder};

use crate::types::{ApnsEnvironment, PushRegistration, Urgency, WakePayload};

/// Decode a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----` … base64 … `-----END …`)
/// into DER bytes — used for the FCM service-account RSA signing key.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| format!("decode PKCS#8 PEM base64: {e}"))
}

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

/// Generate a fresh VAPID (P-256) keypair, so an operator never needs `openssl`.
/// Returns the private key as a **PKCS#8 PEM** (what `GATEWAY_VAPID_KEY_FILE`
/// loads) and the public key as **base64url** (the `applicationServerKey` the
/// device/plugin registers). The two are a matched pair.
pub fn generate_vapid_keypair() -> Result<(String, String), String> {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use rand::Rng;

    // A P-256 scalar must be in [1, n-1]; random 32-byte values are valid with
    // overwhelming probability — reject and retry the negligibly-rare miss.
    let secret = loop {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            break sk;
        }
    };
    let pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("encode VAPID key as PKCS#8 PEM: {e}"))?
        .to_string();
    let public = b64url(
        SigningKey::from(&secret)
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    Ok((pem, public))
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

    /// The VAPID **public** key (base64url, uncompressed P-256 point) subscribers
    /// register as their `applicationServerKey`. Surfaced so an operator can copy
    /// it into the device/plugin config without re-deriving it from the PEM.
    pub fn vapid_public(&self) -> &str {
        &self.vapid_public
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

/// A cached APNs provider token (JWT) and the unix second it was issued.
struct CachedToken {
    jwt: String,
    iat: u64,
}

/// APNs requires a *fresh* provider token at least hourly and refuses tokens
/// regenerated more than once per ~20 minutes (`TooManyProviderTokenUpdates`).
/// 40 minutes sits safely inside that window, so we cache and reuse.
const APNS_TOKEN_REFRESH_SECS: u64 = 40 * 60;

/// APNs error response body — `{"reason":"BadDeviceToken"}`.
#[derive(serde::Deserialize)]
struct ApnsError {
    #[serde(default)]
    reason: String,
}

/// Real APNs sender via the **provider-token (JWT) API** (no per-connection
/// client certificate). The app publisher's APNs auth key (`.p8`, a P-256
/// PKCS#8 key) signs a short-lived ES256 JWT — cached and reused per
/// [`APNS_TOKEN_REFRESH_SECS`] — that authorises HTTP/2 pushes to Apple.
///
/// Delivers the contentless [`WakePayload`] as a **silent background push**
/// (`aps.content-available = 1`, `apns-push-type: background`, priority 5); the
/// hint fields ride as custom keys, never task content (binding §2). The device
/// wakes and drains its mediator. Handles only `apns` registrations.
pub struct ApnsSender {
    /// Apple Developer team id — the JWT `iss` claim.
    team_id: String,
    /// APNs auth key id — the JWT header `kid`.
    key_id: String,
    /// The `.p8` signing key (P-256).
    signing_key: SigningKey,
    client: reqwest::Client,
    /// Cached provider token, refreshed on a timer (see [`APNS_TOKEN_REFRESH_SECS`]).
    token: Mutex<Option<CachedToken>>,
}

impl ApnsSender {
    /// Build a sender from the APNs auth key (`.p8`, P-256 PKCS#8 PEM), its key
    /// id, and the Apple Developer team id.
    pub fn new(p8_pem: Vec<u8>, key_id: String, team_id: String) -> Result<Self, String> {
        let pem = std::str::from_utf8(&p8_pem).map_err(|e| format!("APNs .p8 not utf-8: {e}"))?;
        let secret = SecretKey::from_pkcs8_pem(pem)
            .map_err(|e| format!("parse APNs key (expected P-256 PKCS#8 .p8 PEM): {e}"))?;
        let signing_key = SigningKey::from(&secret);
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| format!("APNs client init: {e}"))?;
        Ok(Self {
            team_id,
            key_id,
            signing_key,
            client,
            token: Mutex::new(None),
        })
    }

    /// The current APNs provider token (JWT), regenerating it when the cached
    /// one is missing or older than [`APNS_TOKEN_REFRESH_SECS`]. The header
    /// carries `kid`; the claims carry `iss` (team id) + `iat`, per Apple's
    /// token-based connection docs.
    fn provider_token(&self) -> Option<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let mut guard = self.token.lock().ok()?;
        if let Some(t) = guard.as_ref() {
            if now.saturating_sub(t.iat) < APNS_TOKEN_REFRESH_SECS {
                return Some(t.jwt.clone());
            }
        }
        let header = b64url(
            &serde_json::to_vec(&serde_json::json!({
                "alg": "ES256",
                "kid": self.key_id,
                "typ": "JWT",
            }))
            .ok()?,
        );
        let claims = b64url(
            &serde_json::to_vec(&serde_json::json!({
                "iss": self.team_id,
                "iat": now,
            }))
            .ok()?,
        );
        let signing_input = format!("{header}.{claims}");
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", b64url(&sig.to_bytes()));
        *guard = Some(CachedToken {
            jwt: jwt.clone(),
            iat: now,
        });
        Some(jwt)
    }
}

#[async_trait]
impl PushSender for ApnsSender {
    fn handles(&self, registration: &PushRegistration) -> bool {
        matches!(registration, PushRegistration::Apns { .. })
    }

    async fn send(&self, registration: &PushRegistration, payload: &WakePayload) -> SendOutcome {
        let PushRegistration::Apns {
            token,
            topic,
            environment,
        } = registration
        else {
            return SendOutcome::TransientFailure; // not ours (select() shouldn't route here)
        };
        // Sandbox vs production is the only difference in host; default to
        // production when the device didn't say.
        let host = match environment {
            Some(ApnsEnvironment::Sandbox) => "api.sandbox.push.apple.com",
            Some(ApnsEnvironment::Production) | None => "api.push.apple.com",
        };
        let url = format!("https://{host}/3/device/{token}");

        let Some(jwt) = self.provider_token() else {
            tracing::warn!("APNs provider token build failed");
            return SendOutcome::TransientFailure;
        };

        // Contentless background push (binding §2): the `aps` content-available
        // flag wakes the app; the WakePayload hint fields ride as custom keys —
        // never task content.
        let mut body = match serde_json::to_value(payload) {
            Ok(serde_json::Value::Object(m)) => m,
            _ => serde_json::Map::new(),
        };
        body.insert(
            "aps".to_string(),
            serde_json::json!({ "content-available": 1 }),
        );

        let resp = self
            .client
            .post(&url)
            .header(AUTHORIZATION, format!("bearer {jwt}"))
            .header("apns-topic", topic)
            .header("apns-push-type", "background")
            // Background (content-available) pushes MUST be priority 5.
            .header("apns-priority", "5")
            .json(&body)
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => SendOutcome::Delivered,
            Ok(r) => {
                let status = r.status();
                let reason = r
                    .json::<ApnsError>()
                    .await
                    .map(|e| e.reason)
                    .unwrap_or_default();
                // 410 Unregistered, or a 400 naming a dead/mismatched token →
                // drop the handle (binding §3.2). Everything else is transient.
                if status == reqwest::StatusCode::GONE
                    || matches!(
                        reason.as_str(),
                        "Unregistered" | "BadDeviceToken" | "DeviceTokenNotForTopic"
                    )
                {
                    SendOutcome::PermanentlyUnregistered
                } else {
                    tracing::warn!(%status, reason, "APNs rejected the wake");
                    SendOutcome::TransientFailure
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "APNs send failed");
                SendOutcome::TransientFailure
            }
        }
    }
}

// ── FCM (Firebase Cloud Messaging) ──────────────────────────────────────────

/// Refresh the OAuth2 access token a little before its ~1h expiry.
const FCM_TOKEN_REFRESH_SECS: u64 = 50 * 60;
/// OAuth2 scope for sending via FCM HTTP v1.
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// The fields the gateway needs from a Google service-account JSON.
#[derive(serde::Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    /// RSA private key, PKCS#8 PEM.
    private_key: String,
    token_uri: String,
}

/// OAuth2 token-endpoint response (the bits we use).
#[derive(serde::Deserialize)]
struct FcmTokenResponse {
    access_token: String,
    expires_in: u64,
}

/// A cached OAuth2 access token + when it was obtained and its lifetime.
struct CachedAccessToken {
    token: String,
    obtained_at: u64,
    ttl: u64,
}

/// Real FCM (Firebase Cloud Messaging) sender via the **HTTP v1** API.
///
/// Authorises with a short-lived OAuth2 **access token**, obtained by signing a
/// service-account assertion JWT (**RS256**, via `aws-lc-rs` — so the vulnerable
/// `rsa` crate never enters the tree, matching the VAPID/APNs senders) and
/// exchanging it at the account's `token_uri`. The token is cached + reused (see
/// [`FCM_TOKEN_REFRESH_SECS`]).
///
/// Delivers the contentless [`WakePayload`] as a **data-only, high-priority**
/// message (no `notification`): FCM `data` values MUST be strings, so the hint
/// fields are stringified; `android.priority: high` wakes a backgrounded app.
/// The device drains its mediator on receipt. Handles only `fcm` registrations.
pub struct FcmSender {
    project_id: String,
    client_email: String,
    token_uri: String,
    signing_key: aws_lc_rs::signature::RsaKeyPair,
    client: reqwest::Client,
    token: tokio::sync::Mutex<Option<CachedAccessToken>>,
}

impl FcmSender {
    /// Build a sender from a Google service-account JSON (`project_id`,
    /// `client_email`, `private_key` (RSA PKCS#8 PEM), `token_uri`).
    pub fn new(service_account_json: &[u8]) -> Result<Self, String> {
        let sa: ServiceAccount = serde_json::from_slice(service_account_json)
            .map_err(|e| format!("parse FCM service-account JSON: {e}"))?;
        let der = pem_to_der(&sa.private_key)?;
        let signing_key = aws_lc_rs::signature::RsaKeyPair::from_pkcs8(&der)
            .map_err(|e| format!("parse FCM service-account key (expected RSA PKCS#8): {e}"))?;
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| format!("FCM client init: {e}"))?;
        Ok(Self {
            project_id: sa.project_id,
            client_email: sa.client_email,
            token_uri: sa.token_uri,
            signing_key,
            client,
            token: tokio::sync::Mutex::new(None),
        })
    }

    /// Mint the service-account assertion JWT (RS256) for the OAuth2 exchange.
    fn assertion_jwt(&self, now: u64) -> Option<String> {
        let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = b64url(
            &serde_json::to_vec(&serde_json::json!({
                "iss": self.client_email,
                "scope": FCM_SCOPE,
                "aud": self.token_uri,
                "iat": now,
                "exp": now + 3600,
            }))
            .ok()?,
        );
        let signing_input = format!("{header}.{claims}");
        let mut sig = vec![0u8; self.signing_key.public_modulus_len()];
        self.signing_key
            .sign(
                &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                signing_input.as_bytes(),
                &mut sig,
            )
            .ok()?;
        Some(format!("{signing_input}.{}", b64url(&sig)))
    }

    /// A valid OAuth2 access token, exchanging a fresh assertion when the cache
    /// is empty or near expiry.
    async fn access_token(&self) -> Option<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let mut guard = self.token.lock().await;
        if let Some(t) = guard.as_ref() {
            if now.saturating_sub(t.obtained_at) < t.ttl.min(FCM_TOKEN_REFRESH_SECS) {
                return Some(t.token.clone());
            }
        }
        let assertion = self.assertion_jwt(now)?;
        // application/x-www-form-urlencoded by hand: the assertion is base64url
        // (URL-safe alphabet, no padding), so only the grant_type's `:` need
        // percent-encoding. Avoids pulling reqwest's `urlencoded` form helper.
        let form_body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        );
        let resp = self
            .client
            .post(&self.token_uri)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(%status, body, "FCM OAuth2 token exchange failed");
            return None;
        }
        let tok: FcmTokenResponse = resp.json().await.ok()?;
        let token = tok.access_token.clone();
        *guard = Some(CachedAccessToken {
            token: tok.access_token,
            obtained_at: now,
            ttl: tok.expires_in,
        });
        Some(token)
    }
}

#[async_trait]
impl PushSender for FcmSender {
    fn handles(&self, registration: &PushRegistration) -> bool {
        matches!(registration, PushRegistration::Fcm { .. })
    }

    async fn send(&self, registration: &PushRegistration, payload: &WakePayload) -> SendOutcome {
        let PushRegistration::Fcm { token } = registration else {
            return SendOutcome::TransientFailure; // not ours (select() shouldn't route here)
        };
        let Some(access) = self.access_token().await else {
            return SendOutcome::TransientFailure;
        };

        // FCM `data` values MUST be strings — stringify the contentless hint
        // fields (binding §2: no task content, no handle, no task type).
        let mut data = serde_json::Map::new();
        data.insert("v".to_string(), payload.v.to_string().into());
        if let Some(m) = &payload.mediator {
            data.insert("mediator".to_string(), m.clone().into());
        }
        if let Some(c) = payload.count {
            data.insert("count".to_string(), c.to_string().into());
        }
        if let Some(u) = payload.urgency {
            let s = match u {
                Urgency::Interactive => "interactive",
                Urgency::Background => "background",
            };
            data.insert("urgency".to_string(), s.into());
        }

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );
        let body = serde_json::json!({
            "message": {
                "token": token,
                "data": data,
                // High priority so a backgrounded app is woken now (the doorbell).
                "android": { "priority": "high" },
            }
        });

        let resp = self
            .client
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {access}"))
            .json(&body)
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => SendOutcome::Delivered,
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                // A dead token → UNREGISTERED / NOT_FOUND; drop the handle
                // (binding §3.2). Everything else is transient.
                if status == reqwest::StatusCode::NOT_FOUND
                    || body.contains("UNREGISTERED")
                    || body.contains("registration-token-not-registered")
                {
                    SendOutcome::PermanentlyUnregistered
                } else {
                    tracing::warn!(%status, body, "FCM rejected the wake");
                    SendOutcome::TransientFailure
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "FCM send failed");
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

    // The APNs `.p8` auth key is the same shape as a VAPID key (P-256 PKCS#8),
    // so the test key doubles as a stand-in auth key.
    const TEST_APNS_P8: &[u8] = TEST_VAPID_PEM;

    #[test]
    fn generated_vapid_keypair_round_trips_through_the_sender() {
        let (pem, public) = generate_vapid_keypair().unwrap();
        // The generated PEM loads as a Web Push sender, and the public key we
        // returned matches what the sender advertises — a matched pair.
        let s = WebPushSender::new(pem.into_bytes(), "mailto:ops@gw".into()).unwrap();
        assert_eq!(s.vapid_public(), public);
        // Distinct each time (it's random).
        let (_, public2) = generate_vapid_keypair().unwrap();
        assert_ne!(public, public2);
    }

    #[test]
    fn apns_sender_handles_only_apns() {
        let s =
            ApnsSender::new(TEST_APNS_P8.to_vec(), "KEYID123".into(), "TEAMID456".into()).unwrap();
        assert!(s.handles(&apns()));
        assert!(!s.handles(&webpush()));
    }

    /// The provider token must be a well-formed ES256 JWT carrying `kid` in the
    /// header and `iss`/`iat` in the claims, signed by the auth key — and it
    /// must be **cached** (a second call returns the same token).
    #[test]
    fn apns_provider_token_is_a_valid_es256_jwt_and_is_cached() {
        use p256::ecdsa::signature::Verifier;

        let s =
            ApnsSender::new(TEST_APNS_P8.to_vec(), "KEYID123".into(), "TEAMID456".into()).unwrap();
        let jwt = s.provider_token().expect("token built");
        assert_eq!(
            s.provider_token().as_deref(),
            Some(jwt.as_str()),
            "token is cached"
        );

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT is header.claims.signature");

        let hdr: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[0]).unwrap()).unwrap();
        assert_eq!(hdr["alg"], "ES256");
        assert_eq!(hdr["kid"], "KEYID123");

        let claims: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "TEAMID456");
        assert!(claims["iat"].is_u64(), "iat present");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&b64url_decode(parts[2]).unwrap()).unwrap();
        s.signing_key
            .verifying_key()
            .verify(signing_input.as_bytes(), &sig)
            .expect("APNs provider-token signature verifies");
    }

    #[test]
    fn select_routes_apns_to_the_apns_sender() {
        let senders: Vec<Box<dyn PushSender>> = vec![
            Box::new(WebPushSender::new(TEST_VAPID_PEM.to_vec(), "mailto:x@y".into()).unwrap()),
            Box::new(
                ApnsSender::new(TEST_APNS_P8.to_vec(), "KEYID123".into(), "TEAMID456".into())
                    .unwrap(),
            ),
            Box::new(EchoSender),
        ];
        // apns now resolves to the real APNs sender, not the echo fallback.
        let s = select(&senders, &apns()).expect("a sender handles apns");
        assert!(s.handles(&apns()));
        // And it is NOT the webpush sender.
        assert!(!s.handles(&webpush()));
    }

    // A throwaway RSA-2048 PKCS#8 key (PEM) standing in for a Google
    // service-account `private_key`. Not used to sign anything verified outside
    // this test; the matching public key is derived from it in-test.
    const TEST_RSA_PKCS8_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD03iRySoK1K/lT
v68JHs2dOHMMXy4u01pau7UzZVTV3RL3bMitU66WfdGZsm2fWjNV+kgpeS2RaM9A
ZgOACqdL7p0ClgkfV1UsIWN2F6F4NJKBDcg9J4SRXq/XNiHuUM2FyHmYVEWwZJTZ
1wGb4i8sEw7U6ibKRsetN2WMK+qW11cUwngeWYk7J5Fan1fRoAqXHP34HGlvNIkK
yxcyGdghsPW+ZHISH/C719vHX1exesolWQrDAv9XGyrOB3JVFh449VTKx75gOTD8
rIHlO94hfnadsky4XcPqRUVPEEjefehpOKDbCT8hrEKlREcbuFb7ps0PZeWmUwgT
hWJcrkGBAgMBAAECggEAEDHzCiYYcAAZDOt0Ga/SXJAjt9FBvjIXW0Hn8Z7FliF5
hCjLOv96YBSxPK+a5XuzQn/7rtaHZ4Mdlf5JQ/owZ2rAMrAWqV5+0RziNajJcqhT
ejqdoEHRWEYBbkPzyY3JkgwY0rTcKRb161R3lEZI5WrbQ8S6zQ0SXsf3rOYorVIu
now8eTRTioOch6r46mDpvX/4WeKQSZ8roolMJErfL+Uh/vjtj1QUayXJF0IkBA0T
KnNu6U3wY0a3cT9V0rLzsdrJEPko/lT3nSlRLChrQkuP2cMJvlo3baghkbVJt+Ms
Yvoml+rxHN9wIlBZXKW/U6C7uDXD+jPlgEWcrBG++QKBgQD9yYSY8sYjVGl1ASq2
8XC4mpwVMISkRfakKWJNZ7UhTQedh9YsSixyBwfzfC4lopLLSREeDRzzEPapXAdh
WNrkCr96h2XMQPWqwWmImeySxrkHhjWMkmw1xh1hflrejnxyy0VzH6+oHnyottqK
TAa9Uwsc3uUJTGGllDpoROVrFQKBgQD3ALcX309vELJLwknsINZWeulHZ2rBZlfG
9DHZ2ZJAXjmqp/UYjgEI7NlX0+8tvEZGDphYKHTRDXemkTomEWsDj3wrXkWChtvv
PAEDMDmQl0oxy/v/SnmlEHwoGWvUYDHfkEZrxXoSV8Ihm+9w+ib0vPN90FLINqHC
KoicQ4YnvQKBgC6YzojKooigGhDKmw4l/H1YneniE6iZ0/RGSO9PaFlp7EkHRNKy
98Aj/Fi/ZzWvyOYcT1FGNReH+NIVvKEqEF6ofom/zHgZQUIN6xOSt3YnmJeCE9jw
lX+2FXTuHz8XyE/HdMPzgGwM1PShRjT4SpB+a97sKf9wD8m4EpVMeRcVAoGAF7e8
3RD3Wq3awQWN/ZuFmVZCEjYu/RUrtpH6O3X14jJqDSYFle8E0GuVzyYtoFGk2dNK
86Qm23AUnizxzXf8s6HShYOO3yK9+bHkUv8NeAHfAPsaXoAzQBNeKKeQQBtgjpwW
9wBGYX6FyJ5llo6esP93zgvz9v+v9qoI5iBhwG0CgYEAurpvo07Z9fzq7aZowf4n
rFNMT5gxftH4vPEF3dxuqzlxAcdkCLinQafjmXcB0b1OEgAmYKV2ks4h8M5dt9/B
fNmjDHN/ElPNZSWT5KOXiBOUYkvON0g7reIWwFzToqKjE9HtLpYiShDsLCxAkMFo
JIdgVjmcJ6J16mUbDYosCYI=
-----END PRIVATE KEY-----"#;

    fn fcm_service_account_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "project_id": "demo-project",
            "client_email": "pusher@demo-project.iam.gserviceaccount.com",
            "private_key": TEST_RSA_PKCS8_PEM,
            "token_uri": "https://oauth2.googleapis.com/token",
        }))
        .unwrap()
    }

    #[test]
    fn fcm_sender_handles_only_fcm() {
        let s = FcmSender::new(&fcm_service_account_json()).expect("FcmSender::new");
        let fcm = PushRegistration::Fcm {
            token: "device-token".into(),
        };
        assert!(s.handles(&fcm));
        assert!(!s.handles(&apns()));
        assert!(!s.handles(&webpush()));
    }

    /// The OAuth2 assertion is a well-formed RS256 JWT carrying the
    /// service-account claims, and its signature verifies under the
    /// service-account public key — proving the aws-lc-rs RS256 path works.
    #[test]
    fn fcm_assertion_is_a_valid_rs256_jwt() {
        use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

        let s = FcmSender::new(&fcm_service_account_json()).expect("FcmSender::new");
        let now = 1_700_000_000;
        let jwt = s.assertion_jwt(now).expect("assertion minted");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT has header.claims.signature");

        let hdr: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[0]).unwrap()).unwrap();
        assert_eq!(hdr["alg"], "RS256");
        assert_eq!(hdr["typ"], "JWT");

        let claims: serde_json::Value =
            serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "pusher@demo-project.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], FCM_SCOPE);
        assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
        assert_eq!(claims["iat"], now);
        assert_eq!(claims["exp"], now + 3600);

        // Verify the RS256 signature under the service-account public key.
        let der = pem_to_der(TEST_RSA_PKCS8_PEM).unwrap();
        let kp = aws_lc_rs::signature::RsaKeyPair::from_pkcs8(&der).unwrap();
        let public = UnparsedPublicKey::new(
            &RSA_PKCS1_2048_8192_SHA256,
            kp.public_key().as_ref().to_vec(),
        );
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = b64url_decode(parts[2]).unwrap();
        public
            .verify(signing_input.as_bytes(), &sig)
            .expect("RS256 assertion signature verifies");
    }
}
