//! vti-push-gateway — the push wake-up gateway for the OpenVTC mobile
//! authenticator. Implements <https://trusttasks.org/binding/push/0.1>: holds
//! the app's platform push credentials, issues opaque wake handles, enforces a
//! VTA-provisioned trigger allowlist, and relays **contentless** wakes.
//!
//! The control plane is the `push/*` Trust Task family, dispatched over two
//! transports that share one core (`api::dispatch_push`):
//! - **DIDComm** (preferred) — when `GATEWAY_IDENTITY_FILE` provides the
//!   gateway's provisioned `did:webvh` identity, a `DIDCommService` connects to
//!   the mediator and authenticates senders via authcrypt.
//! - **HTTPS** — `POST /trust-tasks`, did-signed, for callers that can't speak
//!   DIDComm.
//!
//! Push *delivery* is real for Web Push (VAPID) and APNs when their credentials
//! are configured; the dev `EchoSender` is the fallback (and FCM follows).

use std::path::Path;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use vti_push_gateway::api::{self, AppState};
use vti_push_gateway::didcomm;
use vti_push_gateway::identity::GatewayIdentity;
use vti_push_gateway::sender::{
    generate_vapid_keypair, ApnsSender, EchoSender, PushSender, WebPushSender,
};
use vti_push_gateway::store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Dev subcommands — handled before anything else so their output isn't
    // interleaved with server logs.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("vapid-keygen") {
        return vapid_keygen(args.get(2).map(String::as_str));
    }
    if args.get(1).map(String::as_str) == Some("test-wake") {
        return test_wake(&args).await;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vti_push_gateway=info,tower_http=info".into()),
        )
        .init();

    let bind = std::env::var("GATEWAY_BIND").unwrap_or_else(|_| "127.0.0.1:8300".into());

    // The gateway's provisioned did:webvh identity (push-gateway template),
    // loaded from the opened provision bundle. Present → DIDComm enabled.
    let identity = match std::env::var("GATEWAY_IDENTITY_FILE") {
        Ok(p) => Some(GatewayIdentity::load(Path::new(&p))?),
        Err(_) => None,
    };

    // Handle addressing: a DID `gateway` field means DIDComm (preferred); a URL
    // means HTTPS (others). Advertise the DID when we have a provisioned
    // identity, else the HTTPS URL.
    let gateway_addr = match &identity {
        Some(id) => id.did.clone(),
        None => std::env::var("GATEWAY_ADDR").unwrap_or_else(|_| format!("http://{bind}")),
    };

    // Senders are tried in order (first that `handles` the platform wins). The
    // Web Push (VAPID) sender handles `webpush` and the APNs sender handles
    // `apns` — each enabled only when its credentials are configured; the echo
    // sender (handles every platform) is the fallback for anything left (fcm,
    // or apns/webpush with no credentials).
    let mut senders: Vec<Box<dyn PushSender>> = Vec::new();
    if let Ok(pem_path) = std::env::var("GATEWAY_VAPID_KEY_FILE") {
        let pem = std::fs::read(&pem_path)?;
        let subject = std::env::var("GATEWAY_VAPID_SUBJECT")
            .unwrap_or_else(|_| "mailto:push-gateway@localhost".into());
        match WebPushSender::new(pem, subject) {
            Ok(s) => {
                // Surface the public key so the operator can paste it into the
                // device/plugin config (`pushGatewayVapidPublicKey`) — no need to
                // re-derive it from the PEM.
                tracing::warn!(
                    vapid_public = %s.vapid_public(),
                    "Web Push (VAPID) sender enabled — set this as the device/plugin applicationServerKey"
                );
                senders.push(Box::new(s));
            }
            Err(e) => tracing::error!(error = %e, "Web Push sender init failed; echo fallback"),
        }
    }
    // APNs sender — enabled when the app publisher's auth key + ids are set.
    if let Ok(p8_path) = std::env::var("GATEWAY_APNS_KEY_FILE") {
        let p8 = std::fs::read(&p8_path)?;
        let key_id = std::env::var("GATEWAY_APNS_KEY_ID").unwrap_or_default();
        let team_id = std::env::var("GATEWAY_APNS_TEAM_ID").unwrap_or_default();
        if key_id.is_empty() || team_id.is_empty() {
            tracing::error!(
                "GATEWAY_APNS_KEY_FILE set but GATEWAY_APNS_KEY_ID / GATEWAY_APNS_TEAM_ID \
                 missing; APNs disabled (echo fallback for apns)"
            );
        } else {
            match ApnsSender::new(p8, key_id, team_id) {
                Ok(s) => {
                    tracing::warn!("APNs sender enabled");
                    senders.push(Box::new(s));
                }
                Err(e) => tracing::error!(error = %e, "APNs sender init failed; echo fallback"),
            }
        }
    }
    // Dev echo sender (logs, delivers nothing) — fallback / no-credentials case.
    senders.push(Box::new(EchoSender));

    let state = AppState {
        store: Arc::new(Store::new()),
        senders: Arc::new(senders),
        gateway_addr: gateway_addr.clone(),
    };

    // Start the DIDComm listener (preferred transport) if provisioned.
    let didcomm_shutdown = CancellationToken::new();
    let _didcomm_service = match &identity {
        Some(id) => match didcomm::start(id, state.clone(), didcomm_shutdown.clone()).await {
            Ok(svc) => {
                tracing::warn!(did = %id.did, mediator = %id.mediator,
                    "DIDComm listener started (preferred transport)");
                Some(svc)
            }
            Err(e) => {
                tracing::error!(error = %e, "DIDComm listener failed to start; HTTPS-only");
                None
            }
        },
        None => {
            tracing::warn!("no GATEWAY_IDENTITY_FILE — DIDComm disabled, HTTPS-only");
            None
        }
    };

    let app = api::router(state).layer(tower_http::trace::TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::warn!(
        %bind, %gateway_addr,
        "vti-push-gateway up"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    didcomm_shutdown.cancel();
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

/// Mint a fresh VAPID keypair and write the private key (PKCS#8 PEM) to `path`
/// (default `vapid.pem`), printing the public key the device/plugin registers.
/// Refuses to overwrite an existing file — a clobbered key invalidates every
/// live subscription.
fn vapid_keygen(path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let path = path.unwrap_or("vapid.pem");
    if Path::new(path).exists() {
        return Err(format!("{path} already exists — refusing to overwrite a VAPID key").into());
    }
    let (pem, public) = generate_vapid_keypair()?;
    std::fs::write(path, &pem)?;
    // It's a private key — lock it down on unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("Wrote VAPID private key (PKCS#8 PEM): {path}");
    println!();
    println!("VAPID public key (applicationServerKey):");
    println!("  {public}");
    println!();
    println!("Next:");
    println!("  • run the gateway:  GATEWAY_VAPID_KEY_FILE={path} cargo run");
    println!("  • plugin Settings:  paste the public key as 'Push gateway VAPID public key'");
    Ok(())
}

/// `test-wake <gateway-url> <subscription.json> [mediator-did]` — fire a real
/// contentless wake at a registered subscription, end to end, with no VTA in the
/// loop. Acts as a **legitimate did-signed trigger** (not a backdoor): it mints a
/// throwaway `did:key`, `push/register`s the subscription under that DID (so it's
/// the controller), `push/provision`s itself onto the allowlist, then sends a
/// signed `push/wake`. The gateway runs its normal auth + allowlist + delivery.
///
/// `subscription.json` is the extension service-worker's logged subscription —
/// `{ "endpoint": …, "keys": { "p256dh": …, "auth": … } }` (copy the
/// `[pnm push] subscription:` line). Use it to prove: wake → gateway → Web Push
/// → the browser SW wakes and drains.
async fn test_wake(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let usage = "usage: test-wake <gateway-url> <subscription.json> [mediator-did]";
    let gateway = args.get(2).ok_or(usage)?;
    let sub_path = args.get(3).ok_or(usage)?;
    let mediator = args.get(4).cloned();

    let sub_raw = std::fs::read_to_string(sub_path).map_err(|e| {
        format!(
            "can't read subscription file '{sub_path}': {e}\n  \
             Save the extension service-worker's `[pnm push] subscription:` JSON \
             (its `{{endpoint, keys}}` object) to this path first."
        )
    })?;
    let sub: serde_json::Value = serde_json::from_str(&sub_raw)
        .map_err(|e| format!("'{sub_path}' is not valid JSON: {e}"))?;
    let endpoint = sub["endpoint"]
        .as_str()
        .ok_or("subscription.endpoint missing")?;
    let p256dh = sub["keys"]["p256dh"]
        .as_str()
        .ok_or("subscription.keys.p256dh missing")?;
    let auth = sub["keys"]["auth"]
        .as_str()
        .ok_or("subscription.keys.auth missing")?;

    // A throwaway did:key acting as both controller VTA (to provision) and
    // trigger (to wake) — a real signed caller.
    let mut seed = [0u8; 32];
    {
        use rand::Rng;
        rand::rng().fill_bytes(&mut seed);
    }
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = {
        let mut b = vec![0xed, 0x01];
        b.extend_from_slice(sk.verifying_key().as_bytes());
        format!("did:key:z{}", bs58::encode(b).into_string())
    };

    let base = gateway.trim_end_matches('/');
    let client = reqwest::Client::new();
    let url = format!("{base}/trust-tasks");

    // POST a Trust Task doc; sign the exact body bytes when `signed` (the gateway
    // verifies the X-TT-Signature over the raw body).
    async fn post(
        client: &reqwest::Client,
        url: &str,
        doc: &serde_json::Value,
        signer: Option<(&str, &ed25519_dalek::SigningKey)>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let body = serde_json::to_vec(doc)?;
        let mut req = client.post(url).header("content-type", "application/json");
        if let Some((did, sk)) = signer {
            let sig =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.sign(&body).to_bytes());
            req = req.header("x-tt-did", did).header("x-tt-signature", sig);
        }
        let resp = req.body(body).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(format!("{url} → {status}: {text}").into());
        }
        let v: serde_json::Value = serde_json::from_str(&text)?;
        if v.get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| t.contains("trust-task-error"))
        {
            return Err(format!("gateway rejected: {v}").into());
        }
        Ok(v)
    }

    // 1. register (unauthenticated) → opaque handle.
    let reg = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/push/register/0.2",
        "payload": {
            "registration": { "platform": "webpush", "endpoint": endpoint,
                              "keys": { "p256dh": p256dh, "auth": auth } },
            "controllerVtaDid": did,
        }
    });
    let handle = post(&client, &url, &reg, None)
        .await?
        .pointer("/payload/wakeHandle/handle")
        .and_then(|v| v.as_str())
        .ok_or("register: no handle in response")?
        .to_string();
    println!("1/3 registered → handle {handle}");

    // 2. provision (signed; we are the controller) → allowlist = [self].
    let prov = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/push/provision/0.1",
        "payload": { "handle": handle, "policy": { "allowedTriggers": [did] } }
    });
    post(&client, &url, &prov, Some((&did, &sk))).await?;
    println!("2/3 provisioned → allowlist [self]");

    // 3. wake (signed; we are on the allowlist) → contentless push.
    let mut wake_payload =
        serde_json::json!({ "handle": handle, "v": 1, "urgency": "interactive" });
    if let Some(m) = &mediator {
        wake_payload["mediator"] = serde_json::json!(m);
    }
    let wake = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/push/wake/0.1",
        "payload": wake_payload
    });
    let resp = post(&client, &url, &wake, Some((&did, &sk))).await?;
    let status = resp
        .pointer("/payload/status")
        .and_then(|v| v.as_str())
        .unwrap_or("(see below)");
    println!("3/3 wake → {status}");
    println!("\nIf delivered, the extension service-worker console shows:");
    println!("  [pnm push] push received: …");
    println!("\nfull wake response: {resp}");
    Ok(())
}
