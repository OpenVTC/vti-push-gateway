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
//! Push *delivery* is still the dev `EchoSender` (Web Push / APNs / FCM follow).

use std::path::Path;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use vti_push_gateway::api::{self, AppState};
use vti_push_gateway::didcomm;
use vti_push_gateway::identity::GatewayIdentity;
use vti_push_gateway::sender::{EchoSender, PushSender, WebPushSender};
use vti_push_gateway::store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    // Web Push (VAPID) sender — enabled by GATEWAY_VAPID_KEY_FILE — handles
    // `webpush` for real; the echo sender (handles every platform) is the
    // fallback for apns/fcm (dev) and for webpush when no VAPID key is set.
    let mut senders: Vec<Box<dyn PushSender>> = Vec::new();
    if let Ok(pem_path) = std::env::var("GATEWAY_VAPID_KEY_FILE") {
        let pem = std::fs::read(&pem_path)?;
        let subject = std::env::var("GATEWAY_VAPID_SUBJECT")
            .unwrap_or_else(|_| "mailto:push-gateway@localhost".into());
        match WebPushSender::new(pem, subject) {
            Ok(s) => {
                tracing::warn!("Web Push (VAPID) sender enabled");
                senders.push(Box::new(s));
            }
            Err(e) => tracing::error!(error = %e, "Web Push sender init failed; echo-only"),
        }
    }
    // Dev echo sender (logs, delivers nothing) — fallback / no-VAPID case.
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
        "vti-push-gateway up (echo sender — no real pushes are delivered)"
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
