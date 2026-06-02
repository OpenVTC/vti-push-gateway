//! vti-push-gateway — the push wake-up gateway for the OpenVTC mobile
//! authenticator. Implements <https://trusttasks.org/binding/push/0.1>: holds
//! the app's platform push credentials, issues opaque wake handles, enforces a
//! VTA-provisioned trigger allowlist, and relays **contentless** wakes.
//!
//! Scaffold (Phase 1 / B1): REST surface + in-memory stores + did-signed auth +
//! the dev `EchoSender`. Web Push (VAPID) and APNs/FCM senders follow.

use std::sync::Arc;

use vti_push_gateway::api::{self, AppState};
use vti_push_gateway::sender::{EchoSender, PushSender};
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
    // The address the gateway advertises in issued handles (where triggers send
    // wakes). Defaults to the bind address; set explicitly behind a proxy/TLS.
    let gateway_addr = std::env::var("GATEWAY_ADDR").unwrap_or_else(|_| format!("http://{bind}"));

    // Scaffold: dev echo sender only. Real senders register here behind the
    // same trait. The echo sender does NOT deliver real pushes.
    let senders: Vec<Box<dyn PushSender>> = vec![Box::new(EchoSender)];

    let state = AppState {
        store: Arc::new(Store::new()),
        senders: Arc::new(senders),
        gateway_addr: gateway_addr.clone(),
    };

    let app = api::router(state).layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::warn!(
        %bind, %gateway_addr,
        "vti-push-gateway up (SCAFFOLD: echo sender only — no real pushes are delivered)"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
