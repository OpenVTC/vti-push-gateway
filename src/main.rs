//! vti-push-gateway — the push wake-up gateway for the OpenVTC mobile
//! authenticator. Implements <https://trusttasks.org/binding/push/0.1>: holds
//! the app's platform push credentials, issues opaque wake handles, enforces a
//! VTA-provisioned trigger allowlist, and relays **contentless** wakes.
//!
//! The control plane is the `push/*` Trust Task family, accepted over three
//! transports that share one intake (`intake::receive`), so `push/provision`
//! and `push/wake` are authorised identically on all of them — by the Data
//! Integrity proof on the document, bound to its issuer, fresh, addressed to
//! this gateway's DID, and once only:
//! - **TSP** and **DIDComm** — when `GATEWAY_IDENTITY_FILE` provides the
//!   gateway's provisioned `did:webvh` identity, one messaging service connects
//!   to the mediator and carries both on the same socket.
//! - **HTTPS** — `POST /trust-tasks`.
//!
//! Without an identity the gateway has no DID to be addressed to, so it serves
//! `push/register` only.
//!
//! Push *delivery* is real for Web Push (VAPID) and APNs when their credentials
//! are configured; the dev `EchoSender` is the fallback (and FCM follows).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

use vti_push_gateway::api::{self, AppState};
use vti_push_gateway::didcomm;
use vti_push_gateway::egress::{EgressPolicy, ENV_APNS_TOPICS};
use vti_push_gateway::identity::GatewayIdentity;
use vti_push_gateway::limits::Limits;
use vti_push_gateway::secretfile;
use vti_push_gateway::sender::{
    generate_vapid_keypair, ApnsSender, EchoSender, FcmSender, PushSender, WebPushSender,
};
use vti_push_gateway::store::{Store, StoreLimits};

/// Registry caps and the unprovisioned-handle TTL.
const ENV_MAX_HANDLES: &str = "GATEWAY_MAX_HANDLES";
const ENV_MAX_PER_TOKEN: &str = "GATEWAY_MAX_HANDLES_PER_TOKEN";
const ENV_UNPROVISIONED_TTL_SECS: &str = "GATEWAY_UNPROVISIONED_TTL_SECS";
const ENV_MAX_PER_CONTROLLER: &str = "GATEWAY_MAX_HANDLES_PER_CONTROLLER";
/// Minimum gap between snapshot writes.
const ENV_SNAPSHOT_FLUSH_MS: &str = "GATEWAY_SNAPSHOT_FLUSH_MS";

/// How often the sweeper runs and the per-DID limiter buckets are reclaimed. Not
/// configurable: it only affects how promptly expired handles disappear, and the
/// TTL is the property an operator actually cares about.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

/// Parse a positive integer env var, warning and using `default` when unset or
/// unparseable.
fn env_num<T: std::str::FromStr + Copy>(key: &str, default: T) -> T {
    match std::env::var(key) {
        Err(_) => default,
        Ok(raw) => raw.trim().parse::<T>().unwrap_or_else(|_| {
            tracing::warn!(%key, value = %raw, "invalid number; using the default");
            default
        }),
    }
}

/// Env var enabling the dev echo sender (see where it is pushed, below).
const ENV_DEV_ECHO_SENDER: &str = "GATEWAY_DEV_ECHO_SENDER";

/// Parse a boolean env flag: `1`/`true`/`yes`/`on` enables it.
fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

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
    if args.get(1).map(String::as_str) == Some("test-wake-apns") {
        return test_wake_apns(&args).await;
    }
    if args.get(1).map(String::as_str) == Some("test-wake-fcm") {
        return test_wake_fcm(&args).await;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vti_push_gateway=info,tower_http=info".into()),
        )
        .init();

    let bind = std::env::var("GATEWAY_BIND").unwrap_or_else(|_| "127.0.0.1:8300".into());

    // Egress policy: which Web Push services a registration's endpoint may name
    // (GATEWAY_WEBPUSH_ALLOWED_HOSTS) and which APNs topics it may use
    // (GATEWAY_APNS_TOPICS). An invalid or over-broad value stops startup.
    let egress = Arc::new(EgressPolicy::from_env().map_err(|e| format!("egress policy: {e}"))?);
    tracing::info!(
        hosts = %egress.webpush_hosts().join(","),
        "Web Push endpoint host allow-list"
    );
    match egress.apns_topics() {
        Some(topics) => tracing::info!(
            topics = %topics.iter().map(String::as_str).collect::<Vec<_>>().join(","),
            "APNs topic allow-list"
        ),
        None => tracing::warn!(
            "{ENV_APNS_TOPICS} not set — APNs registrations are not restricted to known topics"
        ),
    }

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
        let pem = secretfile::read_secret_file(Path::new(&pem_path), "VAPID private key")?;
        let subject = std::env::var("GATEWAY_VAPID_SUBJECT")
            .unwrap_or_else(|_| "mailto:push-gateway@localhost".into());
        match WebPushSender::new(pem, subject, egress.clone()) {
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
        let p8 = secretfile::read_secret_file(Path::new(&p8_path), "APNs auth key")?;
        // Trim: a stray newline/space (common when exporting env vars) in the
        // key id or team id silently breaks the JWT → APNs 403 InvalidProviderToken.
        let key_id = std::env::var("GATEWAY_APNS_KEY_ID")
            .unwrap_or_default()
            .trim()
            .to_string();
        let team_id = std::env::var("GATEWAY_APNS_TEAM_ID")
            .unwrap_or_default()
            .trim()
            .to_string();
        if key_id.is_empty() || team_id.is_empty() {
            tracing::error!(
                "GATEWAY_APNS_KEY_FILE set but GATEWAY_APNS_KEY_ID / GATEWAY_APNS_TEAM_ID \
                 missing; APNs disabled (echo fallback for apns)"
            );
        } else {
            // Key ID + Team ID are non-secret identifiers (the JWT `kid` / `iss`);
            // log them so an operator can verify them against the Apple portal —
            // a mismatch is the usual cause of `InvalidProviderToken`.
            match ApnsSender::new(p8, key_id.clone(), team_id.clone()) {
                Ok(s) => {
                    tracing::warn!(
                        key_id = %key_id, team_id = %team_id,
                        "APNs sender enabled (verify these match the Apple Developer portal)"
                    );
                    senders.push(Box::new(s));
                }
                Err(e) => tracing::error!(error = %e, "APNs sender init failed; echo fallback"),
            }
        }
    }
    // FCM sender — enabled when a Google service-account JSON is configured.
    if let Ok(sa_path) = std::env::var("GATEWAY_FCM_SERVICE_ACCOUNT_FILE") {
        let sa = secretfile::read_secret_file(Path::new(&sa_path), "FCM service-account key")?;
        match FcmSender::new(&sa) {
            Ok(s) => {
                tracing::warn!("FCM (Firebase Cloud Messaging) sender enabled");
                senders.push(Box::new(s));
            }
            Err(e) => tracing::error!(error = %e, "FCM sender init failed; echo fallback"),
        }
    }
    // Dev echo sender (logs, delivers nothing) — **opt-in only**.
    //
    // It reports `handles() == true` for every platform, so whenever it is
    // present it is a catch-all: `push/register`'s "no sender configured for this
    // platform" gate can never fire, and a production wake for a platform whose
    // credentials are missing reports `delivered` having sent nothing. That is
    // the wrong answer for a delivery-critical path — a dropped wake is a
    // security control that silently did not happen — so it now requires
    // GATEWAY_DEV_ECHO_SENDER.
    if env_flag(ENV_DEV_ECHO_SENDER) {
        tracing::warn!(
            "{ENV_DEV_ECHO_SENDER} is set — the dev echo sender accepts EVERY platform and \
             reports wakes as delivered without sending them. Do not enable this in production."
        );
        senders.push(Box::new(EchoSender));
    }
    if senders.is_empty() {
        tracing::error!(
            "no push sender is configured — every push/register will be refused. Set \
             GATEWAY_VAPID_KEY_FILE, GATEWAY_APNS_KEY_FILE or \
             GATEWAY_FCM_SERVICE_ACCOUNT_FILE, or {ENV_DEV_ECHO_SENDER}=1 for a \
             credential-free dev gateway."
        );
    }

    // Which controller VTAs this gateway serves. A malformed list stops startup
    // rather than being guessed at; an empty one refuses every registration.
    let controllers = vti_push_gateway::controllers::ControllerPolicy::from_env()?;
    match &controllers {
        vti_push_gateway::controllers::ControllerPolicy::Open => tracing::warn!(
            "{}=* — OPEN MODE: any controller VTA may register handles here. \
             Per-controller, per-handle and fair-share limits still apply; \
             list the VTAs this gateway serves instead.",
            vti_push_gateway::controllers::ENV_ALLOWED_CONTROLLERS
        ),
        vti_push_gateway::controllers::ControllerPolicy::Listed(set) if set.is_empty() => {
            tracing::error!(
                "{} is unset or empty — every push/register will be refused. \
                 List the controller VTA DIDs this gateway serves.",
                vti_push_gateway::controllers::ENV_ALLOWED_CONTROLLERS
            )
        }
        p => tracing::info!(controllers = %p.summary(), "controller allowlist"),
    }

    // Registry bounds. `push/register` is anonymous, so these are the ceilings on
    // what an unauthenticated caller can make the gateway hold.
    let defaults = StoreLimits::default();
    let store_limits = StoreLimits {
        max_handles: env_num(ENV_MAX_HANDLES, defaults.max_handles),
        max_per_token: env_num(ENV_MAX_PER_TOKEN, defaults.max_per_token),
        unprovisioned_ttl_secs: env_num(
            ENV_UNPROVISIONED_TTL_SECS,
            defaults.unprovisioned_ttl_secs,
        ),
        max_per_controller: env_num(ENV_MAX_PER_CONTROLLER, defaults.max_per_controller),
    };
    tracing::info!(
        max_handles = store_limits.max_handles,
        max_per_token = store_limits.max_per_token,
        unprovisioned_ttl_secs = store_limits.unprovisioned_ttl_secs,
        max_per_controller = store_limits.max_per_controller,
        "handle registry limits"
    );

    // Durable store when GATEWAY_STORE_FILE is set (handles/tokens survive a
    // restart); in-memory otherwise.
    let store = Arc::new(match std::env::var("GATEWAY_STORE_FILE") {
        Ok(path) => Store::open_with_limits(path.into(), &egress, store_limits),
        Err(_) => {
            tracing::warn!(
                "GATEWAY_STORE_FILE not set — handle registry is in-memory and lost on restart"
            );
            Store::with_limits(store_limits)
        }
    });
    // Durable TSP relationship store when GATEWAY_RELATIONSHIPS_FILE is set
    // (relationships survive a restart); in-memory otherwise, in which case
    // every peer's gate-admitted relationship is wiped on restart and each
    // re-invites before its next message is admitted.
    let tsp_relationships = match std::env::var("GATEWAY_RELATIONSHIPS_FILE") {
        Ok(path) => Some(vti_push_gateway::relationships::build_relationship_store(
            Some(path.into()),
        )),
        Err(_) => {
            tracing::warn!(
                "GATEWAY_RELATIONSHIPS_FILE not set — TSP relationships are in-memory and lost \
                 on restart; every peer re-invites before its next message is admitted"
            );
            Some(vti_push_gateway::relationships::build_relationship_store(
                None,
            ))
        }
    };

    let limits = Arc::new(Limits::from_env());
    tracing::info!(
        register = ?limits.register_config(),
        per_did = ?limits.per_did_config(),
        http = ?limits.http_config(),
        "rate limits"
    );
    // Verifies the proof on `push/provision` / `push/wake` documents, for every
    // transport. Under the tuned resolver's host policy: the DIDs it resolves
    // are named by inbound documents.
    let tuning = vti_push_gateway::resolver::ResolverTuning::from_env();
    let resolver = Arc::new(
        affinidi_did_resolver_cache_sdk::DIDCacheClient::new(tuning.did_cache_config())
            .await
            .map_err(|e| format!("build proof DID resolver: {e}"))?,
    );
    let proofs = vti_push_gateway::proof::ProofVerifier::new(resolver.clone());
    if identity.is_none() {
        tracing::warn!(
            "no GATEWAY_IDENTITY_FILE — the gateway has no DID for a document to be \
             addressed to, so push/provision and push/wake are refused on every transport"
        );
    }
    let state = AppState {
        store: store.clone(),
        senders: Arc::new(senders),
        gateway_addr: gateway_addr.clone(),
        metrics: Arc::new(vti_push_gateway::metrics::Metrics::default()),
        egress,
        limits: limits.clone(),
        replay: Arc::new(vti_push_gateway::replay::ReplayRecord::default()),
        controllers: Arc::new(controllers),
        proofs,
        gateway_did: identity.as_ref().map(|id| id.did.clone()),
        tsp_relationships: tsp_relationships.clone(),
    };

    // Start the mediator listener if provisioned: DIDComm and TSP on the one
    // socket the mediator allows per DID.
    let didcomm_shutdown = CancellationToken::new();
    let _didcomm_service = match &identity {
        Some(id) => match didcomm::start(id, state.clone(), didcomm_shutdown.clone()).await {
            Ok(svc) => {
                tracing::warn!(did = %id.did, mediator = %id.mediator,
                    "mediator listener started (TSP and DIDComm)");
                // Peers find the TSP endpoint in the DID document; say so if
                // it is not there. Off the startup path: resolution can wait
                // on the network.
                let (resolver, did, mediator) =
                    (resolver.clone(), id.did.clone(), id.mediator.clone());
                tokio::spawn(async move {
                    vti_push_gateway::tsp::check_advertised(&resolver, &did, &mediator).await;
                });
                Some(svc)
            }
            Err(e) => {
                tracing::error!(error = %e, "mediator listener failed to start; HTTPS-only");
                None
            }
        },
        None => {
            tracing::warn!("no GATEWAY_IDENTITY_FILE — TSP and DIDComm disabled, HTTPS-only");
            None
        }
    };

    // Management surface on its own listener, loopback by default. The counters
    // describe a push fleet's volumes and failure modes, and they used to sit on
    // the public router — so an nginx vhost proxying `location /` wholesale (as
    // the vti-setup template does) published them.
    let metrics_bind =
        std::env::var(api::ENV_METRICS_BIND).unwrap_or_else(|_| api::DEFAULT_METRICS_BIND.into());
    let metrics_token = std::env::var(api::ENV_METRICS_TOKEN)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    let metrics_listener = tokio::net::TcpListener::bind(&metrics_bind).await?;
    let off_host = !metrics_listener
        .local_addr()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(false);
    if off_host && metrics_token.is_none() {
        tracing::warn!(
            %metrics_bind,
            "{} is not a loopback address and {} is unset — the operation counters are \
             reachable off-host with no authentication",
            api::ENV_METRICS_BIND,
            api::ENV_METRICS_TOKEN
        );
    }
    tracing::warn!(
        %metrics_bind, authenticated = metrics_token.is_some(),
        "metrics listener up (GET /metrics)"
    );
    let metrics_app = api::metrics_router(state.clone(), metrics_token);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(metrics_listener, metrics_app).await {
            tracing::error!(error = %e, "metrics listener stopped");
        }
    });

    // Background maintenance, all three cheap timers sharing one token:
    //  - expire handles their VTA never provisioned (the root-cause bound on
    //    anonymous growth),
    //  - write the debounced snapshot,
    //  - reclaim per-DID limiter buckets, which are keyed by caller-chosen input
    //    and would otherwise be their own growth vector.
    let maintenance = CancellationToken::new();
    let flush_every = Duration::from_millis(env_num(ENV_SNAPSHOT_FLUSH_MS, 1_000));
    tokio::spawn(
        store
            .clone()
            .sweep_loop(MAINTENANCE_INTERVAL, maintenance.clone()),
    );
    tokio::spawn(store.clone().flush_loop(flush_every, maintenance.clone()));
    // TSP relationship store maintenance: log what survived the restart, write
    // its own debounced snapshot, and sweep idle relationships (7-day default)
    // so an invite that is never followed up doesn't accumulate forever.
    // Spawned once here (not per mediator reconnect), since it holds the store
    // and does not depend on the mediator socket.
    if let Some(relationships) = &tsp_relationships {
        tokio::spawn(
            relationships
                .backend()
                .file_store()
                .flush_loop(flush_every, maintenance.clone()),
        );
        tokio::spawn(vti_push_gateway::relationships::maintenance_loop(
            relationships.clone(),
            maintenance.clone(),
        ));
    }
    {
        let limits = limits.clone();
        let shutdown = maintenance.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(MAINTENANCE_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => limits.shrink(),
                    _ = shutdown.cancelled() => return,
                }
            }
        });
    }

    // Per-peer-IP HTTP limit: an outer guard that sheds a flood with 429 before
    // the body is read, complementing the in-core limiters (which are the ones
    // that also cover DIDComm). `GovernorConfigBuilder::period` is a replenish
    // *interval*, so it is derived from the per-second rate rather than passed
    // straight through. `PeerIpKeyExtractor` is why the service below is built
    // with `into_make_service_with_connect_info`; behind a trusted reverse proxy
    // `SmartIpKeyExtractor` would read `X-Forwarded-For` instead, which is only
    // sound when that proxy is the sole ingress.
    let http = limits.http_config();
    let governor = GovernorConfigBuilder::default()
        .period(Duration::from_nanos(
            1_000_000_000 / u64::from(http.per_second.max(1)),
        ))
        .burst_size(http.burst.max(1))
        .finish()
        .ok_or("invalid per-IP HTTP rate-limit configuration")?;

    let app = api::router(state)
        .layer(GovernorLayer::new(Arc::new(governor)))
        .layer(tower_http::trace::TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::warn!(
        %bind, %gateway_addr,
        "vti-push-gateway up"
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    // Stop the timers, then take one last snapshot so a clean shutdown is
    // durable even if the change landed inside the final flush window.
    maintenance.cancel();
    didcomm_shutdown.cancel();
    store.flush();
    if let Some(relationships) = &tsp_relationships {
        relationships.backend().flush();
    }
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
///
/// The write is a single `create_new` + mode-0600 open, so the key is owner-only
/// from its first byte and the refusal to overwrite is enforced by the kernel.
/// The previous `exists()` check, then write, then `chmod` left two gaps: a race
/// between the check and the write, and a window in which the private key sat at
/// the umask default (typically world-readable).
fn vapid_keygen(path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let path = path.unwrap_or("vapid.pem");
    let (pem, public) = generate_vapid_keypair()?;
    secretfile::write_owner_only_new(Path::new(path), pem.as_bytes()).map_err(|e| {
        if Path::new(path).exists() {
            format!("{path} already exists — refusing to overwrite a VAPID key")
        } else {
            e
        }
    })?;
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

/// Shared core for the `test-wake*` helpers: fire a real contentless wake at a
/// registered subscription, end to end, with no VTA in the loop. Acts as a
/// **legitimate signed caller** (not a backdoor): it mints a throwaway
/// `did:key`, `push/register`s the registration under that DID (so it's the
/// controller), `push/provision`s itself onto the allowlist, then sends a
/// signed `push/wake`. The gateway runs its normal intake — proof, freshness,
/// replay, allowlist — and delivery.
///
/// The provision and wake are addressed to the gateway DID the register
/// response names, so the gateway must have a provisioned identity; and the
/// throwaway DID is a controller only a gateway in open mode
/// (`GATEWAY_ALLOWED_CONTROLLERS=*`) serves.
async fn fire_wake(
    gateway: &str,
    registration: serde_json::Value,
    mediator: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
    use affinidi_secrets_resolver::secrets::Secret;

    // A throwaway did:key acting as both controller VTA (to provision) and
    // trigger (to wake) — a real signed caller, not a backdoor.
    let mut seed = [0u8; 32];
    {
        use rand::Rng;
        rand::rng().fill_bytes(&mut seed);
    }
    let probe = Secret::generate_ed25519(None, Some(&seed));
    let mb = {
        let mut b = vec![0xed, 0x01];
        b.extend_from_slice(probe.get_public_bytes());
        format!("z{}", bs58::encode(b).into_string())
    };
    let did = format!("did:key:{mb}");
    let secret = Secret::generate_ed25519(Some(&format!("{did}#{mb}")), Some(&seed));

    let url = format!("{}/trust-tasks", gateway.trim_end_matches('/'));
    let client = reqwest::Client::new();

    // POST a Trust Task doc; the gateway authenticates it by its own proof.
    async fn post(
        client: &reqwest::Client,
        url: &str,
        doc: &serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let resp = client
            .post(url)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(doc)?)
            .send()
            .await?;
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

    // A document issued by the throwaway DID to `recipient`, signed for
    // `authentication` the way a VTA signs its own operational messages.
    let signed = |type_uri: &str, recipient: &str, payload: serde_json::Value| {
        let mut doc = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuer": did,
            "recipient": recipient,
            "issuedAt": chrono::Utc::now().to_rfc3339(),
            "payload": payload,
        });
        let secret = &secret;
        async move {
            let proof = DataIntegrityProof::sign(
                &doc,
                secret,
                SignOptions::new().with_proof_purpose("authentication"),
            )
            .await
            .map_err(|e| format!("sign: {e}"))?;
            doc["proof"] = serde_json::to_value(&proof)?;
            Ok::<_, Box<dyn std::error::Error>>(doc)
        }
    };

    // 1. register (unauthenticated) → opaque handle, and the gateway's DID.
    let reg = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/push/register/0.2",
        "payload": { "registration": registration, "controllerVtaDid": did }
    });
    let resp = post(&client, &url, &reg).await?;
    let handle = resp
        .pointer("/payload/wakeHandle/handle")
        .and_then(|v| v.as_str())
        .ok_or("register: no handle in response")?
        .to_string();
    let gateway_did = resp
        .pointer("/payload/wakeHandle/gateway")
        .and_then(|v| v.as_str())
        .filter(|g| g.starts_with("did:"))
        .ok_or(
            "register: the gateway names no DID — it has no provisioned identity, \
             so it accepts no signed provision or wake",
        )?
        .to_string();
    println!("1/3 registered → handle {handle} at {gateway_did}");

    // 2. provision (signed; we are the controller) → allowlist = [self].
    let prov = signed(
        "https://trusttasks.org/spec/push/provision/0.2",
        &gateway_did,
        serde_json::json!({ "handle": handle, "policy": { "allowedTriggers": [did] } }),
    )
    .await?;
    post(&client, &url, &prov).await?;
    println!("2/3 provisioned → allowlist [self]");

    // 3. wake (signed; we are on the allowlist) → contentless push.
    let mut wake_payload =
        serde_json::json!({ "handle": handle, "v": 1, "urgency": "interactive" });
    if let Some(m) = &mediator {
        wake_payload["mediator"] = serde_json::json!(m);
    }
    let wake = signed(
        "https://trusttasks.org/spec/push/wake/0.2",
        &gateway_did,
        wake_payload,
    )
    .await?;
    let resp = post(&client, &url, &wake).await?;
    let status = resp
        .pointer("/payload/status")
        .and_then(|v| v.as_str())
        .unwrap_or("(see below)");
    println!("3/3 wake → {status}");
    println!("\nfull wake response: {resp}");
    Ok(())
}

/// `test-wake <gateway-url> <subscription.json> [mediator-did]` — fire a wake at
/// a registered **Web Push** subscription, end to end, with no VTA. The browser
/// service-worker console then shows `[pnm push] push received: …`.
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

    let registration = serde_json::json!({
        "platform": "webpush", "endpoint": endpoint,
        "keys": { "p256dh": p256dh, "auth": auth }
    });
    fire_wake(gateway, registration, mediator).await
}

/// `test-wake-apns <gateway-url> <apns-token-hex> <topic/bundle-id> [mediator-did]`
/// — fire a wake at a registered **APNs** device token, end to end, with no VTA.
/// The token is the hex string the iOS app logs (and shows in its UI; 64–200 hex
/// characters), and the topic must be listed in `GATEWAY_APNS_TOPICS` when that
/// is set. Uses the **sandbox** APNs environment (development builds); edit for
/// production.
async fn test_wake_apns(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let usage =
        "usage: test-wake-apns <gateway-url> <apns-token-hex> <topic/bundle-id> [mediator-did]";
    let gateway = args.get(2).ok_or(usage)?;
    let token = args.get(3).ok_or(usage)?;
    let topic = args.get(4).ok_or(usage)?;
    let mediator = args.get(5).cloned();

    let registration = serde_json::json!({
        "platform": "apns", "token": token, "topic": topic, "environment": "sandbox"
    });
    fire_wake(gateway, registration, mediator).await
}

/// `test-wake-fcm <gateway-url> <fcm-registration-token> [mediator-did]`
/// — fire a wake at a registered **FCM** device token, end to end, with no VTA.
/// The token is the Android app's FCM registration token. Requires the gateway
/// to have been started with `GATEWAY_FCM_SERVICE_ACCOUNT_FILE` set.
async fn test_wake_fcm(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let usage = "usage: test-wake-fcm <gateway-url> <fcm-registration-token> [mediator-did]";
    let gateway = args.get(2).ok_or(usage)?;
    let token = args.get(3).ok_or(usage)?;
    let mediator = args.get(4).cloned();

    let registration = serde_json::json!({ "platform": "fcm", "token": token });
    fire_wake(gateway, registration, mediator).await
}
