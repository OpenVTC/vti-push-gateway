//! End-to-end exercise of the gateway's `push/*` Trust-Task dispatcher:
//! register → provision → wake, plus the auth/allowlist refusals. Posts
//! `TrustTask` documents to `/trust-tasks` and inspects the response document.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use rand::Rng;
use serde_json::{json, Value};
use tower::ServiceExt;

use vti_push_gateway::api::{metrics_router, router, AppState, DEFAULT_METRICS_BIND};
use vti_push_gateway::egress::EgressPolicy;
use vti_push_gateway::limits::{Limits, RateConfig, DEFAULT_HTTP, DEFAULT_PER_DID};
use vti_push_gateway::sender::{generate_vapid_keypair, EchoSender, PushSender, SendOutcome};
use vti_push_gateway::store::{Store, StoreLimits};
use vti_push_gateway::types::{PushRegistration, WakeTriggerPolicy, WebPushKeys};

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const PUSH_REGISTER: &str = "https://trusttasks.org/spec/push/register/0.2";
const PUSH_PROVISION: &str = "https://trusttasks.org/spec/push/provision/0.2";
const PUSH_WAKE: &str = "https://trusttasks.org/spec/push/wake/0.2";
// Retired 0.1 forms — the gateway is 0.2-only (issue #20 clean cutover).
const PUSH_REGISTER_V1: &str = "https://trusttasks.org/spec/push/register/0.1";
const PUSH_PROVISION_V1: &str = "https://trusttasks.org/spec/push/provision/0.1";
const PUSH_WAKE_V1: &str = "https://trusttasks.org/spec/push/wake/0.1";

/// Generate a signing key from OS randomness (rand 0.10), avoiding
/// ed25519-dalek's rand_core-0.6-tied `generate`.
fn signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn did_key_for(sk: &SigningKey) -> String {
    let mut bytes = ED25519_MULTICODEC.to_vec();
    bytes.extend_from_slice(sk.verifying_key().as_bytes());
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}

fn state() -> AppState {
    // Permissive limits by default: these tests exercise the push/* logic, and a
    // rate limit tripping mid-test would be a confusing failure. The tests that
    // are *about* the limits set their own.
    state_with(Store::new(), Limits::permissive())
}

fn state_with(store: Store, limits: Limits) -> AppState {
    let senders: Vec<Box<dyn PushSender>> = vec![Box::new(EchoSender)];
    AppState {
        store: Arc::new(store),
        senders: Arc::new(senders),
        gateway_addr: "https://gw.test".into(),
        metrics: Arc::new(vti_push_gateway::metrics::Metrics::default()),
        egress: Arc::new(EgressPolicy::default()),
        limits: Arc::new(limits),
        replay: Arc::new(vti_push_gateway::replay::ReplayRecord::default()),
    }
}

/// A distinct, valid APNs registration per index — so a flood is not stopped by
/// the per-token cap when the per-request budget is what's under test.
fn apns_registration(n: usize) -> Value {
    json!({ "platform": "apns", "token": format!("{n:064x}"), "topic": "org.openvtc.app" })
}

/// The public router plus a management router sharing one `AppState`, so a test
/// can drive `push/*` and then scrape the counters those calls bumped. `/metrics`
/// no longer lives on the public router.
fn routers() -> (Router, Router) {
    let st = state();
    (router(st.clone()), metrics_router(st, None))
}

/// A syntactically valid 64-character hex APNs device token.
fn apns_token() -> String {
    "a1".repeat(32)
}

/// A valid Web Push subscription key pair (65-byte P-256 point, 16-byte auth).
const P256DH: &str =
    "BHTHkS5TN8hSA9_AzgRusH55jqrZjomGJ42mYrmFNIKH1cc0JnR6ZzwjcWQljvhdjlapl3nOtq2P6e9IMjMoWrY";
const AUTH: &str = "-8GwtL6MnCVPpyjEYoad2A";

/// Scrape `GET /metrics` through the **management** router.
async fn metrics_text(app: &Router) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// A `TrustTask` document with the given type URI + payload.
fn tt_doc(type_uri: &str, payload: Value) -> Value {
    json!({ "id": "urn:uuid:req", "type": type_uri, "payload": payload })
}

/// POST a Trust Task document to `/trust-tasks`, optionally did-signed over the
/// exact body bytes.
fn post(doc: &Value, signer: Option<&SigningKey>) -> Request<Body> {
    let bytes = serde_json::to_vec(doc).unwrap();
    let mut b = Request::builder()
        .method("POST")
        .uri("/trust-tasks")
        .header("content-type", "application/json");
    if let Some(sk) = signer {
        let sig =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.sign(&bytes).to_bytes());
        b = b
            .header("x-tt-did", did_key_for(sk))
            .header("x-tt-signature", sig);
    }
    b.body(Body::from(bytes)).unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// True when the response document is a success (`…#response`) rather than a
/// `trust-task-error`.
fn is_success(doc: &Value) -> bool {
    doc["type"]
        .as_str()
        .is_some_and(|t| t.ends_with("#response"))
}

#[tokio::test]
async fn full_flow_register_provision_wake() {
    let vta = signing_key();
    let mediator = signing_key();
    let app = router(state());

    // 1. Device registers (unauthenticated) → opaque handle.
    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "apns", "token": apns_token(), "topic": "org.openvtc.app" },
            "controllerVtaDid": did_key_for(&vta),
        }),
    );
    let resp = app.clone().oneshot(post(&reg, None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert!(is_success(&doc), "register should succeed: {doc}");
    let handle = doc["payload"]["wakeHandle"]["handle"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. A wake before provisioning is refused (empty allowlist).
    let wake = tt_doc(PUSH_WAKE, json!({ "handle": handle, "v": 1 }));
    let doc = body_json(
        app.clone()
            .oneshot(post(&wake, Some(&mediator)))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        !is_success(&doc),
        "wake before provision must be rejected: {doc}"
    );

    // 3. A non-controller cannot provision.
    let imposter = signing_key();
    let prov = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers": [did_key_for(&imposter)] } }),
    );
    let doc = body_json(
        app.clone()
            .oneshot(post(&prov, Some(&imposter)))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        !is_success(&doc),
        "non-controller provision must be rejected: {doc}"
    );

    // 4. The controller VTA provisions the mediator as an allowed trigger.
    let prov = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers": [did_key_for(&mediator)] } }),
    );
    let doc = body_json(app.clone().oneshot(post(&prov, Some(&vta))).await.unwrap()).await;
    assert!(
        is_success(&doc),
        "controller provision should succeed: {doc}"
    );

    // 5. The allowed trigger wakes the device.
    let wake = tt_doc(
        PUSH_WAKE,
        json!({ "handle": handle, "v": 1, "mediator": "did:web:m", "urgency": "interactive" }),
    );
    let doc = body_json(
        app.clone()
            .oneshot(post(&wake, Some(&mediator)))
            .await
            .unwrap(),
    )
    .await;
    assert!(is_success(&doc), "allowed wake should succeed: {doc}");
    assert_eq!(doc["payload"]["status"], "delivered");

    // 6. A DID not on the allowlist still can't wake it.
    let doc = body_json(
        app.clone()
            .oneshot(post(&wake, Some(&imposter)))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        !is_success(&doc),
        "non-allowed wake must be rejected: {doc}"
    );
}

/// A `push/register/0.2` success response mirrors the request's 0.2 version
/// and carries the opaque `wakeHandle {gateway, handle}`.
#[tokio::test]
async fn register_v2_returns_v2_response() {
    let vta = signing_key();
    let app = router(state());
    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "apns", "token": apns_token(), "topic": "org.openvtc.app" },
            "controllerVtaDid": did_key_for(&vta),
        }),
    );
    let resp = app.oneshot(post(&reg, None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert!(is_success(&doc), "register/0.2 should succeed: {doc}");
    assert_eq!(
        doc["type"], "https://trusttasks.org/spec/push/register/0.2#response",
        "response must mirror the request's 0.2 version: {doc}"
    );
    assert!(
        doc["payload"]["wakeHandle"]["handle"].is_string()
            && doc["payload"]["wakeHandle"]["gateway"].is_string(),
        "0.2 response carries wakeHandle {{gateway, handle}}: {doc}"
    );
}

/// Issue #20 clean cutover: every retired `push/*/0.1` URI is refused with an
/// `unsupported type` error document — the gateway speaks 0.2 only.
#[tokio::test]
async fn v0_1_uris_are_rejected() {
    let vta = signing_key();
    let app = router(state());
    let docs = [
        tt_doc(
            PUSH_REGISTER_V1,
            json!({
                "registration": { "platform": "apns", "token": apns_token(), "topic": "org.openvtc.app" },
                "controllerVtaDid": did_key_for(&vta),
            }),
        ),
        tt_doc(
            PUSH_PROVISION_V1,
            json!({ "handle": "h", "policy": { "allowedTriggers": [] } }),
        ),
        tt_doc(PUSH_WAKE_V1, json!({ "handle": "h", "v": 1 })),
    ];
    for req in &docs {
        let doc = body_json(app.clone().oneshot(post(req, Some(&vta))).await.unwrap()).await;
        assert!(
            !is_success(&doc),
            "retired 0.1 URI {} must be rejected: {doc}",
            req["type"]
        );
    }
}

/// A sender whose push service reports the token permanently unregistered.
struct DeadTokenSender;

#[async_trait::async_trait]
impl PushSender for DeadTokenSender {
    fn handles(&self, _registration: &vti_push_gateway::types::PushRegistration) -> bool {
        true
    }
    async fn send(
        &self,
        _registration: &vti_push_gateway::types::PushRegistration,
        _payload: &vti_push_gateway::types::WakePayload,
    ) -> SendOutcome {
        SendOutcome::PermanentlyUnregistered
    }
}

/// A dead token surfaces as the 0.2 `tokenUnregistered` status (0.1 spelled it
/// `token-unregistered`) and the handle is dropped.
#[tokio::test]
async fn dead_token_reports_v2_token_unregistered_status() {
    let vta = signing_key();
    let mediator = signing_key();
    let senders: Vec<Box<dyn PushSender>> = vec![Box::new(DeadTokenSender)];
    let mut st = state();
    st.senders = Arc::new(senders);
    let app = router(st);

    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "apns", "token": "de".repeat(32), "topic": "org.openvtc.app" },
            "controllerVtaDid": did_key_for(&vta),
        }),
    );
    let handle = body_json(app.clone().oneshot(post(&reg, None)).await.unwrap()).await["payload"]
        ["wakeHandle"]["handle"]
        .as_str()
        .unwrap()
        .to_string();
    let prov = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers": [did_key_for(&mediator)] } }),
    );
    let doc = body_json(app.clone().oneshot(post(&prov, Some(&vta))).await.unwrap()).await;
    assert!(is_success(&doc), "provision should succeed: {doc}");

    let wake = tt_doc(PUSH_WAKE, json!({ "handle": handle, "v": 1 }));
    let doc = body_json(
        app.clone()
            .oneshot(post(&wake, Some(&mediator)))
            .await
            .unwrap(),
    )
    .await;
    assert!(is_success(&doc), "dead-token wake reports in-band: {doc}");
    assert_eq!(
        doc["payload"]["status"], "tokenUnregistered",
        "0.2 camelCase status expected: {doc}"
    );

    // The handle was dropped — a second wake finds it unknown.
    let doc = body_json(app.oneshot(post(&wake, Some(&mediator))).await.unwrap()).await;
    assert!(!is_success(&doc), "dropped handle must be unknown: {doc}");
}

/// The `/metrics` endpoint reflects real operation outcomes: a full
/// register → provision → wake flow plus a refused wake show up as the right
/// Prometheus counters, scraped through the management router that shares the
/// public router's state.
#[tokio::test]
async fn metrics_endpoint_reflects_operations() {
    let vta = signing_key();
    let mediator = signing_key();
    let (app, metrics_app) = routers();

    // register → handle.
    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "apns", "token": apns_token(), "topic": "org.openvtc.app" },
            "controllerVtaDid": did_key_for(&vta),
        }),
    );
    let handle = body_json(app.clone().oneshot(post(&reg, None)).await.unwrap()).await["payload"]
        ["wakeHandle"]["handle"]
        .as_str()
        .unwrap()
        .to_string();

    // provision the mediator, then a delivered wake.
    let prov = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers": [did_key_for(&mediator)] } }),
    );
    app.clone().oneshot(post(&prov, Some(&vta))).await.unwrap();
    let wake = tt_doc(PUSH_WAKE, json!({ "handle": handle, "v": 1 }));
    app.clone()
        .oneshot(post(&wake, Some(&mediator)))
        .await
        .unwrap();

    // a wake from a non-allowlisted trigger → not_allowed.
    let imposter = signing_key();
    app.clone()
        .oneshot(post(&wake, Some(&imposter)))
        .await
        .unwrap();

    // Scrape /metrics.
    let text = metrics_text(&metrics_app).await;

    assert!(text.contains("gateway_register_total 1\n"), "{text}");
    assert!(
        text.contains("gateway_provision_total{outcome=\"ok\"} 1\n"),
        "{text}"
    );
    assert!(
        text.contains("gateway_wake_total{outcome=\"delivered\"} 1\n"),
        "{text}"
    );
    assert!(
        text.contains("gateway_wake_total{outcome=\"not_allowed\"} 1\n"),
        "{text}"
    );
}

#[tokio::test]
async fn wake_unknown_handle_is_rejected() {
    let trigger = signing_key();
    let app = router(state());
    let wake = tt_doc(PUSH_WAKE, json!({ "handle": "nope", "v": 1 }));
    let doc = body_json(app.oneshot(post(&wake, Some(&trigger))).await.unwrap()).await;
    assert!(!is_success(&doc), "unknown handle must be rejected: {doc}");
}

#[tokio::test]
async fn provision_without_auth_is_rejected() {
    let app = router(state());
    // No signature → no authenticated caller → provision refused.
    let prov = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": "h", "policy": { "allowedTriggers": [] } }),
    );
    let doc = body_json(app.oneshot(post(&prov, None)).await.unwrap()).await;
    assert!(
        !is_success(&doc),
        "unauthenticated provision must be rejected: {doc}"
    );
}

/// The PoC `sub-ssrf.json` payload — an unauthenticated `push/register` whose
/// Web Push endpoint points at an internal metadata service — is rejected, and
/// nothing is registered (`gateway_register_total` stays 0).
#[tokio::test]
async fn register_ssrf_webpush_endpoint_is_rejected() {
    let (app, metrics_app) = routers();
    // The exact endpoint from pocs/.../sub-ssrf.json (with the payload's own keys).
    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": {
                "platform": "webpush",
                "endpoint": "http://127.0.0.1:9099/latest/meta-data/iam/security-credentials/",
                "keys": {
                    "p256dh": P256DH,
                    "auth": AUTH,
                }
            },
            "controllerVtaDid": did_key_for(&signing_key()),
        }),
    );
    let resp = app.clone().oneshot(post(&reg, None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert!(
        doc["type"]
            .as_str()
            .is_some_and(|t| t.contains("trust-task-error")),
        "SSRF register must return a trust-task-error: {doc}"
    );
    assert!(
        metrics_text(&metrics_app)
            .await
            .contains("gateway_register_total 0\n"),
        "nothing must be registered"
    );
}

/// A grab-bag of malformed / disallowed registrations are all rejected without
/// registering anything: a non-allowlisted host, an IP-literal endpoint, junk
/// subscription keys, a non-hex APNs token, and a bad controller DID.
#[tokio::test]
async fn register_rejects_invalid_fields() {
    let bad_regs = [
        json!({ "platform": "webpush", "endpoint": "https://evil.example/x",
                "keys": { "p256dh": P256DH, "auth": AUTH } }),
        json!({ "platform": "webpush", "endpoint": "https://169.254.169.254/x",
                "keys": { "p256dh": P256DH, "auth": AUTH } }),
        json!({ "platform": "webpush", "endpoint": "https://fcm.googleapis.com/x",
                "keys": { "p256dh": "k", "auth": "a" } }),
        json!({ "platform": "apns", "token": "../x", "topic": "org.openvtc.app" }),
    ];
    for reg in bad_regs {
        let (app, metrics_app) = routers();
        let reg_is = reg.clone();
        let doc = tt_doc(
            PUSH_REGISTER,
            json!({ "registration": reg, "controllerVtaDid": did_key_for(&signing_key()) }),
        );
        let out = body_json(app.clone().oneshot(post(&doc, None)).await.unwrap()).await;
        assert!(!is_success(&out), "must be rejected: {reg_is} → {out}");
        assert!(metrics_text(&metrics_app)
            .await
            .contains("gateway_register_total 0\n"));
    }

    // A controllerVtaDid that is not a DID is refused even with a valid endpoint.
    let app = router(state());
    let doc = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "webpush", "endpoint": "https://fcm.googleapis.com/x",
                              "keys": { "p256dh": P256DH, "auth": AUTH } },
            "controllerVtaDid": "not-a-did",
        }),
    );
    let out = body_json(app.oneshot(post(&doc, None)).await.unwrap()).await;
    assert!(
        !is_success(&out),
        "bad controller DID must be rejected: {out}"
    );
}

/// A valid Web Push registration to an allowlisted host is accepted.
#[tokio::test]
async fn register_accepts_valid_webpush() {
    let senders: Vec<Box<dyn PushSender>> = vec![Box::new(EchoSender)];
    let mut st = state();
    st.senders = Arc::new(senders);
    let app = router(st);
    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "webpush",
                "endpoint": "https://fcm.googleapis.com/fcm/send/abc",
                "keys": { "p256dh": P256DH, "auth": AUTH } },
            "controllerVtaDid": did_key_for(&signing_key()),
        }),
    );
    let doc = body_json(app.oneshot(post(&reg, None)).await.unwrap()).await;
    assert!(
        is_success(&doc),
        "valid webpush register should succeed: {doc}"
    );
}

/// The 16 KiB body limit rejects an oversized `POST /trust-tasks`.
#[tokio::test]
async fn oversized_body_is_rejected() {
    let app = router(state());
    let big = "a".repeat(17 * 1024);
    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "fcm", "token": big },
            "controllerVtaDid": did_key_for(&signing_key()),
        }),
    );
    let status = app.oneshot(post(&reg, None)).await.unwrap().status();
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "17 KiB body must be 413"
    );
}

/// PG-6: the counters are not on the public router any more — only on the
/// management one, so a proxy forwarding `location /` wholesale cannot publish
/// them. Liveness stays available on both.
#[tokio::test]
async fn metrics_is_not_served_on_the_public_router() {
    let (app, metrics_app) = routers();
    let get = |uri: &str| {
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    };

    assert_eq!(
        app.clone().oneshot(get("/metrics")).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "/metrics must not exist on the public router"
    );
    assert_eq!(
        app.oneshot(get("/healthz")).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        metrics_app.oneshot(get("/metrics")).await.unwrap().status(),
        StatusCode::OK,
        "the management router serves them"
    );
}

/// With `GATEWAY_METRICS_TOKEN` configured, the management router requires that
/// exact bearer token — for when the management port must be reachable off-host.
#[tokio::test]
async fn metrics_router_enforces_its_bearer_token() {
    let app = metrics_router(state(), Some("s3cret".into()));
    let scrape = |auth: Option<&str>| {
        let mut b = Request::builder().method("GET").uri("/metrics");
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        b.body(Body::empty()).unwrap()
    };

    for bad in [
        None,
        Some("Bearer wrong"),
        Some("s3cret"),         // no scheme
        Some("Bearer s3cre"),   // prefix
        Some("Bearer s3crets"), // extension
        Some("bearer s3cret"),  // wrong case
    ] {
        assert_eq!(
            app.clone().oneshot(scrape(bad)).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "{bad:?} must be refused"
        );
    }
    assert_eq!(
        app.oneshot(scrape(Some("Bearer s3cret")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

/// PG-4: `allowedTriggers` is capped at 32, every entry must be a DID, and
/// duplicates collapse while order is preserved. A refused policy must leave the
/// stored allowlist exactly as it was.
#[tokio::test]
async fn provision_bounds_the_allowed_triggers_list() {
    let vta = signing_key();
    let mediator = signing_key();
    let app = router(state());

    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "apns", "token": apns_token(), "topic": "org.openvtc.app" },
            "controllerVtaDid": did_key_for(&vta),
        }),
    );
    let handle = body_json(app.clone().oneshot(post(&reg, None)).await.unwrap()).await["payload"]
        ["wakeHandle"]["handle"]
        .as_str()
        .unwrap()
        .to_string();

    // A good policy first, so a later refusal can be shown to change nothing.
    let good = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers": [did_key_for(&mediator)] } }),
    );
    assert!(is_success(
        &body_json(app.clone().oneshot(post(&good, Some(&vta))).await.unwrap()).await
    ));

    // 33 entries → refused.
    let many: Vec<String> = (0..33).map(|_| did_key_for(&signing_key())).collect();
    let too_many = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers": many } }),
    );
    let out = body_json(
        app.clone()
            .oneshot(post(&too_many, Some(&vta)))
            .await
            .unwrap(),
    )
    .await;
    assert!(!is_success(&out), "33 triggers must be refused: {out}");

    // A non-DID entry → refused.
    let junk = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers": ["not-a-did"] } }),
    );
    let out = body_json(app.clone().oneshot(post(&junk, Some(&vta))).await.unwrap()).await;
    assert!(
        !is_success(&out),
        "a non-DID trigger must be refused: {out}"
    );

    // Neither refusal disturbed the stored allowlist.
    let wake = tt_doc(PUSH_WAKE, json!({ "handle": handle, "v": 1 }));
    let out = body_json(
        app.clone()
            .oneshot(post(&wake, Some(&mediator)))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        is_success(&out),
        "a refused policy must leave the allowlist intact: {out}"
    );

    // Exactly 32 is accepted (the cap is inclusive).
    let thirty_two: Vec<String> = (0..32).map(|_| did_key_for(&signing_key())).collect();
    let at_cap = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers": thirty_two } }),
    );
    let out = body_json(
        app.clone()
            .oneshot(post(&at_cap, Some(&vta)))
            .await
            .unwrap(),
    )
    .await;
    assert!(is_success(&out), "32 triggers must be accepted: {out}");

    // Duplicates collapse; the surviving order is the submitted order.
    let a = did_key_for(&mediator);
    let b = did_key_for(&signing_key());
    let dupes = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers": [&a, &b, &a] } }),
    );
    let out = body_json(app.oneshot(post(&dupes, Some(&vta))).await.unwrap()).await;
    assert!(
        is_success(&out),
        "duplicates are collapsed, not refused: {out}"
    );
    assert_eq!(
        out["payload"]["policy"]["allowedTriggers"],
        json!([&a, &b]),
        "duplicates collapse and order is preserved: {out}"
    );
}

/// PG-7: a payload that does not match the schema gets one fixed reason; the
/// serde detail goes to a debug log, not to the caller.
#[tokio::test]
async fn schema_mismatch_reason_is_generic() {
    let app = router(state());
    // `endpoint` is a number where a string belongs (RUN.md #7).
    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "webpush", "endpoint": 123,
                              "keys": { "p256dh": P256DH, "auth": AUTH } },
            "controllerVtaDid": did_key_for(&signing_key()),
        }),
    );
    let out = body_json(app.oneshot(post(&reg, None)).await.unwrap()).await;
    assert!(!is_success(&out), "must be rejected: {out}");

    let text = out.to_string();
    assert!(
        text.contains("payload does not match the push/* 0.2 schema"),
        "the fixed reason must be returned: {text}"
    );
    for leak in ["invalid type", "expected a string", "integer `123`"] {
        assert!(
            !text.contains(leak),
            "serde detail {leak:?} must not be reflected: {text}"
        );
    }
}

#[tokio::test]
async fn bad_signature_is_401() {
    let trigger = signing_key();
    let app = router(state());
    let wake = tt_doc(PUSH_WAKE, json!({ "handle": "h", "v": 1 }));
    let mut req = post(&wake, Some(&trigger));
    // Replace the body after signing → signature no longer matches.
    *req.body_mut() = Body::from(
        r#"{"id":"urn:uuid:req","type":"https://trusttasks.org/spec/push/wake/0.2","payload":{"handle":"tampered","v":1}}"#,
    );
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

/// A register budget loose enough not to interfere with tests about other
/// limits.
const DEFAULT_REGISTER_FOR_TEST: RateConfig = RateConfig {
    per_second: 1_000_000,
    burst: 1_000_000,
};

/// PG-2, the `register-flood.sh` PoC as a test: 200 anonymous registrations from
/// one caller are accepted only up to the burst, and the register counter stops
/// climbing. The counter is the assertion that matters — it proves the refusals
/// happened before anything was stored, not merely that a reply said "no".
#[tokio::test]
async fn register_flood_is_refused_after_the_burst() {
    let burst = 5;
    // The counters live on the management router now, so both are built over one
    // shared `AppState` — the public one takes the flood, the management one is
    // scraped for what it did.
    let st = state_with(
        Store::new(),
        Limits::new(
            RateConfig {
                per_second: 1,
                burst,
            },
            DEFAULT_PER_DID,
            DEFAULT_HTTP,
        ),
    );
    let app = router(st.clone());
    let metrics_app = metrics_router(st, None);

    let mut accepted = 0;
    for i in 0..200 {
        let reg = tt_doc(
            PUSH_REGISTER,
            json!({
                "registration": apns_registration(i),
                "controllerVtaDid": did_key_for(&signing_key()),
            }),
        );
        let out = body_json(app.clone().oneshot(post(&reg, None)).await.unwrap()).await;
        if is_success(&out) {
            accepted += 1;
        }
    }

    assert_eq!(
        accepted, burst as usize,
        "only the burst may be accepted out of 200"
    );
    let text = metrics_text(&metrics_app).await;
    assert!(
        text.contains(&format!("gateway_register_total {burst}\n")),
        "the register counter must stop climbing at the burst: {text}"
    );
}

/// The per-DID budget throttles one noisy trigger without touching another —
/// the reason the wake/provision limiter is keyed rather than global.
#[tokio::test]
async fn wake_budget_is_per_caller_did() {
    let vta = signing_key();
    let noisy = signing_key();
    let quiet = signing_key();
    let app = router(state_with(
        Store::new(),
        Limits::new(
            DEFAULT_REGISTER_FOR_TEST,
            RateConfig {
                per_second: 1,
                burst: 3,
            },
            DEFAULT_HTTP,
        ),
    ));

    // Register and provision both triggers onto one handle.
    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": apns_registration(1),
            "controllerVtaDid": did_key_for(&vta),
        }),
    );
    let handle = body_json(app.clone().oneshot(post(&reg, None)).await.unwrap()).await["payload"]
        ["wakeHandle"]["handle"]
        .as_str()
        .unwrap()
        .to_string();
    let prov = tt_doc(
        PUSH_PROVISION,
        json!({ "handle": handle, "policy": { "allowedTriggers":
                [did_key_for(&noisy), did_key_for(&quiet)] } }),
    );
    assert!(is_success(
        &body_json(app.clone().oneshot(post(&prov, Some(&vta))).await.unwrap()).await
    ));

    // The noisy trigger burns its own bucket (provision above already spent one
    // of the VTA's, not the triggers').
    let wake = tt_doc(PUSH_WAKE, json!({ "handle": handle, "v": 1 }));
    let mut noisy_ok = 0;
    for _ in 0..10 {
        let out = body_json(
            app.clone()
                .oneshot(post(&wake, Some(&noisy)))
                .await
                .unwrap(),
        )
        .await;
        if is_success(&out) {
            noisy_ok += 1;
        }
    }
    assert_eq!(noisy_ok, 3, "the noisy trigger is capped at its burst");

    // The quiet trigger is unaffected.
    let out = body_json(
        app.clone()
            .oneshot(post(&wake, Some(&quiet)))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        is_success(&out),
        "a different trigger DID must not be throttled: {out}"
    );
}

/// With `max_handles = 10`, the 11th registration is refused and nothing is
/// stored for it.
#[tokio::test]
async fn eleventh_registration_is_refused_at_capacity() {
    let st = state_with(
        Store::with_limits(StoreLimits {
            max_handles: 10,
            ..StoreLimits::default()
        }),
        Limits::permissive(),
    );
    let app = router(st.clone());
    let metrics_app = metrics_router(st, None);

    for i in 0..10 {
        let reg = tt_doc(
            PUSH_REGISTER,
            json!({
                "registration": apns_registration(i),
                "controllerVtaDid": did_key_for(&signing_key()),
            }),
        );
        let out = body_json(app.clone().oneshot(post(&reg, None)).await.unwrap()).await;
        assert!(
            is_success(&out),
            "registration {i} is within the cap: {out}"
        );
    }

    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": apns_registration(10),
            "controllerVtaDid": did_key_for(&signing_key()),
        }),
    );
    let out = body_json(app.clone().oneshot(post(&reg, None)).await.unwrap()).await;
    assert!(!is_success(&out), "the 11th must be refused: {out}");
    assert!(
        out.to_string().contains("gateway at capacity"),
        "the reason should name the limit: {out}"
    );
    let text = metrics_text(&metrics_app).await;
    assert!(
        text.contains("gateway_register_total 10\n"),
        "the refused registration must not be counted: {text}"
    );
}

/// The per-token cap stops one push token from occupying the registry, even
/// though each request is otherwise valid.
#[tokio::test]
async fn repeated_registration_of_one_token_is_capped() {
    let app = router(state_with(
        Store::with_limits(StoreLimits {
            max_per_token: 2,
            ..StoreLimits::default()
        }),
        Limits::permissive(),
    ));

    let mut accepted = 0;
    for _ in 0..6 {
        // The same device token every time.
        let reg = tt_doc(
            PUSH_REGISTER,
            json!({
                "registration": apns_registration(7),
                "controllerVtaDid": did_key_for(&signing_key()),
            }),
        );
        let out = body_json(app.clone().oneshot(post(&reg, None)).await.unwrap()).await;
        if is_success(&out) {
            accepted += 1;
        } else {
            assert!(
                out.to_string()
                    .contains("too many handles for this push token"),
                "{out}"
            );
        }
    }
    assert_eq!(accepted, 2, "one token gets max_per_token handles, no more");
}

// ─── SEC-4045 regression gates ─────────────────────────────────────────────
//
// Everything below re-runs a reproduced PoC step against the merged fix. The
// two gates that use sockets bind **loopback only**, and they assert on a
// listener that accepted nothing: that way, reverting the fix to watch the gate
// go red makes the gateway dial 127.0.0.1 and nothing else. No vector here can
// send a packet off the machine, red or green — the unroutable hosts the PoC
// also tried (`169.254.169.254` and friends) are gated in `egress::tests`,
// which performs no I/O at all.

/// Bind a loopback port that counts accepted connections and answers nothing.
/// Standing in for `poc-harness/listener.py`: the point is the count, since a
/// gate here passes only when it stays at zero.
async fn counting_listener() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            held.push(sock);
        }
    });
    (addr, accepted)
}

/// A real Web Push sender with a throwaway VAPID key — so the wake path runs
/// the production HTTP client rather than `EchoSender`.
fn real_webpush_sender(egress: Arc<EgressPolicy>) -> Box<dyn PushSender> {
    let (pem, _public) = generate_vapid_keypair().expect("VAPID keypair");
    Box::new(
        vti_push_gateway::sender::WebPushSender::new(
            pem.into_bytes(),
            "mailto:ops@gw".into(),
            egress,
        )
        .expect("WebPushSender::new"),
    )
}

/// PG-1, the PoC's whole chain as one gate — and the one the remediation plan
/// asked for by name: a stored record whose endpoint is an internal service
/// (the `sub-ssrf.json` shape, planted by `Store::insert` the way a pre-fix
/// build would have), provisioned, then woken through the router with a **real**
/// `WebPushSender`. `03_ssrf_capture.log` is the PoC's proof that this reached
/// the listener; the gate is that it no longer does.
///
/// `sender::tests::production_policy_never_dials_loopback` makes the same point
/// one layer down. This one is at the dispatch level, so it also pins the wake
/// path's *reported* outcome: a refused endpoint counts as a transient failure,
/// never as `delivered`.
#[tokio::test]
async fn wake_to_a_stored_internal_endpoint_never_dials() {
    let vta = signing_key();
    let trigger = signing_key();
    let (listener_addr, accepted) = counting_listener().await;

    // The PoC endpoint, pointed at the listener this test actually owns.
    //
    // `https`, deliberately. With `http` the hardened client's `https_only`
    // refuses the URL before the endpoint policy is consulted at all, so the
    // gate would stay green even if the policy stopped rejecting internal
    // hosts — it would be pinning the scheme check twice and the SSRF
    // guard not at all. Over `https` the only thing standing between the
    // wake and this listener is `validate_webpush_endpoint`.
    let endpoint = format!("https://{listener_addr}/latest/meta-data/iam/security-credentials/");
    let store = Store::new();
    store
        .insert(
            "legacy-handle".into(),
            PushRegistration::Webpush {
                endpoint: endpoint.clone(),
                keys: WebPushKeys {
                    p256dh: P256DH.into(),
                    auth: AUTH.into(),
                },
            },
            did_key_for(&vta),
        )
        .expect("a pre-fix record goes in unvalidated");
    store.provision(
        "legacy-handle",
        &did_key_for(&vta),
        WakeTriggerPolicy {
            allowed_triggers: vec![did_key_for(&trigger)],
        },
    );

    let egress = Arc::new(EgressPolicy::default());
    let mut st = state_with(store, Limits::permissive());
    st.egress = egress.clone();
    st.senders = Arc::new(vec![real_webpush_sender(egress)]);
    let app = router(st.clone());
    let metrics_app = metrics_router(st, None);

    let wake = tt_doc(PUSH_WAKE, json!({ "handle": "legacy-handle", "v": 1 }));
    let out = body_json(
        app.clone()
            .oneshot(post(&wake, Some(&trigger)))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        !is_success(&out),
        "a wake to a non-allowlisted endpoint must fail: {out}"
    );

    // The listener is the assertion that matters: the send was refused before a
    // socket was opened, not merely reported as failed afterwards.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the internal service must not be contacted"
    );

    let text = metrics_text(&metrics_app).await;
    assert!(
        text.contains("gateway_wake_total{outcome=\"transient_failure\"} 1\n"),
        "a refused endpoint is a transient failure: {text}"
    );
    assert!(
        text.contains("gateway_wake_total{outcome=\"delivered\"} 0\n"),
        "nothing was delivered: {text}"
    );
}

/// The PoC used the *difference* between refusals as a port scanner: an open
/// port answered 200, a 404 path answered 404, a closed port refused the
/// connection, and a redirector pivoted elsewhere (`sub-ssrf.json`,
/// `sub-ssrf-404.json`, `sub-ssrf-closed.json`, `sub-redirect.json`). Register
/// now refuses all four *identically*, so there is no oracle left: the reason is
/// one fixed string, and nothing about the target — host, port or path — comes
/// back in the response document.
///
/// No socket is involved at either end of this gate, which is the point: it
/// stays hermetic whether the guard is in place or reverted.
#[tokio::test]
async fn register_refusals_reveal_nothing_about_the_target() {
    // Verbatim from poc-harness/*.json.
    let fixtures = [
        "http://127.0.0.1:9099/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1:9099/probe-404",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:9098/only-this-was-registered",
    ];
    let mut reasons = Vec::new();
    for endpoint in fixtures {
        let (app, metrics_app) = routers();
        let reg = tt_doc(
            PUSH_REGISTER,
            json!({
                "registration": { "platform": "webpush", "endpoint": endpoint,
                                  "keys": { "p256dh": P256DH, "auth": AUTH } },
                "controllerVtaDid": did_key_for(&signing_key()),
            }),
        );
        let out = body_json(app.oneshot(post(&reg, None)).await.unwrap()).await;
        assert!(!is_success(&out), "{endpoint} must be refused: {out}");

        // Nothing that would let the caller tell one internal target from
        // another — or learn that the gateway looked at all.
        let text = out.to_string();
        for leak in [
            "127.0.0.1",
            "9099",
            "9098",
            "6379",
            "meta-data",
            "security-credentials",
            "probe-404",
            "only-this-was-registered",
        ] {
            assert!(
                !text.contains(leak),
                "the refusal must not echo {leak:?} back: {text}"
            );
        }
        assert!(
            metrics_text(&metrics_app)
                .await
                .contains("gateway_register_total 0\n"),
            "nothing must be registered for {endpoint}"
        );
        let message = out["payload"]["message"].clone();
        assert!(
            message.is_string(),
            "the refusal must carry a message to compare: {out}"
        );
        reasons.push((out["payload"]["code"].clone(), message));
    }
    assert!(
        reasons.windows(2).all(|w| w[0] == w[1]),
        "every refusal must read the same, or the difference is the oracle: {reasons:?}"
    );
}

/// `gateway_register_total` is the counter the PoC quoted as its proof that the
/// flood landed (`07_metrics_after_poc.txt`: 206). Existing gates pin it for the
/// endpoint-policy, field-validation, total-cap and rate-limit refusals; these
/// are the two refusal paths they leave out.
#[tokio::test]
async fn refused_registrations_are_never_counted() {
    // (1) No sender handles the platform (PG-N3): the state carries only a Web
    // Push sender, so an APNs registration has nowhere to go.
    let mut st = state_with(Store::new(), Limits::permissive());
    let egress = Arc::new(EgressPolicy::default());
    st.egress = egress.clone();
    st.senders = Arc::new(vec![real_webpush_sender(egress)]);
    let app = router(st.clone());
    let metrics_app = metrics_router(st, None);

    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": apns_registration(1),
            "controllerVtaDid": did_key_for(&signing_key()),
        }),
    );
    let out = body_json(app.oneshot(post(&reg, None)).await.unwrap()).await;
    assert!(!is_success(&out), "apns has no sender here: {out}");
    assert!(
        out.to_string()
            .contains("no sender configured for this platform"),
        "{out}"
    );
    assert!(
        metrics_text(&metrics_app)
            .await
            .contains("gateway_register_total 0\n"),
        "a platform with no sender must not be counted"
    );

    // (2) The per-token cap. `repeated_registration_of_one_token_is_capped`
    // checks the refusals; this checks that they left the counter alone.
    let st = state_with(
        Store::with_limits(StoreLimits {
            max_per_token: 2,
            ..StoreLimits::default()
        }),
        Limits::permissive(),
    );
    let app = router(st.clone());
    let metrics_app = metrics_router(st, None);
    for _ in 0..6 {
        let reg = tt_doc(
            PUSH_REGISTER,
            json!({
                "registration": apns_registration(7),
                "controllerVtaDid": did_key_for(&signing_key()),
            }),
        );
        app.clone().oneshot(post(&reg, None)).await.unwrap();
    }
    assert!(
        metrics_text(&metrics_app)
            .await
            .contains("gateway_register_total 2\n"),
        "only the two handles that were stored may be counted"
    );
}

/// PG-6 again, from the deployment side: moving the counters onto their own
/// router only helps if that router's default bind is not reachable off-host.
/// `main.rs` warns when an operator overrides it, but the default itself is the
/// thing a refactor could quietly turn into `0.0.0.0`.
#[test]
fn default_metrics_bind_is_loopback() {
    let addr: std::net::SocketAddr = DEFAULT_METRICS_BIND
        .parse()
        .expect("DEFAULT_METRICS_BIND must be a socket address");
    assert!(
        addr.ip().is_loopback(),
        "the management listener must default to loopback, not {addr}"
    );
}
