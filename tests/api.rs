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

use vti_push_gateway::api::{router, AppState};
use vti_push_gateway::egress::EgressPolicy;
use vti_push_gateway::sender::{EchoSender, PushSender, SendOutcome};
use vti_push_gateway::store::Store;

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
    let senders: Vec<Box<dyn PushSender>> = vec![Box::new(EchoSender)];
    AppState {
        store: Arc::new(Store::new()),
        senders: Arc::new(senders),
        gateway_addr: "https://gw.test".into(),
        metrics: Arc::new(vti_push_gateway::metrics::Metrics::default()),
        egress: Arc::new(EgressPolicy::default()),
    }
}

/// A syntactically valid 64-character hex APNs device token.
fn apns_token() -> String {
    "a1".repeat(32)
}

/// A valid Web Push subscription key pair (65-byte P-256 point, 16-byte auth).
const P256DH: &str =
    "BHTHkS5TN8hSA9_AzgRusH55jqrZjomGJ42mYrmFNIKH1cc0JnR6ZzwjcWQljvhdjlapl3nOtq2P6e9IMjMoWrY";
const AUTH: &str = "-8GwtL6MnCVPpyjEYoad2A";

/// Scrape `GET /metrics` through the router.
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
/// Prometheus counters, scraped through the same router.
#[tokio::test]
async fn metrics_endpoint_reflects_operations() {
    let vta = signing_key();
    let mediator = signing_key();
    let app = router(state());

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
    let text = metrics_text(&app).await;

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
    let app = router(state());
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
        metrics_text(&app)
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
        let app = router(state());
        let reg_is = reg.clone();
        let doc = tt_doc(
            PUSH_REGISTER,
            json!({ "registration": reg, "controllerVtaDid": did_key_for(&signing_key()) }),
        );
        let out = body_json(app.clone().oneshot(post(&doc, None)).await.unwrap()).await;
        assert!(!is_success(&out), "must be rejected: {reg_is} → {out}");
        assert!(metrics_text(&app)
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
