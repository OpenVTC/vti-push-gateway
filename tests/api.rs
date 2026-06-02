//! End-to-end exercise of the gateway REST surface: register → provision → wake,
//! plus the auth/allowlist refusals. Drives the router in-process via oneshot.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use rand::rngs::OsRng;
use tower::ServiceExt;

use vta_push_gateway::api::{router, AppState};
use vta_push_gateway::sender::{EchoSender, PushSender};
use vta_push_gateway::store::Store;

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

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
    }
}

/// POST `path` with an unsigned JSON body.
fn req_json(path: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// POST `path` with a body signed by `sk` (did-signed auth).
fn req_signed(path: &str, sk: &SigningKey, body: &serde_json::Value) -> Request<Body> {
    let bytes = serde_json::to_vec(body).unwrap();
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.sign(&bytes).to_bytes());
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("x-tt-did", did_key_for(sk))
        .header("x-tt-signature", sig)
        .body(Body::from(bytes))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}

#[tokio::test]
async fn full_flow_register_provision_wake() {
    let vta = SigningKey::generate(&mut OsRng);
    let mediator = SigningKey::generate(&mut OsRng);
    let app = router(state());

    // 1. Device registers a token, names its controller VTA.
    let reg = req_json(
        "/v1/register",
        &serde_json::json!({
            "registration": { "platform": "apns", "token": "abc", "topic": "org.openvtc.app" },
            "controllerVtaDid": did_key_for(&vta),
        }),
    );
    let resp = app.clone().oneshot(reg).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let handle = body_json(resp).await["wake_handle"]["handle"]
        .as_str()
        .unwrap()
        .to_string();

    // 2a. A wake before provisioning is refused (empty allowlist).
    let early = req_signed(
        "/v1/wake",
        &mediator,
        &serde_json::json!({ "handle": handle, "v": 1 }),
    );
    assert_eq!(
        app.clone().oneshot(early).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    // 2b. A non-controller cannot provision.
    let imposter = SigningKey::generate(&mut OsRng);
    let bad = req_signed(
        "/v1/provision",
        &imposter,
        &serde_json::json!({ "handle": handle, "policy": { "allowed_triggers": [did_key_for(&imposter)] } }),
    );
    assert_eq!(
        app.clone().oneshot(bad).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    // 3. The controller VTA provisions the mediator as an allowed trigger.
    let prov = req_signed(
        "/v1/provision",
        &vta,
        &serde_json::json!({ "handle": handle, "policy": { "allowed_triggers": [did_key_for(&mediator)] } }),
    );
    assert_eq!(
        app.clone().oneshot(prov).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    // 4. The allowed trigger wakes the device.
    let wake = req_signed(
        "/v1/wake",
        &mediator,
        &serde_json::json!({ "handle": handle, "v": 1, "mediator": "did:web:m", "urgency": "interactive" }),
    );
    assert_eq!(
        app.clone().oneshot(wake).await.unwrap().status(),
        StatusCode::ACCEPTED
    );

    // 4b. A DID not on the allowlist still can't wake it.
    let not_allowed = req_signed(
        "/v1/wake",
        &imposter,
        &serde_json::json!({ "handle": handle, "v": 1 }),
    );
    assert_eq!(
        app.clone().oneshot(not_allowed).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn wake_unknown_handle_is_404() {
    let trigger = SigningKey::generate(&mut OsRng);
    let app = router(state());
    let wake = req_signed(
        "/v1/wake",
        &trigger,
        &serde_json::json!({ "handle": "nope", "v": 1 }),
    );
    assert_eq!(
        app.oneshot(wake).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn wake_with_bad_signature_is_401() {
    let trigger = SigningKey::generate(&mut OsRng);
    let app = router(state());
    // Sign one body, send a different one → signature doesn't match.
    let mut r = req_signed(
        "/v1/wake",
        &trigger,
        &serde_json::json!({ "handle": "h", "v": 1 }),
    );
    *r.body_mut() = Body::from(r#"{"handle":"tampered","v":1}"#);
    assert_eq!(
        app.oneshot(r).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
