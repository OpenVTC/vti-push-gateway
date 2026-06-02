//! End-to-end exercise of the gateway's `push/*` Trust-Task dispatcher:
//! register → provision → wake, plus the auth/allowlist refusals. Posts
//! `TrustTask` documents to `/trust-tasks` and inspects the response document.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use tower::ServiceExt;

use vti_push_gateway::api::{router, AppState};
use vti_push_gateway::sender::{EchoSender, PushSender};
use vti_push_gateway::store::Store;

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const PUSH_REGISTER: &str = "https://trusttasks.org/spec/push/register/0.1";
const PUSH_PROVISION: &str = "https://trusttasks.org/spec/push/provision/0.1";
const PUSH_WAKE: &str = "https://trusttasks.org/spec/push/wake/0.1";

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
    let vta = SigningKey::generate(&mut OsRng);
    let mediator = SigningKey::generate(&mut OsRng);
    let app = router(state());

    // 1. Device registers (unauthenticated) → opaque handle.
    let reg = tt_doc(
        PUSH_REGISTER,
        json!({
            "registration": { "platform": "apns", "token": "abc", "topic": "org.openvtc.app" },
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
    let imposter = SigningKey::generate(&mut OsRng);
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

#[tokio::test]
async fn wake_unknown_handle_is_rejected() {
    let trigger = SigningKey::generate(&mut OsRng);
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

#[tokio::test]
async fn bad_signature_is_401() {
    let trigger = SigningKey::generate(&mut OsRng);
    let app = router(state());
    let wake = tt_doc(PUSH_WAKE, json!({ "handle": "h", "v": 1 }));
    let mut req = post(&wake, Some(&trigger));
    // Replace the body after signing → signature no longer matches.
    *req.body_mut() = Body::from(
        r#"{"id":"urn:uuid:req","type":"https://trusttasks.org/spec/push/wake/0.1","payload":{"handle":"tampered","v":1}}"#,
    );
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
