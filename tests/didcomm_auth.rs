//! The DIDComm adapter authorises `push/provision` and `push/wake` on the
//! issuer a document's Data Integrity proof establishes — never on the
//! envelope sender alone. Drives [`didcomm::handle_envelope`] (everything the
//! DIDComm handler does after the service has unpacked a message) with
//! `did:key` parties, which resolve offline.

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_did_resolver_cache_sdk::{config::DIDCacheConfigBuilder, DIDCacheClient};
use affinidi_secrets_resolver::secrets::Secret;
use ed25519_dalek::SigningKey;
use rand::Rng;
use serde_json::{json, Value};

use vti_push_gateway::api::AppState;
use vti_push_gateway::didcomm::{handle_envelope, DidcommState};
use vti_push_gateway::egress::EgressPolicy;
use vti_push_gateway::limits::Limits;
use vti_push_gateway::proof::ProofVerifier;
use vti_push_gateway::sender::{EchoSender, PushSender};
use vti_push_gateway::store::Store;

const PUSH_REGISTER: &str = "https://trusttasks.org/spec/push/register/0.2";
const PUSH_PROVISION: &str = "https://trusttasks.org/spec/push/provision/0.2";
const PUSH_WAKE: &str = "https://trusttasks.org/spec/push/wake/0.2";
const GATEWAY_DID: &str = "did:webvh:scid:gateway.example";

/// An Ed25519 party with a `did:key` identity and the secret that signs as it.
struct Party {
    did: String,
    secret: Secret,
}

impl Party {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let vk = SigningKey::from_bytes(&seed).verifying_key();
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(vk.as_bytes());
        let mb = format!("z{}", bs58::encode(bytes).into_string());
        let did = format!("did:key:{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{did}#{mb}")), Some(&seed));
        assert_eq!(
            secret.get_public_bytes(),
            vk.as_bytes(),
            "helper key mismatch"
        );
        Self { did, secret }
    }

    /// Sign `doc` as this party, attaching an `eddsa-jcs-2022` proof.
    async fn sign(&self, mut doc: Value) -> Value {
        doc.as_object_mut().unwrap().remove("proof");
        let proof = DataIntegrityProof::sign(&doc, &self.secret, SignOptions::new())
            .await
            .expect("signs");
        doc["proof"] = serde_json::to_value(&proof).unwrap();
        doc
    }
}

async fn didcomm_state() -> DidcommState {
    let senders: Vec<Box<dyn PushSender>> = vec![Box::new(EchoSender)];
    let app = AppState {
        store: Arc::new(Store::new()),
        senders: Arc::new(senders),
        gateway_addr: "https://gw.test".into(),
        metrics: Arc::new(vti_push_gateway::metrics::Metrics::default()),
        egress: Arc::new(EgressPolicy::default()),
        limits: Arc::new(Limits::permissive()),
    };
    let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("resolver");
    DidcommState {
        app,
        proofs: ProofVerifier::new(Arc::new(client)),
        gateway_did: GATEWAY_DID.into(),
    }
}

fn doc(type_uri: &str, issuer: Option<&str>, payload: Value) -> Value {
    let mut d = json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": type_uri,
        "issuedAt": "2026-09-25T00:00:00Z",
        "recipient": GATEWAY_DID,
        "payload": payload,
    });
    if let Some(i) = issuer {
        d["issuer"] = json!(i);
    }
    d
}

fn is_success(doc: &Value) -> bool {
    doc["type"]
        .as_str()
        .is_some_and(|t| t.ends_with("#response"))
}

fn error_code(doc: &Value) -> String {
    doc["payload"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

async fn send(st: &DidcommState, from: Option<&str>, body: &Value) -> Value {
    handle_envelope(st, from, body).await.expect("a response")
}

/// Register a handle controlled by `controller` over DIDComm (anonymously).
async fn register(st: &DidcommState, controller: &str) -> String {
    let reg = doc(
        PUSH_REGISTER,
        None,
        json!({
            "registration": { "platform": "apns", "token": "a1".repeat(32), "topic": "org.openvtc.app" },
            "controllerVtaDid": controller,
        }),
    );
    let resp = send(st, None, &reg).await;
    assert!(is_success(&resp), "register: {resp}");
    resp["payload"]["wakeHandle"]["handle"]
        .as_str()
        .unwrap()
        .to_string()
}

fn provision_doc(issuer: &str, handle: &str, trigger: &str) -> Value {
    doc(
        PUSH_PROVISION,
        Some(issuer),
        json!({ "handle": handle, "policy": { "allowedTriggers": [trigger] } }),
    )
}

fn wake_doc(issuer: &str, handle: &str) -> Value {
    doc(
        PUSH_WAKE,
        Some(issuer),
        json!({ "handle": handle, "v": 1, "mediator": "did:web:m.example", "urgency": "interactive" }),
    )
}

#[tokio::test]
async fn signed_provision_and_wake_succeed() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let trigger = Party::new();
    let handle = register(&st, &vta.did).await;

    let prov = vta
        .sign(provision_doc(&vta.did, &handle, &trigger.did))
        .await;
    let resp = send(&st, Some(&vta.did), &prov).await;
    assert!(is_success(&resp), "controller provision: {resp}");

    let wake = trigger.sign(wake_doc(&trigger.did, &handle)).await;
    let resp = send(&st, Some(&trigger.did), &wake).await;
    assert!(is_success(&resp), "allowlisted wake: {resp}");
    assert_eq!(resp["payload"]["status"], "delivered");
}

/// A proof is what authenticates, so an anoncrypt (sender-less) envelope
/// carrying a valid proof is accepted.
#[tokio::test]
async fn a_valid_proof_needs_no_envelope_sender() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let handle = register(&st, &vta.did).await;
    let prov = vta.sign(provision_doc(&vta.did, &handle, &vta.did)).await;
    let resp = send(&st, None, &prov).await;
    assert!(is_success(&resp), "{resp}");
}

/// The envelope naming the controller is not enough: without a proof the
/// document is anonymous and provision/wake are refused.
#[tokio::test]
async fn envelope_sender_alone_does_not_authorise() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let attacker = Party::new();
    let handle = register(&st, &vta.did).await;

    let prov = provision_doc(&vta.did, &handle, &attacker.did);
    let resp = send(&st, Some(&vta.did), &prov).await;
    assert!(!is_success(&resp), "{resp}");
    assert_eq!(error_code(&resp), "proofRequired", "{resp}");

    let wake = wake_doc(&vta.did, &handle);
    let resp = send(&st, Some(&vta.did), &wake).await;
    assert_eq!(error_code(&resp), "proofRequired", "{resp}");

    // The allowlist was not touched: the attacker still cannot wake it, even
    // with a proof of its own.
    let wake = attacker.sign(wake_doc(&attacker.did, &handle)).await;
    let resp = send(&st, Some(&attacker.did), &wake).await;
    assert_eq!(error_code(&resp), "permissionDenied", "{resp}");
}

/// Claiming the controller as `issuer` while signing with another key fails the
/// issuer binding.
#[tokio::test]
async fn proof_by_another_key_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let attacker = Party::new();
    let handle = register(&st, &vta.did).await;

    let prov = attacker
        .sign(provision_doc(&vta.did, &handle, &attacker.did))
        .await;
    let resp = send(&st, Some(&vta.did), &prov).await;
    assert_eq!(error_code(&resp), "proofInvalid", "{resp}");
}

/// A genuine proof whose document was edited afterwards does not verify.
#[tokio::test]
async fn tampered_document_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let attacker = Party::new();
    let handle = register(&st, &vta.did).await;

    let mut prov = vta.sign(provision_doc(&vta.did, &handle, &vta.did)).await;
    prov["payload"]["policy"]["allowedTriggers"] = json!([attacker.did]);
    let resp = send(&st, Some(&vta.did), &prov).await;
    assert_eq!(error_code(&resp), "proofInvalid", "{resp}");
}

/// A self-signed document by a party that is not the controller is refused by
/// the controller check, as over HTTPS.
#[tokio::test]
async fn non_controller_with_a_valid_proof_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let attacker = Party::new();
    let handle = register(&st, &vta.did).await;

    let prov = attacker
        .sign(provision_doc(&attacker.did, &handle, &attacker.did))
        .await;
    let resp = send(&st, Some(&attacker.did), &prov).await;
    assert_eq!(error_code(&resp), "permissionDenied", "{resp}");
}

/// When the envelope names a sender, it must be the proven issuer.
#[tokio::test]
async fn envelope_sender_contradicting_the_proof_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let other = Party::new();
    let handle = register(&st, &vta.did).await;

    let prov = vta.sign(provision_doc(&vta.did, &handle, &vta.did)).await;
    let resp = send(&st, Some(&other.did), &prov).await;
    assert!(!is_success(&resp), "{resp}");
    assert_eq!(error_code(&resp), "identityMismatch", "{resp}");
}

/// A signed document addressed to another gateway is refused.
#[tokio::test]
async fn document_for_another_recipient_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let handle = register(&st, &vta.did).await;

    let mut prov = provision_doc(&vta.did, &handle, &vta.did);
    prov["recipient"] = json!("did:webvh:scid:other-gateway.example");
    let prov = vta.sign(prov).await;
    let resp = send(&st, Some(&vta.did), &prov).await;
    assert_eq!(error_code(&resp), "wrongRecipient", "{resp}");
}

/// A proof with the wrong purpose is refused even though it verifies.
#[tokio::test]
async fn authentication_purpose_proof_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let handle = register(&st, &vta.did).await;

    let mut prov = provision_doc(&vta.did, &handle, &vta.did);
    let proof = DataIntegrityProof::sign(
        &prov,
        &vta.secret,
        SignOptions::new().with_proof_purpose("authentication"),
    )
    .await
    .unwrap();
    prov["proof"] = serde_json::to_value(&proof).unwrap();
    let resp = send(&st, Some(&vta.did), &prov).await;
    assert_eq!(error_code(&resp), "proofInvalid", "{resp}");
}
