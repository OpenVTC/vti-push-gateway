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
use vti_push_gateway::controllers::ControllerPolicy;
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

    /// Sign `doc` as this party with its operational key, the way a service
    /// signs its own messages: `eddsa-jcs-2022`, `proofPurpose: authentication`.
    async fn sign(&self, mut doc: Value) -> Value {
        doc.as_object_mut().unwrap().remove("proof");
        let proof = DataIntegrityProof::sign(
            &doc,
            &self.secret,
            SignOptions::new().with_proof_purpose("authentication"),
        )
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
        replay: Arc::new(vti_push_gateway::replay::ReplayRecord::default()),
        // These suites mint a fresh controller per test; the allowlist has
        // its own tests.
        controllers: Arc::new(vti_push_gateway::controllers::ControllerPolicy::Open),
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
        "issuedAt": chrono::Utc::now().to_rfc3339(),
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

/// An `assertionMethod` proof is an attestation, not a message signature: it is
/// refused even though it verifies (VTI-KEY-106).
#[tokio::test]
async fn assertion_method_proof_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let handle = register(&st, &vta.did).await;

    let mut prov = provision_doc(&vta.did, &handle, &vta.did);
    let proof = DataIntegrityProof::sign(
        &prov,
        &vta.secret,
        SignOptions::new().with_proof_purpose("assertionMethod"),
    )
    .await
    .unwrap();
    prov["proof"] = serde_json::to_value(&proof).unwrap();
    let resp = send(&st, Some(&vta.did), &prov).await;
    assert_eq!(error_code(&resp), "proofInvalid", "{resp}");
}

/// Without a challenge, the recipient is part of what binds the proof, so a
/// signed document must name one (VTI-KEY-107).
#[tokio::test]
async fn signed_document_without_a_recipient_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let handle = register(&st, &vta.did).await;
    let mut prov = provision_doc(&vta.did, &handle, &vta.did);
    prov.as_object_mut().unwrap().remove("recipient");
    let resp = send(&st, Some(&vta.did), &vta.sign(prov).await).await;
    assert_eq!(error_code(&resp), "malformedRequest", "{resp}");
}

/// The time of issue is required and must be inside the acceptance window
/// (VTI-OPS-024).
#[tokio::test]
async fn time_of_issue_outside_the_window_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let handle = register(&st, &vta.did).await;
    let now = chrono::Utc::now();

    let mut stale = provision_doc(&vta.did, &handle, &vta.did);
    stale["issuedAt"] = json!((now - chrono::TimeDelta::minutes(10)).to_rfc3339());
    let resp = send(&st, Some(&vta.did), &vta.sign(stale).await).await;
    assert_eq!(error_code(&resp), "expired", "{resp}");

    let mut future = provision_doc(&vta.did, &handle, &vta.did);
    future["issuedAt"] = json!((now + chrono::TimeDelta::minutes(10)).to_rfc3339());
    let resp = send(&st, Some(&vta.did), &vta.sign(future).await).await;
    assert_eq!(error_code(&resp), "malformedRequest", "{resp}");

    let mut missing = provision_doc(&vta.did, &handle, &vta.did);
    missing.as_object_mut().unwrap().remove("issuedAt");
    let resp = send(&st, Some(&vta.did), &vta.sign(missing).await).await;
    assert_eq!(error_code(&resp), "malformedRequest", "{resp}");
}

/// A captured signed wake delivered again is not executed again: it is answered
/// with the first response and no second push goes out (VTI-OPS-026).
#[tokio::test]
async fn replayed_document_is_not_executed_twice() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let handle = register(&st, &vta.did).await;
    let prov = vta.sign(provision_doc(&vta.did, &handle, &vta.did)).await;
    assert!(is_success(&send(&st, Some(&vta.did), &prov).await));

    let wake = vta.sign(wake_doc(&vta.did, &handle)).await;
    let first = send(&st, Some(&vta.did), &wake).await;
    assert!(is_success(&first), "{first}");
    let delivered = st.app.metrics.render();
    let again = send(&st, Some(&vta.did), &wake).await;
    assert_eq!(
        again, first,
        "a duplicate is answered with the first response"
    );
    assert_eq!(
        st.app.metrics.render(),
        delivered,
        "and nothing is sent again"
    );
}

/// A different document reusing an accepted identifier is refused.
#[tokio::test]
async fn reused_identifier_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let handle = register(&st, &vta.did).await;
    let first = provision_doc(&vta.did, &handle, &vta.did);
    let id = first["id"].clone();
    assert!(is_success(
        &send(&st, Some(&vta.did), &vta.sign(first).await).await
    ));

    let mut second = provision_doc(&vta.did, &handle, &Party::new().did);
    second["id"] = id;
    let resp = send(&st, Some(&vta.did), &vta.sign(second).await).await;
    assert_eq!(error_code(&resp), "idConflict", "{resp}");
}

// ── Regression: the replay record and the time bounds ───────────────────

fn with_senders(st: DidcommState, senders: Vec<Box<dyn PushSender>>) -> DidcommState {
    let mut app = st.app.clone();
    app.senders = Arc::new(senders);
    DidcommState { app, ..st }
}

fn with_record(st: DidcommState, record: vti_push_gateway::replay::ReplayRecord) -> DidcommState {
    let mut app = st.app.clone();
    app.replay = Arc::new(record);
    DidcommState { app, ..st }
}

fn delivered(st: &DidcommState) -> String {
    st.app
        .metrics
        .render()
        .lines()
        .filter(|l| l.contains("delivered"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A handle whose allowlist holds `triggers`, provisioned by `vta`.
async fn provisioned(st: &DidcommState, vta: &Party, triggers: &[&str]) -> String {
    let handle = register(st, &vta.did).await;
    let prov = doc(
        PUSH_PROVISION,
        Some(&vta.did),
        json!({ "handle": handle, "policy": { "allowedTriggers": triggers } }),
    );
    let resp = send(st, Some(&vta.did), &vta.sign(prov).await).await;
    assert!(is_success(&resp), "{resp}");
    handle
}

/// A document whose `expiresAt` has already passed is refused — on every
/// delivery — even though its `issuedAt` is inside the window.
#[tokio::test]
async fn an_already_expired_document_is_refused() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let trigger = Party::new();
    let handle = provisioned(&st, &vta, &[&trigger.did]).await;
    let before = delivered(&st);
    let now = chrono::Utc::now();
    let mut w = wake_doc(&trigger.did, &handle);
    w["issuedAt"] = json!((now - chrono::TimeDelta::seconds(30)).to_rfc3339());
    w["expiresAt"] = json!((now - chrono::TimeDelta::seconds(20)).to_rfc3339());
    let w = trigger.sign(w).await;
    for _ in 0..3 {
        let resp = send(&st, None, &w).await;
        assert_eq!(error_code(&resp), "expired", "{resp}");
    }
    assert_eq!(delivered(&st), before, "nothing was sent");
    assert_eq!(
        st.app.replay.len_for(&trigger.did),
        0,
        "and nothing was recorded"
    );
}

/// An unauthorised issuer reusing a victim's document id leaves no record, so
/// the victim's genuine document is accepted.
#[tokio::test]
async fn an_unauthorised_issuer_cannot_squat_an_identifier() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let trigger = Party::new();
    let attacker = Party::new();
    let handle = provisioned(&st, &vta, &[&trigger.did]).await;

    let victim = wake_doc(&trigger.did, &handle);
    let mut squat = wake_doc(&attacker.did, &handle);
    squat["id"] = victim["id"].clone();
    let resp = send(&st, None, &attacker.sign(squat).await).await;
    assert_eq!(error_code(&resp), "permissionDenied", "{resp}");
    assert_eq!(
        st.app.replay.len_for(&attacker.did),
        0,
        "a refused caller leaves no record"
    );

    let resp = send(&st, Some(&trigger.did), &trigger.sign(victim).await).await;
    assert!(
        is_success(&resp),
        "the victim's document is unaffected: {resp}"
    );
}

/// A flood of self-signed documents from an unauthorised did:key claims
/// nothing, so it cannot evict a legitimate record and make it replayable.
#[tokio::test]
async fn an_unauthorised_flood_cannot_evict_a_record() {
    let st = with_record(
        didcomm_state().await,
        vti_push_gateway::replay::ReplayRecord::new(50, 50),
    );
    let vta = Party::new();
    let trigger = Party::new();
    let attacker = Party::new();
    let handle = provisioned(&st, &vta, &[&trigger.did]).await;
    let legit = trigger.sign(wake_doc(&trigger.did, &handle)).await;
    let first = send(&st, None, &legit).await;
    assert!(is_success(&first), "{first}");
    for _ in 0..60 {
        send(
            &st,
            None,
            &attacker.sign(wake_doc(&attacker.did, &handle)).await,
        )
        .await;
    }
    let sent = delivered(&st);
    let again = send(&st, None, &legit).await;
    assert_eq!(again, first, "still recognised as a duplicate");
    assert_eq!(delivered(&st), sent, "and not sent again");
}

/// One authorised issuer filling its own partition cannot evict another's
/// records; at its bound it is refused rather than evicting its own.
#[tokio::test]
async fn one_issuer_cannot_evict_anothers_records() {
    let st = with_record(
        didcomm_state().await,
        vti_push_gateway::replay::ReplayRecord::new(5, 1_000),
    );
    let vta = Party::new();
    let a = Party::new();
    let b = Party::new();
    let handle = provisioned(&st, &vta, &[&a.did, &b.did]).await;
    let b_wake = b.sign(wake_doc(&b.did, &handle)).await;
    let b_first = send(&st, None, &b_wake).await;
    assert!(is_success(&b_first));
    for i in 0..6 {
        let resp = send(&st, None, &a.sign(wake_doc(&a.did, &handle)).await).await;
        assert_eq!(is_success(&resp), i < 5, "#{i}: {resp}");
    }
    assert_eq!(
        st.app.replay.len_for(&a.did),
        5,
        "a's own records were kept"
    );
    let sent = delivered(&st);
    assert_eq!(
        send(&st, None, &b_wake).await,
        b_first,
        "b's record survives"
    );
    assert_eq!(delivered(&st), sent);
}

/// The same id from two different issuers are two documents.
#[tokio::test]
async fn the_record_is_keyed_by_issuer_and_id() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let a = Party::new();
    let b = Party::new();
    let handle = provisioned(&st, &vta, &[&a.did, &b.did]).await;
    let a_wake = wake_doc(&a.did, &handle);
    let mut b_wake = wake_doc(&b.did, &handle);
    b_wake["id"] = a_wake["id"].clone();
    assert!(is_success(&send(&st, None, &a.sign(a_wake).await).await));
    let resp = send(&st, None, &b.sign(b_wake).await).await;
    assert!(is_success(&resp), "not an idConflict: {resp}");
}

struct FlakySender(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl PushSender for FlakySender {
    fn handles(&self, _: &vti_push_gateway::types::PushRegistration) -> bool {
        true
    }
    async fn send(
        &self,
        _: &vti_push_gateway::types::PushRegistration,
        _: &vti_push_gateway::types::WakePayload,
    ) -> vti_push_gateway::sender::SendOutcome {
        // Fails the first attempt, delivers after that.
        if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            vti_push_gateway::sender::SendOutcome::TransientFailure
        } else {
            vti_push_gateway::sender::SendOutcome::Delivered
        }
    }
}

/// A transient push failure is not cached: a retry of the same document is
/// attempted again, and then its success is what a duplicate gets.
#[tokio::test]
async fn a_transient_failure_is_retried_not_cached() {
    let st = with_senders(
        didcomm_state().await,
        vec![Box::new(FlakySender(std::sync::atomic::AtomicUsize::new(
            0,
        )))],
    );
    let vta = Party::new();
    let trigger = Party::new();
    let handle = provisioned(&st, &vta, &[&trigger.did]).await;
    let w = trigger.sign(wake_doc(&trigger.did, &handle)).await;
    let first = send(&st, None, &w).await;
    assert_eq!(error_code(&first), "taskFailed", "{first}");
    let retry = send(&st, None, &w).await;
    assert!(is_success(&retry), "the retry is attempted: {retry}");
    assert_eq!(
        send(&st, None, &w).await,
        retry,
        "now a duplicate of the success"
    );
}

/// A refused provision (wrong controller) leaves no record either.
#[tokio::test]
async fn a_refused_provision_leaves_no_record() {
    let st = didcomm_state().await;
    let vta = Party::new();
    let other = Party::new();
    let handle = register(&st, &vta.did).await;
    let prov = other
        .sign(provision_doc(&other.did, &handle, &other.did))
        .await;
    assert_eq!(
        error_code(&send(&st, None, &prov).await),
        "permissionDenied"
    );
    assert_eq!(st.app.replay.len_for(&other.did), 0);
}

// ── Regression: self-registered controllers cannot exhaust the record ───

/// Anonymous registration lets anyone make a DID of their own the controller
/// of a handle. A set of such controllers sending fresh provisions must not
/// fill the record and lock a legitimate issuer out.
#[tokio::test]
async fn self_registered_controllers_cannot_lock_others_out() {
    let st = with_record(
        didcomm_state().await,
        vti_push_gateway::replay::ReplayRecord::new(8192, 100),
    );
    let legit_vta = Party::new();
    let legit_trig = Party::new();
    let lh = provisioned(&st, &legit_vta, &[&legit_trig.did]).await;
    for _ in 0..3 {
        let a = Party::new();
        let ah = register(&st, &a.did).await;
        for _ in 0..40 {
            // A different allowlist each time, so none is a no-op.
            let other = Party::new();
            let p = a.sign(provision_doc(&a.did, &ah, &other.did)).await;
            send(&st, None, &p).await;
        }
    }
    let r = send(
        &st,
        None,
        &legit_trig.sign(wake_doc(&legit_trig.did, &lh)).await,
    )
    .await;
    assert!(
        is_success(&r),
        "a legitimate issuer under its share is still admitted: {r}"
    );
}

/// The reviewer's probe as written: the same provision re-applied under fresh
/// ids changes nothing, so it spends no record at all.
#[tokio::test]
async fn reapplying_the_stored_allowlist_spends_no_record() {
    let st = didcomm_state().await;
    let a = Party::new();
    let ah = register(&st, &a.did).await;
    for _ in 0..40 {
        let p = a.sign(provision_doc(&a.did, &ah, &a.did)).await;
        assert!(is_success(&send(&st, None, &p).await));
    }
    assert_eq!(
        st.app.replay.len_for(&a.did),
        1,
        "only the provision that changed something"
    );
}

/// Everyone acting on one handle shares its budget, whichever DIDs they use.
#[tokio::test]
async fn one_handle_cannot_spend_more_than_its_budget() {
    let st = with_record(
        didcomm_state().await,
        vti_push_gateway::replay::ReplayRecord::with_per_handle(8192, 3, 65_536),
    );
    let vta = Party::new();
    let triggers: Vec<Party> = (0..4).map(|_| Party::new()).collect();
    let dids: Vec<&str> = triggers.iter().map(|t| t.did.as_str()).collect();
    let handle = provisioned(&st, &vta, &dids).await; // 1 record
    let mut ok = 0;
    for t in &triggers {
        if is_success(&send(&st, None, &t.sign(wake_doc(&t.did, &handle)).await).await) {
            ok += 1;
        }
    }
    assert_eq!(ok, 2, "the handle's 3-record budget: 1 provision + 2 wakes");
    assert_eq!(st.app.replay.len_for_handle(&handle), 3);
    // Another handle is unaffected.
    let other = provisioned(&st, &vta, &[&triggers[0].did]).await;
    let r = send(
        &st,
        None,
        &triggers[0].sign(wake_doc(&triggers[0].did, &other)).await,
    )
    .await;
    assert!(is_success(&r), "{r}");
}

// ── The controller allowlist ────────────────────────────────────────────

fn with_controllers(st: DidcommState, policy: ControllerPolicy) -> DidcommState {
    let mut app = st.app.clone();
    app.controllers = Arc::new(policy);
    DidcommState { app, ..st }
}

fn register_doc(controller: &str, n: usize) -> Value {
    doc(
        PUSH_REGISTER,
        None,
        json!({
            "registration": { "platform": "apns", "token": format!("{n:064x}"), "topic": "org.openvtc.app" },
            "controllerVtaDid": controller,
        }),
    )
}

/// The default — nothing listed — refuses every registration.
#[tokio::test]
async fn by_default_no_controller_is_served() {
    let st = with_controllers(didcomm_state().await, ControllerPolicy::default());
    let resp = send(&st, None, &register_doc(&Party::new().did, 1)).await;
    assert_eq!(error_code(&resp), "permissionDenied", "{resp}");
}

/// A registration naming an unlisted controller is refused; a listed one is
/// accepted and its handle provisions and wakes as usual.
#[tokio::test]
async fn only_listed_controllers_may_register() {
    let vta = Party::new();
    let trigger = Party::new();
    let st = with_controllers(
        didcomm_state().await,
        ControllerPolicy::listing([vta.did.clone()]),
    );

    let resp = send(&st, None, &register_doc(&Party::new().did, 1)).await;
    assert_eq!(error_code(&resp), "permissionDenied", "{resp}");
    assert_eq!(st.app.store.len(), 0, "nothing was stored");

    let handle = provisioned(&st, &vta, &[&trigger.did]).await;
    let resp = send(
        &st,
        None,
        &trigger.sign(wake_doc(&trigger.did, &handle)).await,
    )
    .await;
    assert!(is_success(&resp), "{resp}");
}

/// A controller dropped from the list can no longer provision a handle it
/// registered earlier (e.g. one restored from a snapshot).
#[tokio::test]
async fn a_delisted_controller_cannot_provision() {
    let vta = Party::new();
    let st = didcomm_state().await; // open, to register the handle
    let handle = register(&st, &vta.did).await;
    let st = with_controllers(st, ControllerPolicy::default());
    let prov = vta.sign(provision_doc(&vta.did, &handle, &vta.did)).await;
    let resp = send(&st, None, &prov).await;
    assert_eq!(error_code(&resp), "permissionDenied", "{resp}");
    assert_eq!(st.app.replay.len_for(&vta.did), 0, "and spends no record");
}

/// Open mode admits any controller, and every other bound still holds.
#[tokio::test]
async fn open_mode_keeps_the_limits() {
    let mut st = with_controllers(didcomm_state().await, ControllerPolicy::Open);
    st.app.store = Arc::new(Store::with_limits(vti_push_gateway::store::StoreLimits {
        max_per_controller: 2,
        ..Default::default()
    }));
    let a = Party::new();
    for n in 0..2 {
        assert!(is_success(&send(&st, None, &register_doc(&a.did, n)).await));
    }
    let resp = send(&st, None, &register_doc(&a.did, 2)).await;
    assert!(
        !is_success(&resp),
        "the per-controller cap still applies: {resp}"
    );

    let st = with_record(
        st,
        vti_push_gateway::replay::ReplayRecord::with_per_handle(8192, 1, 65_536),
    );
    let b = Party::new();
    let handle = provisioned(&st, &b, &[&b.did]).await; // spends the handle's one record
    let resp = send(&st, None, &b.sign(wake_doc(&b.did, &handle)).await).await;
    assert_eq!(
        error_code(&resp),
        "taskFailed",
        "the per-handle budget still applies: {resp}"
    );
}
