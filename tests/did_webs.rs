//! did:webs resolution (VTI-KEY-003): every VTI node resolves did:webs, so a
//! VTA or device whose DID is a did:webs can be resolved by the gateway.
//!
//! Offline: a did:webs is created for a local fixture server's own address
//! (an AID resolves only at a host it designated, so a canned fixture naming
//! some other host cannot resolve here), its `keri.cesr` and `did.json` are
//! served from that server, and the DID is resolved through a resolver built
//! the way `main.rs` builds the gateway's — from [`ResolverTuning`].

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_webs::create::{create, CreateConfig};
use affinidi_did_webs::DidWebs;
use axum::routing::get;
use axum::Router;

use vti_push_gateway::resolver::ResolverTuning;

/// Serve one identifier's artifacts at `/{aid}/keri.cesr` and `/{aid}/did.json`,
/// counting the requests that reach the server.
async fn serve_artifacts(
    listener: tokio::net::TcpListener,
    aid: &str,
    keri_cesr: Vec<u8>,
    did_json: Vec<u8>,
) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let (h1, h2) = (hits.clone(), hits.clone());
    let app = Router::new()
        .route(
            &format!("/{aid}/keri.cesr"),
            get(move || {
                h1.fetch_add(1, Ordering::SeqCst);
                let body = keri_cesr.clone();
                async move { body }
            }),
        )
        .route(
            &format!("/{aid}/did.json"),
            get(move || {
                h2.fetch_add(1, Ordering::SeqCst);
                let body = did_json.clone();
                async move { body }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("fixture server");
    });
    hits
}

/// A did:webs created for `addr`, with its artifacts.
fn created_for(addr: SocketAddr) -> (String, String, Vec<u8>, Vec<u8>) {
    let host = addr.to_string().replace(':', "%3A");
    let result = create(CreateConfig::builder(host).build()).expect("create did:webs");
    let did = result.did().to_string();
    let aid = DidWebs::parse(&did).expect("parse").aid().to_string();
    let artifacts = result.into_artifacts();
    (did, aid, artifacts.keri_cesr, artifacts.did_json)
}

/// A did:webs a fixture server publishes resolves, through the gateway's own
/// resolver construction, to a document whose id is that DID and whose keys
/// come from its verified key event log.
#[tokio::test]
async fn resolves_a_did_webs_vti_key_003() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (did, aid, keri_cesr, did_json) = created_for(addr);
    let hits = serve_artifacts(listener, &aid, keri_cesr, did_json).await;

    // The fixture is on loopback, which only the local-development opt-in
    // reaches (and there over plain HTTP); otherwise the tuning is the default.
    let tuning = ResolverTuning {
        allow_private_did_hosts: true,
        ..ResolverTuning::default()
    };
    let client = DIDCacheClient::new(tuning.did_cache_config())
        .await
        .expect("DID cache client");

    let resolved = client
        .resolve(&did)
        .await
        .expect("a served did:webs must resolve");
    assert_eq!(resolved.doc.id.as_str(), did);
    assert!(
        !resolved.doc.verification_method.is_empty(),
        "a did:webs document carries its KEL's current keys"
    );
    // Both artifacts were fetched: the key event log is what was verified.
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

/// Under the default (public-only) host policy, a did:webs naming a loopback
/// or private host is refused, and the host is never contacted — the same
/// SSRF guard the other web methods have, since inbound senders choose the
/// DIDs the gateway resolves. The failure must be the host policy's: a
/// resolver without did:webs would also fail, as an unsupported method.
#[tokio::test]
async fn default_policy_refuses_a_private_did_webs_without_connecting() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    let client = DIDCacheClient::new(ResolverTuning::default().did_cache_config())
        .await
        .expect("DID cache client");

    let aid = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
    for host in ["localhost", "127.0.0.1", "printer.local", "169.254.169.254"] {
        let did = format!("did:webs:{host}%3A{port}:{aid}");
        let message = client
            .resolve(&did)
            .await
            .expect_err("a non-public did:webs host must be refused")
            .to_string();
        assert!(
            message.contains("host policy"),
            "{did} failed for the wrong reason: {message}"
        );
    }

    // The listener answers nothing, so a refusal that still dialled shows here.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "a refused did:webs DID still connected to its host"
    );
}
