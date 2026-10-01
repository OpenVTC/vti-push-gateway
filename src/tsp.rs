//! The gateway's TSP transport adapter.
//!
//! TSP rides the same mediator websocket as DIDComm: the mediator allows one
//! socket per DID, so `affinidi-messaging-didcomm-service` — the service
//! [`crate::didcomm`] starts — multiplexes both protocols off it and hands each
//! unpacked TSP application message to the [`TspIntake`] here. The service does
//! the TSP work (decode, open, verify the sender's signature, record
//! relationship control messages); this adapter opens the Trust Task binding
//! envelope (<https://trusttasks.org/binding/tsp/0.1>) and passes the document
//! to [`intake::receive`], the intake every transport shares.
//!
//! Like the DIDComm adapter, it adds nothing to authorisation. The sender VID
//! TSP authenticated is handed to the intake as the transport's claim about its
//! sender, just as a DIDComm envelope's `from` is: it must agree with the issuer
//! the document's proof establishes (else `identityMismatch`), and it never
//! stands in for that issuer (see [`crate::intake`]).
//!
//! The reply goes back in the binding envelope, sealed to the sender over the
//! same socket by the service.
//!
//! ## Relationships
//!
//! A TSP peer opens a relationship with an invite before it sends application
//! messages. The service records every control message; this adapter answers an
//! invite with an accept, which completes the relationship. Accepting grants
//! nothing: every document the peer then sends meets the same proof checks as
//! any other. Relationship state is durable when the gateway was built with a
//! store ([`crate::relationships`], wired in [`crate::didcomm::start`]), so a
//! restart does not force every peer to re-invite before its next message is
//! admitted; [`receive`] and [`TspIntake::handle_control`] stamp activity on it
//! so the idle-eviction sweep only ages out relationships that have gone quiet.
//!
//! ## Being reachable over TSP
//!
//! A peer finds the gateway's TSP endpoint in its DID document: a
//! `TSPTransport` service whose `serviceEndpoint` is the DID of the mediator
//! the gateway listens on. [`check_advertised`] resolves the gateway's own DID
//! at startup and warns when that entry is missing or names another mediator.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm_service::{
    DIDCommServiceError, HandlerContext, TspHandler, TspResponse,
};
use affinidi_tdk::messaging::protocols::tsp::ControlMessage;
use affinidi_tdk::tsp::message::control::ControlType;
use serde_json::{json, Value};
use trust_tasks_rs::{RejectReason, TrustTask};
pub use trust_tasks_tsp::ENVELOPE_TYPE;

use crate::api::{reject_value, AppState};
use crate::intake;

/// DID-document service type a TSP endpoint is advertised under.
pub const TSP_SERVICE_TYPE: &str = "TSPTransport";

/// Wrap a Trust Task document in the TSP binding envelope.
pub fn wrap_envelope(document: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "type": ENVELOPE_TYPE, "document": document }))
        .expect("a JSON value serialises")
}

/// Receive one TSP application message: open the binding envelope, hand the
/// document to [`intake::receive`] with `sender_vid` as the transport's claim
/// about its sender, and return the reply payload (the response document in the
/// binding envelope) — or `None` when there is nothing to answer.
///
/// `payload` is the cleartext the service unpacked; `sender_vid` is the VID TSP
/// authenticated it as coming from.
///
/// A Trust Task document sent bare, without the envelope, is answered with
/// `malformedRequest` rather than executed: the envelope is what says the
/// payload is a Trust Task, and the sender VID is proven, so telling a
/// misconfigured peer what is wrong exposes nothing. A payload that is neither
/// is not answered.
pub async fn receive(state: &AppState, sender_vid: &str, payload: &[u8]) -> Option<Vec<u8>> {
    let value: Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, from = %sender_vid, "TSP payload is not JSON");
            return None;
        }
    };
    if value.get("type").and_then(Value::as_str) != Some(ENVELOPE_TYPE) {
        let doc: TrustTask<Value> = serde_json::from_value(value).ok()?;
        tracing::warn!(from = %sender_vid, "refusing a TSP payload that is not a binding envelope");
        let reason = RejectReason::MalformedRequest {
            reason: format!(
                "a Trust Task over TSP must be carried in a `{ENVELOPE_TYPE}` envelope"
            ),
        };
        return Some(wrap_envelope(&reject_value(&doc, reason)));
    }
    let Some(document) = value.get("document") else {
        tracing::warn!(from = %sender_vid, "TSP binding envelope carries no document");
        return None;
    };
    // The SDK's own §7.2.2 gate already refused anything from a VID with no
    // relationship before this adapter runs, so reaching here proves `sender_vid`
    // currently holds one. Stamp it active so the idle-eviction sweep
    // (`relationships::maintenance_loop`) ages out only relationships that have
    // gone quiet, never ones still in use.
    touch_relationship(state, sender_vid).await;
    intake::receive(state, Some(sender_vid), document)
        .await
        .map(|response| wrap_envelope(&response))
}

/// Stamp the durable relationship with `their_vid` as active now, when the
/// gateway has both a durable store and an own DID to stamp it under. Best
/// effort: a failed stamp costs only an extra re-invite once the relationship
/// looks idle, so it is logged, not surfaced.
async fn touch_relationship(state: &AppState, their_vid: &str) {
    let (Some(store), Some(our_vid)) = (&state.tsp_relationships, &state.gateway_did) else {
        return;
    };
    let Some(now_ms) = crate::relationships::unix_millis() else {
        return;
    };
    if let Err(e) = store.touch(our_vid, their_vid, now_ms).await {
        tracing::debug!(peer = %their_vid, error = %e, "could not stamp TSP relationship activity");
    }
}

/// The [`TspHandler`] the service calls for every TSP message on the gateway's
/// socket.
pub struct TspIntake {
    state: AppState,
}

impl TspIntake {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait::async_trait]
impl TspHandler for TspIntake {
    async fn handle(
        &self,
        _ctx: HandlerContext,
        payload: Vec<u8>,
        sender_vid: String,
    ) -> Result<Option<TspResponse>, DIDCommServiceError> {
        Ok(receive(&self.state, &sender_vid, &payload)
            .await
            .map(TspResponse::new))
    }

    /// Accept an inbound relationship invite. The service has already recorded
    /// the control message (and, for the cancellation of a mutual relationship,
    /// sent the §7.3 answer itself); an accept needs no reply.
    async fn handle_control(
        &self,
        ctx: HandlerContext,
        control: ControlMessage,
        sender_vid: String,
        thread_digest: [u8; 32],
    ) {
        if control.control_type != ControlType::RelationshipFormingInvite {
            return;
        }
        match ctx
            .atm
            .tsp()
            .accept_relationship(&ctx.profile, &sender_vid, thread_digest)
            .await
        {
            Ok(state) => {
                tracing::info!(sender = %sender_vid, ?state, "accepted a TSP relationship invite");
                touch_relationship(&self.state, &sender_vid).await;
            }
            Err(e) => tracing::warn!(
                sender = %sender_vid, error = %e,
                "could not send a TSP relationship accept; the invite stays recorded"
            ),
        }
    }
}

/// How a DID document advertises the gateway's TSP endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TspAdvertisement {
    /// A `TSPTransport` service names the mediator the gateway listens on.
    Advertised,
    /// No `TSPTransport` service: peers resolving the DID cannot find TSP.
    Missing,
    /// A `TSPTransport` service names other endpoints than the mediator.
    OtherEndpoint(Vec<String>),
}

/// Read a DID document's `TSPTransport` entries against `mediator`.
pub fn tsp_advertisement(doc: &Value, mediator: &str) -> TspAdvertisement {
    let is_tsp = |svc: &&Value| match svc.get("type") {
        Some(Value::String(t)) => t == TSP_SERVICE_TYPE,
        Some(Value::Array(ts)) => ts.iter().any(|t| t.as_str() == Some(TSP_SERVICE_TYPE)),
        _ => false,
    };
    let endpoints: Vec<String> = doc
        .get("service")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(is_tsp)
        .filter_map(|svc| svc.get("serviceEndpoint"))
        .flat_map(|ep| match ep {
            Value::Array(eps) => eps.clone(),
            other => vec![other.clone()],
        })
        .map(|ep| match ep {
            Value::String(s) => s,
            Value::Object(ref o) => o
                .get("uri")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| ep.to_string()),
            other => other.to_string(),
        })
        .collect();
    if endpoints.is_empty() {
        TspAdvertisement::Missing
    } else if endpoints.iter().any(|ep| ep == mediator) {
        TspAdvertisement::Advertised
    } else {
        TspAdvertisement::OtherEndpoint(endpoints)
    }
}

/// Resolve the gateway's own DID and log whether it advertises TSP through the
/// mediator the gateway listens on. The gateway serves TSP either way; without
/// the entry, only a peer told the route out of band can use it.
pub async fn check_advertised(resolver: &DIDCacheClient, did: &str, mediator: &str) {
    let doc = match resolver.resolve(did).await {
        Ok(resolved) => match serde_json::to_value(&resolved.doc) {
            Ok(doc) => doc,
            Err(e) => {
                tracing::warn!(%did, error = %e, "gateway DID document did not serialise");
                return;
            }
        },
        Err(e) => {
            tracing::warn!(%did, error = %e,
                "could not resolve the gateway's DID to check its TSPTransport service");
            return;
        }
    };
    match tsp_advertisement(&doc, mediator) {
        TspAdvertisement::Advertised => {
            tracing::info!(%did, %mediator, "DID document advertises TSPTransport")
        }
        TspAdvertisement::Missing => tracing::warn!(
            %did, %mediator,
            "the gateway's DID document has no TSPTransport service, so peers cannot find its \
             TSP endpoint; add {{\"id\": \"{did}#tsp\", \"type\": \"TSPTransport\", \
             \"serviceEndpoint\": \"{mediator}\"}}"
        ),
        TspAdvertisement::OtherEndpoint(endpoints) => tracing::warn!(
            %did, %mediator, advertised = ?endpoints,
            "the gateway's TSPTransport service does not name the mediator it listens on"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEDIATOR: &str = "did:webvh:scid:mediator.example";

    fn doc(services: Value) -> Value {
        json!({ "id": "did:webvh:scid:gw.example", "service": services })
    }

    #[test]
    fn a_tsp_service_naming_the_mediator_is_advertised() {
        let d = doc(json!([
            { "id": "#service", "type": ["DIDCommMessaging"], "serviceEndpoint": [{ "uri": "https://x" }] },
            { "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": MEDIATOR },
        ]));
        assert_eq!(
            tsp_advertisement(&d, MEDIATOR),
            TspAdvertisement::Advertised
        );
        let d = doc(json!([
            { "id": "#tsp", "type": ["TSPTransport"], "serviceEndpoint": [{ "uri": MEDIATOR }] },
        ]));
        assert_eq!(
            tsp_advertisement(&d, MEDIATOR),
            TspAdvertisement::Advertised
        );
    }

    #[test]
    fn a_document_without_tsp_is_missing_it() {
        let d = doc(json!([
            { "id": "#service", "type": ["DIDCommMessaging"], "serviceEndpoint": MEDIATOR },
        ]));
        assert_eq!(tsp_advertisement(&d, MEDIATOR), TspAdvertisement::Missing);
        assert_eq!(
            tsp_advertisement(&json!({ "id": "did:x:y" }), MEDIATOR),
            TspAdvertisement::Missing
        );
    }

    #[test]
    fn a_tsp_service_naming_another_mediator_is_flagged() {
        let d = doc(json!([
            { "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:web:elsewhere" },
        ]));
        assert_eq!(
            tsp_advertisement(&d, MEDIATOR),
            TspAdvertisement::OtherEndpoint(vec!["did:web:elsewhere".into()])
        );
    }

    #[test]
    fn the_envelope_is_the_bindings() {
        let wrapped: Value = serde_json::from_slice(&wrap_envelope(&json!({ "id": "x" }))).unwrap();
        assert_eq!(
            wrapped["type"],
            "https://trusttasks.org/binding/tsp/0.1/envelope"
        );
        assert_eq!(wrapped["document"]["id"], "x");
    }
}
