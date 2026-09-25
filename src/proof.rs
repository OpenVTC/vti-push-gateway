//! Document-level authentication for `push/provision` and `push/wake` arriving
//! over DIDComm: an `eddsa-jcs-2022` Data Integrity proof on the Trust Task
//! document, bound to the document's `issuer`.
//!
//! These are a service's own operational messages, not attestations, so the
//! proof is made with the issuer's **operational** key and carries
//! `proofPurpose: authentication` (VTI-KEY-106); `assertionMethod` is reserved
//! for attestation artefacts and is refused here. An `authentication` proof
//! carries no challenge, so what binds it to one delivery is the document's
//! recipient, time of issue and identifier — checked by the caller
//! (`didcomm::authenticate`, VTI-KEY-107).
//!
//! The HTTPS adapter authenticates a caller by a signature over the request
//! body (`auth.rs`). The DIDComm adapter now asks for the equivalent, carried
//! in-band: the controller VTA (or trigger) signs the Trust Task document, and
//! the gateway authorises on the DID that proof establishes. The DIDComm
//! envelope's `from` is **not** an authorising identity on its own — a message
//! whose only claim to a sender is the envelope gets `proofRequired`.
//!
//! [`ProofVerifier::verify_issuer`] returns the proven issuer DID after checking,
//! in order:
//!
//! 1. the document carries a string `issuer` and a `proof`;
//! 2. the proof is `eddsa-jcs-2022` with `proofPurpose: authentication`;
//! 3. the DID part of `proof.verificationMethod` **is** the `issuer` (exact
//!    string equality, no normalisation);
//! 4. the issuer's DID document lists that verification method, the method's
//!    `controller` **is** the issuer, and the method is referenced (or
//!    embedded) under `authentication` — a key the DID lists only for key
//!    agreement or for attestations does not authenticate its messages;
//! 5. the signature verifies over the document with `proof` removed, against
//!    the key from step 4.
//!
//! Verification runs over the raw JSON body, not a typed round-trip, so it is
//! faithful to what the issuer signed, unknown members included.
//!
//! What the caller then does with the DID is authorisation, not this module's
//! concern: `push/provision` requires it to be the handle's controller VTA,
//! `push/wake` requires it to be on the handle's trigger allowlist.

use std::sync::Arc;

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{
    DataIntegrityError, DataIntegrityProof, ResolvedKey, VerificationMethodResolver, VerifyOptions,
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::secrets::KeyType;
use async_trait::async_trait;
use serde_json::Value;

/// The only proof purpose accepted on a `push/*` document.
pub const PROOF_PURPOSE: &str = "authentication";

/// The DID-document verification relationship the proof's method must be in.
const RELATIONSHIP: &str = "authentication";

/// Ed25519 public-key multicodec prefix (`0xed 0x01`).
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Why a document's proof did not establish its issuer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProofError {
    /// The document carries no `proof` member at all.
    #[error("document carries no proof")]
    Missing,
    /// A proof is present but does not establish the issuer.
    #[error("{0}")]
    Invalid(String),
}

fn invalid(reason: impl Into<String>) -> ProofError {
    ProofError::Invalid(reason.into())
}

/// Resolves the DID documents a proof names and verifies the proof against
/// them. Cheap to clone; share one per process.
#[derive(Clone)]
pub struct ProofVerifier {
    client: Arc<DIDCacheClient>,
}

impl ProofVerifier {
    /// Wrap a configured DID resolver. It should be built with the same host
    /// policy as the DIDComm listener's (see [`crate::resolver`]), since the
    /// DIDs it resolves are chosen by whoever sends the gateway a message.
    pub fn new(client: Arc<DIDCacheClient>) -> Self {
        Self { client }
    }

    /// Whether `raw` carries a `proof` member.
    pub fn has_proof(raw: &Value) -> bool {
        raw.get("proof").is_some_and(|p| !p.is_null())
    }

    /// Verify `raw`'s Data Integrity proof and return the issuer DID it proves.
    /// See the module docs for the checks, in order.
    pub async fn verify_issuer(&self, raw: &Value) -> Result<String, ProofError> {
        let proof_value = match raw.get("proof") {
            None | Some(Value::Null) => return Err(ProofError::Missing),
            Some(p) => p,
        };
        let issuer = raw
            .get("issuer")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("document carries a proof but no issuer to bind it to"))?;

        let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())
            .map_err(|_| invalid("proof is not a Data Integrity proof"))?;
        if proof.cryptosuite != CryptoSuite::EddsaJcs2022 {
            return Err(invalid("proof cryptosuite must be eddsa-jcs-2022"));
        }
        if proof.proof_purpose != PROOF_PURPOSE {
            return Err(invalid("proof purpose must be authentication"));
        }

        let vm = proof.verification_method.as_str();
        let (vm_did, fragment) = vm
            .split_once('#')
            .ok_or_else(|| invalid("proof verificationMethod is not a DID URL with a fragment"))?;
        if vm_did != issuer || fragment.is_empty() {
            return Err(invalid(
                "proof verificationMethod is not controlled by the document issuer",
            ));
        }

        let key = self.authentication_key(issuer, vm).await?;

        let mut unsigned = raw.clone();
        if let Some(obj) = unsigned.as_object_mut() {
            obj.remove("proof");
        }
        proof
            .verify(
                &unsigned,
                &PinnedKey(key),
                VerifyOptions::new().with_allowed_suites(vec![CryptoSuite::EddsaJcs2022]),
            )
            .await
            .map_err(|e| {
                tracing::debug!(error = %e, issuer, "push/* proof failed to verify");
                invalid("proof signature does not verify")
            })?;
        Ok(issuer.to_string())
    }

    /// Resolve `issuer` and return the Ed25519 key of verification method `vm`,
    /// provided the document lists it, it is controlled by `issuer`, and it is
    /// an `authentication` method of `issuer`.
    async fn authentication_key(&self, issuer: &str, vm: &str) -> Result<ResolvedKey, ProofError> {
        let resolved = self.client.resolve(issuer).await.map_err(|e| {
            tracing::debug!(error = %e, issuer, "could not resolve the proof issuer");
            invalid("could not resolve the proof issuer's DID document")
        })?;
        let doc = serde_json::to_value(&resolved.doc)
            .map_err(|_| invalid("issuer DID document did not serialise"))?;
        authentication_key_in(&doc, issuer, vm)
    }
}

/// Step 4 over an already-resolved DID document (split out for testing).
pub(crate) fn authentication_key_in(
    doc: &Value,
    issuer: &str,
    vm: &str,
) -> Result<ResolvedKey, ProofError> {
    if doc.get("id").and_then(Value::as_str) != Some(issuer) {
        return Err(invalid("resolved DID document is not the issuer's"));
    }
    let same_vm = |id: &str| absolute(issuer, id) == vm;

    let method = doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            // An `authentication` entry may embed its method rather than
            // reference one from `verificationMethod`.
            doc.get(RELATIONSHIP)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|e| e.is_object()),
        )
        .find(|m| m.get("id").and_then(Value::as_str).is_some_and(same_vm))
        .ok_or_else(|| {
            invalid("issuer DID document does not list the proof's verificationMethod")
        })?;

    if method.get("controller").and_then(Value::as_str) != Some(issuer) {
        return Err(invalid(
            "the proof's verificationMethod is not controlled by the issuer",
        ));
    }

    let is_listed = doc
        .get(RELATIONSHIP)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| match entry {
            Value::String(r) => same_vm(r),
            Value::Object(o) => o.get("id").and_then(Value::as_str).is_some_and(same_vm),
            _ => false,
        });
    if !is_listed {
        return Err(invalid(
            "the proof's verificationMethod is not an authentication method of the issuer",
        ));
    }

    let multibase = method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("verificationMethod carries no publicKeyMultibase"))?;
    let raw = multibase
        .strip_prefix('z')
        .and_then(|b58| bs58::decode(b58).into_vec().ok())
        .ok_or_else(|| invalid("verificationMethod key is not base58btc multibase"))?;
    let key = raw
        .strip_prefix(&ED25519_MULTICODEC[..])
        .filter(|k| k.len() == 32)
        .ok_or_else(|| invalid("verificationMethod key is not an Ed25519 key"))?;
    Ok(ResolvedKey::new(KeyType::Ed25519, key.to_vec()))
}

/// Resolve a possibly-relative DID URL (`#key-0`) against `did`.
fn absolute(did: &str, id: &str) -> String {
    if id.starts_with('#') {
        format!("{did}{id}")
    } else {
        id.to_string()
    }
}

/// A resolver that answers with the one key [`authentication_key_in`] already
/// selected, so the signature is checked against exactly that key.
struct PinnedKey(ResolvedKey);

#[async_trait]
impl VerificationMethodResolver for PinnedKey {
    async fn resolve_vm(&self, _vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
        Ok(ResolvedKey::new(
            self.0.key_type,
            self.0.public_key_bytes.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:webvh:scid:vta.example";
    const KEY_MB: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn doc(vm: Value, relationship: Value) -> Value {
        json!({ "id": DID, "verificationMethod": [vm], "authentication": relationship })
    }

    fn vm(controller: &str) -> Value {
        json!({ "id": format!("{DID}#key-0"), "type": "Multikey",
                "controller": controller, "publicKeyMultibase": KEY_MB })
    }

    #[test]
    fn accepts_an_authentication_method_controlled_by_the_issuer() {
        let d = doc(vm(DID), json!([format!("{DID}#key-0")]));
        assert!(authentication_key_in(&d, DID, &format!("{DID}#key-0")).is_ok());
        // Relative references resolve against the issuer.
        let d = doc(vm(DID), json!(["#key-0"]));
        assert!(authentication_key_in(&d, DID, &format!("{DID}#key-0")).is_ok());
    }

    #[test]
    fn refuses_a_method_controlled_by_someone_else() {
        let d = doc(vm("did:key:zOther"), json!([format!("{DID}#key-0")]));
        assert!(matches!(
            authentication_key_in(&d, DID, &format!("{DID}#key-0")),
            Err(ProofError::Invalid(r)) if r.contains("not controlled")
        ));
    }

    #[test]
    fn refuses_a_method_listed_only_for_attestation() {
        // An attestation key does not authenticate the issuer's messages.
        let d = json!({ "id": DID, "verificationMethod": [vm(DID)],
                        "assertionMethod": [format!("{DID}#key-0")] });
        assert!(matches!(
            authentication_key_in(&d, DID, &format!("{DID}#key-0")),
            Err(ProofError::Invalid(r)) if r.contains("authentication method")
        ));
    }

    #[test]
    fn refuses_a_document_for_another_did() {
        let mut d = doc(vm(DID), json!([format!("{DID}#key-0")]));
        d["id"] = json!("did:webvh:scid:elsewhere.example");
        assert!(authentication_key_in(&d, DID, &format!("{DID}#key-0")).is_err());
    }

    #[test]
    fn refuses_an_unlisted_method() {
        let d = doc(vm(DID), json!([format!("{DID}#key-0")]));
        assert!(authentication_key_in(&d, DID, &format!("{DID}#key-9")).is_err());
    }
}
