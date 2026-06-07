//! Caller authentication for `provision` and `wake`.
//!
//! A caller (the controller VTA, or a trigger) signs the **raw request body
//! bytes** with its `did:key` Ed25519 key and presents:
//!
//! - `X-TT-Did: did:key:z…`        — the caller's did:key (Ed25519).
//! - `X-TT-Signature: <base64url>` — Ed25519 signature over the exact body.
//!
//! The gateway resolves the did:key offline (multibase/multicodec decode — no
//! network) and verifies the signature. `register` is unauthenticated: anyone
//! may register their own token and receive an opaque handle, which is useless
//! until that device's VTA puts a trigger on its allowlist.
//!
//! Replay is acceptable here per the binding's own analysis (§6): a replayed
//! wake is a harmless duplicate doorbell; a replayed provision re-sets the same
//! allowlist (idempotent). No nonce is required for these operations.

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

pub const HEADER_DID: &str = "x-tt-did";
pub const HEADER_SIG: &str = "x-tt-signature";

/// Ed25519 public-key multicodec prefix (`0xed 0x01`) for `did:key`.
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing {0} header")]
    MissingHeader(&'static str),
    #[error("malformed did:key: {0}")]
    BadDid(&'static str),
    #[error("malformed signature: {0}")]
    BadSignature(&'static str),
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Parse a `did:key:z…` Ed25519 DID into its verifying key.
pub fn parse_did_key_ed25519(did: &str) -> Result<VerifyingKey, AuthError> {
    let mb = did
        .strip_prefix("did:key:z")
        .ok_or(AuthError::BadDid("not a base58btc did:key"))?;
    let decoded = bs58::decode(mb)
        .into_vec()
        .map_err(|_| AuthError::BadDid("invalid base58btc"))?;
    let key_bytes = decoded
        .strip_prefix(&ED25519_MULTICODEC[..])
        .ok_or(AuthError::BadDid(
            "not an Ed25519 did:key (multicodec mismatch)",
        ))?;
    let arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| AuthError::BadDid("Ed25519 public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| AuthError::BadDid("invalid Ed25519 point"))
}

/// Verify that `did` signed `body` with the given base64url signature.
/// On success the caller is authenticated as `did`.
pub fn verify_signed(did: &str, sig_b64url: &str, body: &[u8]) -> Result<(), AuthError> {
    let vk = parse_did_key_ed25519(did)?;
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64url.trim())
        .map_err(|_| AuthError::BadSignature("invalid base64url"))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|_| AuthError::BadSignature("not 64 bytes"))?;
    vk.verify_strict(body, &sig)
        .map_err(|_| AuthError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::Rng;

    /// Generate a signing key from OS randomness. (ed25519-dalek's own
    /// `generate` is tied to rand_core 0.6; we seed `from_bytes` from rand 0.10
    /// instead to keep a single rand version in the tree.)
    fn signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    /// Build the `did:key` for a signing key (multicodec-tagged, base58btc).
    fn did_key_for(sk: &SigningKey) -> String {
        let mut bytes = ED25519_MULTICODEC.to_vec();
        bytes.extend_from_slice(sk.verifying_key().as_bytes());
        format!("did:key:z{}", bs58::encode(bytes).into_string())
    }

    #[test]
    fn round_trip_verifies() {
        let sk = signing_key();
        let did = did_key_for(&sk);
        let body = br#"{"handle":"h","v":1}"#;
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.sign(body).to_bytes());

        assert!(verify_signed(&did, &sig, body).is_ok());
        // Tampered body fails.
        assert!(matches!(
            verify_signed(&did, &sig, b"different"),
            Err(AuthError::VerificationFailed)
        ));
    }

    #[test]
    fn rejects_non_ed25519_did() {
        assert!(matches!(
            parse_did_key_ed25519("did:key:zNotEd25519"),
            Err(AuthError::BadDid(_))
        ));
    }
}
