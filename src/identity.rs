//! The gateway's provisioned `did:webvh` identity.
//!
//! The gateway is a **provisioned VTA integration** (the `push-gateway` DID
//! template): an operator runs `pnm bootstrap provision-integration --template
//! push-gateway --var URL=<gateway-didcomm-url>` against the VTA, opens the
//! sealed bundle, and the gateway loads the resulting identity here — its
//! `did:webvh`, its signing + key-agreement private keys (multibase, as the
//! bundle delivers them), and the mediator it connects to.
//!
//! Loaded from a JSON key file (`GATEWAY_IDENTITY_FILE`):
//!
//! ```jsonc
//! { "did": "did:webvh:…:push-gateway",
//!   "signing":      { "id": "did:webvh:…#key-0", "privateKeyMultibase": "z…" },
//!   "keyAgreement": { "id": "did:webvh:…#key-1", "privateKeyMultibase": "z…" },
//!   "mediator": "did:webvh:…:mediator" }
//! ```

use std::path::Path;

use affinidi_secrets_resolver::secrets::Secret;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct KeyEntry {
    /// Verification-method id (DID URL fragment), e.g. `did:webvh:…#key-1`.
    pub id: String,
    #[serde(rename = "privateKeyMultibase")]
    pub private_key_multibase: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayIdentity {
    /// The gateway's `did:webvh`.
    pub did: String,
    /// Ed25519 signing key (`#key-0`).
    pub signing: KeyEntry,
    /// X25519 key-agreement key (`#key-1`) — used to receive authcrypt.
    #[serde(rename = "keyAgreement")]
    pub key_agreement: KeyEntry,
    /// The mediator the gateway connects to for inbound DIDComm.
    pub mediator: String,
}

impl GatewayIdentity {
    /// Load the identity from a JSON key file (produced by opening the
    /// `push-gateway` provision bundle).
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("read identity file {}: {e}", path.display()))?;
        serde_json::from_str(&raw).map_err(|e| format!("parse identity file: {e}"))
    }

    /// The gateway's DIDComm secrets (signing + key-agreement), keyed by their
    /// verification-method ids — for the `TDKProfile` the DIDComm service uses
    /// to unpack inbound authcrypt and sign replies.
    pub fn secrets(&self) -> Result<Vec<Secret>, String> {
        let mut out = Vec::with_capacity(2);
        for k in [&self.signing, &self.key_agreement] {
            let mut secret = Secret::from_multibase(&k.private_key_multibase, None)
                .map_err(|e| format!("construct Secret for {}: {e}", k.id))?;
            secret.id = k.id.clone();
            out.push(secret);
        }
        Ok(out)
    }
}
