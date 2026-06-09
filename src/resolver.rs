//! DID-resolver tuning for the DIDComm transport.
//!
//! The DIDComm listener resolves every sender/recipient DID through the
//! affinidi DID-resolver cache. Left unconfigured it uses the SDK's stock
//! defaults (100-entry cache, **300 s** TTL, **5 s** network timeout) — tight
//! for `did:webvh`, whose resolution fetches a verifiable **log over HTTPS**
//! (slower than `did:key`/`did:web`) yet changes rarely. This module builds a
//! [`TDKConfig`] with a tuned [`DIDCacheConfig`] from env, which the listener
//! takes via `ListenerConfig.tdk_config` (replacing the implicit
//! `TDKConfig::headless()`).
//!
//! Env knobs (all optional; defaults below):
//! - `GATEWAY_DID_CACHE_CAPACITY`   — max cached DID docs (default 250)
//! - `GATEWAY_DID_CACHE_TTL_SECS`   — cache entry TTL (default 900 = 15 min)
//! - `GATEWAY_DID_NETWORK_TIMEOUT_MS` — per-resolution timeout (default 10000)
//! - `GATEWAY_DID_RESOLVER_URL`     — resolve via a remote resolver service
//!   (`ws[s]://…`) instead of locally; unset = local resolution.

use affinidi_did_resolver_cache_sdk::config::{DIDCacheConfig, DIDCacheConfigBuilder};
use affinidi_tdk::common::config::TDKConfig;

/// Resolved DID-resolver tuning (post-env).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverTuning {
    pub cache_capacity: u32,
    pub cache_ttl_secs: u32,
    pub network_timeout_ms: u32,
    /// Remote resolver service address (`ws[s]://…`); `None` = local resolution.
    pub service_address: Option<String>,
}

impl Default for ResolverTuning {
    fn default() -> Self {
        // Tuned for a did:webvh-heavy gateway: longer TTL cuts re-fetch churn on
        // docs that rarely change; a longer timeout absorbs a slow HTTPS log
        // fetch. Both are deliberately above the SDK defaults (300 s / 5000 ms).
        Self {
            cache_capacity: 250,
            cache_ttl_secs: 900,
            network_timeout_ms: 10_000,
            service_address: None,
        }
    }
}

impl ResolverTuning {
    /// Read tuning from the environment, falling back to [`Self::default`] for
    /// any unset/invalid value.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            cache_capacity: env_u32("GATEWAY_DID_CACHE_CAPACITY", d.cache_capacity),
            cache_ttl_secs: env_u32("GATEWAY_DID_CACHE_TTL_SECS", d.cache_ttl_secs),
            network_timeout_ms: env_u32("GATEWAY_DID_NETWORK_TIMEOUT_MS", d.network_timeout_ms),
            service_address: std::env::var("GATEWAY_DID_RESOLVER_URL")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        }
    }

    fn did_cache_config(&self) -> DIDCacheConfig {
        let mut builder = DIDCacheConfigBuilder::default()
            .with_cache_capacity(self.cache_capacity)
            .with_cache_ttl(self.cache_ttl_secs)
            .with_network_timeout(self.network_timeout_ms);
        if let Some(addr) = &self.service_address {
            builder = builder.with_network_mode(addr);
        }
        builder.build()
    }

    /// Build the headless [`TDKConfig`] the listener uses, carrying the tuned DID
    /// cache. Mirrors `TDKConfig::headless()` (no on-disk env, no auto-ATM) plus
    /// the resolver config.
    pub fn tdk_config(&self) -> Result<TDKConfig, String> {
        TDKConfig::builder()
            .with_load_environment(false)
            .with_use_atm(false)
            .with_did_resolver_config(self.did_cache_config())
            .build()
            .map_err(|e| format!("build TDK config: {e}"))
    }

    /// One-line summary for the startup log.
    pub fn summary(&self) -> String {
        format!(
            "cache_capacity={} cache_ttl={}s network_timeout={}ms resolver={}",
            self.cache_capacity,
            self.cache_ttl_secs,
            self.network_timeout_ms,
            self.service_address.as_deref().unwrap_or("local")
        )
    }
}

/// Parse a `u32` env var, logging and falling back to `default` when unset or
/// unparseable. Split from the parsing so the latter is unit-testable.
fn env_u32(key: &str, default: u32) -> u32 {
    parse_u32(std::env::var(key).ok().as_deref(), default).unwrap_or_else(|raw| {
        tracing::warn!(%key, value = %raw, default, "invalid u32; using default");
        default
    })
}

/// Pure parse: `Ok(n)` on a valid value, `Ok(default)` when absent, `Err(raw)`
/// when present but unparseable (so the caller can log it).
fn parse_u32(raw: Option<&str>, default: u32) -> Result<u32, String> {
    match raw {
        None => Ok(default),
        Some(s) => s.trim().parse::<u32>().map_err(|_| s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u32_absent_uses_default() {
        assert_eq!(parse_u32(None, 250), Ok(250));
    }

    #[test]
    fn parse_u32_valid_overrides() {
        assert_eq!(parse_u32(Some(" 500 "), 250), Ok(500));
    }

    #[test]
    fn parse_u32_invalid_reports_raw() {
        assert_eq!(parse_u32(Some("nope"), 250), Err("nope".to_string()));
    }

    #[test]
    fn defaults_exceed_sdk_stock_for_webvh() {
        let d = ResolverTuning::default();
        // Above the SDK's 300 s / 5000 ms — the whole point of the tuning.
        assert!(d.cache_ttl_secs > 300);
        assert!(d.network_timeout_ms > 5000);
        assert!(d.service_address.is_none()); // local by default
    }

    #[test]
    fn builds_a_tdk_config_local_and_remote() {
        // Local.
        assert!(ResolverTuning::default().tdk_config().is_ok());
        // Remote resolver service.
        let remote = ResolverTuning {
            service_address: Some("wss://resolver.example/did/v1".into()),
            ..ResolverTuning::default()
        };
        assert!(remote.tdk_config().is_ok());
        assert!(remote
            .summary()
            .contains("resolver=wss://resolver.example/did/v1"));
    }
}
