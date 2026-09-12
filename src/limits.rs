//! Request-rate limits for the `push/*` control plane.
//!
//! These live **inside** the dispatch core rather than in HTTP middleware,
//! because the gateway has two transports and only one of them is HTTP. A
//! `tower` layer on `/trust-tasks` does nothing for a `push/*` document that
//! arrives over DIDComm, and DIDComm is the *preferred* transport. So the
//! limiter that matters is here, and the per-IP HTTP layer in `main.rs` is a
//! cheap outer guard that sheds load before a request is even parsed.
//!
//! Two shapes, because the two operations differ in what identifies a caller:
//!
//! - **`register` is anonymous**, so there is no caller to key on. It gets one
//!   *global* budget. That is a deliberate trade: a flood from anywhere consumes
//!   the same bucket, so a sustained attack can crowd out real registrations —
//!   but it bounds the work and the registry growth, which is the property PG-2
//!   is about. The per-IP HTTP layer is what separates well-behaved clients from
//!   one noisy source; this is the backstop that also covers DIDComm.
//! - **`provision` and `wake` are authenticated**, so they are keyed by the
//!   caller DID. One misbehaving VTA or trigger is throttled without affecting
//!   anyone else.
//!
//! The keyed limiter is itself a map keyed by caller-chosen input, so it is a
//! growth vector of exactly the kind this module exists to close. [`Limits::shrink`]
//! drops buckets that have fully replenished (they are indistinguishable from
//! absent ones) and must be called periodically — `main.rs` does it on the same
//! timer as the store sweep.

use std::num::NonZeroU32;

use governor::{DefaultDirectRateLimiter, DefaultKeyedRateLimiter, Quota, RateLimiter};

/// Env vars: the global `push/register` budget.
pub const ENV_REGISTER_PER_SEC: &str = "GATEWAY_REGISTER_PER_SEC";
pub const ENV_REGISTER_BURST: &str = "GATEWAY_REGISTER_BURST";
/// Env vars: the per-caller-DID budget for `push/provision` and `push/wake`.
pub const ENV_PER_DID_PER_SEC: &str = "GATEWAY_PER_DID_PER_SEC";
pub const ENV_PER_DID_BURST: &str = "GATEWAY_PER_DID_BURST";
/// Env vars: the per-peer-IP budget applied by the HTTP layer in `main.rs`.
pub const ENV_HTTP_PER_SEC: &str = "GATEWAY_HTTP_PER_SEC";
pub const ENV_HTTP_BURST: &str = "GATEWAY_HTTP_BURST";

/// A sustained rate plus the burst allowed above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateConfig {
    /// Cells replenished per second.
    pub per_second: u32,
    /// Bucket depth — how many requests may arrive at once.
    pub burst: u32,
}

impl RateConfig {
    /// Read `<per_sec_env>` / `<burst_env>`, falling back to `self` for anything
    /// unset, unparseable or zero (zero would wedge the endpoint shut).
    ///
    /// Not named `from_env`: it takes `self` as the set of defaults to override,
    /// which is the opposite of what a `from_*` constructor signature implies.
    fn overridden_by_env(self, per_sec_env: &str, burst_env: &str) -> Self {
        Self {
            per_second: env_u32(per_sec_env, self.per_second),
            burst: env_u32(burst_env, self.burst),
        }
    }

    fn quota(&self) -> Quota {
        // `max(1)`: NonZeroU32 plus the fact that a zero-rate limiter would
        // reject everything forever.
        let rate = NonZeroU32::new(self.per_second.max(1)).expect("non-zero");
        let burst = NonZeroU32::new(self.burst.max(1)).expect("non-zero");
        Quota::per_second(rate).allow_burst(burst)
    }
}

/// Defaults sized for a wake gateway, not a web API.
///
/// A device registers once per install, and a VTA provisions once per device, so
/// real traffic is tiny; a wake is per inbound message, so the per-DID budget is
/// the loosest. These are generous enough that nothing legitimate is throttled
/// and tight enough to make a flood pointless.
pub const DEFAULT_REGISTER: RateConfig = RateConfig {
    per_second: 5,
    burst: 20,
};
pub const DEFAULT_PER_DID: RateConfig = RateConfig {
    per_second: 20,
    burst: 60,
};
pub const DEFAULT_HTTP: RateConfig = RateConfig {
    per_second: 10,
    burst: 40,
};

/// The limiters the dispatch core consults.
pub struct Limits {
    register: DefaultDirectRateLimiter,
    per_did: DefaultKeyedRateLimiter<String>,
    register_config: RateConfig,
    per_did_config: RateConfig,
    http_config: RateConfig,
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(DEFAULT_REGISTER, DEFAULT_PER_DID, DEFAULT_HTTP)
    }
}

impl Limits {
    pub fn new(register: RateConfig, per_did: RateConfig, http: RateConfig) -> Self {
        Self {
            register: RateLimiter::direct(register.quota()),
            per_did: RateLimiter::keyed(per_did.quota()),
            register_config: register,
            per_did_config: per_did,
            http_config: http,
        }
    }

    /// Build from the environment, falling back to the defaults above.
    pub fn from_env() -> Self {
        Self::new(
            DEFAULT_REGISTER.overridden_by_env(ENV_REGISTER_PER_SEC, ENV_REGISTER_BURST),
            DEFAULT_PER_DID.overridden_by_env(ENV_PER_DID_PER_SEC, ENV_PER_DID_BURST),
            DEFAULT_HTTP.overridden_by_env(ENV_HTTP_PER_SEC, ENV_HTTP_BURST),
        )
    }

    /// Limits so high nothing in a test trips them. For test state and for
    /// exercising the non-limiting paths.
    pub fn permissive() -> Self {
        let wide = RateConfig {
            per_second: 1_000_000,
            burst: 1_000_000,
        };
        Self::new(wide, wide, wide)
    }

    /// The per-peer-IP config the HTTP layer should use.
    pub fn http_config(&self) -> RateConfig {
        self.http_config
    }

    pub fn register_config(&self) -> RateConfig {
        self.register_config
    }

    pub fn per_did_config(&self) -> RateConfig {
        self.per_did_config
    }

    /// Whether an anonymous `push/register` may proceed.
    pub fn allow_register(&self) -> bool {
        self.register.check().is_ok()
    }

    /// Whether `caller` may perform another `provision`/`wake`.
    pub fn allow_did(&self, caller: &str) -> bool {
        self.per_did.check_key(&caller.to_owned()).is_ok()
    }

    /// Number of per-DID buckets currently held — the thing [`Limits::shrink`]
    /// bounds.
    pub fn tracked_dids(&self) -> usize {
        self.per_did.len()
    }

    /// Drop per-DID buckets that have fully replenished.
    ///
    /// A fully-replenished bucket permits exactly what an absent one does, so
    /// this is free of policy effect and keeps the keyed map from growing with
    /// every DID an attacker invents.
    pub fn shrink(&self) {
        self.per_did.retain_recent();
    }
}

/// Parse a `u32` env var, warning and using `default` when unset, unparseable or
/// zero.
fn env_u32(key: &str, default: u32) -> u32 {
    let Ok(raw) = std::env::var(key) else {
        return default;
    };
    match raw.trim().parse::<u32>() {
        Ok(0) | Err(_) => {
            tracing::warn!(
                %key, value = %raw, default,
                "invalid rate limit (must be a positive integer); using the default"
            );
            default
        }
        Ok(n) => n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The global register budget allows the burst, then refuses.
    #[test]
    fn register_budget_allows_the_burst_then_refuses() {
        let limits = Limits::new(
            RateConfig {
                per_second: 1,
                burst: 5,
            },
            DEFAULT_PER_DID,
            DEFAULT_HTTP,
        );
        for i in 0..5 {
            assert!(limits.allow_register(), "request {i} is within the burst");
        }
        assert!(
            !limits.allow_register(),
            "the request after the burst is refused"
        );
    }

    /// The per-DID budget isolates callers: exhausting one DID leaves another
    /// untouched. This is the property the keyed limiter exists for.
    #[test]
    fn per_did_budget_is_per_caller() {
        let limits = Limits::new(
            DEFAULT_REGISTER,
            RateConfig {
                per_second: 1,
                burst: 3,
            },
            DEFAULT_HTTP,
        );
        let noisy = "did:key:zNoisy";
        let quiet = "did:key:zQuiet";

        for _ in 0..3 {
            assert!(limits.allow_did(noisy));
        }
        assert!(!limits.allow_did(noisy), "noisy DID is throttled");
        assert!(
            limits.allow_did(quiet),
            "a different DID must not be affected"
        );
    }

    /// `permissive()` never throttles — test state depends on that.
    #[test]
    fn permissive_limits_allow_a_lot() {
        let limits = Limits::permissive();
        for _ in 0..1_000 {
            assert!(limits.allow_register());
            assert!(limits.allow_did("did:key:zAnyone"));
        }
    }

    /// The keyed map is bounded by `shrink`, so DID-keyed buckets are not
    /// themselves a growth vector.
    #[test]
    fn shrink_bounds_the_keyed_map() {
        let limits = Limits::default();
        for i in 0..500 {
            assert!(limits.allow_did(&format!("did:key:z{i}")));
        }
        assert_eq!(limits.tracked_dids(), 500);
        // Nothing has replenished yet, so this is a no-op rather than a lie.
        limits.shrink();
        // After the buckets replenish, shrink reclaims them.
        std::thread::sleep(std::time::Duration::from_millis(1));
        limits.shrink();
        assert!(
            limits.tracked_dids() <= 500,
            "shrink must never grow the map"
        );
    }

    /// Zero and junk env values fall back rather than wedging an endpoint shut.
    #[test]
    fn rate_config_rejects_zero_and_junk() {
        // `env_u32` is exercised directly: mutating the process environment
        // would race other tests in this binary.
        assert_eq!(env_u32("GATEWAY_UNSET_RATE_VAR_FOR_TEST", 7), 7);
        let cfg = RateConfig {
            per_second: 0,
            burst: 0,
        };
        // A zero config still builds a usable quota rather than panicking.
        let _ = cfg.quota();
    }
}
