//! In-process operation counters, exposed at `GET /metrics` in Prometheus
//! text-exposition format. The counters live in [`AppState`](crate::api::AppState)
//! and are bumped inside the transport-agnostic dispatch core, so both transports
//! (HTTPS + DIDComm) are covered by one set of call sites.
//!
//! Dependency-free by design: a handful of `AtomicU64`s plus hand-rolled
//! rendering. The gateway's metric set is small and fixed, so a full Prometheus
//! client crate (registry, encoders, label maps) would be over-built — and it
//! keeps the dependency tree, and the `rsa`/`tail`-free build hygiene, untouched.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counters for the three `push/*` operations, broken down by outcome. Counts
/// only the outcomes an operator acts on (delivery health, allowlist refusals);
/// malformed-document rejects are left to logs/traces.
#[derive(Default)]
pub struct Metrics {
    /// Handles successfully issued (`push/register`).
    registers: AtomicU64,

    /// `push/provision` by outcome.
    provision_ok: AtomicU64,
    provision_unknown_handle: AtomicU64,
    provision_not_controller: AtomicU64,

    /// `push/wake` by outcome — the delivery-health signals.
    wake_delivered: AtomicU64,
    wake_transient_failure: AtomicU64,
    wake_token_unregistered: AtomicU64,
    wake_unknown_handle: AtomicU64,
    wake_not_allowed: AtomicU64,
}

impl Metrics {
    pub fn inc_register(&self) {
        self.registers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_provision_ok(&self) {
        self.provision_ok.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_provision_unknown_handle(&self) {
        self.provision_unknown_handle
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_provision_not_controller(&self) {
        self.provision_not_controller
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_wake_delivered(&self) {
        self.wake_delivered.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_wake_transient_failure(&self) {
        self.wake_transient_failure.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_wake_token_unregistered(&self) {
        self.wake_token_unregistered.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_wake_unknown_handle(&self) {
        self.wake_unknown_handle.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_wake_not_allowed(&self) {
        self.wake_not_allowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the counters as Prometheus text exposition (v0.0.4). One `_total`
    /// counter per operation; provision/wake carry an `outcome` label so series
    /// stay aggregatable.
    pub fn render(&self) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut out = String::new();

        out.push_str("# HELP gateway_register_total Handles issued via push/register.\n");
        out.push_str("# TYPE gateway_register_total counter\n");
        out.push_str(&format!("gateway_register_total {}\n", g(&self.registers)));

        out.push_str("# HELP gateway_provision_total push/provision results by outcome.\n");
        out.push_str("# TYPE gateway_provision_total counter\n");
        for (outcome, v) in [
            ("ok", &self.provision_ok),
            ("unknown_handle", &self.provision_unknown_handle),
            ("not_controller", &self.provision_not_controller),
        ] {
            out.push_str(&format!(
                "gateway_provision_total{{outcome=\"{outcome}\"}} {}\n",
                g(v)
            ));
        }

        out.push_str("# HELP gateway_wake_total push/wake results by outcome.\n");
        out.push_str("# TYPE gateway_wake_total counter\n");
        for (outcome, v) in [
            ("delivered", &self.wake_delivered),
            ("transient_failure", &self.wake_transient_failure),
            ("token_unregistered", &self.wake_token_unregistered),
            ("unknown_handle", &self.wake_unknown_handle),
            ("not_allowed", &self.wake_not_allowed),
        ] {
            out.push_str(&format!(
                "gateway_wake_total{{outcome=\"{outcome}\"}} {}\n",
                g(v)
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_exposition() {
        let m = Metrics::default();
        m.inc_register();
        m.inc_register();
        m.inc_provision_ok();
        m.inc_wake_delivered();
        m.inc_wake_not_allowed();

        let text = m.render();
        // Counters reflect the increments.
        assert!(text.contains("gateway_register_total 2\n"));
        assert!(text.contains("gateway_provision_total{outcome=\"ok\"} 1\n"));
        assert!(text.contains("gateway_wake_total{outcome=\"delivered\"} 1\n"));
        assert!(text.contains("gateway_wake_total{outcome=\"not_allowed\"} 1\n"));
        // Untouched series are still emitted at zero (scrapers expect them).
        assert!(text.contains("gateway_wake_total{outcome=\"transient_failure\"} 0\n"));
        // Each metric carries its HELP/TYPE preamble.
        assert!(text.contains("# TYPE gateway_wake_total counter\n"));
    }
}
