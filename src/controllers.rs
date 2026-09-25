//! Which controller VTAs this gateway serves (`GATEWAY_ALLOWED_CONTROLLERS`).
//!
//! `push/register` is anonymous and names its `controllerVtaDid`, so without a
//! list anyone can make a DID of their own the controller of a handle and then
//! send it correctly signed provisions. The list closes that: a registration
//! naming a controller not on it is refused, and so is a provision by one
//! (which covers handles loaded from a snapshot taken under a wider list).
//!
//! - **Unset or empty** — nothing is on the list, so every registration is
//!   refused. Secure by default: an operator lists the VTAs the gateway serves.
//! - **A comma- or whitespace-separated list of DIDs** — exact string match.
//!   No patterns: a DID-method or host pattern would admit every DID anyone can
//!   mint under that method or host, which is the property the list removes.
//! - **`*`** — open mode, for deliberate use only. Any controller may register;
//!   the startup log warns, and every other bound (per-controller handle cap,
//!   the replay record's per-issuer, per-handle and fair-share budgets) still
//!   applies.

use std::collections::HashSet;

/// Env var holding the controller allowlist.
pub const ENV_ALLOWED_CONTROLLERS: &str = "GATEWAY_ALLOWED_CONTROLLERS";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerPolicy {
    /// Only these controller DIDs (exact match). Empty admits no one.
    Listed(HashSet<String>),
    /// Any controller (`*`). Explicit opt-in only.
    Open,
}

impl Default for ControllerPolicy {
    /// The secure default: nobody is listed.
    fn default() -> Self {
        Self::Listed(HashSet::new())
    }
}

impl ControllerPolicy {
    /// Parse the env-var value. `None`/empty → nothing listed. `*` alone →
    /// open. Otherwise every entry must be a DID; `*` mixed with DIDs, or an
    /// entry that is not a DID, is an error rather than a guess.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        let entries: Vec<&str> = raw
            .unwrap_or("")
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|e| !e.is_empty())
            .collect();
        if entries == ["*"] {
            return Ok(Self::Open);
        }
        let mut set = HashSet::new();
        for e in entries {
            if e == "*" {
                return Err(format!(
                    "{ENV_ALLOWED_CONTROLLERS}: `*` must stand alone (open mode), not in a list"
                ));
            }
            if e.contains('*') {
                return Err(format!(
                    "{ENV_ALLOWED_CONTROLLERS}: `{e}` — patterns are not supported; list exact DIDs"
                ));
            }
            if !e.starts_with("did:") || e.contains('#') || e.len() > 512 {
                return Err(format!(
                    "{ENV_ALLOWED_CONTROLLERS}: `{e}` is not a controller DID"
                ));
            }
            set.insert(e.to_string());
        }
        Ok(Self::Listed(set))
    }

    /// Read [`ENV_ALLOWED_CONTROLLERS`].
    pub fn from_env() -> Result<Self, String> {
        Self::parse(std::env::var(ENV_ALLOWED_CONTROLLERS).ok().as_deref())
    }

    /// A policy listing exactly `dids`.
    pub fn listing<I: IntoIterator<Item = S>, S: Into<String>>(dids: I) -> Self {
        Self::Listed(dids.into_iter().map(Into::into).collect())
    }

    /// Whether `did` may control handles on this gateway.
    pub fn allows(&self, did: &str) -> bool {
        match self {
            Self::Open => true,
            Self::Listed(set) => set.contains(did),
        }
    }

    /// One line for the startup log.
    pub fn summary(&self) -> String {
        match self {
            Self::Open => "open (any controller)".into(),
            Self::Listed(set) => format!("{} listed", set.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_empty_lists_no_one() {
        for raw in [None, Some(""), Some("  , ")] {
            let p = ControllerPolicy::parse(raw).unwrap();
            assert!(!p.allows("did:web:vta.example"));
            assert_eq!(p, ControllerPolicy::default());
        }
    }

    #[test]
    fn a_list_matches_exactly() {
        let p = ControllerPolicy::parse(Some(
            "did:web:a.example, did:webvh:scid:b.example\ndid:key:zC",
        ))
        .unwrap();
        assert!(p.allows("did:web:a.example"));
        assert!(p.allows("did:key:zC"));
        assert!(!p.allows("did:web:a.example:sub"));
        assert!(!p.allows("did:web:A.example"));
    }

    #[test]
    fn star_alone_is_open_and_nowhere_else() {
        assert_eq!(
            ControllerPolicy::parse(Some(" * ")).unwrap(),
            ControllerPolicy::Open
        );
        assert!(ControllerPolicy::parse(Some("*, did:web:a.example")).is_err());
        assert!(
            ControllerPolicy::parse(Some("did:web:*")).is_err(),
            "no patterns"
        );
    }

    #[test]
    fn a_non_did_entry_is_refused() {
        assert!(ControllerPolicy::parse(Some("vta.example")).is_err());
        assert!(ControllerPolicy::parse(Some("did:web:a.example#key-1")).is_err());
    }
}
