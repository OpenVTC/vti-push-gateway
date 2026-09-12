//! Outbound (egress) policy for push delivery.
//!
//! A Web Push subscription names its own delivery URL, and `push/register` is
//! unauthenticated, so the endpoint is caller-controlled input that the gateway
//! later dials. This module is the single place that decides what the gateway
//! is willing to connect to:
//!
//! - [`EgressPolicy::validate_webpush_endpoint`] — `https` only, default port,
//!   no userinfo, no fragment, no IP-literal host, bounded length, and the host
//!   must match the Web Push service allow-list (exact or label-boundary
//!   `*.suffix`). Checked at `push/register` and again right before a send.
//! - [`is_public_ip`] — classifies an address as publicly routable. Loopback,
//!   private, link-local (cloud metadata), CGNAT, documentation, multicast,
//!   reserved and the IPv6 forms that embed one of those are all refused.
//! - [`GuardedResolver`] — a `reqwest` DNS resolver that fails closed when a
//!   name resolves to any non-public address. The connector dials exactly the
//!   addresses returned here, so there is no second, unchecked lookup (DNS
//!   rebinding).
//! - [`hardened_client_builder`] — the one `reqwest` client configuration every
//!   push sender uses: no redirects, no proxies, https only, the guarded
//!   resolver, and connect/total timeouts.
//!
//! The policy also carries the optional APNs topic allow-list, since the topic
//! is forwarded to Apple as a request header.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use url::{Host, Url};

/// Upper bound on a Web Push endpoint URL, in bytes.
pub const MAX_ENDPOINT_LEN: usize = 2048;

/// Env var overriding the Web Push host allow-list (comma-separated; `@default`
/// expands to [`DEFAULT_WEBPUSH_HOSTS`]).
pub const ENV_WEBPUSH_ALLOWED_HOSTS: &str = "GATEWAY_WEBPUSH_ALLOWED_HOSTS";

/// Env var listing the APNs topics (bundle ids) registrations may name.
pub const ENV_APNS_TOPICS: &str = "GATEWAY_APNS_TOPICS";

/// Token in [`ENV_WEBPUSH_ALLOWED_HOSTS`] that expands to the built-in list.
pub const DEFAULT_HOSTS_TOKEN: &str = "@default";

/// Built-in Web Push service hosts: Chrome/Chromium (FCM), Firefox (autopush),
/// Safari (Apple Web Push) and Edge (WNS). `*.` entries match at a label
/// boundary only, so `*.notify.windows.com` does not match
/// `evilnotify.windows.com`.
pub const DEFAULT_WEBPUSH_HOSTS: &[&str] = &[
    "fcm.googleapis.com",
    "updates.push.services.mozilla.com",
    "web.push.apple.com",
    "*.notify.windows.com",
];

/// TCP connect timeout for push-service requests.
pub const PUSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Total (connect + request + response body) timeout for push-service requests.
pub const PUSH_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle keep-alive for pooled push-service connections (APNs reuses HTTP/2).
const PUSH_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Why a Web Push endpoint was refused. Messages are deliberately generic —
/// they describe the policy, never the resolved target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EgressError {
    #[error("endpoint exceeds {MAX_ENDPOINT_LEN} bytes")]
    TooLong,
    #[error("endpoint is not a valid absolute URL")]
    Unparseable,
    #[error("endpoint must use https")]
    NotHttps,
    #[error("endpoint must not carry userinfo")]
    UserInfo,
    #[error("endpoint must use the default https port")]
    Port,
    #[error("endpoint must not carry a fragment")]
    Fragment,
    #[error("endpoint host must be a DNS name, not an IP address")]
    IpLiteral,
    #[error("endpoint host is not an allowed push service")]
    HostNotAllowed,
}

/// One entry of the Web Push host allow-list.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum HostRule {
    /// Matches this host exactly.
    Exact(String),
    /// Matches any host ending in this suffix, which always starts with `.`
    /// (so the match is on a label boundary). Written `*.example.org`.
    Subdomain(String),
}

impl HostRule {
    fn parse(entry: &str) -> Result<Self, String> {
        let entry = entry.to_ascii_lowercase();
        if let Some(base) = entry.strip_prefix("*.") {
            validate_dns_name(base).map_err(|e| format!("`{entry}`: {e}"))?;
            // Without a public-suffix list, require at least three labels in
            // the wildcard base: that refuses `*.com`, `*.co.uk` and
            // registrable-domain wildcards such as `*.googleapis.com`.
            if base.split('.').count() < 3 {
                return Err(format!(
                    "`{entry}` is too broad: a wildcard must sit below a registrable \
                     domain (e.g. `*.push.example.org`)"
                ));
            }
            return Ok(HostRule::Subdomain(format!(".{base}")));
        }
        if entry.contains('*') {
            return Err(format!(
                "`{entry}`: only a leading `*.` wildcard is supported"
            ));
        }
        validate_dns_name(&entry).map_err(|e| format!("`{entry}`: {e}"))?;
        Ok(HostRule::Exact(entry))
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            HostRule::Exact(h) => host == h,
            HostRule::Subdomain(suffix) => host.len() > suffix.len() && host.ends_with(suffix),
        }
    }
}

impl fmt::Display for HostRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostRule::Exact(h) => f.write_str(h),
            HostRule::Subdomain(suffix) => write!(f, "*{suffix}"),
        }
    }
}

/// A lowercase DNS hostname: 1–253 bytes, labels of 1–63 `[a-z0-9-]` not
/// starting or ending with `-`, no trailing dot, and a non-numeric final label
/// (so nothing here can be read as an IPv4 address).
fn validate_dns_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 253 {
        return Err("host name must be 1-253 bytes");
    }
    if name.parse::<IpAddr>().is_ok() {
        return Err("IP addresses are not allowed; use a host name");
    }
    let mut last = "";
    for label in name.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err("not a valid host name");
        }
        last = label;
    }
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Err("not a valid host name");
    }
    Ok(())
}

/// What the gateway is willing to send push traffic to.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    webpush_hosts: Vec<HostRule>,
    /// `None` = not configured (not enforced).
    apns_topics: Option<BTreeSet<String>>,
    /// Test-only: permit plain `http` to, and resolution of, loopback
    /// addresses so senders can be exercised against a local server. Only the
    /// `#[cfg(test)]` constructor sets it.
    allow_loopback: bool,
}

impl Default for EgressPolicy {
    /// The built-in Web Push hosts and no APNs topic restriction.
    fn default() -> Self {
        Self {
            webpush_hosts: default_rules(),
            apns_topics: None,
            allow_loopback: false,
        }
    }
}

fn default_rules() -> Vec<HostRule> {
    DEFAULT_WEBPUSH_HOSTS
        .iter()
        .map(|h| HostRule::parse(h).expect("built-in Web Push host is valid"))
        .collect()
}

impl EgressPolicy {
    /// Build a policy from raw configuration values.
    ///
    /// - `webpush_hosts`: comma-separated hosts / `*.suffix` wildcards;
    ///   `@default` expands to the built-ins. `None` means the built-ins.
    /// - `apns_topics`: comma-separated allowed APNs topics. `None` (or an empty
    ///   value) means topics are not restricted.
    ///
    /// Errors on an invalid or over-broad host entry, or an empty host list, so
    /// a misconfiguration stops the gateway at startup.
    pub fn from_config(
        webpush_hosts: Option<&str>,
        apns_topics: Option<&str>,
    ) -> Result<Self, String> {
        let webpush_hosts = match webpush_hosts {
            None => default_rules(),
            Some(spec) => {
                let mut rules = BTreeSet::new();
                for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                    if entry == DEFAULT_HOSTS_TOKEN {
                        rules.extend(default_rules());
                    } else {
                        rules.insert(
                            HostRule::parse(entry)
                                .map_err(|e| format!("{ENV_WEBPUSH_ALLOWED_HOSTS}: {e}"))?,
                        );
                    }
                }
                if rules.is_empty() {
                    return Err(format!(
                        "{ENV_WEBPUSH_ALLOWED_HOSTS} is set but lists no hosts \
                         (use `{DEFAULT_HOSTS_TOKEN}` for the built-in push services)"
                    ));
                }
                rules.into_iter().collect()
            }
        };
        let apns_topics = apns_topics
            .map(|spec| {
                spec.split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            })
            .filter(|set| !set.is_empty());
        Ok(Self {
            webpush_hosts,
            apns_topics,
            allow_loopback: false,
        })
    }

    /// Build the policy from [`ENV_WEBPUSH_ALLOWED_HOSTS`] and
    /// [`ENV_APNS_TOPICS`].
    pub fn from_env() -> Result<Self, String> {
        let hosts = std::env::var(ENV_WEBPUSH_ALLOWED_HOSTS).ok();
        let topics = std::env::var(ENV_APNS_TOPICS).ok();
        Self::from_config(hosts.as_deref(), topics.as_deref())
    }

    /// Test-only policy: built-in hosts, plus plain `http` to loopback
    /// addresses, so a sender can be pointed at a local server.
    #[cfg(test)]
    pub(crate) fn for_loopback_tests() -> Self {
        Self {
            allow_loopback: true,
            ..Self::default()
        }
    }

    /// The effective Web Push host allow-list, for logging.
    pub fn webpush_hosts(&self) -> Vec<String> {
        self.webpush_hosts.iter().map(ToString::to_string).collect()
    }

    /// The configured APNs topic allow-list (`None` = not enforced).
    pub fn apns_topics(&self) -> Option<&BTreeSet<String>> {
        self.apns_topics.as_ref()
    }

    /// Whether a registration may name this APNs topic.
    pub fn apns_topic_allowed(&self, topic: &str) -> bool {
        self.apns_topics.as_ref().is_none_or(|t| t.contains(topic))
    }

    pub(crate) fn allows_loopback(&self) -> bool {
        self.allow_loopback
    }

    /// Validate a Web Push endpoint and return the parsed URL. Callers must use
    /// the returned URL (not re-parse the raw string) so the checked value and
    /// the dialled value cannot diverge.
    pub fn validate_webpush_endpoint(&self, raw: &str) -> Result<Url, EgressError> {
        if raw.len() > MAX_ENDPOINT_LEN {
            return Err(EgressError::TooLong);
        }
        let url = Url::parse(raw).map_err(|_| EgressError::Unparseable)?;
        // `Url::host` has already normalised numeric forms such as
        // `0x7f000001` or `127.1` into an IPv4 host, so they land in the
        // IP-literal arms below.
        let loopback_ok = self.allow_loopback
            && match url.host() {
                Some(Host::Ipv4(a)) => a.is_loopback(),
                Some(Host::Ipv6(a)) => a.is_loopback(),
                _ => false,
            };
        match url.scheme() {
            "https" => {}
            "http" if loopback_ok => {}
            _ => return Err(EgressError::NotHttps),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EgressError::UserInfo);
        }
        if url.fragment().is_some() {
            return Err(EgressError::Fragment);
        }
        // `Url::port` is `None` when absent or equal to the scheme default, so
        // an explicit `:443` is accepted.
        if url.port().is_some() && !loopback_ok {
            return Err(EgressError::Port);
        }
        match url.host() {
            Some(Host::Domain(host)) => {
                if self.webpush_hosts.iter().any(|r| r.matches(host)) {
                    Ok(url)
                } else {
                    Err(EgressError::HostNotAllowed)
                }
            }
            Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) if loopback_ok => Ok(url),
            Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => Err(EgressError::IpLiteral),
            None => Err(EgressError::Unparseable),
        }
    }
}

/// Whether `ip` is a publicly routable unicast address the gateway may connect
/// to. Everything special-purpose is refused, including IPv6 forms that embed
/// an IPv4 destination (mapped, compatible, NAT64, 6to4), which are classified
/// by that embedded address.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => is_public_ipv4(a),
        IpAddr::V6(a) => is_public_ipv6(a),
    }
}

fn is_public_ipv4(a: Ipv4Addr) -> bool {
    let [o0, o1, o2, _] = a.octets();
    let blocked = o0 == 0 // 0.0.0.0/8 "this network"
        || o0 == 10 // 10.0.0.0/8
        || (o0 == 100 && (64..128).contains(&o1)) // 100.64.0.0/10 CGNAT
        || o0 == 127 // 127.0.0.0/8 loopback
        || (o0 == 169 && o1 == 254) // 169.254.0.0/16 link-local, cloud metadata
        || (o0 == 172 && (16..32).contains(&o1)) // 172.16.0.0/12
        || (o0 == 192 && o1 == 0 && o2 == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o0 == 192 && o1 == 0 && o2 == 2) // 192.0.2.0/24 TEST-NET-1
        || (o0 == 192 && o1 == 88 && o2 == 99) // 192.88.99.0/24 6to4 relay anycast
        || (o0 == 192 && o1 == 168) // 192.168.0.0/16
        || (o0 == 198 && (o1 & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || (o0 == 198 && o1 == 51 && o2 == 100) // 198.51.100.0/24 TEST-NET-2
        || (o0 == 203 && o1 == 0 && o2 == 113) // 203.0.113.0/24 TEST-NET-3
        || o0 >= 224; // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved + broadcast
    !blocked
}

fn is_public_ipv6(a: Ipv6Addr) -> bool {
    if a.is_unspecified() || a.is_loopback() {
        return false;
    }
    // IPv4-mapped (::ffff:a.b.c.d) and deprecated IPv4-compatible (::a.b.c.d):
    // `to_ipv4` covers both.
    if let Some(v4) = a.to_ipv4() {
        return is_public_ipv4(v4);
    }
    let s = a.segments();
    // NAT64 well-known prefix 64:ff9b::/96 embeds the IPv4 destination.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return is_public_ipv4(Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7])));
    }
    // 6to4 2002::/16 embeds the IPv4 address in segments 1-2.
    if s[0] == 0x2002 {
        return is_public_ipv4(Ipv4Addr::from((u32::from(s[1]) << 16) | u32::from(s[2])));
    }
    let blocked = (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // 64:ff9b:1::/48 local-use NAT64
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0]) // 100::/64 discard-only
        || (s[0] == 0x2001 && s[1] < 0x0200) // 2001::/23 IETF protocol assignments (incl. Teredo)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        || (s[0] == 0x3fff && s[1] < 0x1000) // 3fff::/20 documentation
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local (incl. fd00:ec2::254)
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 deprecated site-local
        || (s[0] & 0xff00) == 0xff00; // ff00::/8 multicast
    !blocked
}

/// Raised by [`GuardedResolver`] when a name has no usable public address.
#[derive(Debug)]
pub struct BlockedAddress {
    host: String,
}

impl fmt::Display for BlockedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "egress blocked: {} has a non-public address", self.host)
    }
}

impl std::error::Error for BlockedAddress {}

/// DNS resolver for push clients that refuses to return a non-public address.
///
/// Fails closed on the whole name when *any* answer is non-public, so a
/// dual-stack or round-robin answer cannot smuggle an internal address past
/// happy-eyeballs. IP-literal URLs never reach a resolver (the connector dials
/// them directly), which is why [`EgressPolicy::validate_webpush_endpoint`]
/// refuses them.
#[derive(Debug, Clone, Copy, Default)]
pub struct GuardedResolver {
    allow_loopback: bool,
}

impl GuardedResolver {
    /// A resolver that accepts only public addresses.
    pub fn new() -> Self {
        Self::default()
    }

    fn for_policy(policy: &EgressPolicy) -> Self {
        Self {
            allow_loopback: policy.allows_loopback(),
        }
    }
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let allow_loopback = self.allow_loopback;
        Box::pin(async move {
            // Port 0: reqwest substitutes the URL's port or the scheme default.
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let acceptable = |ip: IpAddr| is_public_ip(ip) || (allow_loopback && ip.is_loopback());
            if addrs.is_empty() || addrs.iter().any(|a| !acceptable(a.ip())) {
                return Err(
                    Box::new(BlockedAddress { host }) as Box<dyn std::error::Error + Send + Sync>
                );
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The client configuration shared by every push sender: redirects disabled
/// (a 3xx is reported as a failed send), system/env proxies ignored (a proxy
/// would bypass the resolver), https only, the [`GuardedResolver`], and
/// bounded connect/total time.
pub fn hardened_client_builder(policy: &EgressPolicy) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(!policy.allows_loopback())
        .dns_resolver(GuardedResolver::for_policy(policy))
        .connect_timeout(PUSH_CONNECT_TIMEOUT)
        .timeout(PUSH_REQUEST_TIMEOUT)
        .pool_idle_timeout(PUSH_POOL_IDLE_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn webpush_endpoint_rejections() {
        let policy = EgressPolicy::default();
        let long = format!(
            "https://fcm.googleapis.com/{}",
            "a".repeat(MAX_ENDPOINT_LEN)
        );
        let cases: &[(&str, EgressError)] = &[
            (
                "http://127.0.0.1:9099/latest/meta-data/iam/security-credentials/",
                EgressError::NotHttps,
            ),
            ("https://127.0.0.1/", EgressError::IpLiteral),
            ("https://[::1]/", EgressError::IpLiteral),
            ("https://169.254.169.254/", EgressError::IpLiteral),
            ("https://0x7f000001/", EgressError::IpLiteral),
            ("https://127.1/", EgressError::IpLiteral),
            ("https://[::ffff:169.254.169.254]/", EgressError::IpLiteral),
            (
                "https://fcm.googleapis.com.evil.test/",
                EgressError::HostNotAllowed,
            ),
            (
                "https://evilnotify.windows.com/",
                EgressError::HostNotAllowed,
            ),
            ("https://notify.windows.com/", EgressError::HostNotAllowed),
            ("https://fcm.googleapis.com./x", EgressError::HostNotAllowed),
            (
                "https://android.googleapis.com/gcm/send/x",
                EgressError::HostNotAllowed,
            ),
            (
                "https://api.push.apple.com/3/device/x",
                EgressError::HostNotAllowed,
            ),
            ("https://localhost/", EgressError::HostNotAllowed),
            ("https://u@fcm.googleapis.com/", EgressError::UserInfo),
            ("https://u:p@fcm.googleapis.com/", EgressError::UserInfo),
            ("https://fcm.googleapis.com:8443/", EgressError::Port),
            ("https://fcm.googleapis.com:80/", EgressError::Port),
            (
                "http://fcm.googleapis.com/fcm/send/x",
                EgressError::NotHttps,
            ),
            ("ftp://fcm.googleapis.com/x", EgressError::NotHttps),
            ("https://fcm.googleapis.com/x#frag", EgressError::Fragment),
            ("fcm.googleapis.com/fcm/send/x", EgressError::Unparseable),
            ("", EgressError::Unparseable),
            (long.as_str(), EgressError::TooLong),
        ];
        for (raw, want) in cases {
            assert_eq!(
                policy.validate_webpush_endpoint(raw).err(),
                Some(*want),
                "{raw}"
            );
        }
    }

    #[test]
    fn webpush_endpoint_acceptances() {
        let policy = EgressPolicy::default();
        for raw in [
            "https://fcm.googleapis.com/fcm/send/x",
            "https://fcm.googleapis.com:443/fcm/send/x",
            "https://FCM.googleapis.com/fcm/send/x",
            "https://updates.push.services.mozilla.com/wpush/v2/x",
            "https://web.push.apple.com/QASECRET-example",
            "https://wns2-par02p.notify.windows.com/w/?token=x",
        ] {
            let url = policy
                .validate_webpush_endpoint(raw)
                .unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(url.scheme(), "https");
        }
    }

    #[test]
    fn loopback_is_only_allowed_by_the_test_policy() {
        let prod = EgressPolicy::default();
        let test = EgressPolicy::for_loopback_tests();
        let raw = "http://127.0.0.1:9099/sub";
        assert!(prod.validate_webpush_endpoint(raw).is_err());
        assert!(test.validate_webpush_endpoint(raw).is_ok());
        // Non-loopback literals stay refused even in the test policy.
        assert!(test.validate_webpush_endpoint("http://10.0.0.1/").is_err());
        assert!(test
            .validate_webpush_endpoint("https://169.254.169.254/")
            .is_err());
    }

    #[test]
    fn is_public_ip_table() {
        let blocked = [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.100.100.200",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "2002:a9fe:a9fe::",
            "2002:7f00:1::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "3fff::1",
            "fc00::1",
            "fd00:ec2::254",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ];
        for ip in blocked {
            assert!(
                !is_public_ip(ip.parse().unwrap()),
                "{ip} must be non-public"
            );
        }
        let public = [
            "8.8.8.8",
            "142.250.72.10",
            "172.32.0.1",
            "100.128.0.1",
            "198.20.0.1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "2001:4860:4860::8888",
            "2607:f8b0:4005:80a::200a",
        ];
        for ip in public {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip} must be public");
        }
    }

    #[test]
    fn host_list_config() {
        // Unset → built-ins.
        let p = EgressPolicy::from_config(None, None).unwrap();
        assert_eq!(p.webpush_hosts().len(), DEFAULT_WEBPUSH_HOSTS.len());

        // @default plus operator additions; wildcard matches on a label boundary.
        let p = EgressPolicy::from_config(
            Some(" @default , push.example.org, *.up.example.net "),
            None,
        )
        .unwrap();
        let hosts = p.webpush_hosts();
        assert!(hosts.contains(&"fcm.googleapis.com".to_string()));
        assert!(hosts.contains(&"*.up.example.net".to_string()));
        assert!(p
            .validate_webpush_endpoint("https://push.example.org/x")
            .is_ok());
        assert!(p
            .validate_webpush_endpoint("https://a.up.example.net/x")
            .is_ok());
        assert!(p
            .validate_webpush_endpoint("https://up.example.net/x")
            .is_err());
        assert!(p
            .validate_webpush_endpoint("https://aup.example.net/x")
            .is_err());

        // Without @default the built-ins are not included.
        let p = EgressPolicy::from_config(Some("push.example.org"), None).unwrap();
        assert!(p
            .validate_webpush_endpoint("https://fcm.googleapis.com/x")
            .is_err());

        for bad in [
            "*.com",
            "*.googleapis.com",
            "*.co.uk",
            "*",
            "fcm.*",
            "a.*.example.org",
            "127.0.0.1",
            "[::1]",
            "https://fcm.googleapis.com",
            "fcm.googleapis.com:443",
            "bad_host.example",
            "",
            " , ",
        ] {
            assert!(
                EgressPolicy::from_config(Some(bad), None).is_err(),
                "`{bad}` must be refused"
            );
        }
    }

    #[test]
    fn apns_topic_config() {
        let open = EgressPolicy::from_config(None, None).unwrap();
        assert!(open.apns_topics().is_none());
        assert!(open.apns_topic_allowed("anything"));

        let empty = EgressPolicy::from_config(None, Some(" ")).unwrap();
        assert!(empty.apns_topics().is_none());

        let p =
            EgressPolicy::from_config(None, Some("org.openvtc.app, org.openvtc.app.voip")).unwrap();
        assert!(p.apns_topic_allowed("org.openvtc.app"));
        assert!(p.apns_topic_allowed("org.openvtc.app.voip"));
        assert!(!p.apns_topic_allowed("org.evil.app"));
    }

    #[tokio::test]
    async fn guarded_resolver_refuses_loopback_names() {
        use reqwest::dns::{Name, Resolve};
        let name = || Name::from_str("localhost").unwrap();
        assert!(GuardedResolver::new().resolve(name()).await.is_err());
        let addrs: Vec<SocketAddr> =
            GuardedResolver::for_policy(&EgressPolicy::for_loopback_tests())
                .resolve(name())
                .await
                .expect("test policy resolves localhost")
                .collect();
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }

    #[tokio::test]
    async fn hardened_client_refuses_plain_http() {
        let client = hardened_client_builder(&EgressPolicy::default())
            .build()
            .unwrap();
        let err = client
            .get("http://fcm.googleapis.com/")
            .send()
            .await
            .expect_err("https_only must refuse http");
        assert!(err.is_builder(), "{err:?}");
    }

    /// DNS rebinding, end to end through the client every sender uses: a *name*
    /// — not an IP literal, which [`EgressPolicy::validate_webpush_endpoint`]
    /// already refuses — that resolves to a non-public address must be refused
    /// **before** a socket is opened.
    ///
    /// `guarded_resolver_refuses_loopback_names` checks the resolver on its own.
    /// This checks that [`hardened_client_builder`] actually installs it, that
    /// the refusal is the resolver's rather than an incidental TLS or
    /// connection-refused failure, and that it lands before the dial — a live
    /// listener is the only witness that can tell "refused" from "tried and
    /// failed".
    ///
    /// `localhost` is the entire vector set here on purpose. This gate binds a
    /// real socket, so reverting the guard to watch it go red must dial
    /// 127.0.0.1 and nothing else; the link-local (cloud-metadata) and
    /// private-range hosts the PoC also aimed at are gated by
    /// `is_public_ip_table`, which opens no socket at all.
    #[tokio::test]
    async fn hardened_client_refuses_a_name_that_resolves_to_loopback() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Instant;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(sock);
            }
        });

        let client = hardened_client_builder(&EgressPolicy::default())
            .build()
            .unwrap();
        let started = Instant::now();
        let err = client
            .get(format!("https://localhost:{port}/sub"))
            .send()
            .await
            .expect_err("a name resolving to loopback must be refused");
        let elapsed = started.elapsed();

        // Walk the source chain: the refusal must be `BlockedAddress`, not
        // something that merely looks like it from the outside.
        let mut chain = err.to_string();
        let mut source: Option<&(dyn std::error::Error + 'static)> =
            std::error::Error::source(&err);
        while let Some(e) = source {
            chain.push_str(" / ");
            chain.push_str(&e.to_string());
            source = e.source();
        }
        assert!(
            chain.contains("non-public address"),
            "the guarded resolver must be what refused: {chain}"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "the refusal must precede the dial"
        );
        assert!(
            elapsed < PUSH_CONNECT_TIMEOUT,
            "a refusal is a lookup, not a connect attempt: took {elapsed:?}"
        );
    }
}
