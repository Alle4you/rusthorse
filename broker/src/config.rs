//! What the broker runs with: phase 1's deadlines, and the hooks that only
//! a build with the `test-upstream` feature has.
//!
//! A release build uses [`Config::release`]: the deadlines of
//! `rusthorse::broker_protocol`, no extra trust, no loopback destination,
//! and it never reads its environment. A build with `test-upstream` (for
//! tests only, never in a release) reads `RUSTHORSE_BROKER_TEST_*` variables
//! once at startup ([`Config::load`]):
//!
//! - `RUSTHORSE_BROKER_TEST_ROOTS`: a PEM file of certificate authorities
//!   trusted besides the system's file;
//! - `RUSTHORSE_BROKER_TEST_ADDRESSES`: IP addresses, separated by commas,
//!   that a resolution returns instead of asking the system's resolver (they
//!   are checked like any resolved address);
//! - `RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS`: how long each resolution
//!   blocks first, as a resolver that hangs would;
//! - `RUSTHORSE_BROKER_TEST_TIMEOUTS`: shorter deadlines, as `name=ms` pairs
//!   separated by commas (`ready`, `header`, `idle`, `body`, `connect`,
//!   `tls`, `response`, `pause`).
//!
//! With the feature, a destination may also be on loopback (`127.0.0.0/8`
//! and `::1`, never another private address). A variable that does not
//! parse stops the broker before it answers.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use rusthorse::broker_protocol::{
    CONNECT_TIMEOUT, IDLE_CONNECTION_TIMEOUT, READY_TIMEOUT, REQUEST_BODY_TIMEOUT,
    REQUEST_HEADER_TIMEOUT, RESPONSE_BODY_IDLE_TIMEOUT, RESPONSE_HEADERS_TIMEOUT,
    TLS_HANDSHAKE_TIMEOUT,
};

/// The deadlines the broker keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// For the install to arrive whole.
    pub ready: Duration,
    /// For a request's head, from the connection's opening or the previous
    /// response on it.
    pub request_header: Duration,
    /// For a connection with no request in progress.
    pub idle_connection: Duration,
    /// For an admitted request's body to arrive whole.
    pub request_body: Duration,
    /// For resolving the destination and connecting to it, both together.
    pub connect: Duration,
    /// For the TLS handshake with the destination.
    pub tls_handshake: Duration,
    /// For the destination's response head.
    pub response_headers: Duration,
    /// For each pause in the response body, either way.
    pub response_body_idle: Duration,
}

impl Limits {
    /// Phase 1's deadlines (ADR 0013).
    pub const PHASE_1: Limits = Limits {
        ready: READY_TIMEOUT,
        request_header: REQUEST_HEADER_TIMEOUT,
        idle_connection: IDLE_CONNECTION_TIMEOUT,
        request_body: REQUEST_BODY_TIMEOUT,
        connect: CONNECT_TIMEOUT,
        tls_handshake: TLS_HANDSHAKE_TIMEOUT,
        response_headers: RESPONSE_HEADERS_TIMEOUT,
        response_body_idle: RESPONSE_BODY_IDLE_TIMEOUT,
    };
}

/// Everything the broker runs with besides the install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The deadlines.
    pub limits: Limits,
    /// Whether a destination may be on loopback (`127.0.0.0/8`, `::1`).
    pub allow_loopback: bool,
    /// A PEM file of certificate authorities trusted besides the system's.
    pub extra_roots: Option<PathBuf>,
    /// Addresses a resolution returns instead of asking the resolver.
    pub addresses: Option<Vec<IpAddr>>,
    /// How long each resolution blocks before it starts.
    pub resolve_delay: Duration,
}

impl Config {
    /// What a release build runs with.
    pub fn release() -> Config {
        Config {
            limits: Limits::PHASE_1,
            allow_loopback: false,
            extra_roots: None,
            addresses: None,
            resolve_delay: Duration::ZERO,
        }
    }

    /// The configuration of this build: [`Config::release`]; the
    /// environment is never read.
    #[cfg(not(feature = "test-upstream"))]
    pub fn load() -> Result<Config, &'static str> {
        Ok(Config::release())
    }

    /// The configuration of this build, for tests only: the release one,
    /// with loopback destinations allowed and the test variables applied.
    #[cfg(feature = "test-upstream")]
    pub fn load() -> Result<Config, &'static str> {
        let get = |name: &str| std::env::var_os(name);
        let text = |name: &str| -> Result<Option<String>, &'static str> {
            get(name)
                .map(|value| {
                    value
                        .into_string()
                        .map_err(|_| "a test variable is not text")
                })
                .transpose()
        };
        let mut config = Config::release();
        config.allow_loopback = true;
        config.extra_roots = get("RUSTHORSE_BROKER_TEST_ROOTS").map(PathBuf::from);
        if let Some(list) = text("RUSTHORSE_BROKER_TEST_ADDRESSES")? {
            config.addresses = Some(parse_addresses(&list)?);
        }
        if let Some(ms) = text("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS")? {
            config.resolve_delay = parse_ms(&ms)?;
        }
        if let Some(pairs) = text("RUSTHORSE_BROKER_TEST_TIMEOUTS")? {
            apply_timeouts(&mut config.limits, &pairs)?;
        }
        Ok(config)
    }
}

/// `ms` milliseconds, from decimal digits.
#[cfg_attr(not(feature = "test-upstream"), allow(dead_code))]
fn parse_ms(ms: &str) -> Result<Duration, &'static str> {
    ms.parse::<u64>()
        .map(Duration::from_millis)
        .map_err(|_| "a test duration is not a number of milliseconds")
}

/// IP addresses separated by commas; at least one.
#[cfg_attr(not(feature = "test-upstream"), allow(dead_code))]
fn parse_addresses(list: &str) -> Result<Vec<IpAddr>, &'static str> {
    let addresses = list
        .split(',')
        .map(|one| one.trim().parse::<IpAddr>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "a test address is not an IP address")?;
    if addresses.is_empty() {
        return Err("no test address");
    }
    Ok(addresses)
}

/// Apply `name=ms` pairs, separated by commas, to `limits`.
#[cfg_attr(not(feature = "test-upstream"), allow(dead_code))]
fn apply_timeouts(limits: &mut Limits, pairs: &str) -> Result<(), &'static str> {
    for pair in pairs.split(',').filter(|pair| !pair.is_empty()) {
        let (name, ms) = pair
            .split_once('=')
            .ok_or("a test timeout is not name=ms")?;
        let value = parse_ms(ms)?;
        let slot = match name {
            "ready" => &mut limits.ready,
            "header" => &mut limits.request_header,
            "idle" => &mut limits.idle_connection,
            "body" => &mut limits.request_body,
            "connect" => &mut limits.connect,
            "tls" => &mut limits.tls_handshake,
            "response" => &mut limits.response_headers,
            "pause" => &mut limits.response_body_idle,
            _ => return Err("an unknown test timeout"),
        };
        *slot = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_release_build_keeps_the_phase_1_deadlines_and_no_hooks() {
        let config = Config::release();
        assert_eq!(config.limits, Limits::PHASE_1);
        assert_eq!(config.limits.ready, Duration::from_secs(10));
        assert_eq!(config.limits.request_header, Duration::from_secs(30));
        assert_eq!(config.limits.idle_connection, Duration::from_secs(60));
        assert_eq!(config.limits.request_body, Duration::from_secs(60));
        assert_eq!(config.limits.connect, Duration::from_secs(10));
        assert_eq!(config.limits.tls_handshake, Duration::from_secs(10));
        assert_eq!(config.limits.response_headers, Duration::from_secs(600));
        assert_eq!(config.limits.response_body_idle, Duration::from_secs(300));
        assert!(!config.allow_loopback);
        assert_eq!(config.extra_roots, None);
        assert_eq!(config.addresses, None);
        assert_eq!(config.resolve_delay, Duration::ZERO);
    }

    /// That the variables change nothing in such a build is shown end to
    /// end (tests/broker.rs starts it with them set).
    #[cfg(not(feature = "test-upstream"))]
    #[test]
    fn without_the_test_feature_the_configuration_is_the_release_one() {
        assert_eq!(Config::load(), Ok(Config::release()));
    }

    #[test]
    fn test_variables_parse_strictly() {
        assert_eq!(parse_ms("250"), Ok(Duration::from_millis(250)));
        assert!(parse_ms("").is_err());
        assert!(parse_ms("1s").is_err());
        assert!(parse_ms("-1").is_err());
        assert_eq!(
            parse_addresses("10.0.0.1, ::1"),
            Ok(vec![
                "10.0.0.1".parse().expect("ip"),
                "::1".parse().expect("ip")
            ])
        );
        assert!(parse_addresses("").is_err());
        assert!(parse_addresses("localhost").is_err());
        let mut limits = Limits::PHASE_1;
        apply_timeouts(&mut limits, "header=100,pause=200,connect=300").expect("pairs");
        assert_eq!(limits.request_header, Duration::from_millis(100));
        assert_eq!(limits.response_body_idle, Duration::from_millis(200));
        assert_eq!(limits.connect, Duration::from_millis(300));
        assert_eq!(limits.ready, READY_TIMEOUT);
        assert!(apply_timeouts(&mut limits, "nap=1").is_err());
        assert!(apply_timeouts(&mut limits, "header").is_err());
        assert!(apply_timeouts(&mut limits, "header=x").is_err());
    }
}
