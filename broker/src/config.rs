//! What the broker runs with: phase 1's deadlines, and the hooks that only
//! a build with the `test-upstream` feature has, and only when its
//! environment asks for them.
//!
//! A release build uses [`Config::release`]: the deadlines of
//! `rusthorse::broker_protocol`, no extra trust, no loopback destination,
//! and the broker's own code reads no environment variable. What it is
//! built on reads a few of its own, all unset in the empty environment the
//! agent starts it with: tokio reads `TOKIO_UNSTABLE_SHARDED_BLOCKING_QUEUE`
//! when the runtime is built, and the C library's loader and DNS resolver
//! read theirs, such as `LD_*`, `GLIBC_TUNABLES`, `LOCALDOMAIN` and
//! `RES_OPTIONS`. std reads `RUST_MIN_STACK` only for a thread started
//! without a stack size, and the runtime gives its threads one; it reads
//! `RUST_BACKTRACE` only in its own panic hook, which the broker replaces.
//!
//! A build with `test-upstream` (for tests only, never in a release; a
//! build without debug assertions refuses it, and `--check` reports it)
//! looks at its environment once at startup ([`Config::load`]) and runs as
//! a release build unless `RUSTHORSE_BROKER_TEST_ROOTS` is set there. The
//! agent starts every broker with an empty environment: a build for tests
//! that a real agent starts trusts nothing more, reaches no loopback
//! destination and reads no other variable. Only with that variable set,
//! as the broker's own tests set it, does such a build read:
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
//!   `tls`, `response`, `pause`);
//! - `RUSTHORSE_BROKER_TEST_PANIC`: `request` makes handling a request
//!   panic, as an internal error would (for the test of the panic hook);
//!
//! and a destination may then be on loopback too (`127.0.0.0/8` and `::1`,
//! never another private address). A variable that does not parse stops
//! the broker before it answers.

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
    /// Whether handling a request panics (for the test of the panic hook).
    #[cfg(feature = "test-upstream")]
    pub panic_on_request: bool,
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
            #[cfg(feature = "test-upstream")]
            panic_on_request: false,
        }
    }

    /// The configuration of this build: [`Config::release`], without
    /// reading any environment variable.
    #[cfg(not(feature = "test-upstream"))]
    pub fn load() -> Result<Config, &'static str> {
        Ok(Config::release())
    }

    /// The configuration of this build, for tests only: see
    /// [`Config::from_test_variables`].
    #[cfg(feature = "test-upstream")]
    pub fn load() -> Result<Config, &'static str> {
        Config::from_test_variables(|name| std::env::var_os(name))
    }

    /// The configuration of a build for tests, from the environment
    /// variables `get` returns: [`Config::release`] unless
    /// `RUSTHORSE_BROKER_TEST_ROOTS` is set, which asks for test behaviour;
    /// with it, the release configuration with that authority trusted too,
    /// loopback destinations allowed and the other test variables applied.
    #[cfg(feature = "test-upstream")]
    fn from_test_variables(
        get: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<Config, &'static str> {
        let mut config = Config::release();
        // Nothing asks for test behaviour (the agent's empty environment):
        // a release build's configuration, and no other variable read.
        let Some(roots) = get("RUSTHORSE_BROKER_TEST_ROOTS") else {
            return Ok(config);
        };
        let text = |name: &str| -> Result<Option<String>, &'static str> {
            get(name)
                .map(|value| {
                    value
                        .into_string()
                        .map_err(|_| "a test variable is not text")
                })
                .transpose()
        };
        config.allow_loopback = true;
        config.extra_roots = Some(PathBuf::from(roots));
        if let Some(list) = text("RUSTHORSE_BROKER_TEST_ADDRESSES")? {
            config.addresses = Some(parse_addresses(&list)?);
        }
        if let Some(ms) = text("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS")? {
            config.resolve_delay = parse_ms(&ms)?;
        }
        if let Some(pairs) = text("RUSTHORSE_BROKER_TEST_TIMEOUTS")? {
            apply_timeouts(&mut config.limits, &pairs)?;
        }
        if let Some(when) = text("RUSTHORSE_BROKER_TEST_PANIC")? {
            if when != "request" {
                return Err("a test panic is not `request`");
            }
            config.panic_on_request = true;
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
        #[cfg(feature = "test-upstream")]
        assert!(!config.panic_on_request);
    }

    /// That the variables change nothing in such a build is shown end to
    /// end (tests/broker.rs starts it with them set).
    #[cfg(not(feature = "test-upstream"))]
    #[test]
    fn without_the_test_feature_the_configuration_is_the_release_one() {
        assert_eq!(Config::load(), Ok(Config::release()));
    }

    /// [`Config::from_test_variables`] with only these variables set.
    #[cfg(feature = "test-upstream")]
    fn with(set: &[(&str, &str)]) -> Result<Config, &'static str> {
        Config::from_test_variables(|name| {
            set.iter()
                .find(|(set, _)| *set == name)
                .map(|(_, value)| value.into())
        })
    }

    #[cfg(feature = "test-upstream")]
    #[test]
    fn a_test_build_runs_as_a_release_one_unless_its_environment_names_a_test_authority() {
        const ROOTS: (&str, &str) = ("RUSTHORSE_BROKER_TEST_ROOTS", "/nonexistent/roots.pem");
        // The agent's empty environment: a release build's configuration.
        assert_eq!(with(&[]), Ok(Config::release()));
        // Without the authority no other variable is read, not even one
        // that does not parse.
        let unparsable = [
            ("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS", "soon"),
            ("RUSTHORSE_BROKER_TEST_TIMEOUTS", "nap=1"),
            ("RUSTHORSE_BROKER_TEST_ADDRESSES", "localhost"),
            ("RUSTHORSE_BROKER_TEST_PANIC", "later"),
        ];
        let valid = [
            ("RUSTHORSE_BROKER_TEST_ADDRESSES", "127.0.0.1"),
            ("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS", "5"),
            ("RUSTHORSE_BROKER_TEST_TIMEOUTS", "body=500"),
            ("RUSTHORSE_BROKER_TEST_PANIC", "request"),
        ];
        assert_eq!(with(&unparsable), Ok(Config::release()));
        assert_eq!(with(&valid), Ok(Config::release()));
        // The authority alone: trusted, and loopback destinations allowed.
        assert_eq!(
            with(&[ROOTS]),
            Ok(Config {
                allow_loopback: true,
                extra_roots: Some(PathBuf::from(ROOTS.1)),
                ..Config::release()
            })
        );
        // With it, the other variables are read.
        let config = with(&[&[ROOTS][..], &valid[..]].concat()).expect("a test configuration");
        assert!(config.allow_loopback);
        assert_eq!(config.extra_roots, Some(PathBuf::from(ROOTS.1)));
        assert_eq!(
            config.addresses,
            Some(vec!["127.0.0.1".parse().expect("ip")])
        );
        assert_eq!(config.resolve_delay, Duration::from_millis(5));
        assert_eq!(config.limits.request_body, Duration::from_millis(500));
        assert!(config.panic_on_request);
        for (name, value) in unparsable {
            assert!(with(&[ROOTS, (name, value)]).is_err(), "{name}");
        }
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
