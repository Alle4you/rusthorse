//! What a grant of the credential broker carries besides its token and its
//! key ([ADR 0013](../docs/adr/0013-credential-broker.md), scope amendment):
//! the destination the human approved, the run's limits, and the rules that
//! the agent and `rusthorse-broker` both apply.
//!
//! There is no profile and no knowledge of any API. The agent names the
//! destination in the run (`--broker VAR=ENTRY@URL`), the human approves it
//! in the dialog, and the broker puts the key where the program put the
//! token. This module holds the pure rules shared by both sides: what a
//! destination may be ([`Destination`]), the limits of a run's grants
//! ([`GrantLimits`]), how a request's method is recorded ([`MethodLabel`]),
//! what looks like a token ([`token_shaped`]), and which values can be sent
//! as a key ([`is_valid_credential`]).

use std::fmt;
use std::ops::{Range, RangeInclusive};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::broker_protocol::{MAX_IN_FLIGHT, TOKEN_LEN, TOKEN_PREFIX};
use crate::util;

/// The lifetimes a run may give its grants, in minutes: up to a day.
pub const MAX_LIFETIME_MINUTES_RANGE: RangeInclusive<u32> = 1..=1440;

/// The lifetime a run's grants get when the run does not say: 12 hours.
pub const DEFAULT_LIFETIME_MINUTES: u32 = 720;

/// The request limits a run may set.
pub const MAX_REQUESTS_RANGE: RangeInclusive<u64> = 1..=1_000_000;

/// Shortest credential, in characters, that a broker presents to a
/// destination ([`is_valid_credential`]). It is above the length under which
/// the redactor ignores a secret ([`crate::redact::MIN_REDACT_LEN`]): the
/// redactor replaces literal copies of any credential the broker accepts.
pub const MIN_CREDENTIAL_CHARS: usize = 8;

/// Longest credential, in characters, that a broker presents to a
/// destination ([`is_valid_credential`]): it travels in a header.
pub const MAX_CREDENTIAL_CHARS: usize = 4096;

// A credential the broker accepts is never too short for the redactor.
const _: () = assert!(MIN_CREDENTIAL_CHARS >= crate::redact::MIN_REDACT_LEN);

/// Longest host name of an origin, as DNS allows.
const MAX_HOST_CHARS: usize = 253;
/// Longest label of a host name, as DNS allows.
const MAX_LABEL_CHARS: usize = 63;
/// Longest destination URL a run may name, in characters.
pub const MAX_DESTINATION_CHARS: usize = 1000;

/// Whether the automatic locks — the screen locking, the computer
/// suspending, the idle timeout — end a run's grants (ADR 0013, decision 8).
/// The explicit `rusthorse lock` ends every grant whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticLocks {
    /// They end the grants.
    End,
    /// They do not: the grants keep working while the screen is locked,
    /// even though the vault itself locks.
    Continue,
}

impl AutomaticLocks {
    /// Both policies.
    pub const ALL: [AutomaticLocks; 2] = [Self::End, Self::Continue];

    /// The serialized form: `end` or `continue`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::End => "end",
            Self::Continue => "continue",
        }
    }
}

impl fmt::Display for AutomaticLocks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AutomaticLocks {
    type Err = GrantError;

    /// The policy written exactly as [`AutomaticLocks::as_str`] writes it.
    fn from_str(text: &str) -> Result<Self, GrantError> {
        Self::ALL
            .into_iter()
            .find(|l| l.as_str() == text)
            .ok_or(GrantError::UnknownLocks)
    }
}

/// Why a destination or a run's limits are refused. The messages never
/// repeat what they refuse: a run's text comes from its requester.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// The destination is not `https://`, a host name with an optional
    /// port, and an optional base path.
    #[error("the destination is not valid: {0}")]
    Destination(&'static str),
    /// The base path of the destination is not `/` and segments.
    #[error("the destination's base path is not valid: {0}")]
    BasePath(&'static str),
    /// The lifetime is outside [`MAX_LIFETIME_MINUTES_RANGE`].
    #[error("the lifetime must be 1 to 1440 minutes, not {0}")]
    Lifetime(u32),
    /// The request limit is outside [`MAX_REQUESTS_RANGE`].
    #[error("the request limit must be 1 to 1000000, not {0}")]
    Requests(u64),
    /// A policy for the automatic locks other than `end` and `continue`.
    #[error("unknown policy for the automatic locks; use end or continue")]
    UnknownLocks,
}

/// The destination of a grant, as the run names it and the human approves
/// it: an HTTPS origin, and the base path of the program's base URL.
///
/// The approval covers the whole origin — scheme, host and port: the broker
/// sends the key to any path there. The base path only sets up the base URL
/// the program is given (`--url`); it limits nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    /// `https://` and a lowercase host name, with an optional port: no IP
    /// address, user information, path, query or fragment.
    pub origin: String,
    /// What the program's base URL adds after the origin: empty, or `/` and
    /// segments of letters, digits, `.`, `_`, `~` and `-`.
    pub base_path: String,
}

impl Destination {
    /// Read the destination a run names: `https://`, a lowercase host name
    /// with an optional port, and an optional base path, with no user
    /// information, query or fragment. A trailing `/` alone is no base path.
    pub fn parse(url: &str) -> Result<Destination, GrantError> {
        if url.chars().count() > MAX_DESTINATION_CHARS {
            return Err(GrantError::Destination("it is too long"));
        }
        let Some(rest) = url.strip_prefix("https://") else {
            return Err(GrantError::Destination("it must start with https://"));
        };
        let (authority, path) = match rest.find('/') {
            Some(slash) => rest.split_at(slash),
            None => (rest, ""),
        };
        let base_path = if path == "/" { "" } else { path };
        let destination = Destination {
            origin: format!("https://{authority}"),
            base_path: base_path.to_string(),
        };
        destination.validate()?;
        Ok(destination)
    }

    /// Check the origin and the base path.
    pub fn validate(&self) -> Result<(), GrantError> {
        check_origin(&self.origin)?;
        check_base_path(&self.base_path)
    }

    /// The origin without its scheme: the host, and the port if the origin
    /// names one. It is the `Host` header the broker sends.
    pub fn authority(&self) -> &str {
        self.origin.strip_prefix("https://").unwrap_or(&self.origin)
    }

    /// The origin's host name.
    pub fn host(&self) -> &str {
        let authority = self.authority();
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
    }

    /// The origin's port: the one it names, or 443. (Only a valid
    /// destination's port means anything: one that does not parse gives 443
    /// too.)
    pub fn port(&self) -> u16 {
        self.authority()
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or(443)
    }

    /// The origin and the base path, as the run named them
    /// (`https://api.openai.com/v1`).
    pub fn url(&self) -> String {
        format!("{}{}", self.origin, self.base_path)
    }

    /// The base URL a command gets for a broker listening on `port`:
    /// `http://127.0.0.1:PORT` and the base path — never `localhost`, which
    /// can resolve to an IPv6 address another program listens on.
    pub fn local_url(&self, port: u16) -> String {
        format!("http://127.0.0.1:{port}{}", self.base_path)
    }
}

/// The limits of a run's grants, which the run sets and the dialog shows:
/// the same for every grant of the run, each counted on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantLimits {
    /// Whether the automatic locks end the grants.
    pub automatic_locks: AutomaticLocks,
    /// The longest a grant lasts, in minutes ([`MAX_LIFETIME_MINUTES_RANGE`]).
    pub max_lifetime_minutes: u32,
    /// The most requests one grant admits ([`MAX_REQUESTS_RANGE`]); `None`
    /// for no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u64>,
}

impl Default for GrantLimits {
    /// No request limit, 12 hours, and grants that keep working through the
    /// automatic locks.
    fn default() -> Self {
        GrantLimits {
            automatic_locks: AutomaticLocks::Continue,
            max_lifetime_minutes: DEFAULT_LIFETIME_MINUTES,
            max_requests: None,
        }
    }
}

impl GrantLimits {
    /// Check the lifetime and the request limit.
    pub fn validate(&self) -> Result<(), GrantError> {
        if !MAX_LIFETIME_MINUTES_RANGE.contains(&self.max_lifetime_minutes) {
            return Err(GrantError::Lifetime(self.max_lifetime_minutes));
        }
        if let Some(limit) = self.max_requests
            && !MAX_REQUESTS_RANGE.contains(&limit)
        {
            return Err(GrantError::Requests(limit));
        }
        Ok(())
    }

    /// The longest a grant lasts.
    pub fn max_lifetime(&self) -> Duration {
        Duration::from_secs(u64::from(self.max_lifetime_minutes) * 60)
    }
}

/// What an approval dialog says of a grant, as label and value pairs: the
/// approved origin; the base path apart from it, which is not a limit; how
/// and when the grant ends; and its limits. The dialog's explanation says
/// that the key may be sent to any path at the approved origin
/// ([`REACHES`]).
pub fn describe(destination: &Destination, limits: &GrantLimits) -> Vec<(String, String)> {
    let lifetime = util::format_duration(limits.max_lifetime());
    let automatic = "screen lock, suspend or idle lock";
    let ends = format!(
        "with the command, on rusthorse lock, revocation or a change to the entry, or after \
         {lifetime}; {}",
        match limits.automatic_locks {
            AutomaticLocks::Continue => format!("not on {automatic}"),
            AutomaticLocks::End => format!("also on {automatic}"),
        }
    );
    let requests = match limits.max_requests {
        Some(limit) => format!("at most {limit}; at most {MAX_IN_FLIGHT} at a time"),
        None => format!("no limit; at most {MAX_IN_FLIGHT} at a time"),
    };
    let mut facts = vec![("Approved origin".to_string(), destination.origin.clone())];
    if !destination.base_path.is_empty() {
        facts.push((
            "Base path".into(),
            format!("{} (not a limit)", destination.base_path),
        ));
    }
    facts.extend([("Ends".into(), ends), ("Requests".into(), requests)]);
    facts
}

/// What an approval of grants covers, as its dialog says it after "requests
/// to the approved origin": the whole origin (ADR 0013, scope amendment).
pub const REACHES: &str = "at any path there: a base path is not a limit";

/// How the audit log and the control channel name a request's method: one
/// of the usual ones, or `OTHER`. Never the raw method, which a client
/// chooses (ADR 0013, scope amendment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MethodLabel {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
    /// Any other method the broker accepts.
    Other,
}

impl MethodLabel {
    /// The label of `method`, compared exactly (`post` is `OTHER`).
    pub fn of(method: &str) -> MethodLabel {
        match method {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            _ => Self::Other,
        }
    }

    /// The label as audit records write it: `GET`, …, `OTHER`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Other => "OTHER",
        }
    }
}

impl fmt::Display for MethodLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where `haystack` holds a token-shaped string: [`TOKEN_PREFIX`] and 64
/// hexadecimal digits, the prefix and the digits recognised without regard
/// to ASCII case, at any byte position, without word boundaries. Each range
/// covers the prefix and the 64 digits; ranges may overlap.
pub fn token_shaped(haystack: &[u8]) -> impl Iterator<Item = Range<usize>> + '_ {
    let prefix = TOKEN_PREFIX.as_bytes();
    (0..haystack.len().saturating_sub(TOKEN_LEN - 1)).filter_map(move |start| {
        let candidate = &haystack[start..start + TOKEN_LEN];
        (candidate[..prefix.len()].eq_ignore_ascii_case(prefix)
            && candidate[prefix.len()..].iter().all(u8::is_ascii_hexdigit))
        .then_some(start..start + TOKEN_LEN)
    })
}

/// Whether `a` and `b` are the same bytes, in a time that depends on their
/// lengths only: every byte is compared, whatever the first difference.
pub fn tokens_equal(a: &[u8], b: &[u8]) -> bool {
    let mut difference = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        difference |= usize::from(x ^ y);
    }
    std::hint::black_box(difference) == 0
}

/// Whether an entry's value can be used with the broker (ADR 0013):
/// [`MIN_CREDENTIAL_CHARS`] to [`MAX_CREDENTIAL_CHARS`] characters, all
/// visible ASCII (`!` to `~`): no spaces, line breaks or other control
/// characters, which could end or split the header it travels in. The
/// agent checks it before the approval dialog; a broker checks it again
/// ([`Install::validate`](crate::broker_protocol::Install::validate)).
pub fn is_valid_credential(value: &str) -> bool {
    // Visible ASCII only, so its length in bytes is its length in
    // characters.
    (MIN_CREDENTIAL_CHARS..=MAX_CREDENTIAL_CHARS).contains(&value.len())
        && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Whether `target` is a request target in origin form: it starts with `/`
/// (it is not `https://…`, `host:port` or `*`), and every byte is visible
/// ASCII (`0x21`–`0x7e`), as in any request target; the HTTP library
/// refuses most other bytes before this. The broker answers any other
/// target `400` while it checks the framing.
pub fn is_origin_form(target: &str) -> bool {
    target.starts_with('/') && target.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Check an origin: `https://` and a lowercase host name (not an IP address
/// in any form a resolver accepts), with an optional port, and nothing else.
pub fn check_origin(origin: &str) -> Result<(), GrantError> {
    let Some(rest) = origin.strip_prefix("https://") else {
        return Err(GrantError::Destination("it must start with https://"));
    };
    if rest.contains('@') {
        return Err(GrantError::Destination(
            "it must not contain user information",
        ));
    }
    if rest.contains('/') {
        return Err(GrantError::Destination(
            "the origin must not contain a path",
        ));
    }
    if rest.contains(['?', '#']) {
        return Err(GrantError::Destination(
            "it must not contain a query or a fragment",
        ));
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    check_host(host)?;
    if let Some(port) = port {
        let valid = !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|b| b.is_ascii_digit())
            && !port.starts_with('0')
            && port.parse::<u16>().is_ok();
        if !valid {
            return Err(GrantError::Destination(
                "the port must be a number from 1 to 65535",
            ));
        }
    }
    Ok(())
}

fn check_host(host: &str) -> Result<(), GrantError> {
    if host.is_empty() {
        return Err(GrantError::Destination("it must name a host"));
    }
    if host.starts_with('[') {
        return Err(GrantError::Destination(
            "it must name a host, not an IP address",
        ));
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(GrantError::Destination(
            "the host name must be in lowercase",
        ));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(GrantError::Destination(
            "the host name may only contain letters, digits, - and . (an international name in \
             its xn-- form)",
        ));
    }
    if host.len() > MAX_HOST_CHARS {
        return Err(GrantError::Destination("the host name is too long"));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(GrantError::Destination(
                "the host name must not have an empty label (two dots, or a dot at an end)",
            ));
        }
        if label.len() > MAX_LABEL_CHARS {
            return Err(GrantError::Destination(
                "a label of the host name is longer than 63 characters",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(GrantError::Destination(
                "a label of the host name must not start or end with -",
            ));
        }
    }
    // Top-level domains start with a letter. A last label that starts with
    // a digit is an IP address in some form a resolver accepts (`1.2.3.4`,
    // `2130706433`, `0x7f.1`).
    let last = host.rsplit('.').next().unwrap_or(host);
    if !last.starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err(GrantError::Destination(
            "it must name a host, not an IP address",
        ));
    }
    Ok(())
}

/// `base_path`: empty, or `/` and non-empty segments of letters, digits,
/// `.`, `_`, `~` and `-`, none made only of dots.
fn check_base_path(path: &str) -> Result<(), GrantError> {
    if path.is_empty() {
        return Ok(());
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err(GrantError::BasePath("it must be empty or start with /"));
    };
    for segment in rest.split('/') {
        if segment.is_empty() {
            return Err(GrantError::BasePath("it must not end with / or contain //"));
        }
        if segment.bytes().all(|b| b == b'.') {
            return Err(GrantError::BasePath("it must not contain . or .. segments"));
        }
        if !segment.bytes().all(is_unreserved) {
            return Err(GrantError::BasePath(
                "it may only contain letters, digits, ., _, ~, - and / (no query or fragment)",
            ));
        }
    }
    Ok(())
}

/// Letters, digits, `.`, `_`, `~` and `-`: the characters of a base path's
/// segments.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_destination_is_an_https_origin_and_an_optional_base_path() {
        let d = Destination::parse("https://api.openai.com/v1").expect("valid");
        assert_eq!(d.origin, "https://api.openai.com");
        assert_eq!(d.base_path, "/v1");
        assert_eq!(d.url(), "https://api.openai.com/v1");
        assert_eq!(d.authority(), "api.openai.com");
        assert_eq!(d.host(), "api.openai.com");
        assert_eq!(d.port(), 443);
        assert_eq!(d.local_url(4242), "http://127.0.0.1:4242/v1");
        let d = Destination::parse("https://api.example.com:8443").expect("valid");
        assert_eq!((d.base_path.as_str(), d.port()), ("", 8443));
        // A trailing slash alone is no base path.
        let d = Destination::parse("https://api.anthropic.com/").expect("valid");
        assert_eq!(d.base_path, "");
        assert_eq!(d.local_url(1), "http://127.0.0.1:1");
        for bad in [
            "http://api.anthropic.com",
            "api.anthropic.com",
            "https://API.anthropic.com",
            "https://user@api.anthropic.com",
            "https://api.anthropic.com?x=1",
            "https://api.anthropic.com/v1?x=1",
            "https://api.anthropic.com#x",
            "https://api.anthropic.com/v1/",
            "https://api.anthropic.com//v1",
            "https://api.anthropic.com/../v1",
            "https://api.anthropic.com/v%31",
            "https://1.2.3.4",
            "https://[::1]",
            "https://localhost:0",
            "https://a..b",
            "https://",
            "",
        ] {
            assert!(Destination::parse(bad).is_err(), "{bad}");
        }
        let long = format!("https://a.com/{}", "a".repeat(MAX_DESTINATION_CHARS));
        assert!(Destination::parse(&long).is_err());
    }

    #[test]
    fn limits_default_to_no_limit_12_hours_and_continue() {
        let limits = GrantLimits::default();
        assert_eq!(limits.max_requests, None);
        assert_eq!(limits.max_lifetime_minutes, 720);
        assert_eq!(limits.automatic_locks, AutomaticLocks::Continue);
        assert!(limits.validate().is_ok());
        for (lifetime, requests) in [
            (0, None),
            (1441, None),
            (60, Some(0)),
            (60, Some(1_000_001)),
        ] {
            let limits = GrantLimits {
                max_lifetime_minutes: lifetime,
                max_requests: requests,
                ..GrantLimits::default()
            };
            assert!(limits.validate().is_err(), "{limits:?}");
        }
        assert_eq!("end".parse::<AutomaticLocks>(), Ok(AutomaticLocks::End));
        assert!("End".parse::<AutomaticLocks>().is_err());
    }

    #[test]
    fn the_dialog_shows_the_origin_and_the_base_path_apart() {
        let d = Destination::parse("https://api.openai.com/v1").expect("valid");
        let facts = describe(&d, &GrantLimits::default());
        let keys: Vec<&str> = facts.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["Approved origin", "Base path", "Ends", "Requests"]);
        assert_eq!(facts[0].1, "https://api.openai.com");
        assert_eq!(facts[1].1, "/v1 (not a limit)");
        let d = Destination::parse("https://api.anthropic.com").expect("valid");
        let keys: Vec<String> = describe(&d, &GrantLimits::default())
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(!keys.iter().any(|k| k == "Base path"), "{keys:?}");
    }

    #[test]
    fn methods_are_recorded_by_label_only() {
        for (method, label) in [
            ("GET", "GET"),
            ("HEAD", "HEAD"),
            ("POST", "POST"),
            ("PUT", "PUT"),
            ("PATCH", "PATCH"),
            ("DELETE", "DELETE"),
            ("post", "OTHER"),
            ("PROPFIND", "OTHER"),
            ("rh_x", "OTHER"),
        ] {
            assert_eq!(MethodLabel::of(method).as_str(), label, "{method}");
        }
        assert_eq!(
            serde_json::to_value(MethodLabel::Other).expect("json"),
            "OTHER"
        );
    }

    #[test]
    fn token_shaped_strings_are_found_anywhere_in_any_case() {
        let token = format!("rh_{}", "ab".repeat(32));
        // Where each token-shaped string starts.
        let at = |haystack: &str| -> Vec<usize> {
            token_shaped(haystack.as_bytes())
                .map(|range: Range<usize>| {
                    assert_eq!(range.len(), TOKEN_LEN);
                    range.start
                })
                .collect()
        };
        assert_eq!(at(&token), [0]);
        assert_eq!(at(&format!("Bearer {token}")), [7]);
        assert_eq!(at(&format!("x{token}x")), [1]);
        assert_eq!(at(&token.to_uppercase()), [0]);
        assert_eq!(at(&format!("Rh_{}", "AB".repeat(32))), [0]);
        assert!(at(&token[..TOKEN_LEN - 1]).is_empty());
        assert!(at(&format!("rh_{}g{}", "a".repeat(10), "a".repeat(53))).is_empty());
        assert_eq!(at(&format!("{token},{token}")).len(), 2);
        assert!(at("").is_empty());
    }

    #[test]
    fn credentials_are_visible_ascii_of_8_to_4096_characters() {
        assert!(is_valid_credential("sk-12345"));
        assert!(!is_valid_credential("sk-1234"));
        assert!(!is_valid_credential("sk 12345"));
        assert!(!is_valid_credential("sk-1234\n"));
        assert!(!is_valid_credential(&"a".repeat(4097)));
        assert!(is_valid_credential(&"a".repeat(4096)));
        assert!(!is_valid_credential("sk-ç12345"));
    }

    #[test]
    fn tokens_are_compared_whole() {
        assert!(tokens_equal(b"abc", b"abc"));
        assert!(!tokens_equal(b"abc", b"abd"));
        assert!(!tokens_equal(b"abc", b"abcd"));
    }
}
