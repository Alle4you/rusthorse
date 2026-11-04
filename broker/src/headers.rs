//! Which headers cross the broker, each way, and the checks of the
//! destination's response head before anything of it reaches the client
//! (ADR 0013, scope amendment).
//!
//! Requests: every header of the client is forwarded but the hop-by-hop
//! ones (`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`,
//! `Upgrade` and every `Proxy-*`) and `Host`, `Content-Length` and
//! `Accept-Encoding`, which the broker sets itself ([`own`]); the token in
//! the forwarded values is replaced with the key (`token`).
//!
//! Responses: every header of the destination is relayed but the hop-by-hop
//! ones, `Content-Length` and `Transfer-Encoding` — the broker frames the
//! body itself, chunked where HTTP allows a body, since redaction changes
//! its length — and any header whose name or value carries the key
//! (ignoring ASCII case) or a token-shaped string (`rh_` and 64 hexadecimal
//! digits, in any case: the grant's token, or any other).

use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use rusthorse::broker_grant::token_shaped;

use crate::answer::Refusal;

/// Whether `name` (lowercase, as the HTTP library gives it) is a hop-by-hop
/// header: `Connection`, `Keep-Alive`, `TE`, `Trailer`,
/// `Transfer-Encoding`, `Upgrade`, or any `Proxy-*`.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "te" | "trailer" | "transfer-encoding" | "upgrade"
    ) || name.starts_with("proxy-")
}

/// Whether the broker forwards the client's header `name`: every one but the
/// hop-by-hop ones and those the broker sets itself (`Host`,
/// `Content-Length`, `Accept-Encoding`). A token in any other header is
/// refused (`token::check`).
pub fn forwards(name: &HeaderName) -> bool {
    let name = name.as_str();
    !is_hop_by_hop(name) && !matches!(name, "host" | "content-length" | "accept-encoding")
}

/// The headers the broker sets itself on every request it sends: `Host`,
/// the approved origin's authority; `Accept-Encoding: identity`; and
/// `Content-Length` when the client declared one (`content_length`, the
/// length of the body the broker read).
pub fn own(authority: &HeaderValue, content_length: Option<u64>) -> HeaderMap {
    let mut own = HeaderMap::new();
    own.insert(HOST, authority.clone());
    own.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    if let Some(length) = content_length {
        own.insert(CONTENT_LENGTH, HeaderValue::from(length));
    }
    own
}

/// Whether `haystack` contains `needle`, ignoring ASCII case.
pub fn contains_ignoring_case(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Whether a response header's name or value carries `key` (ignoring ASCII
/// case) or a token-shaped string.
fn carries_secret(name: &HeaderName, value: &HeaderValue, key: &[u8]) -> bool {
    [name.as_str().as_bytes(), value.as_bytes()]
        .into_iter()
        .any(|part| contains_ignoring_case(part, key) || token_shaped(part).next().is_some())
}

/// The destination's headers that the broker relays to the client: all but
/// the hop-by-hop ones, `Content-Length` and `Transfer-Encoding` (the body
/// goes out framed by the broker), and any that carries `key` or a
/// token-shaped string.
pub fn relayed(destination: &HeaderMap, key: &[u8]) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in destination {
        let framing = is_hop_by_hop(name.as_str()) || name.as_str() == "content-length";
        if !framing && !carries_secret(name, value, key) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Check a response head before anything of it is passed on: no
/// informational or upgrade status, no redirect, no `Content-Encoding` but
/// `identity` (in every occurrence and every member), and no
/// `Transfer-Encoding` but exactly `chunked` — a compressed coding would
/// hide the credential from the redactor.
pub fn check_response(status: StatusCode, headers: &HeaderMap) -> Result<(), Refusal> {
    if status.is_informational() {
        return Err(Refusal::Unexpected);
    }
    if status.is_redirection() {
        return Err(Refusal::Redirect);
    }
    let identity = |value: &HeaderValue| {
        value
            .as_bytes()
            .split(|b| *b == b',')
            .all(|member| member.trim_ascii().eq_ignore_ascii_case(b"identity"))
    };
    if !headers.get_all(CONTENT_ENCODING).iter().all(identity) {
        return Err(Refusal::Encoded);
    }
    let mut codings = headers.get_all(TRANSFER_ENCODING).iter();
    match (codings.next(), codings.next()) {
        (None, _) => {}
        (Some(only), None)
            if only
                .as_bytes()
                .trim_ascii()
                .eq_ignore_ascii_case(b"chunked") => {}
        _ => return Err(Refusal::Encoded),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "rh_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CREDENTIAL: &str = "sk-test-0000SECRET0000";

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("name"),
                HeaderValue::from_str(value).expect("value"),
            );
        }
        map
    }

    fn names(map: &HeaderMap) -> Vec<String> {
        map.iter()
            .map(|(name, value)| format!("{name}: {}", value.to_str().expect("text")))
            .collect()
    }

    #[test]
    fn containment_ignores_case_and_finds_any_position() {
        assert!(contains_ignoring_case(b"Mozilla rh_ABC", b"rh_abc"));
        assert!(contains_ignoring_case(b"rh_abc", b"RH_ABC"));
        assert!(contains_ignoring_case(b"xx-sk-1-yy", b"sk-1"));
        assert!(!contains_ignoring_case(b"sk-", b"sk-1"));
        assert!(!contains_ignoring_case(b"anything", b""));
    }

    #[test]
    fn every_request_header_is_forwarded_but_hop_by_hop_ones_and_the_brokers_own() {
        let forwarded: Vec<&str> = [
            "host",
            "content-length",
            "accept-encoding",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "proxy-authorization",
            "proxy-connection",
            "proxy-x",
            "authorization",
            "x-api-key",
            "x-goog-api-key",
            "content-type",
            "accept",
            "user-agent",
            "cookie",
            "openai-organization",
            "x-forwarded-for",
            "expect",
            "trailers",
            "x-proxy-thing",
        ]
        .into_iter()
        .filter(|name| forwards(&HeaderName::from_static(name)))
        .collect();
        assert_eq!(
            forwarded,
            [
                "authorization",
                "x-api-key",
                "x-goog-api-key",
                "content-type",
                "accept",
                "user-agent",
                "cookie",
                "openai-organization",
                "x-forwarded-for",
                "expect",
                "trailers",
                "x-proxy-thing",
            ]
        );
    }

    #[test]
    fn the_broker_sets_host_accept_encoding_and_a_declared_length() {
        let authority = HeaderValue::from_static("api.example.com:8443");
        assert_eq!(
            names(&own(&authority, Some(12))),
            [
                "host: api.example.com:8443",
                "accept-encoding: identity",
                "content-length: 12"
            ]
        );
        assert_eq!(
            names(&own(&authority, Some(0))),
            [
                "host: api.example.com:8443",
                "accept-encoding: identity",
                "content-length: 0"
            ]
        );
        assert_eq!(
            names(&own(&authority, None)),
            ["host: api.example.com:8443", "accept-encoding: identity"]
        );
    }

    #[test]
    fn every_response_header_is_relayed_but_framing_and_secrets() {
        let other = format!("rh_{}", "F".repeat(64));
        let named_after = format!("x-{TOKEN}");
        let destination = map(&[
            ("content-type", "text/event-stream"),
            ("content-length", "100"),
            ("transfer-encoding", "chunked"),
            ("content-encoding", "identity"),
            ("connection", "close"),
            ("keep-alive", "timeout=5"),
            ("trailer", "x-checksum"),
            ("te", "trailers"),
            ("upgrade", "h2"),
            ("proxy-authenticate", "Basic"),
            ("location", "https://elsewhere.example/"),
            ("set-cookie", "a=b"),
            ("www-authenticate", "Bearer"),
            ("request-id", "req_1"),
            ("x-request-id", &format!("echo {CREDENTIAL}")),
            ("x-upper", &CREDENTIAL.to_uppercase()),
            ("x-token", TOKEN),
            ("x-token-upper", &TOKEN.to_uppercase()),
            ("x-other-token", &format!("a{other}b")),
            (&named_after, "1"),
            ("x-ratelimit-remaining", "10"),
            ("retry-after", "1"),
        ]);
        assert_eq!(
            names(&relayed(&destination, CREDENTIAL.as_bytes())),
            vec![
                "content-type: text/event-stream",
                "content-encoding: identity",
                "location: https://elsewhere.example/",
                "set-cookie: a=b",
                "www-authenticate: Bearer",
                "request-id: req_1",
                "x-ratelimit-remaining: 10",
                "retry-after: 1",
            ]
        );
    }

    #[test]
    fn responses_that_would_hide_or_move_the_body_are_refused() {
        let ok = StatusCode::OK;
        assert_eq!(check_response(ok, &map(&[])), Ok(()));
        for pairs in [
            &[("content-encoding", "identity")][..],
            &[
                ("content-encoding", "Identity"),
                ("content-encoding", " identity "),
            ],
            &[("content-encoding", "identity, identity")],
            &[("transfer-encoding", "chunked")],
            &[("transfer-encoding", "Chunked")],
            &[("content-length", "5")],
        ] {
            assert_eq!(check_response(ok, &map(pairs)), Ok(()), "{pairs:?}");
        }
        for pairs in [
            &[("content-encoding", "gzip")][..],
            &[("content-encoding", "br")],
            &[("content-encoding", "zstd")],
            &[("content-encoding", "identity, gzip")],
            &[
                ("content-encoding", "identity"),
                ("content-encoding", "deflate"),
            ],
            &[("content-encoding", "")],
            &[("content-encoding", "identity,")],
            &[("transfer-encoding", "gzip, chunked")],
            &[("transfer-encoding", "gzip")],
            &[("transfer-encoding", "chunked, chunked")],
            &[
                ("transfer-encoding", "chunked"),
                ("transfer-encoding", "chunked"),
            ],
            &[("transfer-encoding", "identity")],
            &[("transfer-encoding", "")],
        ] {
            assert_eq!(
                check_response(ok, &map(pairs)),
                Err(Refusal::Encoded),
                "{pairs:?}"
            );
        }
        for status in [300, 301, 302, 303, 304, 307, 308] {
            let status = StatusCode::from_u16(status).expect("status");
            assert_eq!(
                check_response(status, &map(&[("location", "https://evil.example/")])),
                Err(Refusal::Redirect),
                "{status}"
            );
        }
        for status in [100, 101, 103] {
            let status = StatusCode::from_u16(status).expect("status");
            assert_eq!(check_response(status, &map(&[])), Err(Refusal::Unexpected));
        }
        for status in [201, 204, 400, 401, 404, 429, 500, 529] {
            let status = StatusCode::from_u16(status).expect("status");
            assert_eq!(check_response(status, &map(&[])), Ok(()), "{status}");
        }
    }
}
