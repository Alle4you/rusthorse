//! Which headers cross the broker, each way, and the checks of the
//! destination's response head before anything of it reaches the client.
//!
//! Only the headers the preset lists cross (`rusthorse::broker_profile`'s
//! rules), and of those, none whose name or value contains the token or the
//! credential, compared ignoring ASCII case: the broker never sends the
//! token in a header, never sends the credential but in the one header it
//! builds, and never passes the credential back.

use http::header::{CONTENT_ENCODING, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use rusthorse::broker_profile::{PresetSpec, forwards_request_header, relays_response_header};

use crate::answer::Refusal;

/// Whether `haystack` contains `needle`, ignoring ASCII case.
pub fn contains_ignoring_case(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Whether a header's name or value contains one of `secrets`.
fn carries_secret(name: &HeaderName, value: &HeaderValue, secrets: &[&[u8]]) -> bool {
    secrets.iter().any(|secret| {
        contains_ignoring_case(name.as_str().as_bytes(), secret)
            || contains_ignoring_case(value.as_bytes(), secret)
    })
}

/// The client's headers that the preset forwards, without any that carries
/// one of `secrets`. The broker adds `Host`, `Content-Length`,
/// `Accept-Encoding` and the credential header itself.
pub fn forwarded(spec: &PresetSpec, client: &HeaderMap, secrets: &[&[u8]]) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in client {
        if forwards_request_header(spec, name.as_str()) && !carries_secret(name, value, secrets) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// The destination's headers that the preset relays, without any that
/// carries one of `secrets`. Never `Content-Length` or `Transfer-Encoding`:
/// the body goes out chunked.
pub fn relayed(spec: &PresetSpec, destination: &HeaderMap, secrets: &[&[u8]]) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in destination {
        if relays_response_header(spec, name.as_str()) && !carries_secret(name, value, secrets) {
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
    use rusthorse::broker_profile::{Preset, latest};

    const TOKEN: &str = "rh_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CREDENTIAL: &str = "sk-ant-test-0000SECRET0000";

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
    fn only_listed_headers_without_a_secret_are_forwarded() {
        let anthropic = latest(Preset::Anthropic);
        let secrets = [TOKEN.as_bytes(), CREDENTIAL.as_bytes()];
        let lower = TOKEN.to_string();
        let upper = TOKEN.to_uppercase();
        let named = format!("x-stainless-{TOKEN}");
        let client = map(&[
            ("host", "127.0.0.1:1"),
            ("x-api-key", TOKEN),
            ("authorization", &format!("Bearer {TOKEN}")),
            ("content-type", "application/json"),
            ("content-length", "12"),
            ("accept-encoding", "gzip"),
            ("connection", "keep-alive"),
            ("anthropic-version", "2023-06-01"),
            ("anthropic-beta", "a, b"),
            ("user-agent", &format!("agent {lower}")),
            ("x-stainless-lang", &upper),
            (&named, "1"),
            ("x-stainless-arch", &format!("x{CREDENTIAL}")),
            ("x-claude-code-session-id", "s1"),
            ("cookie", "a=b"),
            ("openai-organization", "org-1"),
            ("x-stainless-retry-count", "0"),
        ]);
        assert_eq!(
            names(&forwarded(anthropic, &client, &secrets)),
            vec![
                "content-type: application/json",
                "anthropic-version: 2023-06-01",
                "anthropic-beta: a, b",
                "x-claude-code-session-id: s1",
                "x-stainless-retry-count: 0",
            ]
        );
        let openai = latest(Preset::Openai);
        let client = map(&[
            ("authorization", &format!("Bearer {TOKEN}")),
            ("openai-beta", "assistants=v2"),
            ("openai-organization", "org-1"),
            ("openai-project", "p"),
            ("anthropic-version", "2023-06-01"),
            ("accept", "text/event-stream"),
        ]);
        assert_eq!(
            names(&forwarded(openai, &client, &secrets)),
            vec!["openai-beta: assistants=v2", "accept: text/event-stream"]
        );
    }

    #[test]
    fn only_listed_headers_without_the_credential_are_relayed() {
        let spec = latest(Preset::Anthropic);
        let secrets = [CREDENTIAL.as_bytes(), TOKEN.as_bytes()];
        let destination = map(&[
            ("content-type", "text/event-stream"),
            ("content-length", "100"),
            ("transfer-encoding", "chunked"),
            ("content-encoding", "identity"),
            ("location", "https://elsewhere.example/"),
            ("set-cookie", "a=b"),
            ("request-id", "req_1"),
            ("x-request-id", &format!("echo {CREDENTIAL}")),
            ("anthropic-ratelimit-requests-remaining", "10"),
            ("retry-after", &CREDENTIAL.to_lowercase()),
            ("connection", "close"),
            ("www-authenticate", "Bearer"),
        ]);
        assert_eq!(
            names(&relayed(spec, &destination, &secrets)),
            vec![
                "content-type: text/event-stream",
                "request-id: req_1",
                "anthropic-ratelimit-requests-remaining: 10",
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
