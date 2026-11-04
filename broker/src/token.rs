//! Step 2 of every request: the token in the request's head, and the key in
//! its place (ADR 0013, scope amendment, "The token stands for the key
//! where the program puts it").
//!
//! The program presents the token literally wherever it would present the
//! key: in the value of a header the broker forwards, with any prefix
//! (`Authorization: Bearer TOKEN`, `Authorization: Token TOKEN`,
//! `x-api-key: TOKEN`, `x-goog-api-key: TOKEN`). Only those values count.
//! The broker replaces each exact occurrence of the grant's token in them
//! with the key, in one pass, inside larger values too, without decoding
//! the values, folding their case or scanning what it inserted, and changes
//! nothing else ([`substitute`]).
//!
//! A request is refused with the broker's own `401`, before its admission
//! is asked and with nothing forwarded ([`check`]), when:
//!
//! - a token-shaped string is in the method, the request target, a header
//!   name, or the value of a header the broker drops or rebuilds (the
//!   hop-by-hop ones, `Host`, `Content-Length`, `Accept-Encoding`:
//!   [`headers::forwards`]) — the grant's own token there, in any case,
//!   among them;
//! - a token-shaped string in a forwarded header value is not the grant's
//!   token byte for byte (a case variant of it included: it is refused, not
//!   replaced);
//! - no forwarded header value holds the token;
//! - the header block the broker would send, once the key is in, is larger
//!   than [`MAX_REQUEST_HEADER_BYTES`];
//! - the key itself is in the request's head.
//!
//! A token-shaped string is `rh_` and 64 hexadecimal digits, prefix and
//! digits recognised without regard to ASCII case, at any byte position,
//! without word boundaries ([`token_shaped`]): every one is found, in every
//! header value, duplicates included. No other grant's token is looked up.
//!
//! What a client sent is compared with the token only where a token-shaped
//! string is, each in a time that does not depend on where it differs
//! ([`tokens_equal`]); where those strings are is the client's own choice.
//! The search for the key, which runs only once the request has shown the
//! token, compares every position in a time that depends on the lengths
//! alone ([`holds`]). The head is what the HTTP library parsed: the method,
//! the target, and each header's name and value (names in lowercase, as it
//! gives them; a key split by the client between a name and its value is a
//! name and a value, and is forwarded as such).

use std::ops::Range;

use http::{HeaderMap, HeaderValue};
use rusthorse::broker_grant::{token_shaped, tokens_equal};
use rusthorse::broker_protocol::MAX_REQUEST_HEADER_BYTES;
use zeroize::Zeroizing;

use crate::answer::Refusal;
use crate::headers;

/// Why a request's head is refused: the broker's own `401` each time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRefusal {
    /// No forwarded header value holds the grant's token.
    Missing,
    /// A token-shaped string in the method, the target, a header name, or a
    /// header the broker drops or rebuilds.
    Misplaced,
    /// A token-shaped string in a forwarded header value that is not the
    /// grant's token byte for byte.
    Foreign,
    /// The header block, once the key replaces the token, would be larger
    /// than [`MAX_REQUEST_HEADER_BYTES`].
    TooLarge,
    /// The key itself is in the request's head.
    Key,
}

impl From<TokenRefusal> for Refusal {
    fn from(refusal: TokenRefusal) -> Refusal {
        match refusal {
            TokenRefusal::Missing => Refusal::Token,
            TokenRefusal::Misplaced => Refusal::TokenMisplaced,
            TokenRefusal::Foreign => Refusal::ForeignToken,
            TokenRefusal::TooLarge => Refusal::HeadTooLarge,
            TokenRefusal::Key => Refusal::KeyInRequest,
        }
    }
}

/// Check a request's head: `method`, `target` and the `client`'s headers;
/// `own` are the headers the broker sets itself on the request it sends
/// (they count in the size of its header block). `key` is `None` once the
/// grant is closed: the checks that need it are left out, and the request
/// is refused at its admission instead.
pub fn check(
    method: &[u8],
    target: &[u8],
    client: &HeaderMap,
    own: &HeaderMap,
    token: &[u8],
    key: Option<&[u8]>,
) -> Result<(), TokenRefusal> {
    let misplaced = |bytes: &[u8]| token_shaped(bytes).next().is_some();
    if misplaced(method) || misplaced(target) {
        return Err(TokenRefusal::Misplaced);
    }
    let mut presented = 0;
    for (name, value) in client {
        if misplaced(name.as_str().as_bytes()) {
            return Err(TokenRefusal::Misplaced);
        }
        let value = value.as_bytes();
        if !headers::forwards(name) {
            if misplaced(value) {
                return Err(TokenRefusal::Misplaced);
            }
            continue;
        }
        for range in token_shaped(value) {
            if !tokens_equal(&value[range], token) {
                return Err(TokenRefusal::Foreign);
            }
            presented += 1;
        }
    }
    if presented == 0 {
        return Err(TokenRefusal::Missing);
    }
    // The grant is closed: its admission refuses the request.
    let Some(key) = key else {
        return Ok(());
    };
    if sent_head_len(method, target, client, own, token.len(), key.len()) > MAX_REQUEST_HEADER_BYTES
    {
        return Err(TokenRefusal::TooLarge);
    }
    let in_head = holds(method, key)
        || holds(target, key)
        || client.iter().any(|(name, value)| {
            holds(name.as_str().as_bytes(), key) || holds(value.as_bytes(), key)
        });
    if in_head {
        return Err(TokenRefusal::Key);
    }
    Ok(())
}

/// The length of the head the broker sends for a checked request: its
/// request line (`METHOD TARGET HTTP/1.1`), the `client`'s headers it
/// forwards with each occurrence of a token of `token_len` bytes replaced
/// by a key of `key_len`, and its `own` headers, each line `name: value`
/// and CRLF, and the empty line that ends the head.
pub fn sent_head_len(
    method: &[u8],
    target: &[u8],
    client: &HeaderMap,
    own: &HeaderMap,
    token_len: usize,
    key_len: usize,
) -> usize {
    let line = |name: &str, value: usize| name.len() + 2 + value + 2;
    let mut len = method.len() + 1 + target.len() + 1 + "HTTP/1.1".len() + 2;
    for (name, value) in client {
        if headers::forwards(name) {
            let value = value.as_bytes();
            let tokens = token_shaped(value).count();
            let value_len = value.len() - tokens * token_len + tokens * key_len;
            len = len.saturating_add(line(name.as_str(), value_len));
        }
    }
    for (name, value) in own {
        len = len.saturating_add(line(name.as_str(), value.len()));
    }
    len.saturating_add(2)
}

/// The `client`'s headers that the broker forwards ([`headers::forwards`]),
/// in their order, each exact occurrence of `token` in their values
/// replaced by `key` in one pass: what was inserted is never scanned again,
/// and nothing else changes. A value that receives the key is marked
/// sensitive, so that it is never printed. `None` if a value with the key
/// in it is not a valid header value, which a key the broker accepts
/// cannot make.
pub fn substitute(client: &HeaderMap, token: &[u8], key: &[u8]) -> Option<HeaderMap> {
    let mut forwarded = HeaderMap::new();
    for (name, value) in client {
        if !headers::forwards(name) {
            continue;
        }
        let bytes = value.as_bytes();
        let found: Vec<Range<usize>> = token_shaped(bytes)
            .filter(|range| tokens_equal(&bytes[range.clone()], token))
            .collect();
        if found.is_empty() {
            forwarded.append(name.clone(), value.clone());
            continue;
        }
        // One buffer of the final length, wiped when dropped: no
        // reallocation leaves a copy of the key behind.
        let len = bytes.len() - found.len() * token.len() + found.len() * key.len();
        let mut replaced = Zeroizing::new(Vec::with_capacity(len));
        let mut at = 0;
        for range in found {
            replaced.extend_from_slice(&bytes[at..range.start]);
            replaced.extend_from_slice(key);
            at = range.end;
        }
        replaced.extend_from_slice(&bytes[at..]);
        let mut value = HeaderValue::from_bytes(&replaced).ok()?;
        value.set_sensitive(true);
        forwarded.append(name.clone(), value);
    }
    Some(forwarded)
}

/// Whether `haystack` holds `needle`, in a time that depends on their
/// lengths only: every position is compared whole, whatever it holds.
pub fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let mut found = 0u8;
    for window in haystack.windows(needle.len()) {
        let mut difference = 0u8;
        for (a, b) in window.iter().zip(needle) {
            difference |= a ^ b;
        }
        found |= u8::from(difference == 0);
    }
    std::hint::black_box(found) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderName;

    const TOKEN: &str = "rh_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const KEY: &str = "sk-test-0000FAKE0000key";

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

    fn own() -> HeaderMap {
        map(&[("host", "api.example.com"), ("accept-encoding", "identity")])
    }

    fn checked(method: &str, target: &str, pairs: &[(&str, &str)]) -> Result<(), TokenRefusal> {
        check(
            method.as_bytes(),
            target.as_bytes(),
            &map(pairs),
            &own(),
            TOKEN.as_bytes(),
            Some(KEY.as_bytes()),
        )
    }

    fn lines(map: &HeaderMap) -> Vec<String> {
        map.iter()
            .map(|(name, value)| format!("{name}: {}", value.to_str().expect("text")))
            .collect()
    }

    fn substituted(pairs: &[(&str, &str)]) -> Vec<String> {
        lines(&substitute(&map(pairs), TOKEN.as_bytes(), KEY.as_bytes()).expect("valid"))
    }

    /// Another token: of the form, not the grant's.
    fn other() -> String {
        format!("rh_{}", "f".repeat(64))
    }

    #[test]
    fn the_token_in_any_forwarded_header_value_passes() {
        for pairs in [
            &[("x-api-key", TOKEN)][..],
            &[("authorization", &format!("Bearer {TOKEN}"))],
            &[("authorization", &format!("Token {TOKEN}"))],
            &[("authorization", &format!("Basic {TOKEN}"))],
            &[("authorization", &format!("bearer  {TOKEN}"))],
            &[("authorization", TOKEN)],
            &[("x-goog-api-key", TOKEN)],
            &[("x-whatever", &format!("a{TOKEN}b"))],
            &[
                ("x-api-key", TOKEN),
                ("authorization", &format!("Bearer {TOKEN}")),
            ],
            &[("x-api-key", TOKEN), ("x-api-key", TOKEN)],
            &[("cookie", &format!("k={TOKEN}; other=1"))],
            &[("x-list", &format!("{TOKEN},{TOKEN}"))],
            // Hexadecimal digits around it are no word boundary.
            &[("x-api-key", &format!("abc{TOKEN}def"))],
        ] {
            assert_eq!(checked("POST", "/v1/messages", pairs), Ok(()), "{pairs:?}");
        }
    }

    #[test]
    fn without_the_token_in_a_forwarded_value_the_request_is_refused() {
        for pairs in [
            &[][..],
            &[("x-api-key", "")],
            &[("x-api-key", "rh_0123")],
            &[("x-api-key", &TOKEN[..TOKEN.len() - 1])],
            &[("x-api-key", &TOKEN[1..])],
            &[("user-agent", "agent/1")],
        ] {
            assert_eq!(
                checked("GET", "/v1/models", pairs),
                Err(TokenRefusal::Missing),
                "{pairs:?}"
            );
        }
    }

    #[test]
    fn the_token_outside_forwarded_values_is_refused_in_any_case() {
        let upper = TOKEN.to_ascii_uppercase();
        let key = ("x-api-key", TOKEN);
        type Extra = Vec<(String, String)>;
        let cases: Vec<(String, String, Extra)> = vec![
            (TOKEN.into(), "/".into(), vec![]),
            (format!("GET{TOKEN}"), "/".into(), vec![]),
            (upper.clone(), "/".into(), vec![]),
            ("GET".into(), format!("/v1/{TOKEN}"), vec![]),
            ("GET".into(), format!("/?key={TOKEN}"), vec![]),
            ("GET".into(), format!("/?key={upper}"), vec![]),
            ("GET".into(), format!("/{}", other()), vec![]),
            (
                "GET".into(),
                "/".into(),
                vec![(format!("x-{TOKEN}"), "1".into())],
            ),
            (
                "GET".into(),
                "/".into(),
                vec![(format!("x-{}", other()), "1".into())],
            ),
        ];
        for (method, target, extra) in &cases {
            let mut pairs: Vec<(&str, &str)> = vec![key];
            pairs.extend(extra.iter().map(|(n, v)| (n.as_str(), v.as_str())));
            assert_eq!(
                checked(method, target, &pairs),
                Err(TokenRefusal::Misplaced),
                "{method} {target} {extra:?}"
            );
        }
        // In a header the broker drops or rebuilds, even beside the token
        // where it belongs.
        for name in [
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "proxy-authorization",
            "proxy-anything",
            "accept-encoding",
            "content-length",
            "host",
            "transfer-encoding",
            "upgrade",
        ] {
            for value in [TOKEN.to_string(), format!("Bearer {upper}"), other()] {
                assert_eq!(
                    checked("GET", "/", &[key, (name, &value)]),
                    Err(TokenRefusal::Misplaced),
                    "{name}: {value}"
                );
            }
        }
    }

    #[test]
    fn a_token_shaped_string_that_is_not_the_grants_token_is_refused() {
        let upper = TOKEN.to_ascii_uppercase();
        let prefix_upper = format!("RH_{}", &TOKEN[3..]);
        let digits_upper = format!("rh_{}", TOKEN[3..].to_ascii_uppercase());
        for value in [
            other(),
            upper.clone(),
            prefix_upper.clone(),
            digits_upper,
            format!("Bearer {upper}"),
            format!("x{}x", other()),
        ] {
            // Alone, and beside the token where it belongs.
            assert_eq!(
                checked("GET", "/", &[("x-api-key", &value)]),
                Err(TokenRefusal::Foreign),
                "{value}"
            );
            for pairs in [
                &[("x-api-key", TOKEN), ("user-agent", &value)][..],
                &[("x-api-key", TOKEN), ("x-api-key", &value)],
                &[("authorization", &format!("Bearer {TOKEN} {value}"))],
            ] {
                assert_eq!(
                    checked("GET", "/", pairs),
                    Err(TokenRefusal::Foreign),
                    "{pairs:?}"
                );
            }
        }
    }

    #[test]
    fn the_key_anywhere_in_the_head_is_refused() {
        let key = ("x-api-key", TOKEN);
        assert_eq!(checked(KEY, "/", &[key]), Err(TokenRefusal::Key));
        assert_eq!(
            checked("GET", &format!("/{KEY}"), &[key]),
            Err(TokenRefusal::Key)
        );
        for pairs in [
            &[key, ("x-api-key", KEY)][..],
            &[key, ("user-agent", &format!("agent {KEY} 1"))],
            &[key, ("proxy-authorization", KEY)],
            &[("authorization", &format!("Bearer {TOKEN} {KEY}"))],
        ] {
            assert_eq!(
                checked("GET", "/", pairs),
                Err(TokenRefusal::Key),
                "{pairs:?}"
            );
        }
        // A name: names are lowercase, so a key in lowercase is there.
        let key_lower = "sk-test-0000fake0000key";
        let found = check(
            b"GET",
            b"/",
            &map(&[key, (key_lower, "1")]),
            &own(),
            TOKEN.as_bytes(),
            Some(key_lower.as_bytes()),
        );
        assert_eq!(found, Err(TokenRefusal::Key));
        // Part of the key, or another case of it, is not the key.
        for pairs in [
            &[key, ("x-other", &KEY[..KEY.len() - 1])][..],
            &[key, ("x-other", &KEY.to_ascii_lowercase())],
        ] {
            assert_eq!(checked("GET", "/", pairs), Ok(()), "{pairs:?}");
        }
        // Once the grant is closed the key is gone: the admission refuses.
        let closed = check(
            b"GET",
            b"/",
            &map(&[key, ("x-api-key", KEY)]),
            &own(),
            TOKEN.as_bytes(),
            None,
        );
        assert_eq!(closed, Ok(()));
    }

    #[test]
    fn the_header_block_with_the_key_in_must_fit_the_limit() {
        let key = "k".repeat(4096);
        let value = [TOKEN; 7].join(",");
        let pairs = [("x-api-key", value.as_str())];
        let client = map(&pairs);
        let len = sent_head_len(b"GET", b"/", &client, &own(), TOKEN.len(), key.len());
        // The request line, the one header with seven keys, the broker's
        // own headers and the end.
        let expected = "GET / HTTP/1.1\r\n".len()
            + "x-api-key: ".len()
            + 7 * key.len()
            + 6
            + 2
            + "host: api.example.com\r\naccept-encoding: identity\r\n".len()
            + 2;
        assert_eq!(len, expected);
        let fits = |target: &str| {
            check(
                b"GET",
                target.as_bytes(),
                &client,
                &own(),
                TOKEN.as_bytes(),
                Some(key.as_bytes()),
            )
        };
        // Pad the target to the limit exactly, then one byte past it.
        let pad = MAX_REQUEST_HEADER_BYTES - len;
        assert_eq!(fits(&format!("/{}", "a".repeat(pad))), Ok(()));
        assert_eq!(
            fits(&format!("/{}", "a".repeat(pad + 1))),
            Err(TokenRefusal::TooLarge)
        );
        // Small before the key went in: the size counts after it.
        assert!(sent_head_len(b"GET", b"/", &client, &own(), TOKEN.len(), TOKEN.len()) < 1024);
        // Eight keys of 4096 bytes do not fit.
        let value = [TOKEN; 8].join(",");
        assert_eq!(
            check(
                b"GET",
                b"/",
                &map(&[("x-api-key", &value)]),
                &own(),
                TOKEN.as_bytes(),
                Some(key.as_bytes())
            ),
            Err(TokenRefusal::TooLarge)
        );
        // Dropped headers do not count; the broker's own do.
        let dropped = map(&[("x-api-key", TOKEN), ("keep-alive", &"a".repeat(1000))]);
        let kept = map(&[("x-api-key", TOKEN)]);
        assert_eq!(
            sent_head_len(b"GET", b"/", &dropped, &own(), TOKEN.len(), 10),
            sent_head_len(b"GET", b"/", &kept, &own(), TOKEN.len(), 10)
        );
        assert!(
            sent_head_len(b"GET", b"/", &kept, &own(), TOKEN.len(), 10)
                > sent_head_len(b"GET", b"/", &kept, &HeaderMap::new(), TOKEN.len(), 10)
        );
    }

    #[test]
    fn each_occurrence_of_the_token_is_replaced_in_one_pass_and_nothing_else_changes() {
        assert_eq!(
            substituted(&[
                ("authorization", &format!("Bearer {TOKEN}")),
                ("x-api-key", TOKEN),
                ("x-goog-api-key", TOKEN),
                ("x-custom", &format!("Token {TOKEN} and {TOKEN}")),
                ("x-glued", &format!("abc{TOKEN}{TOKEN}def")),
                ("content-type", "application/json"),
                ("user-agent", "Agent/1 (x)"),
            ]),
            vec![
                format!("authorization: Bearer {KEY}"),
                format!("x-api-key: {KEY}"),
                format!("x-goog-api-key: {KEY}"),
                format!("x-custom: Token {KEY} and {KEY}"),
                format!("x-glued: abc{KEY}{KEY}def"),
                "content-type: application/json".to_string(),
                "user-agent: Agent/1 (x)".to_string(),
            ]
        );
        // Duplicates stay, in order, each replaced.
        assert_eq!(
            substituted(&[("x-api-key", TOKEN), ("x-api-key", &format!("2 {TOKEN}"))]),
            vec![format!("x-api-key: {KEY}"), format!("x-api-key: 2 {KEY}")]
        );
        // What is not the token byte for byte stays as it is (the check
        // refuses such a request before).
        let upper = TOKEN.to_ascii_uppercase();
        assert_eq!(
            substituted(&[("x-api-key", &upper)]),
            vec![format!("x-api-key: {upper}")]
        );
        // Headers the broker drops or rebuilds are not forwarded.
        assert_eq!(
            substituted(&[
                ("host", "127.0.0.1:1"),
                ("content-length", "2"),
                ("accept-encoding", "gzip"),
                ("connection", "keep-alive"),
                ("keep-alive", "timeout=5"),
                ("te", "trailers"),
                ("trailer", "x"),
                ("transfer-encoding", "chunked"),
                ("upgrade", "h2c"),
                ("proxy-authorization", "Basic x"),
                ("proxy-connection", "close"),
                ("x-api-key", TOKEN),
            ]),
            vec![format!("x-api-key: {KEY}")]
        );
    }

    #[test]
    fn what_the_key_brings_in_is_never_replaced_again() {
        // A key that holds the token, and one that would make a token with
        // the bytes after it: each occurrence is replaced once.
        let tricky = format!("x{TOKEN}y");
        let value = format!("{TOKEN}-{TOKEN}");
        let replaced = substitute(
            &map(&[("x-api-key", &value)]),
            TOKEN.as_bytes(),
            tricky.as_bytes(),
        )
        .expect("valid");
        assert_eq!(
            lines(&replaced),
            vec![format!("x-api-key: {tricky}-{tricky}")]
        );
        let prefix = "rh_".to_string();
        let value = format!("{TOKEN}{}", &TOKEN[3..]);
        let replaced = substitute(
            &map(&[("x-api-key", &value)]),
            TOKEN.as_bytes(),
            prefix.as_bytes(),
        )
        .expect("valid");
        assert_eq!(lines(&replaced), vec![format!("x-api-key: {TOKEN}")]);
        // The values that got the key are sensitive; the others are not.
        let replaced = substitute(
            &map(&[("x-api-key", TOKEN), ("accept", "*/*")]),
            TOKEN.as_bytes(),
            KEY.as_bytes(),
        )
        .expect("valid");
        assert!(replaced["x-api-key"].is_sensitive());
        assert!(!replaced["accept"].is_sensitive());
    }

    #[test]
    fn the_search_for_the_key_finds_it_anywhere_and_nothing_else() {
        assert!(holds(b"sk-1", b"sk-1"));
        assert!(holds(b"xxsk-1yy", b"sk-1"));
        assert!(holds(b"xxsk-1", b"sk-1"));
        assert!(!holds(b"sk-", b"sk-1"));
        assert!(!holds(b"SK-1", b"sk-1"));
        assert!(!holds(b"anything", b""));
        assert!(!holds(b"", b"sk-1"));
    }
}
