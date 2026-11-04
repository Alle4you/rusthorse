//! Step 1 of every request, the framing (ADR 0013, "Requests and
//! responses"), on what the HTTP library left of the request.
//!
//! hyper has already refused malformed messages, conflicting
//! `Content-Length` values, a `Transfer-Encoding` that does not end in
//! `chunked` and lines folded over several lines; identical duplicate
//! lengths it merged into one, and when a `Transfer-Encoding` came with a
//! `Content-Length` it dropped the length and kept the coding, which is
//! refused here. It also removed a fragment (`#…`) from the request target
//! before the broker sees it: what is checked, and sent, is the target
//! without it.

use http::header::{CONNECTION, HOST, ORIGIN, TRANSFER_ENCODING, UPGRADE};
use http::{HeaderMap, Method, Uri, Version};
use rusthorse::broker_grant::is_origin_form;

use crate::answer::Refusal;

/// A request whose framing passed.
#[derive(Debug, PartialEq, Eq)]
pub struct Framed<'a> {
    /// The request target, in origin form, as it will be sent.
    pub target: &'a str,
    /// The body's declared length (0 without one).
    pub body_len: u64,
}

/// Check the framing of a request: HTTP/1.1; not `CONNECT`, `TRACE` or
/// `OPTIONS`; a target in origin form; exactly one `Host`, `host` itself;
/// no `Transfer-Encoding`, `Upgrade` or `Origin`; a `Connection` that names
/// only `close` or `keep-alive`; and a body, on any method, only with a
/// length. `body_len` is the length hyper read from `Content-Length`
/// (`None` for a chunked body).
pub fn check<'a>(
    method: &Method,
    uri: &'a Uri,
    version: Version,
    headers: &HeaderMap,
    body_len: Option<u64>,
    host: &str,
) -> Result<Framed<'a>, Refusal> {
    if version != Version::HTTP_11 {
        return Err(Refusal::Version);
    }
    if [Method::CONNECT, Method::TRACE, Method::OPTIONS].contains(method) {
        return Err(Refusal::Method);
    }
    let target = match (uri.scheme(), uri.authority(), uri.path_and_query()) {
        (None, None, Some(target)) if is_origin_form(target.as_str()) => target.as_str(),
        _ => return Err(Refusal::Target),
    };
    let mut hosts = headers.get_all(HOST).iter();
    match (hosts.next(), hosts.next()) {
        (Some(one), None) if one.as_bytes() == host.as_bytes() => {}
        _ => return Err(Refusal::Host),
    }
    if headers.contains_key(TRANSFER_ENCODING) {
        return Err(Refusal::TransferEncoding);
    }
    if headers.contains_key(UPGRADE) {
        return Err(Refusal::Upgrade);
    }
    if headers.contains_key(ORIGIN) {
        return Err(Refusal::Origin);
    }
    if !headers
        .get_all(CONNECTION)
        .iter()
        .all(|value| only_close_or_keep_alive(value.as_bytes()))
    {
        return Err(Refusal::Connection);
    }
    let Some(body_len) = body_len else {
        return Err(Refusal::TransferEncoding);
    };
    Ok(Framed { target, body_len })
}

/// Whether a `Connection` value is a list of `close` and `keep-alive` only
/// (ignoring ASCII case and the spaces around each), with no empty member.
fn only_close_or_keep_alive(value: &[u8]) -> bool {
    value.split(|b| *b == b',').all(|member| {
        let member = member.trim_ascii();
        member.eq_ignore_ascii_case(b"close") || member.eq_ignore_ascii_case(b"keep-alive")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    const HOST_HEADER: &str = "127.0.0.1:43210";

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).expect("value"));
        }
        map
    }

    fn checked(
        method: &str,
        target: &str,
        pairs: &[(&'static str, &str)],
        body: Option<u64>,
    ) -> Result<(String, u64), Refusal> {
        let method = Method::from_bytes(method.as_bytes()).expect("method");
        let uri: Uri = target.parse().expect("uri");
        check(
            &method,
            &uri,
            Version::HTTP_11,
            &headers(pairs),
            body,
            HOST_HEADER,
        )
        .map(|framed| (framed.target.to_string(), framed.body_len))
    }

    const HOST: (&str, &str) = ("host", HOST_HEADER);

    #[test]
    fn a_plain_request_passes_with_its_target_and_length() {
        assert_eq!(
            checked("POST", "/v1/messages?beta=true", &[HOST], Some(12)),
            Ok(("/v1/messages?beta=true".into(), 12))
        );
        assert_eq!(
            checked(
                "GET",
                "/v1/models",
                &[HOST, ("connection", "keep-alive")],
                Some(0)
            ),
            Ok(("/v1/models".into(), 0))
        );
        for connection in ["close", "Keep-Alive", " close , keep-alive ", "CLOSE"] {
            assert!(
                checked(
                    "POST",
                    "/v1/messages",
                    &[HOST, ("connection", connection)],
                    Some(0)
                )
                .is_ok(),
                "{connection}"
            );
        }
        // Any target in origin form passes, as it is: nothing decodes or
        // normalizes it.
        for target in ["/v1/%2e%2e/x", "/v1;x", "/v1\\x", "//v1", "/", "/a?b=c&b=d"] {
            assert_eq!(
                checked("POST", target, &[HOST], Some(0)),
                Ok((target.to_string(), 0)),
                "{target}"
            );
        }
        // A body, with its length, on any method the broker serves.
        for method in ["GET", "HEAD", "PUT", "PATCH", "DELETE", "PROPFIND", "post"] {
            assert_eq!(
                checked(method, "/v1/x", &[HOST], Some(10)),
                Ok(("/v1/x".into(), 10)),
                "{method}"
            );
        }
    }

    /// A method, a target, headers, a declared length and the refusal.
    type Case<'a> = (
        &'a str,
        &'a str,
        &'a [(&'static str, &'a str)],
        Option<u64>,
        Refusal,
    );

    #[test]
    fn framing_errors_are_refused() {
        use Refusal::*;
        let cases: &[Case<'_>] = &[
            ("CONNECT", "/v1/messages", &[HOST], Some(0), Method),
            ("TRACE", "/v1/messages", &[HOST], Some(0), Method),
            ("OPTIONS", "/v1/messages", &[HOST], Some(0), Method),
            ("OPTIONS", "*", &[HOST], Some(0), Method),
            ("POST", "*", &[HOST], Some(0), Target),
            (
                "POST",
                "https://api.anthropic.com/v1/messages",
                &[HOST],
                Some(0),
                Target,
            ),
            (
                "POST",
                "http://127.0.0.1:43210/v1/messages",
                &[HOST],
                Some(0),
                Target,
            ),
            ("POST", "127.0.0.1:43210", &[HOST], Some(0), Target),
            ("POST", "/v1/m\u{e9}ssages", &[HOST], Some(0), Target),
            ("POST", "/v1/messages", &[], Some(0), Host),
            (
                "POST",
                "/v1/messages",
                &[("host", "localhost:43210")],
                Some(0),
                Host,
            ),
            (
                "POST",
                "/v1/messages",
                &[("host", "127.0.0.1")],
                Some(0),
                Host,
            ),
            (
                "POST",
                "/v1/messages",
                &[("host", "127.0.0.1:43211")],
                Some(0),
                Host,
            ),
            (
                "POST",
                "/v1/messages",
                &[("host", "api.anthropic.com")],
                Some(0),
                Host,
            ),
            (
                "POST",
                "/v1/messages",
                &[("host", " 127.0.0.1:43210")],
                Some(0),
                Host,
            ),
            ("POST", "/v1/messages", &[HOST, HOST], Some(0), Host),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("transfer-encoding", "chunked")],
                None,
                TransferEncoding,
            ),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("transfer-encoding", "chunked")],
                Some(5),
                TransferEncoding,
            ),
            ("POST", "/v1/messages", &[HOST], None, TransferEncoding),
            (
                "GET",
                "/v1/models",
                &[HOST, ("upgrade", "websocket"), ("connection", "upgrade")],
                Some(0),
                Upgrade,
            ),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("upgrade", "h2c")],
                Some(0),
                Upgrade,
            ),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("origin", "https://evil.example")],
                Some(0),
                Origin,
            ),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("origin", "null")],
                Some(0),
                Origin,
            ),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("connection", "close, user-agent")],
                Some(0),
                Connection,
            ),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("connection", "x-api-key")],
                Some(0),
                Connection,
            ),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("connection", "close"), ("connection", "te")],
                Some(0),
                Connection,
            ),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("connection", "close,")],
                Some(0),
                Connection,
            ),
            (
                "POST",
                "/v1/messages",
                &[HOST, ("connection", "")],
                Some(0),
                Connection,
            ),
            ("GET", "/v1/models", &[HOST], None, TransferEncoding),
        ];
        for (method, target, pairs, body, expected) in cases {
            assert_eq!(
                checked(method, target, pairs, *body),
                Err(*expected),
                "{method} {target} {pairs:?} {body:?}"
            );
        }
        // Another version.
        let uri: Uri = "/v1/messages".parse().expect("uri");
        for version in [
            http::Version::HTTP_10,
            http::Version::HTTP_09,
            http::Version::HTTP_2,
        ] {
            assert_eq!(
                check(
                    &http::Method::POST,
                    &uri,
                    version,
                    &headers(&[HOST]),
                    Some(0),
                    HOST_HEADER
                ),
                Err(Refusal::Version),
                "{version:?}"
            );
        }
    }
}
