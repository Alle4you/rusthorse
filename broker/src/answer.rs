//! What the broker answers itself, and the bodies of every response it
//! gives a client.
//!
//! A local answer carries a short JSON error, of type `rusthorse_broker`,
//! with a fixed message that never echoes the request and starts with
//! [`MESSAGE_PREFIX`], `x-should-retry: false` unless retrying can help
//! (`429`, `503`, and a `502` sent before anything reached the destination),
//! `retry-after: 1` where ADR 0013 says so, and `connection: close` where
//! the connection cannot safely continue: after a framing error, a body
//! that was refused or did not arrive, or any refusal of a request whose
//! body was not read.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_TYPE, RETRY_AFTER};
use http::{HeaderValue, Response, StatusCode};
use hyper::body::{Body, Frame, SizeHint};
use rusthorse::broker_protocol::{AdmissionRefusal, RETRY_AFTER_SECS};
use tokio::sync::mpsc;

use crate::server::BusyGuard;

/// The header that tells the clients' SDKs not to retry.
pub const SHOULD_RETRY: &str = "x-should-retry";

/// How the message of every local answer starts: a program that shows only
/// the message of an API error (Claude Code shows `API Error: 403` and the
/// message) still says that the broker answered, not the destination.
pub const MESSAGE_PREFIX: &str = "rusthorse-broker: ";

/// Why the broker answered a request itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    // Step 1, the framing.
    /// Not HTTP/1.1.
    Version,
    /// `CONNECT`, `TRACE` or `OPTIONS`.
    Method,
    /// A request target not in origin form.
    Target,
    /// No `Host`, several, or one other than `127.0.0.1:PORT`.
    Host,
    /// A `Transfer-Encoding` header, or a body without a length.
    TransferEncoding,
    /// An `Upgrade` header.
    Upgrade,
    /// An `Origin` header.
    Origin,
    /// A `Connection` header naming anything but `close` or `keep-alive`.
    Connection,
    /// A body on a route without one.
    BodyNotAllowed,
    // Step 2.
    /// No token, or not this grant's.
    Token,
    // Step 3.
    /// Not exactly a route of the preset.
    Route,
    // Step 4.
    /// A body larger than `MAX_REQUEST_BODY_BYTES`.
    BodyTooLarge,
    /// No room for the body in the broker's budget.
    NoRoom,
    // Step 5.
    /// The grant was revoked (by the agent, or it is being revoked).
    Revoked,
    /// The grant's lifetime has passed.
    Expired,
    /// The grant's request limit is reached.
    Exhausted,
    /// Too many requests in flight.
    TooManyInFlight,
    /// The admission could not be recorded.
    AuditFailed,
    // Step 6.
    /// The admitted request's body did not arrive in time.
    BodyTimeout,
    // Step 7.
    /// Resolving, connecting or the TLS handshake failed: nothing was sent.
    Unreachable,
    // Step 8, and failures after the request may have been sent.
    /// The destination answered with a redirect.
    Redirect,
    /// The destination's response has a content or transfer coding the
    /// broker refuses.
    Encoded,
    /// The destination answered with an informational or upgrade status.
    Unexpected,
    /// The destination failed after the request was sent.
    DestinationFailed,
    /// The destination did not send its response head in time.
    DestinationTimeout,
}

impl Refusal {
    /// The status of the local answer.
    pub fn status(self) -> StatusCode {
        use Refusal::*;
        match self {
            Version => StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            Method | Target | Host | TransferEncoding | Upgrade | Origin | Connection
            | BodyNotAllowed => StatusCode::BAD_REQUEST,
            Token => StatusCode::UNAUTHORIZED,
            Route => StatusCode::NOT_FOUND,
            BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            NoRoom | AuditFailed => StatusCode::SERVICE_UNAVAILABLE,
            Revoked | Expired | Exhausted => StatusCode::FORBIDDEN,
            TooManyInFlight => StatusCode::TOO_MANY_REQUESTS,
            BodyTimeout => StatusCode::REQUEST_TIMEOUT,
            Unreachable | Redirect | Encoded | Unexpected | DestinationFailed => {
                StatusCode::BAD_GATEWAY
            }
            DestinationTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// The message of the JSON error: fixed text, never the request's.
    pub fn message(self) -> &'static str {
        use Refusal::*;
        match self {
            Version => "rusthorse-broker serves HTTP/1.1 only",
            Method => "CONNECT, TRACE and OPTIONS are not served",
            Target => "the request target must be a path (origin form)",
            Host => "the Host header must be the broker's own address, 127.0.0.1 and its port",
            TransferEncoding => {
                "a request body must be sent with Content-Length, not Transfer-Encoding"
            }
            Upgrade => "protocol upgrades are not served",
            Origin => "requests with an Origin header are not served",
            Connection => "the Connection header may only name close or keep-alive",
            BodyNotAllowed => "this route takes no request body",
            Token => "the request does not present this grant's token",
            Route => "this route is not allowed by the grant",
            BodyTooLarge => "the request body is larger than 16 MiB",
            NoRoom => "the broker holds too many request bodies; retry later",
            Revoked => {
                "the grant has ended; run the command again with rusthorse run for a new grant"
            }
            Expired => {
                "the grant has expired; run the command again with rusthorse run for a new grant"
            }
            Exhausted => {
                "the grant's request limit is reached; run the command again with rusthorse run \
                 for a new grant"
            }
            TooManyInFlight => "the grant has too many requests in flight; retry later",
            AuditFailed => "the request could not be recorded; it was not sent",
            BodyTimeout => "the request body did not arrive in time; it was not sent",
            Unreachable => "the destination could not be reached; nothing was sent",
            Redirect => {
                "the destination answered with a redirect, which the broker does not follow"
            }
            Encoded => {
                "the destination's response is compressed or encoded, which the broker refuses"
            }
            Unexpected => "the destination answered with an informational or upgrade status",
            DestinationFailed => {
                "the destination failed after the request was sent; its outcome is unknown"
            }
            DestinationTimeout => "the destination did not answer in time; its outcome is unknown",
        }
    }

    /// Whether the client may retry: then `x-should-retry: false` is left
    /// out.
    pub fn may_retry(self) -> bool {
        matches!(
            self,
            Refusal::TooManyInFlight
                | Refusal::NoRoom
                | Refusal::AuditFailed
                | Refusal::Unreachable
        )
    }

    /// Whether the answer carries `retry-after: 1`.
    pub fn retry_after(self) -> bool {
        matches!(self, Refusal::TooManyInFlight | Refusal::NoRoom)
    }

    /// Whether the connection is closed after the answer whatever the
    /// request's body: a framing error leaves the stream in doubt, and a
    /// body that was refused or cut leaves unread bytes.
    pub fn closes(self) -> bool {
        use Refusal::*;
        matches!(
            self,
            Version
                | Method
                | Target
                | Host
                | TransferEncoding
                | Upgrade
                | Origin
                | Connection
                | BodyNotAllowed
                | BodyTooLarge
                | BodyTimeout
        )
    }
}

impl From<AdmissionRefusal> for Refusal {
    fn from(refusal: AdmissionRefusal) -> Refusal {
        match refusal {
            AdmissionRefusal::Revoked => Refusal::Revoked,
            AdmissionRefusal::Expired => Refusal::Expired,
            AdmissionRefusal::Exhausted => Refusal::Exhausted,
            AdmissionRefusal::TooManyInFlight => Refusal::TooManyInFlight,
            AdmissionRefusal::AuditFailed => Refusal::AuditFailed,
        }
    }
}

/// The local answer for `refusal`. `unread_body` says whether the request
/// declared a body that was not read: the connection is then closed too.
pub fn local(refusal: Refusal, unread_body: bool) -> Response<ResponseBody> {
    let json = format!(
        r#"{{"type":"error","error":{{"type":"rusthorse_broker","message":"{MESSAGE_PREFIX}{}"}}}}"#,
        refusal.message()
    );
    let mut response = Response::new(ResponseBody::local(Bytes::from(json)));
    *response.status_mut() = refusal.status();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if !refusal.may_retry() {
        headers.insert(SHOULD_RETRY, HeaderValue::from_static("false"));
    }
    if refusal.retry_after() {
        headers.insert(RETRY_AFTER, HeaderValue::from(RETRY_AFTER_SECS));
    }
    if refusal.closes() || unread_body {
        headers.insert(CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// A piece of a relayed response body.
#[derive(Debug)]
pub enum Chunk {
    /// Bytes to pass on, already redacted.
    Data(Bytes),
    /// The whole body was passed on: end it cleanly.
    End,
}

/// A relayed body that stopped before its end: the client sees the stream
/// cut (no final chunk), never a clean end.
#[derive(Debug)]
pub struct Cut;

impl std::fmt::Display for Cut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the response was cut")
    }
}

impl std::error::Error for Cut {}

/// The body of every response the broker gives a client: a local one, sent
/// whole with its length, or a relayed one, streamed chunked from a channel
/// as the destination's arrives. Either keeps the connection busy while it
/// lives.
pub struct ResponseBody {
    kind: Kind,
    _busy: Option<BusyGuard>,
}

enum Kind {
    Local(Option<Bytes>),
    Relay {
        chunks: mpsc::Receiver<Chunk>,
        ended: bool,
    },
}

impl ResponseBody {
    /// A body sent whole.
    pub fn local(data: Bytes) -> ResponseBody {
        ResponseBody {
            kind: Kind::Local(Some(data).filter(|data| !data.is_empty())),
            _busy: None,
        }
    }

    /// A body passed on from `chunks`; ended cleanly only by
    /// [`Chunk::End`].
    pub fn relay(chunks: mpsc::Receiver<Chunk>) -> ResponseBody {
        ResponseBody {
            kind: Kind::Relay {
                chunks,
                ended: false,
            },
            _busy: None,
        }
    }

    /// Keep `busy` until the body is dropped.
    pub fn hold(mut self, busy: BusyGuard) -> ResponseBody {
        self._busy = Some(busy);
        self
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = Cut;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Cut>>> {
        match &mut self.kind {
            Kind::Local(data) => Poll::Ready(data.take().map(|data| Ok(Frame::data(data)))),
            Kind::Relay { chunks, ended } => {
                if *ended {
                    return Poll::Ready(None);
                }
                match chunks.poll_recv(cx) {
                    Poll::Ready(Some(Chunk::Data(data))) => {
                        Poll::Ready(Some(Ok(Frame::data(data))))
                    }
                    Poll::Ready(Some(Chunk::End)) => {
                        *ended = true;
                        Poll::Ready(None)
                    }
                    // The relay stopped without an end: cut the stream.
                    Poll::Ready(None) => {
                        *ended = true;
                        Poll::Ready(Some(Err(Cut)))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.kind {
            Kind::Local(data) => data.is_none(),
            Kind::Relay { ended, .. } => *ended,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.kind {
            Kind::Local(data) => SizeHint::with_exact(data.as_ref().map_or(0, |d| d.len() as u64)),
            // Unknown: hyper sends it chunked, never with a Content-Length.
            Kind::Relay { .. } => SizeHint::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    const ALL: [Refusal; 25] = [
        Refusal::Version,
        Refusal::Method,
        Refusal::Target,
        Refusal::Host,
        Refusal::TransferEncoding,
        Refusal::Upgrade,
        Refusal::Origin,
        Refusal::Connection,
        Refusal::BodyNotAllowed,
        Refusal::Token,
        Refusal::Route,
        Refusal::BodyTooLarge,
        Refusal::NoRoom,
        Refusal::Revoked,
        Refusal::Expired,
        Refusal::Exhausted,
        Refusal::TooManyInFlight,
        Refusal::AuditFailed,
        Refusal::BodyTimeout,
        Refusal::Unreachable,
        Refusal::Redirect,
        Refusal::Encoded,
        Refusal::Unexpected,
        Refusal::DestinationFailed,
        Refusal::DestinationTimeout,
    ];

    #[test]
    fn local_answers_have_the_statuses_of_adr_0013() {
        let status = |r: Refusal| r.status().as_u16();
        for framing in [
            Refusal::Method,
            Refusal::Target,
            Refusal::Host,
            Refusal::TransferEncoding,
            Refusal::Upgrade,
            Refusal::Origin,
            Refusal::Connection,
            Refusal::BodyNotAllowed,
        ] {
            assert_eq!(status(framing), 400, "{framing:?}");
        }
        assert_eq!(status(Refusal::Version), 505);
        assert_eq!(status(Refusal::Token), 401);
        assert_eq!(status(Refusal::Route), 404);
        assert_eq!(status(Refusal::BodyTooLarge), 413);
        assert_eq!(status(Refusal::NoRoom), 503);
        for ended in [Refusal::Revoked, Refusal::Expired, Refusal::Exhausted] {
            assert_eq!(status(ended), 403, "{ended:?}");
        }
        assert_eq!(status(Refusal::TooManyInFlight), 429);
        assert_eq!(status(Refusal::AuditFailed), 503);
        assert_eq!(status(Refusal::BodyTimeout), 408);
        assert_eq!(status(Refusal::Unreachable), 502);
        assert_eq!(status(Refusal::Redirect), 502);
        assert_eq!(status(Refusal::Encoded), 502);
        assert_eq!(status(Refusal::DestinationTimeout), 504);
        // The agent's refusals map as the control channel says.
        assert_eq!(status(AdmissionRefusal::Revoked.into()), 403);
        assert_eq!(status(AdmissionRefusal::Expired.into()), 403);
        assert_eq!(status(AdmissionRefusal::Exhausted.into()), 403);
        assert_eq!(status(AdmissionRefusal::TooManyInFlight.into()), 429);
        assert_eq!(status(AdmissionRefusal::AuditFailed.into()), 503);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_answers_are_short_json_with_the_retry_headers() {
        for refusal in ALL {
            let response = local(refusal, false);
            let headers = response.headers().clone();
            assert_eq!(response.status(), refusal.status());
            assert_eq!(headers["content-type"], "application/json");
            // Only 429, 503 and a 502 before anything was sent may be
            // retried.
            let retriable =
                matches!(refusal.status().as_u16(), 429 | 503) || refusal == Refusal::Unreachable;
            assert_eq!(
                headers.get(SHOULD_RETRY).map(|v| v.as_bytes()),
                (!retriable).then_some(&b"false"[..]),
                "{refusal:?}"
            );
            assert_eq!(
                headers.get("retry-after").map(|v| v.as_bytes()),
                matches!(refusal, Refusal::NoRoom | Refusal::TooManyInFlight).then_some(&b"1"[..]),
                "{refusal:?}"
            );
            assert_eq!(
                headers.get("connection").is_some(),
                refusal.closes(),
                "{refusal:?}"
            );
            let body = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
            assert_eq!(json["type"], "error");
            assert_eq!(json["error"]["type"], "rusthorse_broker");
            assert_eq!(
                json["error"]["message"],
                format!("rusthorse-broker: {}", refusal.message())
            );
            assert!(body.len() < 200, "{refusal:?}: {} bytes", body.len());
            // A grant that has ended says how to get a new one.
            assert_eq!(
                refusal
                    .message()
                    .contains("run the command again with rusthorse run"),
                refusal.status() == 403,
                "{refusal:?}"
            );
        }
        // Any refusal of a request whose body was not read closes.
        let response = local(Refusal::Token, true);
        assert_eq!(response.headers()["connection"], "close");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_relayed_body_ends_cleanly_only_when_told_to() {
        let (tx, rx) = mpsc::channel(4);
        tx.send(Chunk::Data(Bytes::from_static(b"data: one\n\n")))
            .await
            .expect("send");
        tx.send(Chunk::End).await.expect("send");
        let body = ResponseBody::relay(rx);
        assert_eq!(body.size_hint().exact(), None, "never a Content-Length");
        let got = body.collect().await.expect("a clean end").to_bytes();
        assert_eq!(&got[..], b"data: one\n\n");

        let (tx, rx) = mpsc::channel(4);
        tx.send(Chunk::Data(Bytes::from_static(b"partial")))
            .await
            .expect("send");
        drop(tx);
        let mut body = ResponseBody::relay(rx);
        let first = body.frame().await.expect("a frame").expect("data");
        assert_eq!(
            first.into_data().expect("data"),
            Bytes::from_static(b"partial")
        );
        assert!(
            body.frame().await.expect("an error").is_err(),
            "the stream is cut"
        );
        assert!(body.frame().await.is_none());
    }
}
