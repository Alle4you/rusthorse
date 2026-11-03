//! An admitted request, from the agent's answer to the end of its response
//! (ADR 0013, steps 5 to 8): the body read whole, the destination reached
//! over TLS, the request built from what was checked, the response checked
//! and streamed through the redactor.
//!
//! Each request asked for admission runs in a task of its own, which gives
//! the client its response head over a channel and its body as a stream of
//! chunks, so that its end is decided in one place whatever stops it: the
//! end of the response, a deadline, the client going away, or the grant
//! being revoked. That task reports the end of every admitted request with
//! `finished` exactly once, after it has dropped what it held of the
//! credential.
//!
//! The outcomes (`RequestOutcome`): `not_forwarded` when nothing was sent
//! (the body did not arrive in time or the client went away first, or
//! resolving, connecting or TLS failed); `revoked` when a revocation closed
//! the request before anything was sent (an `admitted` that came after the
//! revocation included); `client_closed` when the client went away, or
//! stopped reading, once something was sent; `completed` when the whole
//! response was passed on; `unknown` for anything else once the request may
//! have reached the destination, a revocation during it included.
//!
//! A revocation closes the client's connection too, so a request open then
//! sees its client go at the same moment. Every wait therefore looks at the
//! revocation first (`biased` selects): once the grant is revoked, the
//! request's next step is the revocation's, whatever else became ready. The
//! runtime has a single thread and the revocation comes from another task,
//! so it cannot happen while this one runs; each time this one runs again,
//! the first thing it polls is a wait on the revocation, with tokio's
//! cooperative budget fresh (a wait polled once that budget is spent may
//! say "not yet" without looking, but nothing can have changed by then).
//! So a client found gone anywhere else left before the revocation.
//!
//! The room a request's body reserved in the broker's budget comes back
//! only once the broker holds none of the body. Two holders share it
//! ([`held_body`]): the request keeps it until the destination's response
//! head has arrived, or until the request ends; and the body's bytes keep
//! it for as long as any of them is alive, in hyper's queue of bytes not yet
//! written to the destination's connection among them. hyper drops the
//! request body it sends as soon as it has taken its bytes, long before it
//! has written them all; it keeps the bytes until the destination has read
//! them or the connection is dropped.
//!
//! What it holds of the credential is wiped when dropped, except the copy
//! in the header value that hyper sends, which is an ordinary buffer
//! (`HeaderValue`, marked sensitive so that it is never printed).

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::header::{ACCEPT_ENCODING, CONTENT_LENGTH, HOST};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::TokioIo;
use rusthorse::broker_profile::MatchedRoute;
use rusthorse::broker_protocol::{AdmissionRefusal, MAX_RESPONSE_BODY_BYTES, RequestOutcome};
use rusthorse::protocol::SecretString;
use rusthorse::redact::Redactor;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::answer::{Chunk, Refusal, ResponseBody, local};
use crate::grant::{Answer, Ended, Grant, Reservation};
use crate::headers;
use crate::server::Server;

/// Chunks of a relayed body waiting for the client.
const RELAY_QUEUE: usize = 8;

/// The label of the credential in redacted text: `[REDACTED:credential]`.
const REDACTED_LABEL: &str = "credential";

/// A request whose admission was asked.
pub struct Admission {
    /// Its number on the control channel.
    pub request: u64,
    /// Where the agent's answer will come.
    pub answer: oneshot::Receiver<Answer>,
    /// Its method.
    pub method: Method,
    /// The route it matched, and the target that is sent.
    pub matched: MatchedRoute,
    /// The client's headers, all of them.
    pub headers: HeaderMap,
    /// Its body, not read yet.
    pub body: Incoming,
    /// The body's declared length.
    pub body_len: u64,
    /// The room reserved for the body.
    pub reservation: Reservation,
}

/// Run an admission in a task of its own and give the client its response.
pub async fn respond(server: Arc<Server>, admission: Admission) -> Response<ResponseBody> {
    let (head, response) = oneshot::channel();
    tokio::spawn(run(server, admission, head));
    // Without a head the request was closed (by a revocation, whose
    // connections are dropped anyway): nothing is relayed.
    response
        .await
        .unwrap_or_else(|_| local(Refusal::Revoked, true))
}

/// The client's side of a request: where its response head goes.
struct Client {
    head: Option<oneshot::Sender<Response<ResponseBody>>>,
}

impl Client {
    /// Give the client `response`; whether it is still there to take it.
    fn answer(&mut self, response: Response<ResponseBody>) -> bool {
        self.head
            .take()
            .is_some_and(|head| head.send(response).is_ok())
    }

    /// Whether the client went away before its answer.
    fn is_gone(&self) -> bool {
        self.head.as_ref().is_none_or(|head| head.is_closed())
    }

    /// Wait until the client goes away before its answer.
    async fn gone(&mut self) {
        match &mut self.head {
            Some(head) => head.closed().await,
            None => std::future::pending().await,
        }
    }
}

/// Reports an admitted request's end once: explicitly, or, should the task
/// end otherwise, as `unknown`.
struct Record {
    grant: Arc<Grant>,
    request: u64,
    sent: Arc<AtomicU64>,
    done: bool,
}

impl Record {
    fn finish(mut self, outcome: RequestOutcome, status: Option<u16>, received: u64) {
        self.done = true;
        self.grant.finish(
            self.request,
            Ended {
                outcome,
                status,
                bytes_sent: self.sent.load(Ordering::Relaxed),
                bytes_received: received,
            },
        );
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        if !self.done {
            self.grant.finish(
                self.request,
                Ended {
                    outcome: RequestOutcome::Unknown,
                    status: None,
                    bytes_sent: self.sent.load(Ordering::Relaxed),
                    bytes_received: 0,
                },
            );
        }
    }
}

/// How the forwarding of an admitted request ended.
struct Outcome {
    outcome: RequestOutcome,
    status: Option<u16>,
    received: u64,
}

impl Outcome {
    fn new(outcome: RequestOutcome, status: Option<u16>) -> Outcome {
        Outcome {
            outcome,
            status,
            received: 0,
        }
    }

    fn received(mut self, received: u64) -> Outcome {
        self.received = received;
        self
    }
}

async fn run(
    server: Arc<Server>,
    admission: Admission,
    head: oneshot::Sender<Response<ResponseBody>>,
) {
    let mut client = Client { head: Some(head) };
    let Admission {
        request,
        answer,
        method,
        matched,
        headers,
        body,
        body_len,
        reservation,
    } = admission;
    // The grant keeps the sender until the agent answers.
    let answer = answer
        .await
        .unwrap_or(Answer::Refused(AdmissionRefusal::Revoked));
    if let Answer::Refused(reason) = answer {
        client.answer(local(reason.into(), body_len > 0));
        return;
    }
    let sent = Arc::new(AtomicU64::new(0));
    let record = Record {
        grant: Arc::clone(&server.grant),
        request,
        sent: Arc::clone(&sent),
        done: false,
    };
    let request = Forward {
        method,
        matched,
        headers,
        body,
        body_len,
        reservation,
        sent,
    };
    // Everything the forwarding held, the credential's copies among them,
    // is dropped before `finished` is sent.
    let ended = forward(&server, request, &mut client).await;
    record.finish(ended.outcome, ended.status, ended.received);
}

/// What an admitted request forwards.
struct Forward {
    method: Method,
    matched: MatchedRoute,
    headers: HeaderMap,
    body: Incoming,
    body_len: u64,
    reservation: Reservation,
    sent: Arc<AtomicU64>,
}

/// Steps 6 to 8.
async fn forward(server: &Server, request: Forward, client: &mut Client) -> Outcome {
    use RequestOutcome::*;
    let grant = &server.grant;
    let limits = &server.limits;
    let mut revoked = grant.subscribe();
    // How a request ends when its client went away, `sent` saying whether
    // anything may have reached the destination. Never after a revocation:
    // every wait below looks at it first.
    let left = |sent: bool| if sent { ClientClosed } else { NotForwarded };
    // An admission answered after the revocation is not forwarded.
    if grant.is_revoked() {
        return Outcome::new(Revoked, None);
    }
    if client.is_gone() {
        return Outcome::new(left(false), None);
    }

    // 6. The body, whole, within its deadline.
    let body = tokio::select! {
        biased;
        _ = revoked.wait_for(|revoked| *revoked) => return Outcome::new(Revoked, None),
        body = timeout(limits.request_body, read_body(request.body, request.body_len)) => match body {
            Ok(Some(body)) => body,
            // Cut short: the client went away.
            Ok(None) => return Outcome::new(left(false), None),
            Err(_) => {
                client.answer(local(Refusal::BodyTimeout, true));
                return Outcome::new(NotForwarded, Some(408));
            }
        },
        _ = client.gone() => return Outcome::new(left(false), None),
    };
    // The body's room: held here until the response head arrives, and by
    // the body's bytes for as long as any of them is alive.
    let room = Arc::new(request.reservation);
    let body = held_body(body, Arc::clone(&room));
    let Some(credential) = grant.credential() else {
        return Outcome::new(Revoked, None);
    };

    // 7. The destination: resolved, connected, TLS.
    let unreachable = |client: &mut Client| {
        client.answer(local(Refusal::Unreachable, false));
        Outcome::new(NotForwarded, Some(502))
    };
    let tcp = tokio::select! {
        biased;
        _ = revoked.wait_for(|revoked| *revoked) => return Outcome::new(Revoked, None),
        tcp = server.destination.connect() => match tcp {
            Ok(tcp) => tcp,
            Err(_) => return unreachable(client),
        },
        _ = client.gone() => return Outcome::new(left(false), None),
    };
    let _ = tcp.set_nodelay(true);
    let handshake = server.tls.connect(server.server_name.clone(), tcp);
    let tls = tokio::select! {
        biased;
        _ = revoked.wait_for(|revoked| *revoked) => return Outcome::new(Revoked, None),
        tls = timeout(limits.tls_handshake, handshake) => match tls {
            Ok(Ok(tls)) => tls,
            _ => return unreachable(client),
        },
        _ = client.gone() => return Outcome::new(left(false), None),
    };
    // Writes queued as they are, never copied into hyper's own buffer: the
    // body's bytes stay in the allocation that keeps its room until they are
    // written (`held_body`).
    let Ok((mut sender, connection)) = hyper::client::conn::http1::Builder::new()
        .writev(true)
        .handshake::<_, OutBody>(TokioIo::new(tls))
        .await
    else {
        return unreachable(client);
    };
    let _connection = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let body = OutBody::new(body, request.sent);
    let Some(outgoing) = build_request(
        server,
        &request.method,
        &request.matched,
        &request.headers,
        body,
        &credential,
    ) else {
        return unreachable(client);
    };
    drop(request.headers);

    // From here on, the request may reach the destination.
    let response = tokio::select! {
        biased;
        _ = revoked.wait_for(|revoked| *revoked) => return Outcome::new(Unknown, None),
        response = timeout(limits.response_headers, sender.send_request(outgoing)) => match response {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                client.answer(local(Refusal::DestinationFailed, false));
                return Outcome::new(Unknown, Some(502));
            }
            Err(_) => {
                client.answer(local(Refusal::DestinationTimeout, false));
                return Outcome::new(Unknown, Some(504));
            }
        },
        _ = client.gone() => return Outcome::new(left(true), None),
    };
    // The destination answered: from now on, only the bytes of the body
    // that hyper has not written yet keep its room.
    drop(room);

    // 8. The response: checked before anything is passed on.
    let status = response.status();
    let code = Some(status.as_u16());
    if let Err(refusal) = headers::check_response(status, response.headers()) {
        client.answer(local(refusal, false));
        return Outcome::new(Unknown, code);
    }
    let (head, mut body) = response.into_parts();
    let secrets = [credential.as_bytes(), grant.token().as_bytes()];
    let relayed = headers::relayed(grant.spec(), &head.headers, &secrets);
    if status == StatusCode::NO_CONTENT {
        // Nothing to stream.
        let mut answer = Response::new(ResponseBody::local(Bytes::new()));
        *answer.status_mut() = status;
        *answer.headers_mut() = relayed;
        let delivered = client.answer(answer);
        return Outcome::new(if delivered { Completed } else { left(true) }, code);
    }
    let (chunks, stream) = mpsc::channel(RELAY_QUEUE);
    let mut answer = Response::new(ResponseBody::relay(stream));
    *answer.status_mut() = status;
    *answer.headers_mut() = relayed;
    if !client.answer(answer) {
        return Outcome::new(left(true), code);
    }
    let mut redactor = Redactor::new([(REDACTED_LABEL, credential.as_bytes())]);
    let pause = limits.response_body_idle;
    let mut received: u64 = 0;
    loop {
        let frame = tokio::select! {
            biased;
            _ = revoked.wait_for(|revoked| *revoked) => {
                return Outcome::new(Unknown, code).received(received);
            }
            frame = timeout(pause, body.frame()) => frame,
            // The client went away while the destination was quiet.
            _ = chunks.closed() => return Outcome::new(left(true), code).received(received),
        };
        let (data, end) = match frame {
            Ok(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => (data, false),
                // Trailers are dropped.
                Err(_) => continue,
            },
            Ok(None) => (Bytes::new(), true),
            // The destination failed, paused too long or cut the stream.
            Ok(Some(Err(_))) | Err(_) => return Outcome::new(Unknown, code).received(received),
        };
        received = received.saturating_add(data.len() as u64);
        if received > MAX_RESPONSE_BODY_BYTES {
            // Too long: the stream is cut.
            return Outcome::new(Unknown, code).received(received);
        }
        let mut safe = redactor.push(&data);
        if end {
            safe.extend(redactor.finish());
        }
        let mut pieces = Vec::with_capacity(2);
        if !safe.is_empty() {
            pieces.push(Chunk::Data(Bytes::from(safe)));
        }
        if end {
            pieces.push(Chunk::End);
        }
        for piece in pieces {
            match deliver(&chunks, piece, pause, &mut revoked).await {
                Delivery::Delivered => {}
                Delivery::Gone => return Outcome::new(left(true), code).received(received),
                Delivery::Revoked => return Outcome::new(Unknown, code).received(received),
            }
        }
        if end {
            return Outcome::new(Completed, code).received(received);
        }
    }
}

/// What became of a chunk for the client.
enum Delivery {
    Delivered,
    /// The client went away, or took no chunk for the longest pause allowed.
    Gone,
    Revoked,
}

async fn deliver(
    chunks: &mpsc::Sender<Chunk>,
    chunk: Chunk,
    pause: Duration,
    revoked: &mut watch::Receiver<bool>,
) -> Delivery {
    tokio::select! {
        biased;
        _ = revoked.wait_for(|revoked| *revoked) => Delivery::Revoked,
        sent = timeout(pause, chunks.send(chunk)) => match sent {
            Ok(Ok(())) => Delivery::Delivered,
            Ok(Err(_)) | Err(_) => Delivery::Gone,
        },
    }
}

/// Read a body of `len` bytes whole; `None` if it ends early or breaks.
async fn read_body(mut body: Incoming, len: u64) -> Option<BytesMut> {
    let len = usize::try_from(len).ok()?;
    let mut whole = BytesMut::with_capacity(len);
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.ok()?.into_data() {
            if data.len() > len - whole.len() {
                return None;
            }
            whole.extend_from_slice(&data);
        }
    }
    (whole.len() == len).then_some(whole)
}

/// A request body read whole, and its share of the body's room in the
/// budget.
struct HeldBody {
    data: BytesMut,
    _room: Arc<Reservation>,
}

impl AsRef<[u8]> for HeldBody {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// The bytes of a request body read whole, which keep a share of `room`
/// until the last of them is dropped, wherever they went meanwhile (hyper
/// keeps the ones it has not written yet). The room comes back once every
/// share of it is dropped.
fn held_body(data: BytesMut, room: Arc<Reservation>) -> Bytes {
    Bytes::from_owner(HeldBody { data, _room: room })
}

/// The request to the destination, from what was checked: the method, the
/// target exactly as matched, `Host` the profile's authority, the client's
/// headers the preset forwards (none carrying the token or the credential),
/// `Accept-Encoding: identity`, `Content-Length` for a method with a body,
/// and the credential header the broker builds.
fn build_request(
    server: &Server,
    method: &Method,
    matched: &MatchedRoute,
    client: &HeaderMap,
    body: OutBody,
    credential: &SecretString,
) -> Option<Request<OutBody>> {
    let grant = &server.grant;
    let spec = grant.spec();
    let secrets = [grant.token().as_bytes(), credential.as_bytes()];
    let mut headers = headers::forwarded(spec, client, &secrets);
    headers.insert(
        HOST,
        HeaderValue::from_str(grant.profile().authority()).ok()?,
    );
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    if method == Method::POST {
        headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
    let header = spec.credential_header;
    let mut value = HeaderValue::from_str(&header.value(credential)).ok()?;
    value.set_sensitive(true);
    headers.insert(HeaderName::from_static(header.name()), value);
    let mut outgoing = Request::new(body);
    *outgoing.method_mut() = method.clone();
    *outgoing.uri_mut() = Uri::try_from(matched.path_and_query.as_str()).ok()?;
    *outgoing.version_mut() = Version::HTTP_11;
    *outgoing.headers_mut() = headers;
    Some(outgoing)
}

/// A request body sent whole, counting what was handed to the connection.
/// hyper drops it as soon as it has taken its bytes, long before it has
/// written them all: the bytes themselves keep their share of the body's
/// room ([`held_body`]).
pub struct OutBody {
    data: Option<Bytes>,
    len: u64,
    sent: Arc<AtomicU64>,
}

impl OutBody {
    fn new(data: Bytes, sent: Arc<AtomicU64>) -> OutBody {
        OutBody {
            len: data.len() as u64,
            data: Some(data).filter(|data| !data.is_empty()),
            sent,
        }
    }

    fn len(&self) -> u64 {
        self.len
    }
}

impl Body for OutBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let data = self.data.take();
        if let Some(data) = &data {
            self.sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        Poll::Ready(data.map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.as_ref().map_or(0, |data| data.len() as u64))
    }
}

/// A task stopped when this is dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Budget;
    use bytes::Buf;

    fn body_of(data: &[u8], room: &Arc<Reservation>) -> Bytes {
        held_body(BytesMut::from(data), Arc::clone(room))
    }

    #[test]
    fn a_bodys_room_comes_back_once_neither_the_request_nor_its_bytes_hold_it() {
        let budget = Budget::new(100);
        // The request lets go first; hyper still holds bytes not written.
        let room = Arc::new(budget.reserve(60).expect("fits"));
        let body = body_of(b"0123456789", &room);
        let mut queued = body.clone();
        drop(body);
        queued.advance(4);
        drop(room);
        assert_eq!(budget.held(), 60, "the unwritten bytes hold it");
        assert_eq!(&queued[..], b"456789");
        drop(queued);
        assert_eq!(budget.held(), 0);
        // The bytes go first (all written); the request still holds it.
        let room = Arc::new(budget.reserve(60).expect("fits"));
        drop(body_of(b"0123456789", &room));
        assert_eq!(budget.held(), 60, "the request holds it");
        drop(room);
        assert_eq!(budget.held(), 0);
    }
}
