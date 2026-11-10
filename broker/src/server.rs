//! Serving the grant once the broker is ready: the listening socket, each
//! client connection, and steps 1 to 4 of every request (ADR 0013,
//! "Requests and responses", as its scope amendment changes them) before
//! an admitted one goes on in `exchange`.
//!
//! Connections: at most the install's `max_connections` are open at once
//! (one more is closed as soon as it is accepted); a request's head must
//! arrive within the header deadline of the connection's opening or of the
//! previous response, and of at most `MAX_REQUEST_HEADER_BYTES` bytes and
//! `MAX_REQUEST_HEADERS` header lines (`431`); a
//! connection with no request in progress is closed after the idle
//! deadline; every connection open when the grant closes — revoked, or past
//! its lifetime, which a task of its own watches — is closed at once.
//! HTTP/1.1 only, without upgrades.
//!
//! Requests, in order: the framing (`400`, `505`), the token and the key in
//! its place (`401`, `token`), room for the body (`413`, `503`), the
//! admission (`403`, `429`, `503`, or the agent's answer), which names the
//! request by its method's label alone. There is no route: the target goes
//! to the approved origin as the client sent it. A request that hyper cannot
//! parse it answers itself (`400`, or `431` for a head too large or with
//! too many header lines) and closes the connection. Every request refused
//! before its admission was asked, those included, is counted, for
//! `revoked`; once the grant is closed,
//! every request that passes the token gets `403`.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::header::CONTENT_LENGTH;
use http::{HeaderValue, Request, Response};
use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rusthorse::broker_grant::{self, MethodLabel};
use rusthorse::broker_protocol::{
    FromBroker, MAX_REQUEST_BODY_BYTES, MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS,
    REQUEST_BODY_BUDGET_BYTES, VERSION,
};
use rustls_pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::answer::{self, Refusal, ResponseBody};
use crate::config::{Config, Limits};
use crate::destination::Destination;
use crate::exchange::{self, Admission};
use crate::grant::{Budget, Grant};
use crate::setup::Prepared;
use crate::{EXIT_SETUP, control, framing, headers, token};

/// The largest buffer of a client connection: a whole head fits.
const MAX_BUFFER_BYTES: usize = 64 * 1024;

const _: () = assert!(MAX_REQUEST_HEADER_BYTES < MAX_BUFFER_BYTES);

/// Everything every connection and request shares.
pub struct Server {
    /// The grant.
    pub grant: Arc<Grant>,
    /// Room for request bodies.
    pub budget: Arc<Budget>,
    /// `127.0.0.1:PORT`: the only `Host` served.
    pub host: String,
    /// The approved origin's authority: the `Host` the destination gets.
    pub authority: HeaderValue,
    /// How the destination is reached.
    pub destination: Destination,
    /// TLS to the destination.
    pub tls: TlsConnector,
    /// The destination's host, for SNI and the certificate's name.
    pub server_name: ServerName<'static>,
    /// The deadlines.
    pub limits: Limits,
    /// The most client connections open at once.
    pub max_connections: usize,
    /// Whether handling a request panics, as an internal error would (a
    /// hook of the test feature, for the test of the panic hook).
    #[cfg(feature = "test-upstream")]
    pub panic_on_request: bool,
}

/// Answer `ready` and serve the grant until the control channel ends or the
/// agent breaks it; returns the broker's exit status. Whatever can fail is
/// done before `ready` is queued, the first message: a broker that cannot
/// serve exits without answering.
pub async fn run(prepared: Prepared, config: Config) -> u8 {
    let Prepared {
        control,
        install,
        received,
        listener,
        port,
        tls,
    } = prepared;
    // The approved origin, which `Install::validate` checked: the host,
    // the port, the TLS server name and `Host` all come from it.
    let approved = broker_grant::Destination {
        origin: install.origin.clone(),
        base_path: String::new(),
    };
    let Ok(server_name) = ServerName::try_from(approved.host().to_string()) else {
        return EXIT_SETUP;
    };
    let Ok(authority) = HeaderValue::from_str(approved.authority()) else {
        return EXIT_SETUP;
    };
    let listener = match listener
        .set_nonblocking(true)
        .and_then(|()| TcpListener::from_std(listener))
    {
        Ok(listener) => listener,
        Err(_) => return EXIT_SETUP,
    };
    let control = match control
        .set_nonblocking(true)
        .and_then(|()| tokio::net::UnixStream::from_std(control))
    {
        Ok(control) => control,
        Err(_) => return EXIT_SETUP,
    };
    let (from_agent, to_agent) = control.into_split();
    let (queue, queued) = mpsc::unbounded_channel();
    let ready = FromBroker::Ready {
        version: VERSION,
        grant: install.grant.clone(),
    };
    if queue.send(ready).is_err() {
        return EXIT_SETUP;
    }
    let destination = Destination::new(approved.host(), approved.port(), &config);
    let max_connections = install.max_connections as usize;
    let server = Arc::new(Server {
        grant: Grant::new(install, received, queue),
        budget: Budget::new(REQUEST_BODY_BUDGET_BYTES),
        host: format!("127.0.0.1:{port}"),
        authority,
        destination,
        tls: TlsConnector::from(tls),
        server_name,
        limits: config.limits,
        max_connections,
        #[cfg(feature = "test-upstream")]
        panic_on_request: config.panic_on_request,
    });
    // The grant closes when its lifetime ends, whether or not the agent
    // says `revoke` by then.
    tokio::spawn(Arc::clone(&server.grant).watch_lifetime(config.lifetime_lag));
    tokio::spawn(accept(listener, Arc::clone(&server)));
    tokio::select! {
        code = control::read(from_agent, &server.grant) => code,
        code = control::write(to_agent, queued) => code,
    }
}

/// Accept connections for ever, at most `max_connections` open at once.
async fn accept(listener: TcpListener, server: Arc<Server>) {
    let slots = Arc::new(Semaphore::new(server.max_connections));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => match Arc::clone(&slots).try_acquire_owned() {
                Ok(slot) => {
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(connection(stream, Arc::clone(&server), slot));
                }
                // One too many: closed at once.
                Err(_) => drop(stream),
            },
            // Out of descriptors, most likely: wait instead of spinning.
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Serve one client connection until it ends, it idles too long, or the
/// grant closes (if it was open then).
async fn connection(stream: TcpStream, server: Arc<Server>, _slot: OwnedSemaphorePermit) {
    let activity = Activity::new();
    let open_at_closing = !server.grant.is_closed();
    let mut closed = server.grant.subscribe();
    let service = {
        let server = Arc::clone(&server);
        let activity = Arc::clone(&activity);
        service_fn(move |request| handle(request, Arc::clone(&server), Arc::clone(&activity)))
    };
    // The broker's own limit on the number of headers, not hyper's default
    // (the same number today), which a new version could change: hyper
    // counts header lines and answers one too many with `431`.
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(server.limits.request_header)
        .max_header_size(MAX_REQUEST_HEADER_BYTES)
        .max_headers(MAX_REQUEST_HEADERS)
        .max_buf_size(MAX_BUFFER_BYTES)
        .keep_alive(true)
        .half_close(false);
    let served = http.serve_connection(TokioIo::new(stream), service);
    // Dropping the connection closes it, and the stream in it.
    tokio::select! {
        served = served => {
            // hyper answered a malformed request itself (`400`, `431`) and
            // closed the connection: one more request refused before its
            // admission was asked.
            if served.is_err_and(|e| e.is_parse()) {
                server.grant.count_refusal();
            }
        }
        _ = closed.wait_for(|closed| *closed), if open_at_closing => {}
        _ = activity.idle(server.limits.idle_connection) => {}
    }
}

/// One request: steps 1 to 4 here, the rest in `exchange`.
async fn handle(
    request: Request<Incoming>,
    server: Arc<Server>,
    activity: Arc<Activity>,
) -> Result<Response<ResponseBody>, Infallible> {
    #[cfg(feature = "test-upstream")]
    if server.panic_on_request {
        panic!("a panic of the test feature, as an internal error would be");
    }
    let busy = activity.start();
    let response = match screen(&server, request) {
        Ok(admission) => exchange::respond(Arc::clone(&server), admission).await,
        Err((refusal, unread_body)) => {
            server.grant.count_refusal();
            answer::local(refusal, unread_body)
        }
    };
    Ok(response.map(|body| body.hold(busy)))
}

/// Steps 1 to 4 up to the question to the agent: the admission asked, or
/// the local refusal and whether the request's body is left unread.
fn screen(server: &Server, request: Request<Incoming>) -> Result<Admission, (Refusal, bool)> {
    let (parts, body) = request.into_parts();
    let declared = body.size_hint().exact();
    let unread = declared != Some(0);
    let refuse = |refusal: Refusal| (refusal, unread);
    let grant = &server.grant;
    // 1. The framing.
    let framed = framing::check(
        &parts.method,
        &parts.uri,
        parts.version,
        &parts.headers,
        declared,
        &server.host,
    )
    .map_err(refuse)?;
    let body_len = framed.body_len;
    // What the broker sets itself: `Host`, `Accept-Encoding`, and the
    // length the client declared, if it declared one.
    let declared_length = parts.headers.contains_key(CONTENT_LENGTH);
    let own = headers::own(&server.authority, declared_length.then_some(body_len));
    // 2. The token where the key goes, and the head the broker would send
    // with the key in. Without the key (the grant is closed), the admission
    // refuses the request below.
    let credential = grant.credential();
    token::check(
        parts.method.as_str().as_bytes(),
        framed.target.as_bytes(),
        &parts.headers,
        &own,
        grant.token().as_bytes(),
        credential.as_ref().map(|key| key.as_bytes()),
    )
    .map_err(|refusal| refuse(refusal.into()))?;
    drop(credential);
    // 3. Room for the body.
    if body_len > MAX_REQUEST_BODY_BYTES as u64 {
        return Err(refuse(Refusal::BodyTooLarge));
    }
    let reservation = server
        .budget
        .reserve(body_len)
        .ok_or_else(|| refuse(Refusal::NoRoom))?;
    // 4. The admission: the broker's own checks, then the question, with
    // the method's label alone.
    let (number, answer) = grant
        .ask_admission(MethodLabel::of(parts.method.as_str()))
        .map_err(|held| refuse(held.into()))?;
    Ok(Admission {
        request: number,
        answer,
        method: parts.method,
        target: parts.uri,
        headers: parts.headers,
        own,
        body,
        body_len,
        reservation,
    })
}

/// Whether a connection has a request in progress, and since when it has
/// had none.
pub struct Activity {
    state: Mutex<(usize, Instant)>,
    changed: Notify,
}

/// A request in progress on a connection: from its head until its response
/// body is dropped.
pub struct BusyGuard(Arc<Activity>);

impl Activity {
    fn new() -> Arc<Activity> {
        Arc::new(Activity {
            state: Mutex::new((0, Instant::now())),
            changed: Notify::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (usize, Instant)> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn start(self: &Arc<Self>) -> BusyGuard {
        self.lock().0 += 1;
        self.changed.notify_one();
        BusyGuard(Arc::clone(self))
    }

    /// Return once the connection has had no request in progress for
    /// `limit`.
    async fn idle(&self, limit: Duration) {
        loop {
            let (busy, since) = *self.lock();
            if busy > 0 {
                self.changed.notified().await;
                continue;
            }
            tokio::select! {
                _ = tokio::time::sleep_until(since + limit) => return,
                _ = self.changed.notified() => {}
            }
        }
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.0 -= 1;
        if state.0 == 0 {
            state.1 = Instant::now();
        }
        drop(state);
        self.0.changed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_connection_idles_only_without_a_request_in_progress() {
        let activity = Activity::new();
        let limit = Duration::from_secs(60);
        // Idle from the start.
        let started = Instant::now();
        activity.idle(limit).await;
        assert_eq!(started.elapsed(), limit);
        // Not while busy, however long.
        let busy = activity.start();
        let waited = tokio::time::timeout(Duration::from_secs(600), activity.idle(limit)).await;
        assert!(waited.is_err(), "idle while a request was in progress");
        // From the end of the request.
        let ended = Instant::now();
        drop(busy);
        activity.idle(limit).await;
        assert_eq!(ended.elapsed(), limit);
        // A request that starts and ends meanwhile restarts the clock (the
        // connection has been idle for the whole limit by now: a request
        // ends first, so that the wait starts afresh).
        drop(activity.start());
        let idle = tokio::spawn({
            let activity = Arc::clone(&activity);
            async move { activity.idle(limit).await }
        });
        tokio::time::sleep(Duration::from_secs(30)).await;
        let restarted = Instant::now();
        drop(activity.start());
        idle.await.expect("join");
        assert_eq!(restarted.elapsed(), limit);
    }
}
