//! The test harness of `rusthorse-broker`: a certificate authority made for
//! the test, a fake HTTPS destination in the test process that records
//! exactly what it receives, the real broker program played by a fake agent
//! over a socket pair, and a small HTTP/1.1 client that talks to the broker
//! over raw TCP.
//!
//! Every key here is fake, and nothing leaves the loopback interface.

#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rusthorse::broker_profile::{BrokerProfile, Preset, ProfileRequest};
use rusthorse::broker_protocol::{
    self, AdmissionRefusal, EndReason, FromBroker, Install, MAX_CONNECTIONS, MAX_IN_FLIGHT,
    ToBroker, VERSION,
};
use rusthorse::protocol::SecretString;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// The fake key the broker presents to the destination.
pub const CREDENTIAL: &str = "sk-ant-test-0000FAKE0000credential-0000";

/// How long a test waits for anything before it fails.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// The broker program under test.
pub fn program() -> &'static str {
    env!("CARGO_BIN_EXE_rusthorse-broker")
}

/// Whether the broker was built with its `test-upstream` feature: only then
/// does it trust the test's authority and reach a loopback destination.
pub const TEST_UPSTREAM: bool = cfg!(feature = "test-upstream");

// ===== The certificate authority =====

/// A certificate authority made for one test, its certificate in a PEM file
/// (the broker's `RUSTHORSE_BROKER_TEST_ROOTS`).
pub struct TestCa {
    dir: tempfile::TempDir,
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TestCa {
    pub fn new() -> TestCa {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "rusthorse broker test CA");
        let key = KeyPair::generate().expect("key");
        let issuer = CertifiedIssuer::self_signed(params, key).expect("CA");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("roots.pem"), issuer.pem()).expect("write roots");
        TestCa { dir, issuer }
    }

    /// The PEM file of the authority.
    pub fn roots(&self) -> PathBuf {
        self.dir.path().join("roots.pem")
    }

    /// A TLS server configuration with a certificate for `names`, signed by
    /// this authority, speaking the `versions` given.
    pub fn server_config(
        &self,
        names: &[&str],
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Arc<rustls::ServerConfig> {
        let key = KeyPair::generate().expect("key");
        let params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .expect("params");
        let cert = params.signed_by(&key, &self.issuer).expect("sign");
        let chain = vec![cert.der().clone(), self.issuer.der().clone()];
        server_config(chain, key, versions)
    }
}

fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: KeyPair,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server config");
    // h2 first: had the broker offered it, it would be chosen.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Both TLS versions the broker speaks.
pub const BOTH_VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

// ===== The fake destination =====

/// A request as the destination received it.
#[derive(Debug, Clone)]
pub struct Received {
    /// The name the client sent in its TLS hello.
    pub sni: Option<String>,
    /// The application protocol negotiated.
    pub alpn: Option<Vec<u8>>,
    /// The TLS version negotiated.
    pub tls: Option<rustls::ProtocolVersion>,
    pub method: String,
    pub target: String,
    pub version: String,
    /// Every header line, in order, name as received.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl Received {
    /// The values of the header `name` (ignoring case), as text.
    pub fn values(&self, name: &str) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .collect()
    }

    /// The header names, in lowercase, in order.
    pub fn names(&self) -> Vec<String> {
        self.headers
            .iter()
            .map(|(n, _)| n.to_ascii_lowercase())
            .collect()
    }

    /// The whole head as text, for searching.
    pub fn head_text(&self) -> String {
        let mut text = format!("{} {} {}\r\n", self.method, self.target, self.version);
        for (name, value) in &self.headers {
            text.push_str(&format!("{name}: {}\r\n", String::from_utf8_lossy(value)));
        }
        text
    }
}

/// The destination's side of one connection: writes go out at once.
pub struct Peer {
    stream: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
}

impl Peer {
    /// Write `bytes` and flush them to the network.
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes)?;
        self.stream.flush()
    }

    /// Write `bytes` as one chunk of a chunked body.
    pub fn chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut frame = format!("{:x}\r\n", bytes.len()).into_bytes();
        frame.extend_from_slice(bytes);
        frame.extend_from_slice(b"\r\n");
        self.send(&frame)
    }

    /// End a chunked body.
    pub fn end_chunks(&mut self) -> io::Result<()> {
        self.send(b"0\r\n\r\n")
    }

    /// Whether the broker closed the connection within `limit` (a read
    /// that times out, or that gets data, is not a close).
    pub fn closed_within(&mut self, limit: Duration) -> bool {
        let _ = self.stream.sock.set_read_timeout(Some(limit));
        let mut byte = [0u8; 1];
        match self.stream.read(&mut byte) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => !is_timeout(&e),
        }
    }
}

/// How the destination answers a request.
pub type Handler = Arc<dyn Fn(&Received, &mut Peer) + Send + Sync>;

/// A plain answer: `status`, `headers` and `body` with its length.
pub fn answer(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Handler {
    let mut head = format!("HTTP/1.1 {status} Whatever\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    ));
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    Arc::new(move |_, peer| {
        let _ = peer.send(&bytes);
    })
}

/// The fake HTTPS destination: a TLS server on `127.0.0.1` with a
/// certificate of the test's authority, one thread per connection, which
/// reads one request (or only its head), records it and lets the handler
/// answer.
pub struct Destination {
    pub port: u16,
    received: Arc<(Mutex<Vec<Received>>, Condvar)>,
    connections: Arc<AtomicUsize>,
    failures: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Destination {
    /// A destination for `localhost` signed by `ca`, answering with
    /// `handler`.
    pub fn new(ca: &TestCa, handler: Handler) -> Destination {
        Self::with_config(ca.server_config(&["localhost"], BOTH_VERSIONS), handler)
    }

    pub fn with_config(config: Arc<rustls::ServerConfig>, handler: Handler) -> Destination {
        Self::start(config, handler, true)
    }

    /// A destination for `localhost` signed by `ca` that reads each
    /// request's head only, never its body, before `handler` answers (what
    /// came of the body with the head is recorded as its body). Its
    /// connections take little into their receive buffers, so that what
    /// it does not read stays with the broker.
    pub fn head_only(ca: &TestCa, handler: Handler) -> Destination {
        Self::start(
            ca.server_config(&["localhost"], BOTH_VERSIONS),
            handler,
            false,
        )
    }

    fn start(config: Arc<rustls::ServerConfig>, handler: Handler, whole: bool) -> Destination {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let received = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let failures = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (received, connections, failures, stop) = (
                received.clone(),
                connections.clone(),
                failures.clone(),
                stop.clone(),
            );
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(stream) = stream else { continue };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (config, handler, received, failures) = (
                        config.clone(),
                        handler.clone(),
                        received.clone(),
                        failures.clone(),
                    );
                    std::thread::spawn(move || {
                        if serve_one(stream, config, handler, received, whole).is_err() {
                            failures.fetch_add(1, Ordering::SeqCst);
                        }
                    });
                }
            })
        };
        Destination {
            port,
            received,
            connections,
            failures,
            stop,
            thread: Some(thread),
        }
    }

    /// The origin of a profile for this destination.
    pub fn origin(&self) -> String {
        format!("https://localhost:{}", self.port)
    }

    /// The requests received so far.
    pub fn received(&self) -> Vec<Received> {
        self.received.0.lock().expect("lock").clone()
    }

    /// Wait until `count` requests have been received.
    pub fn wait_for(&self, count: usize) -> Vec<Received> {
        let (lock, changed) = &*self.received;
        let deadline = Instant::now() + PATIENCE;
        let mut received = lock.lock().expect("lock");
        while received.len() < count {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "{} requests received, not {count}",
                received.len()
            );
            received = changed.wait_timeout(received, left).expect("wait").0;
        }
        received.clone()
    }

    /// TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Connections that ended before a whole request arrived (a TLS
    /// handshake refused, say).
    pub fn failures(&self) -> usize {
        self.failures.load(Ordering::SeqCst)
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_one(
    stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
    handler: Handler,
    received: Arc<(Mutex<Vec<Received>>, Condvar)>,
    whole: bool,
) -> io::Result<()> {
    stream.set_read_timeout(Some(PATIENCE))?;
    if !whole {
        // A fixed, small receive buffer (no growing as data arrives).
        nix::sys::socket::setsockopt(&stream, nix::sys::socket::sockopt::RcvBuf, &(64 * 1024))
            .map_err(io::Error::from)?;
    }
    let connection = rustls::ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    // The head, then the body by its length.
    let mut data = Vec::new();
    let head_end = loop {
        if let Some(end) = find(&data, b"\r\n\r\n") {
            break end;
        }
        let mut buf = [0u8; 4096];
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        data.extend_from_slice(&buf[..n]);
        if data.len() > 1 << 20 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    };
    let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let version = parts.next().unwrap_or_default().to_string();
    let headers: Vec<(String, Vec<u8>)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.to_string(), v.trim().as_bytes().to_vec()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| std::str::from_utf8(v).ok()?.parse().ok())
        .unwrap_or(0);
    let mut body = data[head_end + 4..].to_vec();
    while whole && body.len() < length {
        let mut buf = vec![0u8; length - body.len()];
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        body.extend_from_slice(&buf[..n]);
    }
    let request = Received {
        sni: tls.conn.server_name().map(str::to_string),
        alpn: tls.conn.alpn_protocol().map(<[u8]>::to_vec),
        tls: tls.conn.protocol_version(),
        method,
        target,
        version,
        headers,
        body,
    };
    {
        let (lock, changed) = &*received;
        lock.lock().expect("lock").push(request.clone());
        changed.notify_all();
    }
    let mut peer = Peer { stream: tls };
    handler(&request, &mut peer);
    peer.stream.conn.send_close_notify();
    let _ = peer.stream.flush();
    Ok(())
}

/// Whether a read failed only because its timeout passed.
fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ===== The broker and the fake agent =====

/// How the fake agent answers `admit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// `admitted`, at once.
    All,
    /// `refused`, at once, with this reason.
    Refuse(AdmissionRefusal),
    /// Nothing: the test answers.
    Manual,
}

/// What a broker is started with.
pub struct Options {
    pub profile: BrokerProfile,
    pub credential: String,
    pub max_in_flight: u32,
    pub max_connections: u32,
    pub lifetime_secs: u64,
    pub admit: Admit,
    /// Environment variables (the agent gives none; the tests' hooks).
    pub env: Vec<(String, String)>,
}

impl Options {
    /// An Anthropic grant for `origin`, admitting everything, reaching
    /// `127.0.0.1` only, with the test's authority trusted (`ca`).
    pub fn anthropic(origin: &str, ca: &TestCa) -> Options {
        Self::preset(Preset::Anthropic, origin, ca)
    }

    pub fn preset(preset: Preset, origin: &str, ca: &TestCa) -> Options {
        let profile = ProfileRequest {
            origin: Some(origin.to_string()),
            ..ProfileRequest::new(preset)
        }
        .resolve()
        .expect("profile");
        let lifetime_secs = u64::from(profile.max_lifetime_minutes) * 60;
        Options {
            profile,
            credential: CREDENTIAL.to_string(),
            max_in_flight: MAX_IN_FLIGHT,
            max_connections: MAX_CONNECTIONS,
            lifetime_secs,
            admit: Admit::All,
            env: vec![
                (
                    "RUSTHORSE_BROKER_TEST_ROOTS".into(),
                    ca.roots().display().to_string(),
                ),
                ("RUSTHORSE_BROKER_TEST_ADDRESSES".into(), "127.0.0.1".into()),
            ],
        }
    }

    /// Without a destination the test can reach: requests are answered
    /// before they would be forwarded.
    pub fn nowhere(ca: &TestCa) -> Options {
        Self::anthropic("https://localhost:9", ca)
    }

    pub fn admit(mut self, admit: Admit) -> Options {
        self.admit = admit;
        self
    }

    pub fn env(mut self, name: &str, value: &str) -> Options {
        self.env.retain(|(n, _)| n != name);
        self.env.push((name.into(), value.into()));
        self
    }

    pub fn without_env(mut self, name: &str) -> Options {
        self.env.retain(|(n, _)| n != name);
        self
    }

    /// Shorter deadlines, as `name=ms` pairs (the broker's
    /// `RUSTHORSE_BROKER_TEST_TIMEOUTS`).
    pub fn timeouts(self, pairs: &str) -> Options {
        self.env("RUSTHORSE_BROKER_TEST_TIMEOUTS", pairs)
    }

    /// The install for these options, with a new grant ID and token.
    pub fn install(&self) -> Install {
        Install {
            version: VERSION,
            grant: broker_protocol::new_grant_id(),
            token: broker_protocol::new_token(),
            credential: SecretString::new(self.credential.clone()),
            profile: self.profile.clone(),
            max_in_flight: self.max_in_flight,
            max_connections: self.max_connections,
            lifetime_secs: self.lifetime_secs,
        }
    }
}

/// What the fake agent saw on the control channel.
#[derive(Default)]
struct Seen {
    messages: Vec<FromBroker>,
    /// The channel ended (the broker closed it, or reading failed).
    ended: bool,
}

/// A broker process, before or after `ready`.
pub struct Process {
    pub child: Child,
    /// The agent's end of the control channel.
    pub agent: UnixStream,
}

impl Process {
    /// Start the broker as the agent does: no arguments, the environment
    /// given (the agent gives none), `/` as working directory, its own
    /// process group, standard input and output one end of a socket pair;
    /// standard error is kept for the test.
    pub fn spawn(env: &[(String, String)]) -> Process {
        let (agent, broker) = UnixStream::pair().expect("socket pair");
        let output = broker.try_clone().expect("clone");
        let mut command = Command::new(program());
        command
            .env_clear()
            .envs(env.iter().map(|(n, v)| (n, v)))
            .current_dir("/")
            .process_group(0)
            .stdin(Stdio::from(OwnedFd::from(broker)))
            .stdout(Stdio::from(OwnedFd::from(output)))
            .stderr(Stdio::piped());
        let child = command.spawn().expect("start the broker");
        Process { child, agent }
    }

    /// Send `message` with `fds` attached.
    pub fn send(&self, message: &ToBroker, fds: &[BorrowedFd<'_>]) {
        broker_protocol::write_message(&self.agent, message, fds).expect("send");
    }

    /// Send `message` with `fds` attached, if the broker is still there to
    /// read it (one that cannot serve may have left already).
    pub fn try_send(&self, message: &ToBroker, fds: &[BorrowedFd<'_>]) -> bool {
        broker_protocol::write_message(&self.agent, message, fds).is_ok()
    }

    /// The next message, if one comes within `limit`.
    pub fn read(&self, limit: Duration) -> io::Result<FromBroker> {
        broker_protocol::read_message::<FromBroker>(&self.agent, Some(Instant::now() + limit))
            .map(|(message, _)| message)
    }

    /// The exit status, if the broker exits within `limit`.
    pub fn exit_within(&mut self, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().expect("wait") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// What the broker wrote to standard error (once it has exited).
    pub fn stderr(&mut self) -> String {
        let mut text = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            let _ = stderr.read_to_string(&mut text);
        }
        text
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(self.child.id() as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = self.child.wait();
        }
    }
}

/// A broker serving a grant, with the fake agent's side of its control
/// channel: a thread reads every message and answers `admit` as the options
/// say.
pub struct Broker {
    process: Process,
    writer: Arc<Mutex<UnixStream>>,
    seen: Arc<(Mutex<Seen>, Condvar)>,
    reader: Option<JoinHandle<()>>,
    /// The agent's copy of the listening socket, kept as the agent does.
    _listener: TcpListener,
    pub port: u16,
    pub grant: String,
    pub token: String,
    pub started: Instant,
}

impl Broker {
    /// Start a broker and wait for its `ready`.
    pub fn start(options: Options) -> Broker {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let install = options.install();
        let grant = install.grant.clone();
        let token = install.token.to_string();
        let mut process = Process::spawn(&options.env);
        process.send(&ToBroker::Install(install), &[listener.as_fd()]);
        let started = Instant::now();
        match process.read(PATIENCE) {
            Ok(FromBroker::Ready {
                version,
                grant: ready,
            }) => {
                assert_eq!(version, VERSION);
                assert_eq!(ready, grant);
            }
            other => {
                let _ = process.exit_within(Duration::from_secs(5));
                panic!("no ready: {other:?}; the broker said: {}", process.stderr())
            }
        }
        let writer = Arc::new(Mutex::new(process.agent.try_clone().expect("clone")));
        let reader_end = process.agent.try_clone().expect("clone");
        let seen: Arc<(Mutex<Seen>, Condvar)> = Arc::default();
        let reader = {
            let (writer, seen, admit) = (writer.clone(), seen.clone(), options.admit);
            std::thread::spawn(move || {
                loop {
                    let message = broker_protocol::read_message::<FromBroker>(&reader_end, None);
                    let (lock, changed) = &*seen;
                    let Ok((message, _)) = message else {
                        lock.lock().expect("lock").ended = true;
                        changed.notify_all();
                        return;
                    };
                    // Recorded before it is answered: a test that sees the
                    // answer's effect sees the message too.
                    let answer = match (&message, admit) {
                        (FromBroker::Admit { request, .. }, Admit::All) => {
                            Some(ToBroker::Admitted { request: *request })
                        }
                        (FromBroker::Admit { request, .. }, Admit::Refuse(reason)) => {
                            Some(ToBroker::Refused {
                                request: *request,
                                reason,
                            })
                        }
                        _ => None,
                    };
                    lock.lock().expect("lock").messages.push(message);
                    changed.notify_all();
                    if let Some(answer) = answer {
                        let stream = writer.lock().expect("lock");
                        let _ = broker_protocol::write_message(&stream, &answer, &[]);
                    }
                }
            })
        };
        Broker {
            process,
            writer,
            seen,
            reader: Some(reader),
            _listener: listener,
            port,
            grant,
            token,
            started,
        }
    }

    /// The broker's process ID.
    pub fn pid(&self) -> u32 {
        self.process.child.id()
    }

    /// Send the broker a message.
    pub fn tell(&self, message: &ToBroker) {
        let stream = self.writer.lock().expect("lock");
        broker_protocol::write_message(&stream, message, &[]).expect("send");
    }

    pub fn admitted(&self, request: u64) {
        self.tell(&ToBroker::Admitted { request });
    }

    pub fn refused(&self, request: u64, reason: AdmissionRefusal) {
        self.tell(&ToBroker::Refused { request, reason });
    }

    pub fn revoke(&self, reason: EndReason) {
        self.tell(&ToBroker::Revoke { reason });
    }

    /// Every message the broker sent after `ready`, so far.
    pub fn messages(&self) -> Vec<FromBroker> {
        self.seen.0.lock().expect("lock").messages.clone()
    }

    /// Wait until a message satisfies `matches`, and return it.
    pub fn wait_for(&self, what: &str, matches: impl Fn(&FromBroker) -> bool) -> FromBroker {
        let (lock, changed) = &*self.seen;
        let deadline = Instant::now() + PATIENCE;
        let mut seen = lock.lock().expect("lock");
        loop {
            if let Some(found) = seen.messages.iter().find(|m| matches(m)) {
                return found.clone();
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero() && !seen.ended,
                "no {what}; the broker sent {:?}",
                seen.messages
            );
            seen = changed.wait_timeout(seen, left).expect("wait").0;
        }
    }

    /// Wait for `admit` number `request`.
    pub fn wait_admit(&self, request: u64) -> FromBroker {
        self.wait_for(
            &format!("admit {request}"),
            |m| matches!(m, FromBroker::Admit { request: n, .. } if *n == request),
        )
    }

    /// Wait for the `finished` of request `request`.
    pub fn wait_finished(&self, request: u64) -> FromBroker {
        self.wait_for(
            &format!("finished {request}"),
            |m| matches!(m, FromBroker::Finished { request: n, .. } if *n == request),
        )
    }

    /// Wait for `revoked`, and return its count of refusals.
    pub fn wait_revoked(&self) -> u64 {
        match self.wait_for("revoked", |m| matches!(m, FromBroker::Revoked { .. })) {
            FromBroker::Revoked { refused } => refused,
            _ => unreachable!(),
        }
    }

    /// The number of `admit` messages so far.
    pub fn admits(&self) -> usize {
        self.messages()
            .iter()
            .filter(|m| matches!(m, FromBroker::Admit { .. }))
            .count()
    }

    /// A copy of the agent's end of the control channel, for writing what
    /// the agent would never write.
    pub fn raw_channel(&self) -> UnixStream {
        self.writer
            .lock()
            .expect("lock")
            .try_clone()
            .expect("clone")
    }

    /// Close the agent's end of the control channel.
    pub fn close_channel(&self) {
        let _ = self.process.agent.shutdown(Shutdown::Both);
    }

    /// The exit status, if the broker exits within `limit`.
    pub fn exit_within(&mut self, limit: Duration) -> Option<ExitStatus> {
        self.process.exit_within(limit)
    }

    /// Whether the control channel ended (the broker closed it or exited).
    pub fn channel_ended(&self, limit: Duration) -> bool {
        let (lock, changed) = &*self.seen;
        let deadline = Instant::now() + limit;
        let mut seen = lock.lock().expect("lock");
        while !seen.ended {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            seen = changed.wait_timeout(seen, left).expect("wait").0;
        }
        true
    }

    /// A request in the form clients send: `method target`, `Host` the
    /// broker's address, the token in `x-api-key`, and `headers` and
    /// `body` (with its length when there is one).
    pub fn request(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut all = vec![("x-api-key".to_string(), self.token.clone())];
        all.extend(headers.iter().map(|(n, v)| (n.to_string(), v.to_string())));
        raw_request(method, target, self.port, &all, body)
    }

    /// The same, the token in `Authorization: Bearer`.
    pub fn bearer_request(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut all = vec![(
            "authorization".to_string(),
            format!("Bearer {}", self.token),
        )];
        all.extend(headers.iter().map(|(n, v)| (n.to_string(), v.to_string())));
        raw_request(method, target, self.port, &all, body)
    }

    /// Send `raw` on a new connection and read the response.
    pub fn send(&self, raw: &[u8]) -> Response {
        let mut client = Client::connect(self.port);
        client.write(raw);
        client.response()
    }

    /// Open a connection to the broker.
    pub fn connect(&self) -> Client {
        Client::connect(self.port)
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.close_channel();
        let _ = self.process.exit_within(Duration::from_secs(5));
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Raw bytes of a request: the request line, `Host: 127.0.0.1:PORT`, the
/// headers given, `content-length` when there is a body, and the body.
pub fn raw_request(
    method: &str,
    target: &str,
    port: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut head = format!("{method} {target} HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() {
        head.push_str(&format!("content-length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

// ===== The HTTP client =====

/// A response as the client read it.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Whether the body ended as its framing says (the last chunk, or its
    /// whole length); a body cut short is not complete.
    pub complete: bool,
}

impl Response {
    /// The value of header `name` (ignoring case), if there is one.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The header names, in lowercase.
    pub fn names(&self) -> Vec<String> {
        self.headers
            .iter()
            .map(|(n, _)| n.to_ascii_lowercase())
            .collect()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.text()))
    }

    /// Assert a local answer of the broker: `status`, a short JSON error,
    /// and `x-should-retry: false` unless the status is 429 or 503.
    pub fn assert_local(&self, status: u16) {
        let retry = !matches!(status, 429 | 503);
        self.assert_local_with(status, retry);
    }

    /// Assert the local `502` of a destination that could not be reached:
    /// nothing was sent, so the client may retry (no `x-should-retry`).
    pub fn assert_unreachable(&self) {
        self.assert_local_with(502, false);
    }

    fn assert_local_with(&self, status: u16, should_retry_false: bool) {
        assert_eq!(self.status, status, "{self:?}");
        assert_eq!(self.header("content-type"), Some("application/json"));
        let json = self.json();
        assert_eq!(json["type"], "error", "{json}");
        assert_eq!(json["error"]["type"], "rusthorse_broker", "{json}");
        assert!(self.body.len() < 200, "{self:?}");
        let retry = should_retry_false.then_some("false");
        assert_eq!(self.header("x-should-retry"), retry, "{self:?}");
    }
}

/// A client connection to the broker.
pub struct Client {
    pub stream: TcpStream,
    buffer: Vec<u8>,
}

impl Client {
    pub fn connect(port: u16) -> Client {
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the broker");
        stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
        Client {
            stream,
            buffer: Vec::new(),
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("write");
    }

    /// Whether writing `bytes` succeeded (a closed connection may refuse).
    pub fn try_write(&mut self, bytes: &[u8]) -> bool {
        self.stream.write_all(bytes).is_ok()
    }

    fn fill(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 16384];
        let n = self.stream.read(&mut buf)?;
        self.buffer.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    /// Whether the broker closed the connection within `limit` without
    /// sending anything (more). A read that times out is not a close, and
    /// data that arrives is kept for the next response.
    pub fn closed_within(&mut self, limit: Duration) -> bool {
        self.stream.set_read_timeout(Some(limit)).expect("timeout");
        let closed = match self.fill() {
            Ok(0) => self.buffer.is_empty(),
            Ok(_) => false,
            Err(e) => !is_timeout(&e) && self.buffer.is_empty(),
        };
        self.stream
            .set_read_timeout(Some(PATIENCE))
            .expect("timeout");
        closed
    }

    /// The head of the next response: status and headers.
    pub fn head(&mut self) -> (u16, Vec<(String, String)>) {
        let end = loop {
            if let Some(end) = find(&self.buffer, b"\r\n\r\n") {
                break end;
            }
            match self.fill() {
                Ok(0) => panic!(
                    "the connection closed before a response head: {:?}",
                    String::from_utf8_lossy(&self.buffer)
                ),
                Ok(_) => {}
                Err(e) => panic!("no response head: {e}"),
            }
        };
        let head = String::from_utf8_lossy(&self.buffer[..end]).into_owned();
        self.buffer.drain(..end + 4);
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status = status_line
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("a status line: {status_line:?}"));
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(n, v)| (n.to_string(), v.trim().to_string()))
            .collect();
        (status, headers)
    }

    /// The next chunk of a chunked body: `Some(data)`, `Some(empty)` for the
    /// last chunk, `None` if the connection ended first.
    pub fn chunk(&mut self) -> Option<Vec<u8>> {
        let line_end = loop {
            if let Some(end) = find(&self.buffer, b"\r\n") {
                break end;
            }
            if !matches!(self.fill(), Ok(n) if n > 0) {
                return None;
            }
        };
        let size_text = String::from_utf8_lossy(&self.buffer[..line_end]).into_owned();
        let size = usize::from_str_radix(size_text.trim(), 16)
            .unwrap_or_else(|_| panic!("a chunk size: {size_text:?}"));
        while self.buffer.len() < line_end + 2 + size + 2 {
            if !matches!(self.fill(), Ok(n) if n > 0) {
                return None;
            }
        }
        let data = self.buffer[line_end + 2..line_end + 2 + size].to_vec();
        assert_eq!(
            &self.buffer[line_end + 2 + size..line_end + 4 + size],
            b"\r\n"
        );
        self.buffer.drain(..line_end + 4 + size);
        Some(data)
    }

    /// The next whole response.
    pub fn response(&mut self) -> Response {
        let (status, headers) = self.head();
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _): &&(String, String)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let mut body = Vec::new();
        let complete;
        if header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
            loop {
                match self.chunk() {
                    Some(data) if data.is_empty() => {
                        complete = true;
                        break;
                    }
                    Some(data) => body.extend_from_slice(&data),
                    None => {
                        complete = false;
                        break;
                    }
                }
            }
        } else if let Some(length) = header("content-length") {
            let length: usize = length.parse().expect("a length");
            while self.buffer.len() < length {
                if !matches!(self.fill(), Ok(n) if n > 0) {
                    break;
                }
            }
            complete = self.buffer.len() >= length;
            let take = length.min(self.buffer.len());
            body = self.buffer.drain(..take).collect();
        } else if status == 204 || status == 304 || status < 200 {
            complete = true;
        } else {
            while matches!(self.fill(), Ok(n) if n > 0) {}
            body = std::mem::take(&mut self.buffer);
            complete = true;
        }
        Response {
            status,
            headers,
            body,
            complete,
        }
    }
}

/// A listener that only counts the connections it gets (a proxy that
/// should never be used, say).
pub struct Counter {
    pub port: u16,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Counter {
    pub fn new() -> Counter {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (count, stop) = (count.clone(), stop.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if stream.is_ok() {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        };
        Counter {
            port,
            count,
            stop,
            thread: Some(thread),
        }
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Drop for Counter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A listener that accepts connections and never answers on them: a
/// destination whose TLS handshake stalls. It keeps them open until it is
/// dropped.
pub struct Silent {
    pub port: u16,
    accepted: Arc<(Mutex<Vec<TcpStream>>, Condvar)>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Silent {
    pub fn new() -> Silent {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let accepted: Arc<(Mutex<Vec<TcpStream>>, Condvar)> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (accepted, stop) = (accepted.clone(), stop.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Ok(stream) = stream {
                        let (lock, changed) = &*accepted;
                        lock.lock().expect("lock").push(stream);
                        changed.notify_all();
                    }
                }
            })
        };
        Silent {
            port,
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    /// The origin of a profile for this listener.
    pub fn origin(&self) -> String {
        format!("https://localhost:{}", self.port)
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.accepted.0.lock().expect("lock").len()
    }

    /// Connection `n` (from 0), once it has been accepted.
    fn connection(&self, n: usize) -> TcpStream {
        let (lock, changed) = &*self.accepted;
        let deadline = Instant::now() + PATIENCE;
        let mut accepted = lock.lock().expect("lock");
        while accepted.len() <= n {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "{} connections, not {}",
                accepted.len(),
                n + 1
            );
            accepted = changed.wait_timeout(accepted, left).expect("wait").0;
        }
        accepted[n].try_clone().expect("clone")
    }

    /// Wait until the other end of connection `n` has sent something (the
    /// start of a TLS handshake), and leave it unread.
    pub fn wait_for_data(&self, n: usize) {
        let stream = self.connection(n);
        stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
        let mut byte = [0u8; 1];
        assert!(
            matches!(stream.peek(&mut byte), Ok(1)),
            "connection {n} sent nothing"
        );
    }

    /// Whether the other end of connection `n` closed it within `limit`
    /// (what it sent is read and dropped).
    pub fn closed_within(&self, n: usize, limit: Duration) -> bool {
        let mut stream = self.connection(n);
        let deadline = Instant::now() + limit;
        let mut buf = [0u8; 4096];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            stream.set_read_timeout(Some(left)).expect("timeout");
            match stream.read(&mut buf) {
                Ok(0) => return true,
                Ok(_) => {}
                Err(e) if is_timeout(&e) => return false,
                Err(_) => return true,
            }
        }
    }
}

impl Drop for Silent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The largest send buffer a TCP socket grows to (Linux's `tcp_wmem`), if
/// it can be read.
pub fn largest_send_buffer() -> Option<usize> {
    let limits = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_wmem").ok()?;
    limits.split_whitespace().nth(2)?.parse().ok()
}

/// A one-shot signal between a test and a destination's handler.
pub fn signal() -> (mpsc::Sender<()>, Arc<Mutex<mpsc::Receiver<()>>>) {
    let (tx, rx) = mpsc::channel();
    (tx, Arc::new(Mutex::new(rx)))
}

/// Whether `path` exists (for the error messages of the setup tests).
pub fn exists(path: &Path) -> bool {
    path.exists()
}
