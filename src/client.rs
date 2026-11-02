//! The client side of the agent protocol.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use zeroize::Zeroizing;

use crate::protocol::{self, BrokerRunRequest, Frame, Request, Response, RunRequest};

/// The request was sent, but no usable answer came back (the connection was
/// lost, or the answer could not be understood): the request may or may not
/// have taken effect — a command may or may not have run, a change may or may
/// not have been saved. Callers should not simply retry an operation that is
/// not idempotent.
#[derive(Debug)]
pub struct OutcomeUnknown(pub String);

impl std::fmt::Display for OutcomeUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no usable answer from the agent after the request was sent ({})",
            self.0
        )
    }
}

impl std::error::Error for OutcomeUnknown {}

/// Signal number reported when the client's own output is closed while it is
/// relaying a run (the shell convention for a broken pipe, 128 + 13).
const SIGPIPE: i32 = 13;

/// A connection factory for the agent socket.
#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
}

/// Where the input of a redacted run comes from and where its output goes,
/// for [`Client::run_with`].
pub struct RunIo {
    /// Read and forwarded to the command when the request sets
    /// `forward_stdin`. It is read on a helper thread that stops within about
    /// 100 ms after [`Client::run_with`] returns; it is only read after
    /// `poll` reports data, so it is not consumed beyond the run unless
    /// another reader drains it at the same moment.
    pub input: Option<OwnedFd>,
    /// Receives the command's (redacted) standard output.
    pub stdout: Box<dyn Write + Send>,
    /// Receives the command's (redacted) standard error.
    pub stderr: Box<dyn Write + Send>,
}

/// How much the agent still accepts on stdin (granted with credit frames).
struct InputCredit {
    available: Mutex<usize>,
    changed: Condvar,
}

impl InputCredit {
    /// No credit at first: the agent grants the window once the command has
    /// started, so no input is read for a request that is denied or fails.
    fn new() -> Self {
        Self {
            available: Mutex::new(0),
            changed: Condvar::new(),
        }
    }

    fn grant(&self, amount: usize) {
        let mut available = self.available.lock().unwrap_or_else(|p| p.into_inner());
        *available = available
            .saturating_add(amount)
            .min(protocol::INITIAL_CREDIT);
        self.changed.notify_all();
    }

    /// Wait until at least `amount` may be sent; `false` once `done` is set.
    fn wait_for(&self, amount: usize, done: &AtomicBool) -> bool {
        let mut available = self.available.lock().unwrap_or_else(|p| p.into_inner());
        while *available < amount {
            if done.load(Ordering::SeqCst) {
                return false;
            }
            available = self
                .changed
                .wait_timeout(available, Duration::from_millis(100))
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        true
    }

    fn take(&self, amount: usize) {
        let mut available = self.available.lock().unwrap_or_else(|p| p.into_inner());
        *available = available.saturating_sub(amount);
    }

    fn wake(&self) {
        self.changed.notify_all();
    }
}

impl Client {
    /// A client for the agent listening at `socket`.
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// The socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    fn connect(&self) -> anyhow::Result<UnixStream> {
        UnixStream::connect(&self.socket).with_context(|| {
            format!(
                "cannot reach the agent at {} — is it running? \
                 Start it with `systemctl --user start rusthorse-agent` (see docs/installation.md)",
                self.socket.display()
            )
        })
    }

    /// Check that the agent speaks this build's protocol version (for
    /// example after upgrading the binary without restarting the agent).
    pub fn check_compatible(&self) -> anyhow::Result<()> {
        let Response::Status(info) = self.call(&Request::Status)? else {
            bail!("the agent did not answer the version check; is it a Rusthorse agent?");
        };
        if info.protocol_version != protocol::PROTOCOL_VERSION {
            bail!(
                "the running agent speaks protocol {} (version {}) but this rusthorse speaks {} \
                 (version {}); restart the agent: `systemctl --user restart rusthorse-agent`",
                info.protocol_version,
                info.agent_version,
                protocol::PROTOCOL_VERSION,
                env!("CARGO_PKG_VERSION")
            );
        }
        Ok(())
    }

    /// Send one request and wait for the response. Once a request that
    /// [has effects](Request::has_effects) is sent, a missing or unreadable
    /// answer is an [`OutcomeUnknown`] error.
    pub fn call(&self, request: &Request) -> anyhow::Result<Response> {
        let stream = self.connect()?;
        protocol::send_frame(&stream, request, &[]).context("cannot send the request")?;
        protocol::read_message(&stream).map_err(|e| {
            if request.has_effects() {
                anyhow::Error::new(OutcomeUnknown(e.to_string()))
            } else {
                anyhow::anyhow!("no usable answer from the agent ({e})")
            }
        })
    }

    /// Ask the agent to run a command using this process's standard input,
    /// output and error, and wait until it has finished. Meant for the CLI.
    ///
    /// Without redaction, the three descriptors are handed to the command.
    /// With redaction, see [`Client::run_with`].
    pub fn run(&self, request: RunRequest) -> anyhow::Result<Response> {
        let (redact, forward_stdin) = (request.redact, request.forward_stdin);
        self.run_here(Request::Run(request), redact, forward_stdin)
    }

    /// [`Client::run`] for a run with broker bindings
    /// ([`Request::BrokerRun`]); a run without any is a [`RunRequest`].
    pub fn broker_run(&self, request: BrokerRunRequest) -> anyhow::Result<Response> {
        let (redact, forward_stdin) = (request.run.redact, request.run.forward_stdin);
        self.run_here(Request::BrokerRun(request), redact, forward_stdin)
    }

    /// [`Client::run`] for `request`, a [`Request::Run`] or a
    /// [`Request::BrokerRun`] whose run has these `redact` and
    /// `forward_stdin`.
    fn run_here(
        &self,
        request: Request,
        redact: bool,
        forward_stdin: bool,
    ) -> anyhow::Result<Response> {
        if !redact {
            let stream = self.connect()?;
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let fds = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
            protocol::send_frame(&stream, &request, &fds).context("cannot send the request")?;
            return protocol::read_message(&stream)
                .map_err(|e| anyhow::Error::new(OutcomeUnknown(e.to_string())));
        }
        let input = if forward_stdin {
            Some(
                std::io::stdin()
                    .as_fd()
                    .try_clone_to_owned()
                    .context("cannot duplicate stdin")?,
            )
        } else {
            None
        };
        self.relay(
            request,
            forward_stdin,
            RunIo {
                input,
                stdout: Box::new(std::io::stdout()),
                stderr: Box::new(std::io::stderr()),
            },
        )
    }

    /// Ask the agent to run a command with redaction, relaying its output to
    /// `io.stdout` and `io.stderr` and (with `forward_stdin`) its input from
    /// `io.input`. Returns once the command has finished and all its output
    /// has been written.
    ///
    /// Each output channel is written by its own thread and flow-controlled
    /// separately (the client grants the agent credit as it writes), so a
    /// destination that blocks does not hold up the other one. If writing a
    /// destination fails (it was closed), the connection is closed — which
    /// makes the agent stop the command — and the result reports `SIGPIPE`
    /// within about half a second, even if the other destination is blocked:
    /// a writer still blocked in its destination after that is left running
    /// detached (`Write` offers no way to interrupt it), and ends when that
    /// destination accepts the data or fails.
    pub fn run_with(&self, request: RunRequest, io: RunIo) -> anyhow::Result<Response> {
        if !request.redact {
            bail!("run_with relays output and needs redaction; use `run` to pass descriptors");
        }
        let forward = request.forward_stdin;
        self.relay(Request::Run(request), forward, io)
    }

    /// [`Client::run_with`] for a run with broker bindings
    /// ([`Request::BrokerRun`]); a run without any is a [`RunRequest`].
    pub fn broker_run_with(
        &self,
        request: BrokerRunRequest,
        io: RunIo,
    ) -> anyhow::Result<Response> {
        if !request.run.redact {
            bail!(
                "broker_run_with relays output and needs redaction; use `broker_run` to pass \
                 descriptors"
            );
        }
        let forward = request.run.forward_stdin;
        self.relay(Request::BrokerRun(request), forward, io)
    }

    /// Send `request`, a [`Request::Run`] or a [`Request::BrokerRun`] with
    /// redaction, and relay its output and (with `forward`) its input, as
    /// [`Client::run_with`] says.
    fn relay(&self, request: Request, forward: bool, io: RunIo) -> anyhow::Result<Response> {
        let stream = self.connect()?;
        // Everything that can fail locally is prepared before the request is
        // sent: once it is, a failure means the outcome is unknown.
        let sender = Arc::new(Mutex::new(
            stream.try_clone().context("cannot clone the connection")?,
        ));
        // Used only to shut the connection down, so that cancelling never
        // waits for the send lock.
        let canceller = Arc::new(stream.try_clone().context("cannot clone the connection")?);
        let broken = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let input_credit = Arc::new(InputCredit::new());

        // The relay threads too: the output writers only wait for data, and
        // the input forwarder reads nothing before the agent grants credit.
        let nothing_to_forward = forward && io.input.is_none();
        let mut writers = Vec::new();
        let mut queues = Vec::new();
        let mut input_worker = None;
        let prepared = (|| -> anyhow::Result<()> {
            for (channel, dest) in [(protocol::STDOUT, io.stdout), (protocol::STDERR, io.stderr)] {
                let (tx, rx) = mpsc::channel::<Zeroizing<Vec<u8>>>();
                let (sender, canceller, broken) = (
                    Arc::clone(&sender),
                    Arc::clone(&canceller),
                    Arc::clone(&broken),
                );
                writers.push(
                    thread::Builder::new()
                        .name("rusthorse-output".into())
                        .spawn(move || write_output(rx, dest, channel, sender, canceller, broken))
                        .context("cannot start an output thread")?,
                );
                queues.push(tx);
            }
            if let (true, Some(input)) = (forward, io.input) {
                let (sender, done, credit) = (
                    Arc::clone(&sender),
                    Arc::clone(&done),
                    Arc::clone(&input_credit),
                );
                input_worker = Some(
                    thread::Builder::new()
                        .name("rusthorse-input".into())
                        .spawn(move || forward_input(input, sender, credit, done))
                        .context("cannot start the input thread")?,
                );
            }
            Ok(())
        })();
        let sent = prepared.and_then(|()| {
            protocol::send_frame(&stream, &request, &[]).context("cannot send the request")
        });
        if let Err(e) = sent {
            // Nothing reached the agent: stop the threads and report it.
            drop(queues);
            done.store(true, Ordering::SeqCst);
            input_credit.wake();
            for writer in writers {
                let _ = writer.join();
            }
            if let Some(worker) = input_worker {
                let _ = worker.join();
            }
            return Err(e);
        }
        if nothing_to_forward {
            // Forwarding was requested but there is nothing to read.
            let _ = protocol::send_data(&stream, protocol::STDIN, &[]);
        }

        // The output queues are bounded by the credit window the agent
        // respects, so pushing into them never blocks this loop.
        let result = loop {
            match protocol::recv_any_before(&stream, None) {
                Ok(Frame::Data(protocol::STDOUT, data)) => {
                    let _ = queues[0].send(data);
                }
                Ok(Frame::Data(protocol::STDERR, data)) => {
                    let _ = queues[1].send(data);
                }
                Ok(Frame::Data(protocol::CREDIT_STDIN, data)) if data.len() == 4 => {
                    input_credit
                        .grant(u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize);
                }
                Ok(Frame::Data(..)) => {}
                Ok(Frame::Message(body, _fds)) => {
                    break serde_json::from_slice::<Response>(&body).map_err(|e| {
                        anyhow::Error::new(OutcomeUnknown(format!("malformed response: {e}")))
                    });
                }
                Err(e) => break Err(anyhow::Error::new(OutcomeUnknown(e.to_string()))),
            }
        };
        drop(queues);
        join_writers(writers, &broken);
        done.store(true, Ordering::SeqCst);
        input_credit.wake();
        if let Some(worker) = input_worker {
            join_within(worker, Duration::from_millis(500));
        }
        if broken.load(Ordering::SeqCst) {
            return Ok(Response::Exited {
                code: None,
                signal: Some(SIGPIPE),
            });
        }
        result
    }
}

/// Wait for the output writers to deliver everything — however long a slow
/// destination takes — unless one of them failed: then wait at most half a
/// second more and leave any writer still blocked in its destination behind.
fn join_writers(writers: Vec<thread::JoinHandle<()>>, broken: &AtomicBool) {
    let mut failed_at: Option<Instant> = None;
    while !writers.iter().all(|w| w.is_finished()) {
        if broken.load(Ordering::SeqCst) {
            let since = *failed_at.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_millis(500) {
                return;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    for writer in writers {
        let _ = writer.join();
    }
}

/// Write one output channel and grant the agent credit for what was written.
fn write_output(
    queue: mpsc::Receiver<Zeroizing<Vec<u8>>>,
    mut dest: Box<dyn Write + Send>,
    channel: u8,
    sender: Arc<Mutex<UnixStream>>,
    canceller: Arc<UnixStream>,
    broken: Arc<AtomicBool>,
) {
    for chunk in queue {
        if broken.load(Ordering::SeqCst) {
            continue; // drain without writing
        }
        if dest.write_all(&chunk).and_then(|()| dest.flush()).is_err() {
            broken.store(true, Ordering::SeqCst);
            let _ = canceller.shutdown(std::net::Shutdown::Both);
            continue;
        }
        let stream = sender.lock().unwrap_or_else(|p| p.into_inner());
        let _ = protocol::send_credit(&stream, channel, chunk.len() as u32);
    }
}

/// Send `input` to the agent until end-of-file, or until the run is done,
/// never more than the agent's stdin credit allows.
fn forward_input(
    input: OwnedFd,
    sender: Arc<Mutex<UnixStream>>,
    credit: Arc<InputCredit>,
    done: Arc<AtomicBool>,
) {
    const CHUNK: usize = 16 * 1024;
    let mut input = File::from(input);
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let send = |data: &[u8]| -> bool {
        let stream = sender.lock().unwrap_or_else(|p| p.into_inner());
        protocol::send_data(&stream, protocol::STDIN, data).is_ok()
    };
    while !done.load(Ordering::SeqCst) {
        // Read only what the agent can take now, so a command that does not
        // read its input leaves the rest unread here.
        if !credit.wait_for(CHUNK, &done) {
            return;
        }
        let mut fds = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(100u16)) {
            Ok(0) | Err(Errno::EINTR) => continue,
            Ok(_) => {}
            Err(_) => break,
        }
        // Checked again right before reading, so that input arriving after
        // the run is left for whoever reads it next.
        if done.load(Ordering::SeqCst) {
            return;
        }
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                credit.take(n);
                if !send(&buf[..n]) {
                    return;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::Interrupted
                    || e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }
    if !done.load(Ordering::SeqCst) {
        let _ = send(&[]);
    }
}

/// Wait up to `limit` for a thread; after that, leave it running detached.
fn join_within(handle: thread::JoinHandle<()>, limit: Duration) {
    let deadline = Instant::now() + limit;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = handle.join();
}
