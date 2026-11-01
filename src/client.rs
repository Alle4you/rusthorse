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

use crate::protocol::{self, Frame, Request, Response, RunRequest};

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
    fn new() -> Self {
        Self {
            available: Mutex::new(protocol::INITIAL_CREDIT),
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

    /// Send one request and wait for the response.
    pub fn call(&self, request: &Request) -> anyhow::Result<Response> {
        let stream = self.connect()?;
        protocol::send_frame(&stream, request, &[]).context("cannot send the request")?;
        protocol::read_message(&stream).context("the agent closed the connection")
    }

    /// Ask the agent to run a command using this process's standard input,
    /// output and error, and wait until it has finished. Meant for the CLI.
    ///
    /// Without redaction, the three descriptors are handed to the command.
    /// With redaction, see [`Client::run_with`].
    pub fn run(&self, request: RunRequest) -> anyhow::Result<Response> {
        if !request.redact {
            let stream = self.connect()?;
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let fds = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
            protocol::send_frame(&stream, &Request::Run(request), &fds)
                .context("cannot send the request")?;
            return protocol::read_message(&stream).context("the agent closed the connection");
        }
        let input = if request.forward_stdin {
            Some(
                std::io::stdin()
                    .as_fd()
                    .try_clone_to_owned()
                    .context("cannot duplicate stdin")?,
            )
        } else {
            None
        };
        self.run_with(
            request,
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
        let stream = self.connect()?;
        protocol::send_frame(&stream, &Request::Run(request), &[])
            .context("cannot send the request")?;

        let sender = Arc::new(Mutex::new(
            stream.try_clone().context("cannot clone the connection")?,
        ));
        // Used only to shut the connection down, so that cancelling never
        // waits for the send lock.
        let canceller = Arc::new(stream.try_clone().context("cannot clone the connection")?);
        let broken = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let input_credit = Arc::new(InputCredit::new());

        let mut writers = Vec::new();
        let mut queues = Vec::new();
        for (channel, dest) in [(protocol::STDOUT, io.stdout), (protocol::STDERR, io.stderr)] {
            let (tx, rx) = mpsc::channel::<Zeroizing<Vec<u8>>>();
            let (sender, canceller, broken) = (
                Arc::clone(&sender),
                Arc::clone(&canceller),
                Arc::clone(&broken),
            );
            writers.push(thread::spawn(move || {
                write_output(rx, dest, channel, sender, canceller, broken)
            }));
            queues.push(tx);
        }
        let input_worker = match (forward, io.input) {
            (true, Some(input)) => {
                let (sender, done, credit) = (
                    Arc::clone(&sender),
                    Arc::clone(&done),
                    Arc::clone(&input_credit),
                );
                Some(thread::spawn(move || {
                    forward_input(input, sender, credit, done)
                }))
            }
            (true, None) => {
                // Forwarding was requested but there is nothing to read.
                let _ = protocol::send_data(&stream, protocol::STDIN, &[]);
                None
            }
            (false, _) => None,
        };

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
                    break serde_json::from_slice::<Response>(&body).context("malformed response");
                }
                Err(e) => {
                    break Err(anyhow::Error::from(e).context("the agent closed the connection"));
                }
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
