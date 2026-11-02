//! Bounded, cancellable requests. No GTK objects cross the worker boundary.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rusthorse::protocol::{self, ErrorCode, Request, Response};

pub(crate) struct Failure {
    pub message: String,
    pub uncertain: bool,
    /// Nothing listens on the agent's socket: the agent is not running.
    pub not_running: bool,
}

impl Failure {
    fn new(message: impl Into<String>, uncertain: bool) -> Self {
        Self {
            message: message.into(),
            uncertain,
            not_running: false,
        }
    }
    /// The worker ended without an answer: the request may have been sent.
    pub fn lost() -> Self {
        Self::new(
            "The request worker stopped unexpectedly. Refresh and look before retrying.",
            true,
        )
    }

    pub fn text(&self) -> String {
        if self.uncertain {
            format!(
                "Outcome unknown. The operation may have taken effect. Refresh and inspect before retrying. {}",
                self.message
            )
        } else {
            self.message.clone()
        }
    }
}

#[derive(Default)]
struct Cancellation {
    closed: bool,
    socket: Option<UnixStream>,
}

impl Cancellation {
    fn close(&mut self) {
        self.closed = true;
        if let Some(s) = self.socket.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

pub(crate) struct Job {
    pub result: mpsc::Receiver<Result<Response, Failure>>,
    cancel: Arc<Mutex<Cancellation>>,
    worker: Option<JoinHandle<()>>,
}

impl Job {
    pub fn start(path: PathBuf, request: Request) -> Result<Self, String> {
        Self::with_limit(path, request, Duration::from_secs(600))
    }

    fn with_limit(path: PathBuf, request: Request, limit: Duration) -> Result<Self, String> {
        let cancel = Arc::new(Mutex::new(Cancellation::default()));
        let (tx, result) = mpsc::sync_channel(1);
        let worker_cancel = Arc::clone(&cancel);
        let worker = thread::Builder::new().name("manager-request".into()).spawn(move || {
            let result = (|| {
                let status = exchange(&path, &Request::Status, &worker_cancel, Duration::from_secs(5))?;
                let Response::Status(info) = status else { return Err(Failure::new("The agent did not return status.", false)); };
                if info.protocol_version != protocol::PROTOCOL_VERSION {
                    return Err(Failure::new("Incompatible agent protocol. Upgrade matching programs and restart the agent yourself.", false));
                }
                if matches!(request, Request::Status) { return Ok(Response::Status(info)); }
                exchange(&path, &request, &worker_cancel, limit)
            })();
            let _ = tx.send(result);
            worker_cancel.lock().unwrap_or_else(|p| p.into_inner()).socket.take();
        }).map_err(|e| format!("Cannot start a request worker: {e}"))?;
        Ok(Self {
            result,
            cancel,
            worker: Some(worker),
        })
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        self.cancel
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .close();
        // shutdown interrupts active I/O. A thread between connect and socket
        // registration sees `closed` and sends nothing. Do not block GTK while
        // it finishes; the process exits when the application window closes.
        if let Some(worker) = self.worker.take()
            && worker.is_finished()
        {
            let _ = worker.join();
        }
    }
}

fn exchange(
    path: &Path,
    request: &Request,
    cancel: &Mutex<Cancellation>,
    limit: Duration,
) -> Result<Response, Failure> {
    let stream = connect_by(path, cancel)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Failure::new(e.to_string(), false))?;
    {
        let mut state = cancel.lock().unwrap_or_else(|p| p.into_inner());
        if state.closed {
            return Err(Failure::new("Connection closed before sending.", false));
        }
        state.socket = Some(
            stream
                .try_clone()
                .map_err(|e| Failure::new(e.to_string(), false))?,
        );
    }
    protocol::send_frame(&stream, request, &[])
        .map_err(|e| Failure::new(format!("Cannot send request: {e}"), false))?;
    let effects = request.has_effects();
    let (body, fds) = protocol::recv_frame_before(&stream, Some(Instant::now() + limit))
        .map_err(|_| Failure::new("No complete answer arrived from the agent.", effects))?;
    if !fds.is_empty() {
        return Err(Failure::new(
            "Unexpected descriptors in the answer.",
            effects,
        ));
    }
    // Never include a malformed body, deserializer error, or Debug response
    // in messages: an unexpected response may contain a secret.
    let response = serde_json::from_slice::<Response>(&body).map_err(|_| {
        #[derive(serde::Deserialize)]
        struct Kind {
            #[serde(rename = "type")]
            kind: String,
        }
        let unknown_error = serde_json::from_slice::<Kind>(&body).is_ok_and(|r| r.kind == "error");
        Failure::new(
            "The answer could not be understood (including an unknown error code).",
            effects || unknown_error,
        )
    })?;
    validate(request, response)
}

// AF_UNIX connect can block when the listener's backlog is full. No GTK
// thread or unregistered blocking connect may outlive cancellation forever.
fn connect_by(path: &Path, cancel: &Mutex<Cancellation>) -> Result<UnixStream, Failure> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
    use std::os::fd::AsRawFd;
    let addr = UnixAddr::new(path).map_err(|e| Failure::new(e.to_string(), false))?;
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if cancel.lock().unwrap_or_else(|p| p.into_inner()).closed || Instant::now() >= end {
            return Err(Failure::new(
                "Connection cancelled or timed out before sending.",
                false,
            ));
        }
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(|e| Failure::new(e.to_string(), false))?;
        match connect(fd.as_raw_fd(), &addr) {
            Ok(()) => {
                fcntl(&fd, FcntlArg::F_SETFL(OFlag::empty()))
                    .map_err(|e| Failure::new(e.to_string(), false))?;
                return Ok(UnixStream::from(fd));
            }
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {
                thread::sleep(Duration::from_millis(20))
            }
            // No socket, or nobody listening on it.
            Err(nix::errno::Errno::ENOENT | nix::errno::Errno::ECONNREFUSED) => {
                return Err(Failure {
                    not_running: true,
                    ..Failure::new(
                        "The agent is not running. Start it with Start agent, or see the installation guide.",
                        false,
                    )
                });
            }
            Err(e) => {
                return Err(Failure::new(
                    format!("Cannot reach the agent: {e}. See the installation guide."),
                    false,
                ));
            }
        }
    }
}

fn validate(request: &Request, response: Response) -> Result<Response, Failure> {
    if let Response::Error { code, message } = response {
        return Err(Failure::new(message, code == ErrorCode::OutcomeUnknown));
    }
    let expected = match request {
        Request::Status => "status",
        Request::List => "entries",
        Request::Show { .. } => "entry",
        Request::Reveal { .. } => "secret",
        Request::KeyringItems => "keyring_items",
        Request::DotenvNames { .. } => "names",
        Request::Grants => "grants",
        _ => "ok",
    };
    if response.kind() != expected {
        return Err(Failure::new(
            "The agent returned an unexpected kind of answer.",
            request.has_effects(),
        ));
    }
    Ok(response)
}

#[cfg(test)]
#[allow(clippy::err_expect)] // expect_err would Debug-print an unexpected Secret response.
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn status() -> Response {
        serde_json::from_value(serde_json::json!({"type":"status","protocol_version":protocol::PROTOCOL_VERSION,"agent_version":"test","vault":"/fake","vault_exists":true,"locked":false,"idle_timeout_secs":0,"remembered_approvals":0})).expect("status")
    }

    #[test]
    fn reply_kinds_and_uncertain_errors_are_not_successes() {
        let change = Request::Remove {
            name: "fake-uuid".into(),
        };
        let wrong = Response::Secret {
            value: "fake-value".to_owned().into(),
        };
        let failure = validate(&change, wrong).err().expect("failure");
        assert!(failure.uncertain);
        assert!(!failure.text().contains("fake-value"));
        assert!(
            !validate(&Request::Lock, status())
                .err()
                .expect("failure")
                .uncertain
        );
        assert!(
            validate(
                &change,
                Response::Error {
                    code: ErrorCode::OutcomeUnknown,
                    message: "uncertain".into()
                }
            )
            .err()
            .expect("failure")
            .uncertain
        );
        assert!(
            !validate(
                &change,
                Response::Error {
                    code: ErrorCode::Denied,
                    message: "denied".into()
                }
            )
            .err()
            .expect("failure")
            .uncertain
        );
    }

    #[test]
    fn a_lost_answer_after_a_change_is_uncertain_and_a_deadline_bounds_it() {
        let dir = tempfile::tempdir().expect("dir");
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).expect("listen");
        let server = thread::spawn(move || {
            let (s, _) = listener.accept().expect("accept");
            let _: Request = protocol::read_message(&s).expect("status request");
            protocol::send_frame(&s, &status(), &[]).expect("status answer");
            let (s, _) = listener.accept().expect("accept");
            let r: Request = protocol::read_message(&s).expect("request");
            assert!(matches!(r, Request::Remove { .. }));
            thread::sleep(Duration::from_millis(200));
        });
        let job = Job::with_limit(
            socket,
            Request::Remove {
                name: "fake".into(),
            },
            Duration::from_millis(50),
        )
        .expect("job");
        let failure = job
            .result
            .recv_timeout(Duration::from_secs(2))
            .expect("result")
            .err()
            .expect("failure");
        assert!(failure.uncertain);
        drop(job);
        server.join().expect("server");
    }

    #[test]
    fn closing_a_job_interrupts_its_wait_and_an_old_agent_gets_no_change() {
        for old in [false, true] {
            let dir = tempfile::tempdir().expect("dir");
            let socket = dir.path().join("agent.sock");
            let listener = UnixListener::bind(&socket).expect("listen");
            let (tx, rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let (s, _) = listener.accept().expect("accept");
                let _: Request = protocol::read_message(&s).expect("request");
                if old {
                    let Response::Status(mut info) = status() else {
                        unreachable!()
                    };
                    // Protocol 3: its `copy` dialog promised a single paste.
                    info.protocol_version = 3;
                    protocol::send_frame(&s, &Response::Status(info), &[]).expect("answer");
                    listener.set_nonblocking(true).expect("nonblocking");
                    thread::sleep(Duration::from_millis(100));
                    assert!(listener.accept().is_err());
                } else {
                    tx.send(()).expect("ready");
                    s.set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("timeout");
                    use std::io::Read;
                    assert_eq!((&s).read(&mut [0u8]).expect("closed"), 0);
                }
            });
            let job = Job::start(
                socket,
                Request::Remove {
                    name: "fake".into(),
                },
            )
            .expect("job");
            if old {
                let e = job
                    .result
                    .recv_timeout(Duration::from_secs(2))
                    .expect("reply")
                    .err()
                    .expect("failure");
                assert!(!e.uncertain);
            } else {
                rx.recv_timeout(Duration::from_secs(2)).expect("ready");
            }
            drop(job);
            server.join().expect("server");
        }
    }

    #[test]
    fn an_unknown_error_code_is_uncertain_even_for_lock() {
        let dir = tempfile::tempdir().expect("dir");
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).expect("listen");
        let server = thread::spawn(move || {
            let (s, _) = listener.accept().expect("accept");
            let _: Request = protocol::read_message(&s).expect("request");
            protocol::send_frame(&s, &status(), &[]).expect("status");
            let (s, _) = listener.accept().expect("accept");
            let _: Request = protocol::read_message(&s).expect("request");
            protocol::send_frame(
                &s,
                &serde_json::json!({"type":"error","code":"future_error","message":"fake"}),
                &[],
            )
            .expect("answer");
        });
        let job = Job::start(socket, Request::Lock).expect("job");
        assert!(
            job.result
                .recv_timeout(Duration::from_secs(2))
                .expect("reply")
                .err()
                .expect("error")
                .uncertain
        );
        drop(job);
        server.join().expect("server");
    }

    #[test]
    fn a_full_listen_backlog_does_not_trap_a_cancelled_connect() {
        use nix::sys::socket::{Backlog, listen};
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("full.sock");
        let listener = UnixListener::bind(&path).expect("listener");
        listen(&listener, Backlog::new(0).expect("backlog")).expect("listen");
        let _queued = UnixStream::connect(&path).expect("fill single slot");
        let cancel = Arc::new(Mutex::new(Cancellation::default()));
        let other = Arc::clone(&cancel);
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = tx.send(connect_by(&path, &other));
        });
        // A normal blocking connect cannot see this flag; the timeout fails.
        thread::sleep(Duration::from_millis(100));
        cancel.lock().expect("lock").close();
        assert!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("cancellation")
                .is_err()
        );
        worker.join().expect("worker");
    }
}
