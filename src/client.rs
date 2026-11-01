//! The client side of the agent protocol.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::protocol::{self, Frame, Request, Response, RunRequest};

/// A connection factory for the agent socket.
#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
}

/// Signal number reported when the client's own stdout is closed while it is
/// relaying output (the shell convention for a broken pipe, 128 + 13).
const SIGPIPE: i32 = 13;

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

    /// Ask the agent to run a command and wait until it has finished.
    ///
    /// With redaction (the default), the agent sends the command's output
    /// back as data frames, which this process writes to its own stdout and
    /// stderr; with `forward_stdin`, this process reads its own stdin and
    /// sends it on. The agent never touches this process's descriptors.
    /// Without redaction, the three descriptors are handed to the command.
    pub fn run(&self, request: RunRequest) -> anyhow::Result<Response> {
        let stream = self.connect()?;
        if !request.redact {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let fds = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
            protocol::send_frame(&stream, &Request::Run(request), &fds)
                .context("cannot send the request")?;
            return protocol::read_message(&stream).context("the agent closed the connection");
        }

        let forward = request.forward_stdin;
        protocol::send_frame(&stream, &Request::Run(request), &[])
            .context("cannot send the request")?;
        if forward {
            let writer = stream.try_clone().context("cannot clone the connection")?;
            // Not joined: it ends with this process, right after the result.
            std::thread::spawn(move || forward_input(writer));
        }
        let mut stdout = std::io::stdout().lock();
        let mut stderr = std::io::stderr().lock();
        loop {
            let frame = protocol::recv_any_before(&stream, None)
                .context("the agent closed the connection")?;
            let written = match frame {
                Frame::Data(protocol::STDOUT, data) => {
                    stdout.write_all(&data).and_then(|()| stdout.flush())
                }
                Frame::Data(protocol::STDERR, data) => {
                    stderr.write_all(&data).and_then(|()| stderr.flush())
                }
                Frame::Data(..) => Ok(()),
                Frame::Message(body, _fds) => {
                    return serde_json::from_slice(&body).context("malformed response");
                }
            };
            if written.is_err() {
                // Our own output is gone (e.g. `| head` exited): behave like a
                // process killed by SIGPIPE. Closing the connection makes the
                // agent stop the command.
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Ok(Response::Exited {
                    code: None,
                    signal: Some(SIGPIPE),
                });
            }
        }
    }
}

/// Send this process's stdin to the agent until end-of-file.
fn forward_input(stream: UnixStream) {
    let mut stdin = std::io::stdin().lock();
    let mut buf = zeroize::Zeroizing::new(vec![0u8; 16 * 1024]);
    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if protocol::send_data(&stream, protocol::STDIN, &buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = protocol::send_data(&stream, protocol::STDIN, &[]);
}
