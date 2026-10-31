//! The client side of the agent protocol.

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::protocol::{self, Request, Response, RunRequest};

/// A connection factory for the agent socket.
#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
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

    /// Ask the agent to run a command. This process's stdin, stdout and
    /// stderr are handed to the agent, which connects them to the command.
    /// Returns once the command has finished (or the request failed).
    pub fn run(&self, request: RunRequest) -> anyhow::Result<Response> {
        let stream = self.connect()?;
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let fds = [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
        protocol::send_frame(&stream, &Request::Run(request), &fds)
            .context("cannot send the request")?;
        protocol::read_message(&stream).context("the agent closed the connection")
    }
}
