//! Identifying the process on the other end of the agent socket.
//!
//! The kernel reports the connecting process's pid and uid (`SO_PEERCRED`);
//! the agent rejects other users and shows the process chain in dialogs so the
//! human can tell *who* is asking (for example `bash ← claude`).
//!
//! The chain is informative only: process names are chosen by the processes
//! themselves and pids can be reused. It is never used for access decisions.
//!
//! A peer also lends the request's connection, to tell whether the requester
//! is still there ([`Peer::gone`]): a borrow of the connection, so that no
//! peer, nor any copy of one, outlives the connection it was read from.

use std::os::unix::net::UnixStream;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::ui::Connection;

/// How many ancestors to collect.
const MAX_CHAIN: usize = 8;

/// One process in the requester chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process id.
    pub pid: i32,
    /// Command name (`/proc/<pid>/comm`).
    pub name: String,
}

/// The process that opened a connection, and its ancestors; and, for a
/// request being handled, that connection (`'a`), to watch.
#[derive(Debug, Clone)]
pub struct Peer<'a> {
    /// User id of the connecting process.
    pub uid: u32,
    /// Process id of the connecting process.
    pub pid: i32,
    /// The connecting process first, then its parent, grandparent, ...
    pub chain: Vec<ProcessInfo>,
    /// The connection, borrowed: [`Connection::none`] until
    /// [`Peer::connected`].
    connection: Connection<'a>,
}

impl Peer<'static> {
    /// Read the credentials of the process connected to `stream`. The
    /// connection itself is not watched until [`Peer::connected`].
    pub fn of(stream: &UnixStream) -> std::io::Result<Peer<'static>> {
        let creds = getsockopt(stream, PeerCredentials)?;
        Ok(Peer {
            uid: creds.uid(),
            pid: creds.pid(),
            chain: process_chain(creds.pid()),
            connection: Connection::none(),
        })
    }

    /// A peer representing the agent itself (for audit records it
    /// originates); it has no connection, so it is never gone.
    pub fn agent() -> Peer<'static> {
        let pid = std::process::id() as i32;
        Peer {
            uid: nix::unistd::getuid().as_raw(),
            pid,
            chain: vec![ProcessInfo {
                pid,
                name: "rusthorse-agent".into(),
            }],
            connection: Connection::none(),
        }
    }
}

impl<'a> Peer<'a> {
    /// This peer, with the connection its request came on. The borrow keeps
    /// the peer, and every copy of it, from outliving the connection:
    ///
    /// ```compile_fail,E0597
    /// use std::os::fd::AsFd;
    /// use rusthorse::{peer::Peer, ui::Connection};
    /// let kept = {
    ///     let (stream, _other) = std::os::unix::net::UnixStream::pair().unwrap();
    ///     let peer = Peer::of(&stream).unwrap();
    ///     peer.connected(Connection::new(stream.as_fd(), false)).clone()
    /// };
    /// assert!(!kept.gone());
    /// ```
    pub fn connected<'b>(self, connection: Connection<'b>) -> Peer<'b> {
        Peer {
            uid: self.uid,
            pid: self.pid,
            chain: self.chain,
            connection,
        }
    }

    /// The connection, for a dialog shown for this peer to watch.
    pub fn connection(&self) -> Connection<'a> {
        self.connection
    }

    /// Whether the requester has gone ([`Connection::gone`]); never, for a
    /// peer without a connection.
    pub fn gone(&self) -> bool {
        self.connection.gone()
    }

    /// `rusthorse[4242] ← bash[4200] ← claude[3990]`.
    pub fn describe(&self) -> String {
        if self.chain.is_empty() {
            return format!("pid {}", self.pid);
        }
        self.chain
            .iter()
            .map(|p| format!("{}[{}]", crate::util::visible(&p.name), p.pid))
            .collect::<Vec<_>>()
            .join(" ← ")
    }
}

/// Walk `/proc/<pid>/stat` upwards until pid 1 or eight processes.
pub fn process_chain(pid: i32) -> Vec<ProcessInfo> {
    let mut chain = Vec::new();
    let mut current = pid;
    while current > 1 && chain.len() < MAX_CHAIN {
        let Some((name, parent)) = read_stat(current) else {
            break;
        };
        chain.push(ProcessInfo { pid: current, name });
        current = parent;
    }
    chain
}

/// When process `pid` started, in clock ticks since boot (`/proc/<pid>/stat`,
/// field 22): with the pid, it tells one process from a later one that
/// reuses its pid.
pub fn start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.iter().rposition(|&b| b == b')')?;
    std::str::from_utf8(stat.get(close + 1..)?)
        .ok()?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Parse the command name and parent pid out of `/proc/<pid>/stat`.
fn read_stat(pid: i32) -> Option<(String, i32)> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    // Format: "pid (comm) state ppid ..."; comm may contain any byte,
    // including ')' and spaces, and need not be UTF-8.
    let open = stat.iter().position(|&b| b == b'(')?;
    let close = stat.iter().rposition(|&b| b == b')')?;
    let name = String::from_utf8_lossy(stat.get(open + 1..close)?).into_owned();
    let mut rest = std::str::from_utf8(stat.get(close + 1..)?)
        .ok()?
        .split_whitespace();
    let _state = rest.next()?;
    let parent = rest.next()?.parse().ok()?;
    Some((name, parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_has_a_start_time_and_keeps_it() {
        let me = std::process::id() as i32;
        let first = start_time(me).expect("start time");
        assert_eq!(start_time(me), Some(first));
        assert!(start_time(1).is_some_and(|init| init <= first));
    }

    #[test]
    fn chain_starts_with_ourselves() {
        let me = std::process::id() as i32;
        let chain = process_chain(me);
        assert_eq!(chain.first().map(|p| p.pid), Some(me));
    }

    #[test]
    fn socket_pair_peer_is_ourselves() {
        let (a, _b) = UnixStream::pair().expect("pair");
        let peer = Peer::of(&a).expect("peer");
        assert_eq!(peer.pid, std::process::id() as i32);
        assert_eq!(peer.uid, nix::unistd::getuid().as_raw());
        assert!(peer.describe().contains(&format!("[{}]", peer.pid)));
    }

    #[test]
    fn a_peer_is_gone_once_its_connection_is_closed() {
        use std::os::fd::AsFd;
        assert!(!Peer::agent().gone());
        let (a, b) = UnixStream::pair().expect("pair");
        let peer = Peer::of(&a).expect("peer");
        assert!(!peer.gone(), "not watched before it is connected");
        let peer = peer.connected(Connection::new(a.as_fd(), false));
        let copy = peer.clone();
        assert!(!peer.gone() && !copy.gone());
        // Closed: seen once no other copy of `b` remains (a process forked
        // by another test holds one until its exec).
        drop(b);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !peer.gone() {
            assert!(
                std::time::Instant::now() < until,
                "a closed connection not seen"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(copy.gone());
    }
}
