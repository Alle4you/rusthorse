//! Supervising the helper processes the agent starts for dialogs
//! (`rusthorse-dialog`, zenity) and that `doctor` starts to check them.
//!
//! A supervised process runs in its own process group. Every read and write
//! with it is bounded by one absolute deadline, recalculated before each
//! system call, so that a process sending a byte at a time cannot stretch
//! it. Its exit is observed without reaping it; when the supervisor is
//! dropped, the whole group is killed and only then is the leader reaped —
//! while it is unreaped its process group id cannot be reused, so the kill
//! cannot reach anyone else, and no descendant outlives it (one that moved
//! to another session or group escapes, as with approved commands).
//!
//! A read that waits for a dialog's answer also watches the connection of
//! the program the dialog is for, and stops when that program goes away
//! ([`is_gone`]): the dialog is then killed as at the deadline.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::Pid;
use zeroize::Zeroizing;

use crate::ui::Connection;

/// How long past a dialog's own timeout the agent waits before it kills the
/// dialog program.
pub(crate) const GRACE: Duration = Duration::from_secs(5);

/// How a supervised process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    /// It exited with this status.
    Code(i32),
    /// A signal ended it.
    Signal(i32),
}

impl Exit {
    /// The exit status, if it exited rather than being killed.
    pub(crate) fn code(self) -> Option<i32> {
        match self {
            Exit::Code(code) => Some(code),
            Exit::Signal(_) => None,
        }
    }

    /// Whether it exited with status 0.
    pub(crate) fn success(self) -> bool {
        self == Exit::Code(0)
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Exit::Code(code) => write!(f, "exit status {code}"),
            Exit::Signal(signal) => write!(f, "killed by signal {signal}"),
        }
    }
}

/// A process in its own group, killed with its group when dropped.
pub(crate) struct Supervised {
    child: Child,
    group: Pid,
}

impl Supervised {
    /// Start `cmd` (its standard streams already set) as the leader of a new
    /// process group. Dropping the command afterwards closes the caller's
    /// copies of the descriptors given to it.
    pub(crate) fn spawn(mut cmd: Command) -> io::Result<Self> {
        cmd.process_group(0);
        let spawned = cmd.spawn();
        drop(cmd);
        let child = spawned?;
        let group = Pid::from_raw(child.id() as i32);
        Ok(Self { child, group })
    }

    /// How the leader ended, if it has, without reaping it.
    pub(crate) fn exited(&self) -> io::Result<Option<Exit>> {
        let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG;
        loop {
            return match waitid(Id::Pid(self.group), flags) {
                Ok(WaitStatus::Exited(_, code)) => Ok(Some(Exit::Code(code))),
                Ok(WaitStatus::Signaled(_, signal, _)) => Ok(Some(Exit::Signal(signal as i32))),
                Ok(_) => Ok(None),
                Err(Errno::EINTR) => continue,
                Err(e) => Err(e.into()),
            };
        }
    }

    /// Wait until the leader has ended or `deadline` passes.
    pub(crate) fn exit_by(&self, deadline: Instant) -> io::Result<Option<Exit>> {
        loop {
            if let Some(exit) = self.exited()? {
                return Ok(Some(exit));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The group's process id, for tests.
    #[cfg(test)]
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Supervised {
    fn drop(&mut self) {
        // The leader is not reaped yet, so neither its process id nor its
        // group's can have been reused: kill the group (descendants), then
        // the leader itself, which may have moved to another group, and only
        // then wait — for a process that is certainly dying.
        let _ = killpg(self.group, Signal::SIGKILL);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The time left before `deadline`, or a `TimedOut` error.
fn left(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline passed"))
}

fn retry(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// `poll(2)` on raw descriptors, once. `nix`'s `PollFd::revents()` returns
/// `None` when the kernel reports a bit `nix` does not name (`POLLRDHUP`,
/// needed to notice a half-closed connection), so the agent reads the events
/// itself. A signal that interrupts it is an error of the kind
/// `Interrupted`: the caller waits again, for what it has left
/// ([`poll_by`]).
#[allow(unsafe_code)]
pub(crate) fn poll_raw(fds: &mut [nix::libc::pollfd], timeout_ms: i32) -> io::Result<usize> {
    // SAFETY: `fds` is a valid, exclusively borrowed slice of pollfd.
    let n = unsafe { nix::libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout_ms) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Wait with `poll`, given the milliseconds left before `deadline` each
/// time, until it reports something or the deadline passes (then `Ok(0)`).
/// A wait that a signal interrupts is resumed for the time that is left,
/// never for its first timeout, so that no number of interruptions can
/// stretch it.
pub(crate) fn poll_by(
    deadline: Instant,
    mut poll: impl FnMut(i32) -> io::Result<usize>,
) -> io::Result<usize> {
    loop {
        let Ok(wait) = left(deadline) else {
            return Ok(0);
        };
        let millis = wait.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
        match poll(millis) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            polled => return polled,
        }
    }
}

/// Why a read stopped when the requester went away (see [`is_gone`]).
#[derive(Debug)]
struct RequesterGone;

impl fmt::Display for RequesterGone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the program that asked went away")
    }
}

impl std::error::Error for RequesterGone {}

/// Whether a read failed because the requester it watched went away.
pub(crate) fn is_gone(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<RequesterGone>())
}

/// One `read`, waiting at most until `deadline` — and, while it waits, only
/// as long as `requester` is not gone (then an error that [`is_gone`]
/// recognises; a requester that leaves is noticed before data that arrived
/// at the same moment).
pub(crate) fn read_by(
    socket: &UnixStream,
    buf: &mut [u8],
    deadline: Instant,
    requester: Connection<'_>,
) -> io::Result<usize> {
    loop {
        if let Some(watched) = requester.pollfd() {
            // Past the deadline, the wait below returns at once: stop here.
            left(deadline)?;
            let mut fds = [
                nix::libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: nix::libc::POLLIN,
                    revents: 0,
                },
                watched,
            ];
            poll_by(deadline, |millis| poll_raw(&mut fds, millis))?;
            if requester.left(fds[1].revents) {
                return Err(io::Error::other(RequesterGone));
            }
            if fds[0].revents == 0 {
                continue;
            }
        }
        socket.set_read_timeout(Some(left(deadline)?))?;
        match (&*socket).read(buf) {
            Err(e) if retry(&e) => continue,
            other => return other,
        }
    }
}

/// Fill `buf`, all of it before `deadline` (and while `requester` is there).
pub(crate) fn read_exact_by(
    socket: &UnixStream,
    buf: &mut [u8],
    deadline: Instant,
    requester: Connection<'_>,
) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match read_by(socket, &mut buf[filled..], deadline, requester)? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => filled += n,
        }
    }
    Ok(())
}

/// Write all of `data` before `deadline`.
pub(crate) fn write_all_by(socket: &UnixStream, data: &[u8], deadline: Instant) -> io::Result<()> {
    let mut written = 0;
    while written < data.len() {
        socket.set_write_timeout(Some(left(deadline)?))?;
        match (&*socket).write(&data[written..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => written += n,
            Err(e) if retry(&e) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read until end of stream, at most `limit` bytes, before `deadline` (and
/// while `requester` is there).
pub(crate) fn read_to_end_by(
    socket: &UnixStream,
    limit: usize,
    deadline: Instant,
    requester: Connection<'_>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(1024));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        match read_by(socket, &mut chunk[..], deadline, requester)? {
            0 => return Ok(out),
            n if out.len() + n > limit => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("more than {limit} bytes"),
                ));
            }
            n => out.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Read one frame (a 4-byte big-endian length, then that many bytes) of at
/// most `max` bytes, before `deadline` (and while `requester` is there).
pub(crate) fn read_frame_by(
    socket: &UnixStream,
    max: usize,
    deadline: Instant,
    requester: Connection<'_>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut length = [0u8; 4];
    read_exact_by(socket, &mut length, deadline, requester)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {length} bytes, limit {max}"),
        ));
    }
    let mut body = Zeroizing::new(vec![0u8; length]);
    read_exact_by(socket, &mut body, deadline, requester)?;
    Ok(body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::fd::OwnedFd;
    use std::process::Stdio;

    /// Whether a process exists and is not a zombie.
    pub(crate) fn alive(pid: u32) -> bool {
        match std::fs::read(format!("/proc/{pid}/stat")) {
            Ok(stat) => {
                let close = stat.iter().rposition(|&b| b == b')').unwrap_or(0);
                !matches!(stat.get(close + 2), Some(b'Z' | b'X'))
            }
            Err(_) => false,
        }
    }

    /// Wait up to 2 seconds for `pid` to be gone.
    pub(crate) fn gone(pid: u32) -> bool {
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if !alive(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn sh(script: &str, out: UnixStream) -> Supervised {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::from(OwnedFd::from(out)))
            .stderr(Stdio::null());
        Supervised::spawn(cmd).expect("spawn")
    }

    #[test]
    fn a_trickle_of_bytes_cannot_stretch_the_deadline() {
        let (ours, theirs) = UnixStream::pair().expect("pair");
        let _child = sh(
            "for i in 1 2 3 4 5 6 7 8 9 10; do printf x; sleep 0.1; done",
            theirs,
        );
        let started = Instant::now();
        let mut buf = [0u8; 10];
        let err = read_exact_by(
            &ours,
            &mut buf,
            started + Duration::from_millis(300),
            Connection::none(),
        )
        .expect_err("too slow");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn interruptions_cannot_stretch_a_wait() {
        // A hundred interruptions of 10 ms each, far more than fit in a
        // wait of 200 ms. Resumed for what is left, the wait ends at its
        // deadline: at most 21 calls fit, since a sleep never ends early,
        // each given less time than the one before. A wait resumed for its
        // first timeout would take all of them.
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut given = Vec::new();
        let polled = poll_by(deadline, |millis| {
            given.push(millis);
            if given.len() <= 100 {
                std::thread::sleep(Duration::from_millis(10));
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(0)
            }
        });
        assert_eq!(polled.expect("poll"), 0);
        assert!(Instant::now() >= deadline);
        assert!(given.len() <= 21, "{} calls: {given:?}", given.len());
        assert!(given.windows(2).all(|w| w[1] < w[0]), "{given:?}");
        // Another error ends the wait as it is.
        let polled = poll_by(Instant::now() + Duration::from_secs(10), |_| {
            Err(io::ErrorKind::InvalidInput.into())
        });
        assert_eq!(
            polled.expect_err("an error").kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn dropping_kills_the_whole_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("pid");
        let (_ours, theirs) = UnixStream::pair().expect("pair");
        let child = sh(
            &format!("sleep 30 & echo $! > '{}'; exit 0", pidfile.display()),
            theirs,
        );
        // The leader exits at once; its descendant keeps running.
        assert_eq!(
            child
                .exit_by(Instant::now() + Duration::from_secs(5))
                .expect("wait"),
            Some(Exit::Code(0))
        );
        let descendant: u32 = std::fs::read_to_string(&pidfile)
            .expect("pid")
            .trim()
            .parse()
            .expect("number");
        assert!(alive(descendant));
        let leader = child.id();
        drop(child);
        assert!(gone(descendant), "a descendant outlived the supervisor");
        assert!(gone(leader), "the leader was not reaped");
    }

    #[test]
    fn a_leader_that_leaves_its_group_is_still_killed() {
        if !std::path::Path::new("/usr/bin/python3").exists() {
            eprintln!("skipped: no python3 to move a process to another group");
            return;
        }
        let (ours, theirs) = UnixStream::pair().expect("pair");
        let mut cmd = Command::new("/usr/bin/python3");
        cmd.args([
            "-c",
            "import os, sys, time; os.setpgid(0, os.getpgid(os.getppid())); \
             sys.stdout.write('moved'); sys.stdout.flush(); time.sleep(30)",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(theirs)))
        .stderr(Stdio::null());
        let child = Supervised::spawn(cmd).expect("spawn");
        let leader = child.id();
        // Wait until it has left its group.
        let mut moved = [0u8; 5];
        read_exact_by(
            &ours,
            &mut moved,
            Instant::now() + Duration::from_secs(10),
            Connection::none(),
        )
        .expect("it says when it has moved");
        assert_eq!(&moved, b"moved");
        // Dropping must not wait for the 30 seconds.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(child);
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(3))
            .expect("dropping the supervisor hung");
        assert!(gone(leader));
    }

    #[test]
    fn reading_to_the_end_is_bounded_in_size_and_time() {
        let (ours, theirs) = UnixStream::pair().expect("pair");
        let _child = sh("printf 0123456789", theirs);
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            &read_to_end_by(&ours, 10, deadline, Connection::none()).expect("read")[..],
            b"0123456789"
        );
        let (ours, theirs) = UnixStream::pair().expect("pair");
        let _child = sh("printf 0123456789", theirs);
        assert!(read_to_end_by(&ours, 9, deadline, Connection::none()).is_err());
        // A descendant holding the stream open: end of stream never comes.
        let (ours, theirs) = UnixStream::pair().expect("pair");
        let _child = sh("printf ok; sleep 30 & exit 0", theirs);
        let started = Instant::now();
        let err = read_to_end_by(
            &ours,
            100,
            started + Duration::from_millis(300),
            Connection::none(),
        )
        .expect_err("no end");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(600));
    }
}
