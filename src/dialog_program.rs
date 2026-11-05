//! Showing dialogs with `rusthorse-dialog`, Rusthorse's own dialog program,
//! and falling back to zenity only when it is not installed
//! ([ADR 0006](../docs/adr/0006-own-dialog-program.md)).
//!
//! The program is found next to the agent's executable, started with a
//! minimal environment and a private configuration directory, and given one
//! end of a socket pair for both the request and the answer. One deadline
//! covers the whole exchange; after it, the program is killed. Anything but a
//! well-formed answer to this request, followed by end of stream and a clean
//! exit, is an error — a denial for the caller.

use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};

use crate::dialog_protocol::{self as wire, Answer, Dialog, Remember, Reply, Request};
use crate::helper_program;
use crate::supervise::{Exit, GRACE, Supervised, read_by, read_frame_by, write_all_by};
use crate::ui::{
    ApprovalRequest, Decision, Prompt, Typed, Ui, ZenityUi, dialog_env, dialog_text, remember_note,
};
use crate::util::format_duration;

// Every helper program is found and checked the same way; these keep their
// names here for the callers of this module.
pub use crate::helper_program::{Located, check_program};

/// File name of the dialog program, looked for next to the agent's
/// executable.
pub const PROGRAM: &str = "rusthorse-dialog";

/// The only session variables the program receives.
const PASSED: [&str; 9] = [
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "LANG",
    "LC_ALL",
    "LC_MESSAGES",
    "LANGUAGE",
];

/// Find the dialog program next to this process's executable
/// ([`helper_program::locate`]). When it is [`Located::Absent`], dialogs use
/// zenity; when it is [`Located::Unusable`], they are refused.
pub fn locate() -> Located {
    helper_program::locate(PROGRAM)
}

/// Find and check the dialog program in `dir`
/// ([`helper_program::locate_in`]).
pub fn locate_in(dir: &Path) -> Located {
    helper_program::locate_in(dir, PROGRAM)
}

/// The program's environment: the display, D-Bus and locale variables of
/// the session (the agent's own environment, never a request's), the X
/// authority file resolved before `HOME` is replaced, and `private` for
/// everything per-user, so that no per-user GTK configuration, style sheet,
/// theme or setting applies.
pub fn environment(session: &[(String, String)], private: &Path) -> Vec<(String, String)> {
    let get = |name: &str| {
        session
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let mut env: Vec<(String, String)> = PASSED
        .iter()
        .filter_map(|name| get(name).map(|value| (name.to_string(), value)))
        .collect();
    if get("XAUTHORITY").is_none() && get("DISPLAY").is_some() {
        let home = get("HOME").map(PathBuf::from).or_else(|| {
            nix::unistd::User::from_uid(nix::unistd::getuid())
                .ok()
                .flatten()
                .map(|user| user.dir)
        });
        if let Some(file) = home.map(|home| home.join(".Xauthority"))
            && file.is_file()
        {
            env.push(("XAUTHORITY".into(), file.display().to_string()));
        }
    }
    let private = private.display().to_string();
    for name in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"] {
        env.push((name.into(), private.clone()));
    }
    env.push(("XDG_DATA_DIRS".into(), "/usr/local/share:/usr/share".into()));
    env.push(("GSETTINGS_BACKEND".into(), "memory".into()));
    env
}

/// A new, empty directory (mode `0700`) for one dialog, removed when dropped.
#[derive(Debug)]
pub struct PrivateDir(PathBuf);

impl PrivateDir {
    /// Create one in `base`.
    pub fn create(base: &Path) -> io::Result<Self> {
        let path = base.join(format!("rusthorse-dialog-{}", random_hex(12)?));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }

    /// Its path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn random_hex(bytes: usize) -> io::Result<String> {
    let mut out = String::with_capacity(bytes * 2);
    for _ in 0..bytes.div_ceil(4) {
        let word = getrandom::u32().map_err(io::Error::other)?;
        out.push_str(&format!("{word:08x}"));
    }
    out.truncate(bytes * 2);
    Ok(out)
}

/// How an exchange went wrong.
enum Broken {
    /// The deadline passed.
    Deadline,
    /// Anything else.
    Failed(anyhow::Error),
}

/// An I/O error, or the deadline if it is why.
fn io_broken(e: io::Error, what: &str, deadline: Instant) -> Broken {
    if e.kind() == io::ErrorKind::TimedOut && Instant::now() >= deadline {
        Broken::Deadline
    } else {
        Broken::Failed(anyhow!("{what}: {e}"))
    }
}

/// Show one dialog with `program` and return the human's reply. One deadline
/// covers sending the request, reading the answer, the end of the stream and
/// the program's exit; when it passes before the answer, the reply is
/// [`Reply::TimedOut`]. Any other problem is an error. In every case the
/// program's whole process group is killed and the program reaped before
/// this returns.
pub fn exchange(
    program: &Path,
    env: &[(String, String)],
    request: &Request,
    deadline: Instant,
) -> anyhow::Result<Reply> {
    let (ours, theirs) = UnixStream::pair().context("cannot create a socket pair")?;
    let mut cmd = Command::new(program);
    cmd.current_dir("/")
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::from(OwnedFd::from(
            theirs.try_clone().context("cannot duplicate a socket")?,
        )))
        .stdout(Stdio::from(OwnedFd::from(theirs)))
        .stderr(Stdio::null());
    let child =
        Supervised::spawn(cmd).with_context(|| format!("cannot run {}", program.display()))?;
    match talk(&ours, &child, request, deadline) {
        Ok(reply) => Ok(reply),
        Err(Broken::Deadline) => Ok(Reply::TimedOut),
        Err(Broken::Failed(e)) => Err(explain(&child, e, deadline)),
    }
}

fn talk(
    socket: &UnixStream,
    child: &Supervised,
    request: &Request,
    deadline: Instant,
) -> Result<Reply, Broken> {
    let mut frame = Vec::new();
    wire::write_frame(&mut frame, request, wire::MAX_REQUEST)
        .map_err(|e| Broken::Failed(anyhow!("cannot frame the request: {e}")))?;
    write_all_by(socket, &frame, deadline)
        .map_err(|e| io_broken(e, "cannot send the request", deadline))?;
    // One request only: the program sees its end.
    socket
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| Broken::Failed(anyhow!("cannot finish the request: {e}")))?;
    let body = read_frame_by(socket, wire::MAX_ANSWER, deadline)
        .map_err(|e| io_broken(e, "no usable answer", deadline))?;
    let answer: Answer = wire::parse(&body).map_err(|e| Broken::Failed(anyhow!("{e}")))?;
    if answer.version != wire::VERSION || answer.id != request.id {
        return Err(Broken::Failed(anyhow!(
            "the answer is not for this request"
        )));
    }
    // From here on the human has answered: a program that does not finish
    // properly is a failure, not a timeout.
    let after = |broken: Broken| match broken {
        Broken::Deadline => Broken::Failed(anyhow!("it answered, then did not exit")),
        failed => failed,
    };
    // Exactly one frame: then end of stream.
    let mut extra = [0u8; 1];
    match read_by(socket, &mut extra, deadline) {
        Ok(0) => {}
        Ok(_) => return Err(Broken::Failed(anyhow!("more than one answer"))),
        Err(e) => return Err(after(io_broken(e, "the answer did not end", deadline))),
    }
    // And a clean exit, within the deadline.
    match child.exit_by(deadline) {
        Ok(Some(exit)) if exit.success() => Ok(answer.reply),
        Ok(Some(exit)) => Err(Broken::Failed(anyhow!("it answered, then failed ({exit})"))),
        Ok(None) => Err(Broken::Failed(anyhow!("it answered, then did not exit"))),
        Err(e) => Err(Broken::Failed(e.into())),
    }
}

/// Add what the program's exit status says to an error, waiting for it to
/// exit at most a second and never past the deadline.
fn explain(child: &Supervised, error: anyhow::Error, deadline: Instant) -> anyhow::Error {
    let until = deadline.min(Instant::now() + Duration::from_secs(1));
    let code = child.exit_by(until).ok().flatten().and_then(Exit::code);
    let reason = match code {
        Some(wire::EXIT_INCOMPATIBLE) => {
            "it speaks another protocol version: install the same version of rusthorse and \
             rusthorse-dialog, then restart the agent"
                .to_string()
        }
        Some(wire::EXIT_INVALID) => "it refused the request as malformed".to_string(),
        _ => error.to_string(),
    };
    anyhow!("the dialog program failed ({reason})")
}

/// The decision an approval reply stands for. `offered` tells whether
/// "Allow for N" was offered.
pub fn decision(reply: Reply, offered: bool, remember_for: Duration) -> anyhow::Result<Decision> {
    Ok(match reply {
        Reply::AllowOnce => Decision::AllowOnce,
        Reply::AllowFor if offered => Decision::AllowFor(remember_for),
        Reply::Deny => Decision::Deny,
        Reply::TimedOut => Decision::TimedOut,
        other => bail!("the dialog program gave an answer that was not offered ({other:?})"),
    })
}

/// What an entry reply stands for.
pub fn typed(reply: Reply) -> anyhow::Result<Typed> {
    Ok(match reply {
        Reply::Typed { text } if text.len() <= wire::MAX_TYPED => Typed::Value(text),
        Reply::Typed { .. } => bail!("the dialog program returned too much text"),
        Reply::Cancel => Typed::Cancelled,
        Reply::TimedOut => Typed::TimedOut,
        other => bail!("the dialog program gave an answer that was not offered ({other:?})"),
    })
}

fn pairs(pairs: &[(String, String)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (dialog_text(k), dialog_text(v)))
        .collect()
}

/// The dialogs the agent shows: `rusthorse-dialog` when it is installed next
/// to the agent, zenity when it is not.
#[derive(Debug)]
pub struct DesktopUi {
    /// How long "Allow for …" lasts and how long a dialog waits: settings
    /// of the agent, which `configure` changes while it runs
    /// ([`Ui::set_timing`]). Each dialog uses those of the moment it starts.
    timing: std::sync::Mutex<Timing>,
}

/// See [`DesktopUi`].
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// How long "Allow for …" lasts; zero hides that button.
    remember_for: Duration,
    /// How long a dialog waits before giving up.
    timeout: Duration,
}

impl DesktopUi {
    /// Dialogs that offer "Allow for `remember_for`" (zero: not at all) and
    /// wait `timeout` for an answer.
    pub fn new(remember_for: Duration, timeout: Duration) -> Self {
        DesktopUi {
            timing: std::sync::Mutex::new(Timing {
                remember_for,
                timeout,
            }),
        }
    }

    fn timing(&self) -> Timing {
        *self.timing.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn zenity(timing: Timing) -> ZenityUi {
        ZenityUi {
            remember_for: timing.remember_for,
            timeout: timing.timeout,
        }
    }

    fn show(
        &self,
        program: &Path,
        title: &str,
        dialog: Dialog,
        timeout: Duration,
    ) -> anyhow::Result<Reply> {
        let session = dialog_env();
        let base = session
            .iter()
            .find(|(k, _)| k == "XDG_RUNTIME_DIR")
            .map(|(_, v)| PathBuf::from(v))
            .filter(|dir| dir.is_dir())
            .unwrap_or_else(std::env::temp_dir);
        let private =
            PrivateDir::create(&base).context("cannot create a directory for the dialog")?;
        let env = environment(&session, private.path());
        let timeout = timeout.max(Duration::from_secs(1));
        let request = Request {
            version: wire::VERSION,
            id: random_hex(16)?,
            timeout_secs: timeout.as_secs(),
            title: dialog_text(title),
            dialog,
        };
        exchange(program, &env, &request, Instant::now() + timeout + GRACE)
    }

    fn entry(&self, prompt: &Prompt) -> anyhow::Result<Typed> {
        let timing = self.timing();
        match locate() {
            Located::Absent(_) => {
                // The agent checked the height only if it expected zenity:
                // check again, now that zenity it is.
                if let Some(height) = crate::ui::prompt_too_tall(prompt) {
                    bail!("this dialog would be too tall to read at once ({height} pixels)");
                }
                Self::zenity(timing).master_password(prompt)
            }
            Located::Unusable(why) => bail!("cannot show the dialog: {why}"),
            Located::Program(program) => {
                let dialog = Dialog::Entry {
                    headline: dialog_text(&prompt.headline),
                    explanation: dialog_text(&prompt.explanation),
                    notice: prompt.notice.as_deref().map(dialog_text),
                    details: pairs(&prompt.details),
                    field: dialog_text(&prompt.field),
                    confirm: dialog_text(&prompt.confirm),
                };
                typed(self.show(&program, &prompt.title, dialog, timing.timeout)?)
            }
        }
    }
}

impl Ui for DesktopUi {
    fn master_password(&self, prompt: &Prompt) -> anyhow::Result<Typed> {
        self.entry(prompt)
    }

    fn secret_value(&self, prompt: &Prompt) -> anyhow::Result<Typed> {
        self.entry(prompt)
    }

    fn approve(&self, request: &ApprovalRequest) -> anyhow::Result<Decision> {
        let timing = self.timing();
        match locate() {
            Located::Absent(_) => {
                // The agent checked the height only if it expected zenity:
                // check again, now that zenity it is.
                if let Some(height) = crate::ui::approval_too_tall(request) {
                    bail!("this dialog would be too tall to read at once ({height} pixels)");
                }
                Self::zenity(timing).approve(request)
            }
            Located::Unusable(why) => bail!("cannot show the dialog: {why}"),
            Located::Program(program) => {
                let offered = request.can_remember && !timing.remember_for.is_zero();
                let label = format!("Allow for {}", format_duration(timing.remember_for));
                let note = remember_note(&label, timing.remember_for);
                let dialog = Dialog::Approval {
                    headline: dialog_text(&request.summary),
                    explanation: dialog_text(&request.explanation),
                    warnings: request.warnings.iter().map(|w| dialog_text(w)).collect(),
                    command: request.command.as_deref().map(dialog_text),
                    details: pairs(&request.details),
                    facts: pairs(&request.facts),
                    remember: offered.then(|| Remember {
                        label: dialog_text(&label),
                        note: dialog_text(note.trim()),
                    }),
                };
                let reply = self.show(&program, &request.title, dialog, timing.timeout)?;
                decision(reply, offered, timing.remember_for)
            }
        }
    }

    fn limits_height(&self) -> bool {
        !matches!(locate(), Located::Program(_))
    }

    fn set_timing(&self, remember_for: Duration, timeout: Duration) {
        *self.timing.lock().unwrap_or_else(|p| p.into_inner()) = Timing {
            remember_for,
            timeout,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use crate::protocol::SecretString;

    fn request(id: &str) -> Request {
        Request {
            version: wire::VERSION,
            id: id.into(),
            timeout_secs: 1,
            title: "t".into(),
            dialog: Dialog::Approval {
                headline: "h".into(),
                explanation: String::new(),
                warnings: Vec::new(),
                command: Some("true".into()),
                details: Vec::new(),
                facts: Vec::new(),
                remember: None,
            },
        }
    }

    fn frame(answer: &Answer) -> Vec<u8> {
        let mut out = Vec::new();
        wire::write_frame(&mut out, answer, wire::MAX_ANSWER).expect("frame");
        out
    }

    fn answer(id: &str, reply: Reply) -> Answer {
        Answer {
            version: wire::VERSION,
            id: id.into(),
            reply,
        }
    }

    /// A fake dialog program: writes `output` to the socket, then runs
    /// `then` (shell).
    fn fake(dir: &Path, output: &[u8], then: &str) -> PathBuf {
        let data = dir.join("answer.bin");
        fs::write(&data, output).expect("write answer");
        let program = dir.join(PROGRAM);
        // It reads the whole request (the agent ends it), as the real
        // program does, then answers.
        fs::write(
            &program,
            format!(
                "#!/bin/sh\n/bin/cat >/dev/null\n/bin/cat '{}'\n{then}\n",
                data.display()
            ),
        )
        .expect("write program");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("chmod");
        program
    }

    /// Run a fake program just written. Running a file right after writing
    /// it fails with "Text file busy" while a process forked by another test
    /// still holds the writing descriptor (until its exec); only tests run
    /// programs they have just written, so only they retry.
    fn run(program: &Path, id: &str, deadline: Duration) -> anyhow::Result<Reply> {
        let busy = |e: &anyhow::Error| {
            e.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .and_then(io::Error::raw_os_error)
                    == Some(nix::libc::ETXTBSY)
            })
        };
        for _ in 0..50 {
            match exchange(program, &[], &request(id), Instant::now() + deadline) {
                Err(e) if busy(&e) => std::thread::sleep(Duration::from_millis(20)),
                other => return other,
            }
        }
        exchange(program, &[], &request(id), Instant::now() + deadline)
    }

    #[test]
    fn a_well_formed_answer_is_returned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let program = fake(
            dir.path(),
            &frame(&answer("abc", Reply::AllowOnce)),
            "exit 0",
        );
        assert_eq!(
            run(&program, "abc", Duration::from_secs(10)).expect("reply"),
            Reply::AllowOnce
        );
    }

    #[test]
    fn answers_to_another_request_or_version_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let program = fake(
            dir.path(),
            &frame(&answer("other", Reply::AllowOnce)),
            "exit 0",
        );
        assert!(run(&program, "abc", Duration::from_secs(10)).is_err());
        let mut old = answer("abc", Reply::AllowOnce);
        old.version = wire::VERSION + 1;
        let program = fake(dir.path(), &frame(&old), "exit 0");
        assert!(run(&program, "abc", Duration::from_secs(10)).is_err());
    }

    #[test]
    fn partial_oversized_or_extra_output_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = frame(&answer("abc", Reply::AllowOnce));
        let mut partial = 100u32.to_be_bytes().to_vec();
        partial.extend_from_slice(b"{\"version\":1");
        let mut oversized = (wire::MAX_ANSWER as u32 + 1).to_be_bytes().to_vec();
        oversized.extend_from_slice(&good[4..]);
        let mut extra = good.clone();
        extra.push(b'x');
        let mut twice = good.clone();
        twice.extend_from_slice(&good);
        for output in [partial, oversized, extra, twice, Vec::new()] {
            let program = fake(dir.path(), &output, "exit 0");
            let reply = run(&program, "abc", Duration::from_secs(10));
            assert!(reply.is_err(), "{output:?} gave {reply:?}");
        }
    }

    #[test]
    fn a_failure_after_a_valid_answer_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = frame(&answer("abc", Reply::AllowOnce));
        let program = fake(dir.path(), &good, "exit 1");
        assert!(run(&program, "abc", Duration::from_secs(10)).is_err());
        // Answering, then not exiting: refused once the deadline passes.
        let program = fake(dir.path(), &good, "exec /bin/sleep 30");
        let started = Instant::now();
        assert!(run(&program, "abc", Duration::from_secs(1)).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_program_that_hangs_is_killed_at_the_deadline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let program = fake(dir.path(), b"", "exec /bin/sleep 30");
        let started = Instant::now();
        let reply = run(&program, "abc", Duration::from_secs(1)).expect("reply");
        assert_eq!(reply, Reply::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_trickling_answer_cannot_stretch_the_deadline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let answer = frame(&answer("abc", Reply::AllowOnce));
        let data = dir.path().join("answer.bin");
        fs::write(&data, &answer).expect("write");
        let program = dir.path().join(PROGRAM);
        // One byte every 100 ms: the answer would take seconds.
        fs::write(
            &program,
            format!(
                "#!/bin/sh\n/bin/cat >/dev/null\n\
                 i=1; while [ $i -le {} ]; do /usr/bin/head -c $i '{}' | /usr/bin/tail -c 1; \
                 /bin/sleep 0.1; i=$((i+1)); done\n",
                answer.len(),
                data.display()
            ),
        )
        .expect("write");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("chmod");
        let started = Instant::now();
        let reply = run(&program, "abc", Duration::from_millis(400)).expect("reply");
        assert_eq!(reply, Reply::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn descendants_of_the_program_do_not_survive_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("pid");
        let good = frame(&answer("abc", Reply::AllowOnce));
        // It answers, leaves a descendant holding the socket, and exits.
        let program = fake(
            dir.path(),
            &good,
            &format!("/bin/sleep 30 & echo $! > '{}'; exit 0", pidfile.display()),
        );
        let started = Instant::now();
        let reply = run(&program, "abc", Duration::from_millis(500));
        assert!(reply.is_err(), "{reply:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
        let descendant: u32 = fs::read_to_string(&pidfile)
            .expect("pid")
            .trim()
            .parse()
            .expect("number");
        assert!(
            crate::supervise::tests::gone(descendant),
            "a descendant survived"
        );
    }

    #[test]
    fn an_incompatible_program_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let program = fake(
            dir.path(),
            b"",
            &format!("exit {}", wire::EXIT_INCOMPATIBLE),
        );
        let err = run(&program, "abc", Duration::from_secs(10)).expect_err("refused");
        assert!(
            err.to_string().contains("another protocol version"),
            "{err}"
        );
    }

    #[test]
    fn only_offered_answers_count() {
        let ten = Duration::from_secs(600);
        assert_eq!(
            decision(Reply::AllowOnce, false, ten).expect("once"),
            Decision::AllowOnce
        );
        assert_eq!(
            decision(Reply::AllowFor, true, ten).expect("for"),
            Decision::AllowFor(ten)
        );
        assert!(decision(Reply::AllowFor, false, ten).is_err());
        assert!(decision(Reply::Cancel, true, ten).is_err());
        let text = || SecretString::new("t".into());
        assert!(decision(Reply::Typed { text: text() }, true, ten).is_err());
        assert!(matches!(
            typed(Reply::Typed { text: text() }).expect("typed"),
            Typed::Value(_)
        ));
        let long = SecretString::new("x".repeat(wire::MAX_TYPED + 1));
        assert!(typed(Reply::Typed { text: long }).is_err());
        assert!(typed(Reply::AllowOnce).is_err());
        assert!(matches!(
            typed(Reply::Cancel).expect("cancel"),
            Typed::Cancelled
        ));
    }

    #[test]
    fn the_dialog_program_is_looked_for_by_its_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let program = dir.path().join(PROGRAM);
        assert_eq!(locate_in(dir.path()), Located::Absent(program.clone()));
        // A program of another name is not it.
        let other = dir.path().join("rusthorse-broker");
        fs::write(&other, "#!/bin/sh\n").expect("write");
        fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(locate_in(dir.path()), Located::Absent(program.clone()));
        // Checked as every helper is (helper_program has the cases).
        fs::write(&program, "#!/bin/sh\n").expect("write");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o775)).expect("chmod");
        assert!(matches!(locate_in(dir.path()), Located::Unusable(_)));
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).expect("chmod");
        let real = fs::canonicalize(&program).expect("canonical");
        assert_eq!(locate_in(dir.path()), Located::Program(real.clone()));
        assert_eq!(
            locate_in(dir.path()),
            helper_program::locate_in(dir.path(), PROGRAM)
        );
    }

    #[test]
    fn the_environment_is_the_sessions_minus_anything_per_user() {
        let private = Path::new("/run/user/1000/rusthorse-dialog-x");
        let session = |extra: &[(&str, &str)]| -> Vec<(String, String)> {
            [
                ("DISPLAY", ":0"),
                ("WAYLAND_DISPLAY", "wayland-0"),
                ("HOME", "/nonexistent-home"),
                ("GTK_MODULES", "evil"),
                ("LD_PRELOAD", "/tmp/evil.so"),
                ("GTK_DEBUG", "interactive"),
            ]
            .iter()
            .chain(extra)
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
        };
        let env = environment(&session(&[("XAUTHORITY", "/run/user/1000/xauth")]), private);
        let get = |env: &[(String, String)], k: &str| {
            env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        };
        assert_eq!(get(&env, "DISPLAY").as_deref(), Some(":0"));
        assert_eq!(
            get(&env, "XAUTHORITY").as_deref(),
            Some("/run/user/1000/xauth")
        );
        for name in ["GTK_MODULES", "LD_PRELOAD", "GTK_DEBUG"] {
            assert_eq!(get(&env, name), None, "{name} passed");
        }
        for name in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"] {
            assert_eq!(
                get(&env, name).as_deref(),
                Some("/run/user/1000/rusthorse-dialog-x")
            );
        }
        assert_eq!(get(&env, "GSETTINGS_BACKEND").as_deref(), Some("memory"));
        assert_eq!(
            get(&env, "XDG_DATA_DIRS").as_deref(),
            Some("/usr/local/share:/usr/share")
        );

        // Without XAUTHORITY: the file in the real home, found before HOME
        // is replaced.
        let home = tempfile::tempdir().expect("tempdir");
        let home_str = home.path().display().to_string();
        let mut without = session(&[]);
        without.retain(|(k, _)| k != "HOME");
        without.push(("HOME".into(), home_str.clone()));
        assert_eq!(get(&environment(&without, private), "XAUTHORITY"), None);
        fs::write(home.path().join(".Xauthority"), b"").expect("xauth");
        assert_eq!(
            get(&environment(&without, private), "XAUTHORITY"),
            Some(format!("{home_str}/.Xauthority"))
        );
        // Without a display, no authority file is needed.
        without.retain(|(k, _)| k != "DISPLAY");
        assert_eq!(get(&environment(&without, private), "XAUTHORITY"), None);
    }

    #[test]
    fn the_private_directory_is_private_and_removed() {
        let base = tempfile::tempdir().expect("tempdir");
        let path = {
            let private = PrivateDir::create(base.path()).expect("create");
            let mode = fs::metadata(private.path())
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
            fs::write(private.path().join("cache"), b"x").expect("write");
            private.path().to_path_buf()
        };
        assert!(!path.exists(), "left behind");
        // Every dialog gets its own.
        let a = PrivateDir::create(base.path()).expect("a");
        let b = PrivateDir::create(base.path()).expect("b");
        assert_ne!(a.path(), b.path());
    }
}
