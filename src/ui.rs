//! Human interaction: the dialogs the agent shows.
//!
//! Dialogs are shown **by the agent**, never by the client, so a client cannot
//! answer them by writing to a terminal. The production implementation uses
//! `zenity` (tested with 3.44). Tests use their own [`Ui`] implementation.

use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, bail};

use zeroize::Zeroizing;

use crate::protocol::SecretString;
use crate::util::{format_duration, visible};

/// A password-style prompt (master password or a new secret value).
#[derive(Debug, Clone)]
pub struct Prompt {
    /// Window title.
    pub title: String,
    /// Explanation shown above the input field.
    pub message: String,
    /// Label of the confirm button.
    pub confirm: String,
}

/// A request for the human's approval.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Window title.
    pub title: String,
    /// One-sentence summary of what is being asked.
    pub summary: String,
    /// Label/value pairs with the details (command, program, secrets, ...).
    pub details: Vec<(String, String)>,
    /// Warnings shown below the details.
    pub warnings: Vec<String>,
    /// Whether "allow for a while" may be offered.
    pub can_remember: bool,
}

/// The human's answer to an [`ApprovalRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Refuse (also the result of closing the dialog or a timeout).
    Deny,
    /// Allow this one request.
    AllowOnce,
    /// Allow this request and identical ones for the given duration.
    AllowFor(Duration),
}

/// Something that can ask the human questions.
pub trait Ui: Send + Sync {
    /// Ask for the master password. `Ok(None)` means cancelled.
    fn master_password(&self, prompt: &Prompt) -> anyhow::Result<Option<SecretString>>;
    /// Ask for a secret value to store. `Ok(None)` means cancelled.
    fn secret_value(&self, prompt: &Prompt) -> anyhow::Result<Option<SecretString>>;
    /// Ask whether to allow a request.
    fn approve(&self, request: &ApprovalRequest) -> anyhow::Result<Decision>;
}

/// Dialogs implemented with `zenity`.
#[derive(Debug, Clone)]
pub struct ZenityUi {
    /// How long "Allow for …" lasts; zero hides that button.
    pub remember_for: Duration,
    /// How long a dialog waits before giving up (deny / cancel).
    pub timeout: Duration,
}

/// Where zenity is looked for. `PATH` is never consulted.
const ZENITY_PATHS: [&str; 2] = ["/usr/bin/zenity", "/usr/local/bin/zenity"];

/// The only environment variables zenity receives. In particular, zenity
/// lets `ZENITY_*` variables remap its exit statuses, so nothing else is
/// inherited.
const DIALOG_ENV: [&str; 9] = [
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_MESSAGES",
];

/// Room the agent reserves in a dialog for the note explaining "Allow for …"
/// (see [`remember_note`]).
pub const REMEMBER_NOTE_MAX: usize = 240;

/// The note shown next to the "Allow for …" button.
pub fn remember_note(label: &str, duration: Duration) -> String {
    format!(
        "\n\n“{label}” lets identical requests run without asking for {} — even if \
         they read different input or files. Prefer “Allow once”.",
        format_duration(duration)
    )
}

/// Exit status zenity uses for a timeout.
const ZENITY_TIMEOUT: i32 = 5;

impl ZenityUi {
    fn command(&self, title: &str) -> anyhow::Result<Command> {
        let program = ZENITY_PATHS
            .iter()
            .find(|p| Path::new(p).is_file())
            .context(
                "zenity not found in /usr/bin or /usr/local/bin (`sudo apt install zenity`)",
            )?;
        let mut cmd = Command::new(program);
        cmd.arg(format!("--title={title}"))
            .arg(format!("--timeout={}", self.timeout.as_secs().max(1)))
            .arg("--width=680")
            // zenity looks for its UI definition relative to the working
            // directory before the installed one.
            .current_dir("/")
            .env_clear()
            .envs(dialog_env())
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        Ok(cmd)
    }

    fn hidden_entry(&self, prompt: &Prompt) -> anyhow::Result<Option<SecretString>> {
        let mut cmd = self.command(&prompt.title)?;
        cmd.arg("--entry")
            .arg("--hide-text")
            .arg(format!("--text={}", entry_label(&prompt.message)))
            .arg(format!("--ok-label={}", prompt.confirm));
        let (status, output) = capture_through_socket(cmd)?;
        match status {
            Some(0) => {
                let mut value = String::from_utf8(output.to_vec())
                    .map(SecretString::new)
                    .map_err(|_| anyhow::anyhow!("zenity returned invalid UTF-8"))?;
                if value.ends_with('\n') {
                    value.pop();
                }
                Ok(Some(value))
            }
            Some(1) | Some(ZENITY_TIMEOUT) => Ok(None),
            other => bail!("zenity failed (exit status {other:?})"),
        }
    }
}

/// Run a dialog program and collect what it prints. Its stdout is one end of
/// a socket pair, not a pipe: another process of the same user can open a
/// pipe through `/proc/<pid>/fd/1` and race us for the typed password, but
/// opening a socket that way fails (`ENXIO`).
pub fn capture_through_socket(
    mut cmd: Command,
) -> anyhow::Result<(Option<i32>, Zeroizing<Vec<u8>>)> {
    let (mut ours, theirs) = UnixStream::pair().context("cannot create a socket pair")?;
    cmd.stdout(Stdio::from(OwnedFd::from(theirs)));
    let spawned = cmd.spawn();
    // Dropping the command closes our copy of the child's end, so that
    // reading below sees end-of-file when the child exits.
    drop(cmd);
    let mut child = spawned.context("cannot run the dialog program")?;
    let mut output = Zeroizing::new(Vec::with_capacity(4096));
    let read = ours.read_to_end(&mut output);
    let status = child.wait().context("cannot wait for the dialog program")?;
    read.context("cannot read the dialog's answer")?;
    Ok((status.code(), output))
}

/// Interpret zenity's answer to a question dialog. Only two exact outcomes
/// allow anything: status 0 with no output ("Allow once"), and status 1 with
/// the exact label of the extra button when one was offered. Everything else
/// — Deny, closing the window, a timeout, an unexpected status or output — is
/// a denial.
pub fn decision_from(
    status: Option<i32>,
    output: &[u8],
    remember: Option<(&str, Duration)>,
) -> Decision {
    let printed = String::from_utf8_lossy(output);
    let printed = printed.trim_end_matches('\n');
    match (status, remember) {
        (Some(0), _) if printed.is_empty() => Decision::AllowOnce,
        (Some(1), Some((label, duration))) if printed == label => Decision::AllowFor(duration),
        _ => Decision::Deny,
    }
}

/// Text for zenity's entry dialog, which (unlike the question dialog with
/// `--no-markup`) passes its text through `g_strcompress` — so `\n` or
/// `\000` sequences would be interpreted — and then uses it as a GTK mnemonic
/// label, where a single `_` underlines the next letter and disappears.
/// Backslashes must be escaped first, then underscores.
fn entry_label(text: &str) -> String {
    text.replace('\\', r"\\").replace('_', "__")
}

impl Ui for ZenityUi {
    fn master_password(&self, prompt: &Prompt) -> anyhow::Result<Option<SecretString>> {
        self.hidden_entry(prompt)
    }

    fn secret_value(&self, prompt: &Prompt) -> anyhow::Result<Option<SecretString>> {
        self.hidden_entry(prompt)
    }

    fn approve(&self, request: &ApprovalRequest) -> anyhow::Result<Decision> {
        let remember_label = format!("Allow for {}", format_duration(self.remember_for));
        let offer_remember = request.can_remember && !self.remember_for.is_zero();

        let mut text = approval_text(request);
        if offer_remember {
            text.push_str(&remember_note(&remember_label, self.remember_for));
        }
        let mut cmd = self.command(&request.title)?;
        cmd.arg("--question")
            // Literal text: no Pango markup and no escape-sequence processing.
            .arg("--no-markup")
            .arg("--default-cancel")
            .arg(format!("--text={text}"))
            .arg("--ok-label=Allow once")
            .arg("--cancel-label=Deny");
        if offer_remember {
            cmd.arg(format!("--extra-button={remember_label}"));
        }
        let (status, output) = capture_through_socket(cmd)?;
        let remember = offer_remember.then_some((remember_label.as_str(), self.remember_for));
        Ok(decision_from(status, &output, remember))
    }
}

/// The text of an approval dialog. Every value goes through [`visible`] so a
/// requester cannot inject line breaks or bidirectional overrides.
pub fn approval_text(request: &ApprovalRequest) -> String {
    let mut text = visible(&request.summary);
    text.push_str("\n\n");
    for (label, value) in &request.details {
        text.push_str(&format!("{label}: {}\n", visible(value)));
    }
    for warning in &request.warnings {
        text.push_str(&format!("\n⚠ {}", visible(warning)));
    }
    text
}

/// The environment for dialogs: the [`DIALOG_ENV`] variables of the agent,
/// plus the session's display variables from `systemctl --user
/// show-environment` when the agent started before the desktop exported them.
fn dialog_env() -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = DIALOG_ENV
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();
    let has_display = env
        .iter()
        .any(|(k, _)| k == "DISPLAY" || k == "WAYLAND_DISPLAY");
    if has_display {
        return env;
    }
    let Ok(output) = Command::new("/usr/bin/systemctl")
        .args(["--user", "show-environment"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return env;
    };
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if DIALOG_ENV.contains(&k) && !v.starts_with("$'") && !env.iter().any(|(e, _)| e == k) {
            env.push((k.to_string(), v.to_string()));
        }
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_output_arrives_through_a_socket() {
        // On a thread with a deadline: a broken capture (one that keeps a
        // copy of the child's end open) would wait forever for end-of-file.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", "readlink /proc/self/fd/1"]);
            let _ = tx.send(capture_through_socket(cmd).map(|(s, o)| (s, o.to_vec())));
        });
        let (status, output) = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("capture hung")
            .expect("run");
        assert_eq!(status, Some(0));
        let target = String::from_utf8_lossy(&output);
        assert!(target.starts_with("socket:"), "fd 1 was {target}");
    }

    #[test]
    fn a_missing_dialog_program_is_an_error() {
        let cmd = Command::new("/nonexistent/zenity");
        assert!(capture_through_socket(cmd).is_err());
    }

    #[test]
    fn only_exact_zenity_results_approve() {
        let ten = Duration::from_secs(600);
        let remember = Some(("Allow for 10m", ten));
        assert_eq!(decision_from(Some(0), b"", None), Decision::AllowOnce);
        assert_eq!(decision_from(Some(0), b"", remember), Decision::AllowOnce);
        assert_eq!(
            decision_from(Some(1), b"Allow for 10m\n", remember),
            Decision::AllowFor(ten)
        );
        // Extra button not offered, or a different label: deny.
        assert_eq!(
            decision_from(Some(1), b"Allow for 10m\n", None),
            Decision::Deny
        );
        assert_eq!(
            decision_from(Some(1), b"Allow for 1h\n", remember),
            Decision::Deny
        );
        // Deny, timeout, crash, unexpected output.
        assert_eq!(decision_from(Some(1), b"", remember), Decision::Deny);
        assert_eq!(decision_from(Some(5), b"", remember), Decision::Deny);
        assert_eq!(decision_from(None, b"", remember), Decision::Deny);
        assert_eq!(
            decision_from(Some(0), b"surprise", remember),
            Decision::Deny
        );
        assert_eq!(decision_from(Some(255), b"", remember), Decision::Deny);
    }

    #[test]
    fn the_remember_note_fits_its_reserved_room() {
        let label = format!(
            "Allow for {}",
            format_duration(Duration::from_secs(359_999))
        );
        let note = remember_note(&label, Duration::from_secs(359_999));
        assert!(
            note.chars().count() <= REMEMBER_NOTE_MAX,
            "{}",
            note.chars().count()
        );
    }

    #[test]
    fn entry_labels_are_escaped_for_zenity() {
        assert_eq!(entry_label(r"prod\000HIDDEN"), r"prod\\000HIDDEN");
        assert_eq!(entry_label("OPENAI_API_KEY"), "OPENAI__API__KEY");
        assert_eq!(entry_label(r"a\_b"), r"a\\__b");
    }

    #[test]
    fn approval_text_neutralizes_injection() {
        let request = ApprovalRequest {
            title: "t".into(),
            summary: "Run a command".into(),
            details: vec![("Command".into(), "echo ok\nSecrets: none".into())],
            warnings: vec!["careful".into()],
            can_remember: true,
        };
        let text = approval_text(&request);
        assert!(text.contains("Command: echo ok\\u{a}Secrets: none\n"));
        assert!(text.ends_with("⚠ careful"));
    }
}
