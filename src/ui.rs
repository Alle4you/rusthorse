//! Human interaction: the dialogs the agent shows.
//!
//! Dialogs are shown **by the agent**, never by the client, so a client cannot
//! answer them by writing to a terminal. The production implementation uses
//! `zenity` (tested with 3.44), using only options that zenity 4 also has,
//! and no colours or icons of its own, so the dialogs follow the desktop's
//! theme. Tests use their own [`Ui`] implementation.

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
    /// The question, as a short headline.
    pub summary: String,
    /// One or two sentences under the headline: what approving means. May
    /// be empty.
    pub explanation: String,
    /// What to read before deciding (command, program, secrets, ...), as
    /// label/value pairs; each is shown as its own block.
    pub details: Vec<(String, String)>,
    /// Context shown in one quieter line under the details (input, output
    /// handling, ...), as label/value pairs.
    pub facts: Vec<(String, String)>,
    /// Warnings shown below the details.
    pub warnings: Vec<String>,
    /// Whether "allow for a while" may be offered.
    pub can_remember: bool,
}

/// The human's answer to an [`ApprovalRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Refuse (also the result of closing the dialog).
    Deny,
    /// Nobody answered before the dialog's timeout: a denial, reported as
    /// such so that "nobody looked" is not mistaken for "the human said no".
    TimedOut,
    /// Allow this one request.
    AllowOnce,
    /// Allow this request and identical ones for the given duration.
    AllowFor(Duration),
}

/// The human's answer to a dialog that asks them to type something.
#[derive(Debug)]
pub enum Typed {
    /// They confirmed what they typed — possibly nothing.
    Value(SecretString),
    /// They cancelled or closed the dialog.
    Cancelled,
    /// Nobody answered before the dialog's timeout.
    TimedOut,
}

/// Something that can ask the human questions.
pub trait Ui: Send + Sync {
    /// Ask for the master password.
    fn master_password(&self, prompt: &Prompt) -> anyhow::Result<Typed>;
    /// Ask for a secret value to store.
    fn secret_value(&self, prompt: &Prompt) -> anyhow::Result<Typed>;
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

    fn hidden_entry(&self, prompt: &Prompt) -> anyhow::Result<Typed> {
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
                Ok(Typed::Value(value))
            }
            Some(1) => Ok(Typed::Cancelled),
            Some(ZENITY_TIMEOUT) => Ok(Typed::TimedOut),
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
/// a denial; a timeout is told apart as [`Decision::TimedOut`].
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
        (Some(ZENITY_TIMEOUT), _) => Decision::TimedOut,
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
    fn master_password(&self, prompt: &Prompt) -> anyhow::Result<Typed> {
        self.hidden_entry(prompt)
    }

    fn secret_value(&self, prompt: &Prompt) -> anyhow::Result<Typed> {
        self.hidden_entry(prompt)
    }

    fn approve(&self, request: &ApprovalRequest) -> anyhow::Result<Decision> {
        let remember_label = format!("Allow for {}", format_duration(self.remember_for));
        let offer_remember = request.can_remember && !self.remember_for.is_zero();

        let note = offer_remember.then(|| remember_note(&remember_label, self.remember_for));
        let text = approval_markup(request, note.as_deref());
        let mut cmd = self.command(&request.title)?;
        cmd.arg("--question")
            // Pango markup built by `approval_markup`: every value in it went
            // through `markup_text`.
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

/// The text of an approval dialog, without formatting: what the dialog says,
/// used to measure it. Every value goes through [`visible`] so a requester
/// cannot inject line breaks or bidirectional overrides.
pub fn approval_text(request: &ApprovalRequest) -> String {
    let mut text = visible(&request.summary);
    if !request.explanation.is_empty() {
        text.push('\n');
        text.push_str(&visible(&request.explanation));
    }
    text.push_str("\n\n");
    for (label, value) in request.details.iter().chain(&request.facts) {
        text.push_str(&format!("{label}: {}\n", visible(value)));
    }
    for warning in &request.warnings {
        text.push_str(&format!("\n⚠ {}", visible(warning)));
    }
    text
}

/// A small vertical gap between blocks.
const GAP: &str = "<span size=\"5000\"> </span>\n";

/// The approval dialog as Pango markup: the headline, the explanation, one
/// block per detail (a small label over a monospaced value), the facts in one
/// quieter line, the warnings in bold and the "Allow for" note, if any.
/// Secondary text is dimmed with `alpha`, a transparency of the theme's own
/// text colour, so it reads on light and dark themes alike. Every string goes
/// through [`markup_text`], so nothing a requester controls can add a tag.
pub fn approval_markup(request: &ApprovalRequest, note: Option<&str>) -> String {
    let mut out = format!(
        "<span size=\"x-large\" weight=\"bold\">{}</span>\n",
        markup_text(&request.summary)
    );
    if !request.explanation.is_empty() {
        out.push_str(&format!(
            "<span alpha=\"70%\">{}</span>\n",
            markup_text(&request.explanation)
        ));
    }
    for (label, value) in &request.details {
        out.push_str(GAP);
        out.push_str(&format!(
            "<span size=\"small\" alpha=\"70%\" weight=\"bold\">{}</span>\n<tt>{}</tt>\n",
            markup_text(&label.to_uppercase()),
            markup_text(value)
        ));
    }
    if !request.facts.is_empty() {
        let facts: Vec<String> = request
            .facts
            .iter()
            .map(|(label, value)| format!("{}: {}", markup_text(label), markup_text(value)))
            .collect();
        out.push_str(GAP);
        out.push_str(&format!(
            "<span alpha=\"70%\">{}</span>\n",
            facts.join(" · ")
        ));
    }
    for warning in &request.warnings {
        out.push_str(GAP);
        out.push_str(&format!("<b>⚠  {}</b>\n", markup_text(warning)));
    }
    if let Some(note) = note {
        out.push_str(GAP);
        out.push_str(&format!(
            "<span size=\"small\" alpha=\"70%\">{}</span>\n",
            markup_text(note.trim())
        ));
    }
    out.truncate(out.trim_end_matches('\n').len());
    out
}

/// Text to place in Pango markup: [`visible`] first (control and format
/// characters become `\u{…}`), then `&`, `<`, `>`, quotes and backslashes
/// become character references, so the text can neither open a tag nor end
/// one. A backslash is written `&#92;` rather than doubled: zenity 3 passes
/// markup through `g_strcompress` (which turns `\n` into a line break) before
/// parsing it, and other versions may not; a reference reads the same either
/// way, so the dialog shows exactly the value.
pub fn markup_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in visible(text).chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\\' => out.push_str("&#92;"),
            c => out.push(c),
        }
    }
    out
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
        assert_eq!(decision_from(Some(5), b"", remember), Decision::TimedOut);
        assert_eq!(decision_from(Some(5), b"", None), Decision::TimedOut);
        assert_eq!(
            decision_from(Some(5), b"Allow for 10m\n", remember),
            Decision::TimedOut
        );
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
            explanation: String::new(),
            details: vec![("Command".into(), "echo ok\nSecrets: none".into())],
            facts: Vec::new(),
            warnings: vec!["careful".into()],
            can_remember: true,
        };
        let text = approval_text(&request);
        assert!(text.contains("Command: echo ok\\u{a}Secrets: none\n"));
        assert!(text.ends_with("⚠ careful"));
    }

    /// The tags `approval_markup` writes itself.
    const OUR_TAGS: [&str; 9] = [
        "<span size=\"x-large\" weight=\"bold\">",
        "<span alpha=\"70%\">",
        "<span size=\"small\" alpha=\"70%\" weight=\"bold\">",
        "<span size=\"small\" alpha=\"70%\">",
        "<span size=\"5000\">",
        "</span>",
        "<tt>",
        "</tt>",
        "<b>",
    ];

    /// Remove our tags and decode character references: what the dialog
    /// shows. Panics on any other tag or reference.
    fn shown(markup: &str) -> String {
        let mut rest = markup;
        let mut out = String::new();
        while let Some(c) = rest.chars().next() {
            if c == '<' {
                let tag = OUR_TAGS
                    .iter()
                    .chain(&["</b>"])
                    .find(|t| rest.starts_with(**t))
                    .unwrap_or_else(|| panic!("unexpected tag at {rest:?}"));
                rest = &rest[tag.len()..];
            } else if c == '&' {
                let end = rest.find(';').expect("reference end");
                out.push(match &rest[..=end] {
                    "&amp;" => '&',
                    "&lt;" => '<',
                    "&gt;" => '>',
                    "&quot;" => '"',
                    "&#39;" => '\'',
                    "&#92;" => '\\',
                    other => panic!("unexpected reference {other}"),
                });
                rest = &rest[end + 1..];
            } else {
                assert!(c != '>' && c != '\\', "raw {c:?} in {markup}");
                out.push(c);
                rest = &rest[c.len_utf8()..];
            }
        }
        out
    }

    #[test]
    fn nothing_a_requester_sends_can_add_markup() {
        let hostile = [
            "</tt><span size=\"1\">hidden</span><tt>",
            "a & b; c &amp; d &#60;",
            r"printf 'a\nb' \\ end",
            "quote \" and ' and > and <b>bold</b>",
            "line\nbreak \u{202E}reversed",
        ];
        for value in hostile {
            let request = ApprovalRequest {
                title: "t".into(),
                summary: format!("Headline {value}"),
                explanation: format!("Explained {value}"),
                details: vec![
                    ("Command".into(), value.into()),
                    (format!("Label {value}"), value.into()),
                ],
                facts: vec![("Input".into(), value.into())],
                warnings: vec![value.into()],
                can_remember: true,
            };
            let markup = approval_markup(&request, Some(value));
            let text = shown(&markup);
            let seen = visible(value);
            // Every value is shown exactly, as text, everywhere it appears.
            assert_eq!(text.matches(&seen).count(), 7, "{markup}");
            assert!(text.contains(&format!("Headline {seen}")));
            assert!(text.contains(&format!("⚠  {seen}")));
        }
    }

    #[test]
    fn a_backslash_reads_the_same_with_or_without_escape_processing() {
        let markup = markup_text(r"a\nb \\ c");
        assert_eq!(markup, "a&#92;nb &#92;&#92; c");
        assert!(!markup.contains('\\'));
    }

    #[test]
    fn the_approval_markup_has_a_block_per_detail_and_one_line_of_facts() {
        let request = ApprovalRequest {
            title: "t".into(),
            summary: "Run a command with your secrets?".into(),
            explanation: "Read it.".into(),
            details: vec![
                ("Command".into(), "true".into()),
                ("Requested by".into(), "bash[1]".into()),
            ],
            facts: vec![
                ("Input".into(), "none".into()),
                ("Output".into(), "redacted".into()),
            ],
            warnings: vec!["careful".into()],
            can_remember: false,
        };
        let markup = approval_markup(&request, None);
        assert!(markup.starts_with(
            "<span size=\"x-large\" weight=\"bold\">Run a command with your secrets?</span>\n"
        ));
        assert!(markup.contains(">COMMAND</span>\n<tt>true</tt>"));
        assert!(markup.contains(">REQUESTED BY</span>\n<tt>bash[1]</tt>"));
        assert!(markup.contains("<span alpha=\"70%\">Input: none · Output: redacted</span>"));
        assert!(markup.ends_with("<b>⚠  careful</b>"));
        assert_eq!(
            shown(&markup),
            "Run a command with your secrets?\nRead it.\n \nCOMMAND\ntrue\n \nREQUESTED BY\nbash[1]\n \nInput: none · Output: redacted\n \n⚠  careful"
        );
        // The text that is measured against the dialog limit has it all.
        assert_eq!(
            approval_text(&request),
            "Run a command with your secrets?\nRead it.\n\nCommand: true\nRequested by: bash[1]\n\
             Input: none\nOutput: redacted\n\n⚠ careful"
        );
    }
}
