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
use crate::util::format_duration;

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
            .arg(format!(
                "--text={}",
                entry_label(&dialog_lines(&prompt.message))
            ))
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
/// used to measure it. Every value goes through [`dialog_text`], as in the
/// dialog itself.
pub fn approval_text(request: &ApprovalRequest) -> String {
    let mut text = dialog_text(&request.summary);
    if !request.explanation.is_empty() {
        text.push('\n');
        text.push_str(&dialog_text(&request.explanation));
    }
    text.push_str("\n\n");
    for (label, value) in request.details.iter().chain(&request.facts) {
        text.push_str(&format!("{label}: {}\n", dialog_text(value)));
    }
    for warning in &request.warnings {
        text.push_str(&format!("\n⚠ {}", dialog_text(warning)));
    }
    text
}

/// A small vertical gap between blocks.
const GAP: &str = "<span size=\"5000\"> </span>\n";

/// Whether a character is shown as itself in a dialog. Only characters whose
/// glyphs have an ordinary width and stay on their own line are: printable
/// ASCII, the letters of Latin-1 and Latin Extended-A (the accented letters of
/// European languages) except those that pass for ASCII (`×`, `÷`, `ı`, `Ĳ`,
/// `ĳ`, `ĸ`, `ŉ`, `ſ`), and the punctuation of Rusthorse's own texts.
fn shown_as_is(c: char) -> bool {
    match c {
        '\u{D7}' | '\u{F7}' | '\u{131}' | '\u{132}' | '\u{133}' | '\u{138}' | '\u{149}'
        | '\u{17F}' => false,
        ' '..='~' | '\u{C0}'..='\u{17F}' => true,
        '\u{B7}' | '\u{2013}' | '\u{2014}' | '\u{2018}' | '\u{2019}' | '\u{201C}' | '\u{201D}'
        | '\u{2026}' | '\u{2190}' | '\u{2192}' => true,
        _ => false,
    }
}

/// Text as dialogs show it: every character that is not an ordinary one
/// (printable ASCII, the letters of Latin-1 and Latin Extended-A except
/// look-alikes of ASCII, and a little punctuation) — controls, separators,
/// invisible and combining characters, other scripts, emoji — becomes a
/// `\u{…}` escape. What is drawn
/// is then predictable in width and height and cannot hide, reorder or
/// overlap anything. Text that literally contains `\u{…}` looks the same as
/// an escape, so a reader must take any `\u{…}` for the character it names.
pub fn dialog_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if shown_as_is(c) {
            out.push(c);
        } else {
            out.extend(c.escape_unicode());
        }
    }
    out
}

/// [`dialog_text`] for a message whose line breaks are its own (requester
/// values in it are already one line each).
fn dialog_lines(message: &str) -> String {
    message
        .split('\n')
        .map(dialog_text)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Text metrics for estimating a dialog's height: pixels for an 11-point
/// interface font at 96 DPI (Mint, Ubuntu and GNOME default to 10 or 11
/// points), each rounded so that the estimate errs high.
pub mod metrics {
    /// Usable width of the text: the dialog is 680 pixels wide, less its icon
    /// and margins.
    pub const WIDTH: usize = 560;
    /// Advance of a monospaced character (0.6 em, 8.8 pixels).
    pub const MONO: usize = 9;
    /// Advance of the widest proportional character, a bold "W": used for
    /// text that may come from the requester.
    pub const WIDEST: usize = 15;
    /// Advance assumed for Rusthorse's own sentences and labels (ordinary
    /// English averages about 7 pixels).
    pub const PROSE: usize = 9;
    /// Height of a headline line (x-large).
    pub const HEADLINE: usize = 28;
    /// Height of a line of text.
    pub const TEXT: usize = 19;
    /// Height of a line of small text.
    pub const SMALL: usize = 16;
    /// Height of the gap between blocks.
    pub const GAP: usize = 9;
    /// The most an approval dialog's content may take: with an 11-point font,
    /// 200 pixels remain for the title bar, buttons and a desktop panel on a
    /// screen 1080 pixels high, even when the estimate is nearly exact (text
    /// built to be wide). In the dialogs measured, the estimate exceeded the
    /// real height by 1 to 60 per cent.
    pub const MAX_HEIGHT: usize = 880;
}

/// Columns per line of text that may come from the requester, at the widest
/// character's advance.
const TEXT_COLUMNS: usize = metrics::WIDTH / metrics::WIDEST;
/// Columns per line of Rusthorse's own sentences.
const PROSE_COLUMNS: usize = metrics::WIDTH / metrics::PROSE;
/// Columns per line of Rusthorse's own x-large headlines (1.44 times larger).
const HEADLINE_COLUMNS: usize = metrics::WIDTH * 100 / (metrics::PROSE * 144);
/// Columns per line of Rusthorse's own small text (0.83 times as large).
const SMALL_COLUMNS: usize = metrics::WIDTH * 100 / (metrics::PROSE * 83);
/// Columns of monospaced text per line.
pub const MONO_COLUMNS: usize = metrics::WIDTH / metrics::MONO;

/// Height reserved for the "Allow for" note: six lines, a margin over the two
/// the longest note takes by the estimate (a test checks that it fits).
pub const REMEMBER_NOTE_HEIGHT: usize = metrics::GAP + 6 * metrics::SMALL;

/// Lines `text` takes when wrapped at `columns`, each character `width`
/// columns wide. It breaks only after spaces — Pango may break at more
/// places, which only saves lines — and anywhere in a word longer than a
/// line, so a text made of words just over half a line long counts one line
/// per word, as it is drawn.
fn wrapped_lines(text: &str, columns: usize, width: fn(char) -> usize) -> usize {
    let mut lines = 1;
    let mut used = 0;
    for (i, word) in text.split(' ').enumerate() {
        let w: usize = word.chars().map(width).sum();
        let space = usize::from(i > 0);
        if used + space + w <= columns {
            used += space + w;
            continue;
        }
        if used > 0 {
            lines += 1;
        }
        if w > columns {
            let full = (w - 1) / columns;
            lines += full;
            used = w - full * columns;
        } else {
            used = w;
        }
    }
    lines
}

/// Lines of proportional text, every character counted as the widest.
fn text_lines(text: &str, columns: usize) -> usize {
    wrapped_lines(&dialog_text(text), columns, |_| 1)
}

/// Lines of monospaced text, as dialogs show it; a character outside ASCII
/// counts twice, in case the monospaced font lacks it and another, wider font
/// draws it.
pub fn mono_lines(text: &str) -> usize {
    wrapped_lines(&dialog_text(text), MONO_COLUMNS, |c| {
        if c.is_ascii() { 1 } else { 2 }
    })
}

/// An estimate, erring high, of the height in pixels of the content of
/// [`approval_markup`] without the "Allow for" note (see
/// [`REMEMBER_NOTE_HEIGHT`]). The headline, explanation, labels and facts are
/// Rusthorse's own text and measured as ordinary prose; details are
/// monospaced; warnings may quote the requester and are measured at the
/// widest character.
pub fn approval_height(request: &ApprovalRequest) -> usize {
    use metrics::{GAP, HEADLINE, SMALL, TEXT};
    let mut height = HEADLINE * text_lines(&request.summary, HEADLINE_COLUMNS);
    if !request.explanation.is_empty() {
        height += TEXT * text_lines(&request.explanation, PROSE_COLUMNS);
    }
    for (label, value) in &request.details {
        height += GAP + SMALL * text_lines(&label.to_uppercase(), SMALL_COLUMNS);
        height += TEXT * mono_lines(value);
    }
    if !request.facts.is_empty() {
        let facts: Vec<String> = request
            .facts
            .iter()
            .map(|(label, value)| format!("{label}: {value}"))
            .collect();
        height += GAP + TEXT * text_lines(&facts.join(" · "), PROSE_COLUMNS);
    }
    for warning in &request.warnings {
        // "WW" stands for the "⚠" sign and its spaces, which are drawn as
        // they are, not escaped.
        height += GAP + TEXT * text_lines(&format!("WW {warning}"), TEXT_COLUMNS);
    }
    height
}

/// An estimate, erring high, of the height in pixels of a prompt's message.
pub fn prompt_height(message: &str) -> usize {
    message
        .split('\n')
        .map(|line| metrics::TEXT * text_lines(line, TEXT_COLUMNS))
        .sum()
}

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

/// Text to place in Pango markup: [`dialog_text`] first (anything but
/// ordinary characters becomes `\u{…}`), then `&`, `<`, `>`, quotes and
/// backslashes become character references, so the text can neither open a
/// tag nor end one. A backslash is written `&#92;` rather than doubled: zenity 3 passes
/// markup through `g_strcompress` (which turns `\n` into a line break) before
/// parsing it, and other versions may not; a reference reads the same either
/// way, so the dialog shows exactly the value.
pub fn markup_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in dialog_text(text).chars() {
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
            // Characters `visible` keeps but dialogs must not draw.
            "p\u{430}ypal \u{6F22}\u{8F0}\u{8F0}\u{8F0} \u{2800}",
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
            let seen = dialog_text(value);
            // Every value is shown exactly, as text, everywhere it appears.
            assert_eq!(text.matches(&seen).count(), 7, "{markup}");
            assert!(text.contains(&format!("Headline {seen}")));
            assert!(text.contains(&format!("⚠  {seen}")));
        }
    }

    #[test]
    fn a_line_separator_cannot_stretch_the_dialog() {
        let request = ApprovalRequest {
            title: "t".into(),
            summary: "Run a command with your secrets?".into(),
            explanation: String::new(),
            details: vec![(
                "Command".into(),
                format!("printf '{}'", "\u{2028}".repeat(60)),
            )],
            facts: Vec::new(),
            warnings: Vec::new(),
            can_remember: false,
        };
        let markup = approval_markup(&request, None);
        assert!(!markup.contains('\u{2028}'));
        assert!(markup.contains("&#92;u{2028}"));
        // Shown as escapes, the value is long: the estimate counts its lines.
        assert!(
            approval_height(&request) > 8 * metrics::TEXT,
            "{}",
            approval_height(&request)
        );
    }

    #[test]
    fn a_typical_run_dialog_leaves_room_for_a_long_command() {
        let chain = "rusthorse[3564435] ← codex[3564163] ← claude[2728718] ← bash[2728357] \
                     ← gnome-terminal-[2616696] ← systemd[1231]";
        let request = |command: String| ApprovalRequest {
            title: "t".into(),
            summary: "Run a command with your secrets?".into(),
            explanation: "Rusthorse runs it as you, outside any sandbox, with the secrets in \
                          its environment; programs it starts can use them too. Read the \
                          command before you allow it."
                .into(),
            details: vec![
                ("Command".into(), command),
                (
                    "Secrets".into(),
                    "OPENAI_API_KEY ← OPENAI_API_KEY (2a8f40e5)".into(),
                ),
                ("Program".into(), "/usr/bin/dash (sh)".into()),
                ("Directory".into(), "/home/someone/dev/project".into()),
                ("Requested by (unverified)".into(), chain.into()),
            ],
            facts: vec![
                ("Input".into(), "none (/dev/null)".into()),
                ("Output".into(), "secret values are redacted".into()),
            ],
            warnings: vec![
                "These variables can change what the program executes: GIT_SSH_COMMAND=ssh".into(),
            ],
            can_remember: true,
        };
        // A long command line (800 of the 1000 characters a run request may
        // have) fits with the "Allow for" note, whether it is made of
        // ordinary words or is one long word.
        let words: String =
            "curl -sS -H 'Authorization: Bearer $TOKEN' https://api.example.com/v1/items "
                .repeat(11)
                .chars()
                .take(800)
                .collect();
        for command in [words, "x".repeat(800)] {
            let height = approval_height(&request(command)) + REMEMBER_NOTE_HEIGHT;
            assert!(height <= metrics::MAX_HEIGHT, "{height}");
        }
        // A short one leaves room for 15 more lines of command.
        let short = approval_height(&request("true".into())) + REMEMBER_NOTE_HEIGHT;
        assert!(short + 15 * metrics::TEXT <= metrics::MAX_HEIGHT, "{short}");
    }

    #[test]
    fn only_ordinary_characters_are_shown_as_themselves() {
        assert_eq!(
            dialog_text("ls -la ~/Documents/ação"),
            "ls -la ~/Documents/ação"
        );
        assert_eq!(dialog_text("A ← B → C — “D” …"), "A ← B → C — “D” …");
        for (raw, shown) in [
            ("\u{2028}", "\\u{2028}"),                             // line separator
            ("\u{8F0}", "\\u{8f0}"),                               // combining mark of any block
            ("e\u{301}", "e\\u{301}"),                             // even a single one
            ("\u{2800}", "\\u{2800}"),                             // blank Braille pattern
            ("\u{6F22}", "\\u{6f22}"),                             // CJK, drawn double width
            ("\u{FF37}", "\\u{ff37}"),                             // fullwidth W
            ("\u{1F600}", "\\u{1f600}"),                           // emoji
            ("p\u{430}ypal", "p\\u{430}ypal"),                     // Cyrillic a, a look-alike
            ("\u{D7}\u{131}\u{17F}", "\\u{d7}\\u{131}\\u{17f}"),   // ×, ı, ſ
            ("\u{132}\u{133}\u{149}", "\\u{132}\\u{133}\\u{149}"), // Ĳ, ĳ, ŉ
            ("\u{A0}\u{AD}", "\\u{a0}\\u{ad}"),                    // no-break space, soft hyphen
            ("\u{7F}\u{85}", "\\u{7f}\\u{85}"),                    // controls
        ] {
            assert_eq!(dialog_text(raw), shown, "{raw:?}");
        }
    }

    #[test]
    fn wrapping_counts_the_lines_wasted_by_half_line_words() {
        // Words one column over half a line: one word per line.
        let half = "x".repeat(MONO_COLUMNS / 2 + 1);
        let text = [half.as_str(); 10].join(" ");
        assert_eq!(wrapped_lines(&text, MONO_COLUMNS, |_| 1), 10);
        // A word longer than a line is broken anywhere.
        let long = "x".repeat(MONO_COLUMNS * 3 + 1);
        assert_eq!(wrapped_lines(&long, MONO_COLUMNS, |_| 1), 4);
        assert_eq!(wrapped_lines("a b c", MONO_COLUMNS, |_| 1), 1);
        // Characters outside ASCII count twice in monospaced text.
        let wide = "é".repeat(MONO_COLUMNS / 2 + 1);
        assert_eq!(mono_lines(&wide), 2);
    }

    #[test]
    fn warnings_are_measured_at_the_widest_character() {
        // A warning can quote the requester (an environment variable's
        // value), so it is measured as if every character were a bold "W".
        let request = |warning: String| ApprovalRequest {
            title: "t".into(),
            summary: "s".into(),
            explanation: String::new(),
            details: Vec::new(),
            facts: Vec::new(),
            warnings: vec![warning],
            can_remember: false,
        };
        // One "W" fits on the sign's line; ten lines of them, one word too
        // long for it, start on the next line.
        let one = approval_height(&request("W".into()));
        let ten = approval_height(&request("W".repeat(TEXT_COLUMNS * 10)));
        assert_eq!(ten - one, 10 * metrics::TEXT);
    }

    #[test]
    fn the_longest_remember_note_fits_its_reserved_height() {
        let duration = Duration::from_secs(359_999);
        let label = format!("Allow for {}", format_duration(duration));
        let note = remember_note(&label, duration);
        let lines = text_lines(note.trim(), SMALL_COLUMNS);
        assert!(
            metrics::GAP + lines * metrics::SMALL <= REMEMBER_NOTE_HEIGHT,
            "{lines} lines"
        );
    }

    #[test]
    fn prompts_are_shown_and_measured_as_dialogs_show_them() {
        let message = "Entry \"\u{6F22}\".\n\nRequested by: x";
        assert_eq!(
            dialog_lines(message),
            "Entry \"\\u{6f22}\".\n\nRequested by: x"
        );
        assert_eq!(prompt_height(message), 3 * metrics::TEXT);
        assert_eq!(
            prompt_height(&"W".repeat(TEXT_COLUMNS * 2)),
            2 * metrics::TEXT
        );
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
