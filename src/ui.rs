//! Human interaction: the dialogs the agent shows.
//!
//! Dialogs are shown **by the agent**, never by the client, so a client cannot
//! answer them by writing to a terminal. The production implementation uses
//! `zenity` (tested with 3.44), using only options that zenity 4 also has,
//! and no colours or icons of its own, so the dialogs follow the desktop's
//! theme. Tests use their own [`Ui`] implementation.

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
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
    /// What to type, as one sentence.
    pub headline: String,
    /// One or two sentences under it; may be empty.
    pub explanation: String,
    /// A line shown first, after a wrong or empty attempt.
    pub notice: Option<String>,
    /// Label/value pairs: vault, entry, requester.
    pub details: Vec<(String, String)>,
    /// Label of the input field.
    pub field: String,
    /// Label of the confirm button.
    pub confirm: String,
}

/// A prompt as one block of text, as zenity's entry dialog shows it and as
/// it is measured: the notice, the headline, the explanation, then one
/// `label: value` line per detail. Every part goes through [`dialog_text`],
/// so no value can add a line.
pub fn prompt_text(prompt: &Prompt) -> String {
    let mut lines = Vec::new();
    if let Some(notice) = &prompt.notice {
        lines.push(dialog_text(notice));
        lines.push(String::new());
    }
    lines.push(dialog_text(&prompt.headline));
    if !prompt.explanation.is_empty() {
        lines.push(dialog_text(&prompt.explanation));
    }
    if !prompt.details.is_empty() {
        lines.push(String::new());
        for (label, value) in &prompt.details {
            lines.push(format!("{}: {}", dialog_text(label), dialog_text(value)));
        }
    }
    lines.join("\n")
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
    /// The command line, for `run`; shown before the details.
    pub command: Option<String>,
    /// What to read before deciding (program, secrets, ...), as label/value
    /// pairs; each is shown as its own block.
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
    /// The program that asked went away while the dialog was open, and the
    /// dialog was taken down: nobody answered, and nothing is done.
    RequesterGone,
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
    /// The program that asked went away while the dialog was open, and the
    /// dialog was taken down.
    RequesterGone,
}

/// The connection of the program a dialog is shown for, watched so that the
/// dialog is taken down when that program goes away. Nothing is read from
/// it or written to it: it is only polled, for a close by the other end —
/// with `half_close_ends`, also for a half-close (`shutdown(SHUT_WR)`), which
/// ends a `run`. A connection that another process still holds open is not
/// closed, so its requester is not gone.
#[derive(Debug, Clone, Copy)]
pub struct Connection<'a> {
    watched: Option<(BorrowedFd<'a>, bool)>,
}

impl<'a> Connection<'a> {
    /// The connection `socket`; a half-close ends it if `half_close_ends`.
    pub fn new(socket: BorrowedFd<'a>, half_close_ends: bool) -> Self {
        Connection {
            watched: Some((socket, half_close_ends)),
        }
    }

    /// No connection to watch (the agent's own requests, tests): never gone.
    pub const fn none() -> Connection<'static> {
        Connection { watched: None }
    }

    /// Whether the program at the other end has gone: it closed the
    /// connection (or shut it down both ways), or, when a half-close ends
    /// it, half-closed it. A failure to poll counts as not gone.
    pub fn gone(&self) -> bool {
        let Some(mut fd) = self.pollfd() else {
            return false;
        };
        loop {
            match crate::supervise::poll_raw(std::slice::from_mut(&mut fd), 0) {
                // Interrupted by a signal: ask again (it waits for nothing).
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                polled => return polled.is_ok_and(|_| self.left(fd.revents)),
            }
        }
    }

    /// What to give `poll(2)` to watch it, if there is a connection.
    pub(crate) fn pollfd(&self) -> Option<nix::libc::pollfd> {
        self.watched
            .map(|(socket, half_close_ends)| nix::libc::pollfd {
                fd: socket.as_raw_fd(),
                events: if half_close_ends {
                    nix::libc::POLLRDHUP
                } else {
                    0
                },
                revents: 0,
            })
    }

    /// Whether `revents`, as `poll(2)` reported them for [`Self::pollfd`],
    /// say that the other end has gone.
    pub(crate) fn left(&self, revents: i16) -> bool {
        use nix::libc::{POLLERR, POLLHUP, POLLNVAL, POLLRDHUP};
        let Some((_, half_close_ends)) = self.watched else {
            return false;
        };
        let mask = POLLHUP | POLLERR | POLLNVAL | if half_close_ends { POLLRDHUP } else { 0 };
        revents & mask != 0
    }
}

/// Something that can ask the human questions. Each dialog is for the
/// program at the other end of `requester`: when it goes away while the
/// dialog is open, the dialog is taken down and the answer is
/// [`Typed::RequesterGone`] or [`Decision::RequesterGone`].
pub trait Ui: Send + Sync {
    /// Ask for the master password.
    fn master_password(&self, prompt: &Prompt, requester: Connection<'_>) -> anyhow::Result<Typed>;
    /// Ask for a secret value to store.
    fn secret_value(&self, prompt: &Prompt, requester: Connection<'_>) -> anyhow::Result<Typed>;
    /// Ask whether to allow a request.
    fn approve(
        &self,
        request: &ApprovalRequest,
        requester: Connection<'_>,
    ) -> anyhow::Result<Decision>;
    /// Whether approval dialogs must fit on the screen without scrolling, so
    /// that requests taller than [`metrics::MAX_HEIGHT`] are refused (zenity);
    /// `false` for dialogs whose content scrolls while the buttons stay in
    /// view.
    fn limits_height(&self) -> bool {
        true
    }
    /// The agent's settings changed (`configure`): from now on "Allow for …"
    /// lasts `remember_for` (zero does not offer it) and dialogs wait
    /// `timeout`. A dialog already shown keeps what it was shown with. Ways
    /// of asking that have no such settings ignore it.
    fn set_timing(&self, _remember_for: Duration, _timeout: Duration) {}
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
const DIALOG_ENV: [&str; 10] = [
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_MESSAGES",
    "LANGUAGE",
];

/// Room the agent reserves in a dialog for the note explaining "Allow for …"
/// (see [`remember_note`]).
pub const REMEMBER_NOTE_MAX: usize = 240;

/// Longest text an approval or prompt dialog may contain. The agent refuses
/// requests whose dialog would be longer: the human must be able to read all
/// of it.
pub const MAX_DIALOG_CHARS: usize = 4000;

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
    /// When the agent stops waiting for zenity: its own timeout, plus a grace.
    fn deadline(&self) -> std::time::Instant {
        std::time::Instant::now()
            + self.timeout.max(Duration::from_secs(1))
            + crate::supervise::GRACE
    }

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

    fn hidden_entry(&self, prompt: &Prompt, requester: Connection<'_>) -> anyhow::Result<Typed> {
        let mut cmd = self.command(&prompt.title)?;
        cmd.arg("--entry")
            .arg("--hide-text")
            .arg(format!("--text={}", entry_label(&prompt_text(prompt))))
            .arg(format!("--ok-label={}", prompt.confirm));
        typed_from(capture_through_socket(cmd, self.deadline(), requester)?)
    }
}

/// What zenity's entry dialog answered, from how it ended: `None`, the
/// requester went away and the dialog was taken down.
fn typed_from(captured: Option<DialogExit>) -> anyhow::Result<Typed> {
    let Some((status, output)) = captured else {
        return Ok(Typed::RequesterGone);
    };
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

/// What zenity's question dialog answered, from how it ended
/// ([`decision_from`]): `None`, the requester went away and the dialog was
/// taken down.
fn approval_from(captured: Option<DialogExit>, remember: Option<(&str, Duration)>) -> Decision {
    match captured {
        None => Decision::RequesterGone,
        Some((status, output)) => decision_from(status, &output, remember),
    }
}

/// Most a dialog program may print.
const MAX_DIALOG_OUTPUT: usize = 64 * 1024;

/// How a dialog program ended — its exit status, if it exited — and what it
/// printed.
pub type DialogExit = (Option<i32>, Zeroizing<Vec<u8>>);

/// Run a dialog program and collect what it prints, before `deadline`. Its
/// stdout is one end of a socket pair, not a pipe: another process of the
/// same user can open a pipe through `/proc/<pid>/fd/1` and race us for the
/// typed password, but opening a socket that way fails (`ENXIO`). It runs
/// under the agent's supervision of helper processes: its own process group,
/// killed when done. A program that has not finished by the deadline is
/// reported as zenity reports a timeout. If `requester` goes away before
/// the program has printed its answer, the program is killed the same way
/// and the result is `None`.
pub fn capture_through_socket(
    mut cmd: Command,
    deadline: std::time::Instant,
    requester: Connection<'_>,
) -> anyhow::Result<Option<DialogExit>> {
    use crate::supervise::{Supervised, is_gone, read_to_end_by};
    let timed_out = || Some((Some(ZENITY_TIMEOUT), Zeroizing::new(Vec::new())));
    let (ours, theirs) = UnixStream::pair().context("cannot create a socket pair")?;
    cmd.stdout(Stdio::from(OwnedFd::from(theirs)));
    let child = Supervised::spawn(cmd).context("cannot run the dialog program")?;
    let output = match read_to_end_by(&ours, MAX_DIALOG_OUTPUT, deadline, requester) {
        Ok(output) => output,
        Err(e) if is_gone(&e) => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Ok(timed_out()),
        Err(e) => return Err(e).context("cannot read the dialog's answer"),
    };
    match child
        .exit_by(deadline)
        .context("cannot wait for the dialog program")?
    {
        Some(exit) => Ok(Some((exit.code(), output))),
        None => Ok(timed_out()),
    }
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
    fn master_password(&self, prompt: &Prompt, requester: Connection<'_>) -> anyhow::Result<Typed> {
        self.hidden_entry(prompt, requester)
    }

    fn secret_value(&self, prompt: &Prompt, requester: Connection<'_>) -> anyhow::Result<Typed> {
        self.hidden_entry(prompt, requester)
    }

    fn approve(
        &self,
        request: &ApprovalRequest,
        requester: Connection<'_>,
    ) -> anyhow::Result<Decision> {
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
        let captured = capture_through_socket(cmd, self.deadline(), requester)?;
        let remember = offer_remember.then_some((remember_label.as_str(), self.remember_for));
        Ok(approval_from(captured, remember))
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
    let facts = request.facts.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    for (label, value) in blocks(request).into_iter().chain(facts) {
        text.push_str(&format!("{label}: {}\n", dialog_text(value)));
    }
    for warning in &request.warnings {
        text.push_str(&format!("\n⚠ {}", dialog_text(warning)));
    }
    text
}

/// The blocks a zenity approval dialog shows: the command, then the details.
fn blocks(request: &ApprovalRequest) -> Vec<(&str, &str)> {
    let command = request.command.as_deref().map(|c| ("Command", c));
    command
        .into_iter()
        .chain(
            request
                .details
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        )
        .collect()
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
    for (label, value) in blocks(request) {
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

/// With zenity, the height of an approval dialog — counting the "Allow for"
/// note if it may be offered — when it is too tall to read at once.
pub fn approval_too_tall(request: &ApprovalRequest) -> Option<usize> {
    let note = if request.can_remember {
        REMEMBER_NOTE_HEIGHT
    } else {
        0
    };
    let height = approval_height(request) + note;
    (height > metrics::MAX_HEIGHT).then_some(height)
}

/// With zenity, the height of a prompt when it is too tall to read at once.
pub fn prompt_too_tall(prompt: &Prompt) -> Option<usize> {
    let height = prompt_height(&prompt_text(prompt));
    (height > metrics::MAX_HEIGHT).then_some(height)
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
    for (label, value) in blocks(request) {
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
pub(crate) fn dialog_env() -> Vec<(String, String)> {
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
    use std::os::fd::AsFd;

    #[test]
    fn dialog_output_arrives_through_a_socket() {
        // On a thread with a deadline: a broken capture (one that keeps a
        // copy of the child's end open) would wait forever for end-of-file.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", "readlink /proc/self/fd/1"]);
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let _ = tx.send(
                capture_through_socket(cmd, deadline, Connection::none())
                    .map(|c| c.map(|(s, o)| (s, o.to_vec()))),
            );
        });
        let (status, output) = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("capture hung")
            .expect("run")
            .expect("nobody to go away");
        assert_eq!(status, Some(0));
        let target = String::from_utf8_lossy(&output);
        assert!(target.starts_with("socket:"), "fd 1 was {target}");
    }

    #[test]
    fn a_missing_dialog_program_is_an_error() {
        let cmd = Command::new("/nonexistent/zenity");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        assert!(capture_through_socket(cmd, deadline, Connection::none()).is_err());
    }

    #[test]
    fn a_dialog_program_that_hangs_is_stopped_with_its_descendants() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("pid");
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            &format!("sleep 30 & echo $! > '{}'; sleep 30", pidfile.display()),
        ]);
        let started = std::time::Instant::now();
        let (status, output) = capture_through_socket(
            cmd,
            started + Duration::from_millis(500),
            Connection::none(),
        )
        .expect("capture")
        .expect("nobody to go away");
        assert_eq!(status, Some(ZENITY_TIMEOUT));
        assert!(output.is_empty());
        assert!(started.elapsed() < Duration::from_secs(3));
        let descendant: u32 = std::fs::read_to_string(&pidfile)
            .expect("pid")
            .trim()
            .parse()
            .expect("number");
        assert!(
            crate::supervise::tests::gone(descendant),
            "a descendant survived"
        );
    }

    /// A dialog program that never answers, with a descendant; returns the
    /// file that names the descendant once it runs.
    fn hanging_dialog(dir: &Path) -> (Command, std::path::PathBuf) {
        let pidfile = dir.join("pid");
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            &format!("sleep 30 & echo $! > '{}'; sleep 30", pidfile.display()),
        ]);
        (cmd, pidfile)
    }

    /// Wait (at most 10 seconds) for a program to have written its
    /// descendant's process id.
    fn descendant_of(pidfile: &Path) -> u32 {
        let until = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(pid) = std::fs::read_to_string(pidfile)
                .ok()
                .and_then(|text| text.trim().parse().ok())
            {
                return pid;
            }
            assert!(std::time::Instant::now() < until, "the program never ran");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_dialog_whose_requester_goes_away_is_taken_down() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cmd, pidfile) = hanging_dialog(dir.path());
        // The requester's connection: closed by its other end once the
        // dialog runs.
        let (watched, requester) = UnixStream::pair().expect("pair");
        let leaving = pidfile.clone();
        let leaves = std::thread::spawn(move || {
            descendant_of(&leaving);
            drop(requester);
        });
        let started = std::time::Instant::now();
        let captured = capture_through_socket(
            cmd,
            started + Duration::from_secs(60),
            Connection::new(watched.as_fd(), false),
        )
        .expect("capture");
        assert!(captured.is_none(), "the requester's departure was missed");
        assert!(started.elapsed() < Duration::from_secs(30));
        leaves.join().expect("join");
        let descendant = descendant_of(&pidfile);
        assert!(
            crate::supervise::tests::gone(descendant),
            "a descendant survived"
        );
    }

    #[test]
    fn a_requester_that_stays_or_only_half_closes_leaves_the_dialog_alone() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        // Bytes it sent and nobody read, and a half-close that does not end
        // the request: still there, so the dialog runs to its deadline.
        let (watched, mut requester) = UnixStream::pair().expect("pair");
        requester.write_all(b"\x80\x00\x00\x01\x00").expect("write");
        requester
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close");
        let (cmd, _) = hanging_dialog(dir.path());
        let captured = capture_through_socket(
            cmd,
            std::time::Instant::now() + Duration::from_millis(500),
            Connection::new(watched.as_fd(), false),
        )
        .expect("capture");
        assert_eq!(
            captured.map(|(status, _)| status),
            Some(Some(ZENITY_TIMEOUT))
        );
        // The same half-close ends a request that a half-close ends.
        let (cmd, _) = hanging_dialog(dir.path());
        let started = std::time::Instant::now();
        let captured = capture_through_socket(
            cmd,
            started + Duration::from_secs(60),
            Connection::new(watched.as_fd(), true),
        )
        .expect("capture");
        assert!(captured.is_none());
        assert!(started.elapsed() < Duration::from_secs(30));
        drop(requester);
    }

    #[test]
    fn a_connection_is_gone_only_once_its_other_end_closes() {
        use std::io::Write;
        assert!(!Connection::none().gone());
        let (watched, mut other) = UnixStream::pair().expect("pair");
        let run = Connection::new(watched.as_fd(), true);
        let request = Connection::new(watched.as_fd(), false);
        assert!(!run.gone() && !request.gone());
        // Unread bytes are neither read nor taken for a departure.
        other.write_all(b"\x80\x00\x00\x01\x00").expect("write");
        assert!(!run.gone() && !request.gone());
        other
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close");
        assert!(run.gone(), "a half-close ends a run");
        assert!(!request.gone(), "a half-closed client can still read");
        let mut pending = [0u8; 5];
        use std::io::Read;
        (&watched).read_exact(&mut pending).expect("still there");
        assert_eq!(&pending, b"\x80\x00\x00\x01\x00");
        // Shut down both ways (as the manager cancels), or closed — seen
        // once no other copy of it remains (a process forked by another
        // test holds one until its exec).
        other.shutdown(std::net::Shutdown::Both).expect("shutdown");
        assert!(run.gone() && request.gone());
        let (watched, other) = UnixStream::pair().expect("pair");
        drop(other);
        let closed = Connection::new(watched.as_fd(), false);
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while !closed.gone() {
            assert!(
                std::time::Instant::now() < until,
                "a closed connection not seen"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
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
    fn zenity_answers_mean_what_they_say_and_a_dialog_taken_down_none() {
        let ended =
            |status: i32, output: &[u8]| Some((Some(status), Zeroizing::new(output.to_vec())));
        assert!(matches!(
            typed_from(ended(0, b"fake typed\n")).expect("typed"),
            Typed::Value(v) if v.as_str() == "fake typed"
        ));
        assert!(matches!(
            typed_from(ended(1, b"")).expect("cancel"),
            Typed::Cancelled
        ));
        assert!(matches!(
            typed_from(ended(ZENITY_TIMEOUT, b"")).expect("timeout"),
            Typed::TimedOut
        ));
        assert!(typed_from(ended(3, b"")).is_err());
        assert!(typed_from(Some((None, Zeroizing::new(Vec::new())))).is_err());
        assert_eq!(approval_from(ended(0, b""), None), Decision::AllowOnce);
        assert_eq!(approval_from(ended(1, b""), None), Decision::Deny);
        // Taken down because the requester went away: neither a timeout nor
        // a denial, so that the agent records it as such and does not answer.
        assert!(matches!(
            typed_from(None).expect("gone"),
            Typed::RequesterGone
        ));
        assert_eq!(approval_from(None, None), Decision::RequesterGone);
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
            command: None,
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
                command: None,
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
            command: None,
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
            command: None,
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
            command: None,
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
        let prompt = Prompt {
            title: "t".into(),
            headline: "Type the value.".into(),
            explanation: String::new(),
            notice: Some("Wrong.".into()),
            details: vec![("Entry".into(), "\u{6F22}\nForged: line".into())],
            field: "Value".into(),
            confirm: "Save".into(),
        };
        let text = prompt_text(&prompt);
        assert_eq!(
            text,
            "Wrong.\n\nType the value.\n\nEntry: \\u{6f22}\\u{a}Forged: line"
        );
        assert_eq!(prompt_height(&text), 5 * metrics::TEXT);
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
            command: None,
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
