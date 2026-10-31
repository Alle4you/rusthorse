//! Human interaction: the dialogs the agent shows.
//!
//! Dialogs are shown **by the agent**, never by the client, so a client cannot
//! answer them by writing to a terminal. The production implementation uses
//! `zenity` (tested with 3.44). Tests use their own [`Ui`] implementation.

use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, bail};

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

/// Exit status zenity uses for a timeout.
const ZENITY_TIMEOUT: i32 = 5;

impl ZenityUi {
    fn command(&self, title: &str) -> Command {
        let mut cmd = Command::new("zenity");
        cmd.arg(format!("--title={title}"))
            .arg(format!("--timeout={}", self.timeout.as_secs().max(1)))
            .arg("--width=640")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        cmd.envs(graphical_session_env());
        cmd
    }

    fn hidden_entry(&self, prompt: &Prompt) -> anyhow::Result<Option<SecretString>> {
        let mut cmd = self.command(&prompt.title);
        cmd.arg("--entry")
            .arg("--hide-text")
            // The entry dialog's label uses GTK mnemonics: a single `_` would
            // underline the next letter and disappear.
            .arg(format!("--text={}", prompt.message.replace('_', "__")))
            .arg(format!("--ok-label={}", prompt.confirm));
        let output = cmd
            .output()
            .context("cannot run zenity (is it installed? `sudo apt install zenity`)")?;
        let stdout = zeroize::Zeroizing::new(output.stdout);
        match output.status.code() {
            Some(0) => {
                let mut value =
                    String::from_utf8(stdout.to_vec()).context("zenity returned invalid UTF-8")?;
                if value.ends_with('\n') {
                    value.pop();
                }
                Ok(Some(SecretString::new(value)))
            }
            Some(1) | Some(ZENITY_TIMEOUT) => Ok(None),
            other => bail!("zenity failed (exit status {other:?})"),
        }
    }
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

        let mut cmd = self.command(&request.title);
        cmd.arg("--question")
            .arg("--no-markup")
            .arg("--default-cancel")
            .arg(format!("--text={}", approval_text(request)))
            .arg("--ok-label=Allow once")
            .arg("--cancel-label=Deny");
        if offer_remember {
            cmd.arg(format!("--extra-button={remember_label}"));
        }
        let output = cmd
            .output()
            .context("cannot run zenity (is it installed? `sudo apt install zenity`)")?;
        let pressed = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(match output.status.code() {
            Some(0) => Decision::AllowOnce,
            // zenity reports the extra button as exit status 1 plus its label.
            Some(1) if offer_remember && pressed == remember_label => {
                Decision::AllowFor(self.remember_for)
            }
            Some(1) | Some(ZENITY_TIMEOUT) => Decision::Deny,
            other => bail!("zenity failed (exit status {other:?})"),
        })
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

/// Variables a dialog needs to reach the desktop session. When the agent was
/// started before the session exported them to systemd, read them from
/// `systemctl --user show-environment`.
fn graphical_session_env() -> Vec<(String, String)> {
    const WANTED: [&str; 4] = [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
    ];
    if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return Vec::new();
    }
    let Ok(output) = Command::new("systemctl")
        .args(["--user", "show-environment"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(k, v)| WANTED.contains(k) && !v.starts_with("$'"))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
