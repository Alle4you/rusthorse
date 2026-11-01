//! The protocol between the agent and `rusthorse-dialog`, the program that
//! shows its dialogs ([ADR 0006](../docs/adr/0006-own-dialog-program.md)).
//!
//! The agent gives the program one end of a socket pair as its standard input
//! and output — never a pipe, which other processes could open through
//! `/proc/<pid>/fd`. Each direction carries one frame: a 4-byte big-endian
//! length and a UTF-8 JSON object. The answer echoes the request's version and
//! identifier; anything unexpected is a denial.

use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::protocol::SecretString;

/// Version of this protocol. Both sides refuse any other.
pub const VERSION: u32 = 1;
/// Largest request frame, in bytes.
pub const MAX_REQUEST: usize = 64 * 1024;
/// Largest answer frame, in bytes: room for [`MAX_TYPED`] bytes of text even
/// if JSON escapes every one of them as `\u00XX`.
pub const MAX_ANSWER: usize = 32 * 1024;
/// Longest text a password or value dialog returns, in bytes.
pub const MAX_TYPED: usize = 4096;
/// Exit status of the program for a request of another version.
pub const EXIT_INCOMPATIBLE: i32 = 3;
/// Exit status of the program for a malformed request, or one with text that
/// dialogs must not draw.
pub const EXIT_INVALID: i32 = 4;

/// What the agent asks the program to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// [`VERSION`].
    pub version: u32,
    /// A random identifier the answer must repeat.
    pub id: String,
    /// Seconds after which the program answers [`Reply::TimedOut`].
    pub timeout_secs: u64,
    /// Window title.
    pub title: String,
    /// The dialog itself.
    pub dialog: Dialog,
}

/// The two kinds of dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Dialog {
    /// Allow or deny a request.
    Approval {
        /// The question, as a short headline.
        headline: String,
        /// What approving means; may be empty.
        explanation: String,
        /// Warnings shown before everything else.
        warnings: Vec<String>,
        /// The command line, for `run`.
        command: Option<String>,
        /// Label/value pairs, shown in two columns.
        details: Vec<(String, String)>,
        /// Context, label/value pairs shown more quietly.
        facts: Vec<(String, String)>,
        /// The "Allow for N" button, when it is offered.
        remember: Option<Remember>,
    },
    /// Type a master password or a secret value.
    Entry {
        /// What to type, as a short headline.
        headline: String,
        /// One or two sentences under it; may be empty.
        explanation: String,
        /// A line shown first, after a wrong or empty attempt.
        notice: Option<String>,
        /// Label/value pairs (vault, entry, requester).
        details: Vec<(String, String)>,
        /// Label of the input field.
        field: String,
        /// Label of the confirm button.
        confirm: String,
    },
}

/// The "Allow for N" button and the note that explains it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remember {
    /// Button label, such as "Allow for 15m".
    pub label: String,
    /// The note shown above the buttons.
    pub note: String,
}

/// What the program answers.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    /// [`VERSION`].
    pub version: u32,
    /// The request's identifier.
    pub id: String,
    /// The human's answer.
    pub reply: Reply,
}

/// The human's answer. `Debug` never shows typed text. On the wire it is
/// `{"kind": "allow_once"}` and so on, with `text` only for `typed`; any other
/// field is refused.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "WireReply", into = "WireReply")]
pub enum Reply {
    /// Approval: allow this request once.
    AllowOnce,
    /// Approval: allow it and identical ones for the offered duration.
    AllowFor,
    /// Approval: deny (also Escape and closing the window).
    Deny,
    /// Entry: the text the human typed and confirmed.
    Typed {
        /// The text, at most [`MAX_TYPED`] bytes.
        text: SecretString,
    },
    /// Entry: cancelled (also Escape and closing the window).
    Cancel,
    /// Nobody answered before the timeout.
    TimedOut,
}

/// [`Reply`] as it travels: a plain struct, so that unknown fields are
/// refused (serde does not refuse them in tagged unit variants).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReply {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<SecretString>,
}

impl TryFrom<WireReply> for Reply {
    type Error = String;

    fn try_from(wire: WireReply) -> Result<Self, String> {
        Ok(match (wire.kind.as_str(), wire.text) {
            ("allow_once", None) => Reply::AllowOnce,
            ("allow_for", None) => Reply::AllowFor,
            ("deny", None) => Reply::Deny,
            ("typed", Some(text)) => Reply::Typed { text },
            ("cancel", None) => Reply::Cancel,
            ("timed_out", None) => Reply::TimedOut,
            (kind, _) => return Err(format!("unexpected reply {kind:?}")),
        })
    }
}

impl From<Reply> for WireReply {
    fn from(reply: Reply) -> Self {
        let (kind, text) = match reply {
            Reply::AllowOnce => ("allow_once", None),
            Reply::AllowFor => ("allow_for", None),
            Reply::Deny => ("deny", None),
            Reply::Typed { text } => ("typed", Some(text)),
            Reply::Cancel => ("cancel", None),
            Reply::TimedOut => ("timed_out", None),
        };
        WireReply {
            kind: kind.into(),
            text,
        }
    }
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Reply::AllowOnce => "AllowOnce",
            Reply::AllowFor => "AllowFor",
            Reply::Deny => "Deny",
            Reply::Typed { .. } => "Typed(<hidden>)",
            Reply::Cancel => "Cancel",
            Reply::TimedOut => "TimedOut",
        })
    }
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer")
            .field("version", &self.version)
            .field("id", &self.id)
            .field("reply", &self.reply)
            .finish()
    }
}

impl Request {
    /// Every string the dialog shows, so that both sides can check it went
    /// through [`crate::ui::dialog_text`].
    pub fn texts(&self) -> Vec<&str> {
        fn pairs(pairs: &[(String, String)]) -> impl Iterator<Item = &str> {
            pairs.iter().flat_map(|(k, v)| [k.as_str(), v.as_str()])
        }
        let mut texts = vec![self.title.as_str()];
        match &self.dialog {
            Dialog::Approval {
                headline,
                explanation,
                warnings,
                command,
                details,
                facts,
                remember,
            } => {
                texts.extend([headline.as_str(), explanation.as_str()]);
                texts.extend(warnings.iter().map(String::as_str));
                texts.extend(command.as_deref());
                texts.extend(pairs(details));
                texts.extend(pairs(facts));
                if let Some(r) = remember {
                    texts.extend([r.label.as_str(), r.note.as_str()]);
                }
            }
            Dialog::Entry {
                headline,
                explanation,
                notice,
                details,
                field,
                confirm,
            } => {
                texts.extend([headline.as_str(), explanation.as_str()]);
                texts.extend(notice.as_deref());
                texts.extend(pairs(details));
                texts.extend([field.as_str(), confirm.as_str()]);
            }
        }
        texts
    }

    /// Whether every string is drawn as it is by dialogs, that is, has
    /// already been through [`crate::ui::dialog_text`].
    pub fn is_drawable(&self) -> bool {
        self.texts().iter().all(|t| crate::ui::dialog_text(t) == *t)
    }
}

/// Write `value` as one frame, refusing one larger than `max`.
pub fn write_frame<T: Serialize>(out: &mut impl Write, value: &T, max: usize) -> io::Result<()> {
    let body = Zeroizing::new(serde_json::to_vec(value).map_err(io::Error::other)?);
    if body.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame of {} bytes, limit {max}", body.len()),
        ));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    out.write_all(&frame)?;
    out.flush()
}

/// Read one frame's body, refusing one larger than `max` before reading it.
pub fn read_frame(input: &mut impl Read, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {length} bytes, limit {max}"),
        ));
    }
    let mut body = Zeroizing::new(vec![0u8; length]);
    input.read_exact(&mut body)?;
    Ok(body)
}

/// Parse a frame's body.
pub fn parse<T: DeserializeOwned>(body: &[u8]) -> io::Result<T> {
    serde_json::from_slice(body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval() -> Request {
        Request {
            version: VERSION,
            id: "0123456789abcdef".into(),
            timeout_secs: 120,
            title: "Rusthorse — use a secret".into(),
            dialog: Dialog::Approval {
                headline: "Run a command with your secrets?".into(),
                explanation: "Read it.".into(),
                warnings: vec!["careful".into()],
                command: Some("printf 'a\\nb'".into()),
                details: vec![("Program".into(), "/usr/bin/printf".into())],
                facts: vec![("Input".into(), "none".into())],
                remember: Some(Remember {
                    label: "Allow for 15m".into(),
                    note: "“Allow for 15m” lets …".into(),
                }),
            },
        }
    }

    #[test]
    fn frames_round_trip() {
        let request = approval();
        let mut wire = Vec::new();
        write_frame(&mut wire, &request, MAX_REQUEST).expect("write");
        assert_eq!(
            u32::from_be_bytes(wire[..4].try_into().expect("4")) as usize,
            wire.len() - 4
        );
        let body = read_frame(&mut wire.as_slice(), MAX_REQUEST).expect("read");
        assert_eq!(parse::<Request>(&body).expect("parse"), request);
    }

    #[test]
    fn oversized_frames_are_refused_before_reading() {
        let mut wire = (MAX_ANSWER as u32 + 1).to_be_bytes().to_vec();
        wire.extend_from_slice(b"{}");
        let err = read_frame(&mut wire.as_slice(), MAX_ANSWER).expect_err("too large");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let big = approval();
        assert!(write_frame(&mut Vec::new(), &big, 10).is_err());
    }

    #[test]
    fn a_partial_frame_is_an_error() {
        let mut wire = 100u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"{\"version\":1");
        assert!(read_frame(&mut wire.as_slice(), MAX_ANSWER).is_err());
    }

    #[test]
    fn unknown_fields_and_kinds_are_refused() {
        let ok = br#"{"version":1,"id":"x","reply":{"kind":"allow_once"}}"#;
        assert!(parse::<Answer>(ok).is_ok());
        for bad in [
            &br#"{"version":1,"id":"x","reply":{"kind":"allow_always"}}"#[..],
            br#"{"version":1,"id":"x","reply":{"kind":"allow_once"},"extra":1}"#,
            br#"{"version":1,"id":"x","reply":{"kind":"allow_once","why":"x"}}"#,
            br#"{"version":1,"reply":{"kind":"allow_once"}}"#,
            br#"{"version":1,"id":"x","reply":{"kind":"deny","text":"x"}}"#,
            br#"{"version":1,"id":"x","reply":{"kind":"typed"}}"#,
        ] {
            assert!(
                parse::<Answer>(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let typed = br#"{"version":1,"id":"x","reply":{"kind":"typed","text":"t"}}"#;
        assert!(parse::<Answer>(typed).is_ok());
        // The request side: an unknown field anywhere is refused.
        let mut wire = serde_json::to_value(approval()).expect("value");
        wire["dialog"]["surprise"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Request>(wire).is_err());
        let mut wire = serde_json::to_value(approval()).expect("value");
        wire["dialog"]["remember"]["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Request>(wire).is_err());
    }

    #[test]
    fn the_longest_typed_text_fits_an_answer_frame() {
        // Control characters cost six bytes each in JSON.
        let answer = Answer {
            version: VERSION,
            id: "0123456789abcdef0123456789abcdef".into(),
            reply: Reply::Typed {
                text: SecretString::new("\u{1}".repeat(MAX_TYPED)),
            },
        };
        let mut wire = Vec::new();
        write_frame(&mut wire, &answer, MAX_ANSWER).expect("fits");
    }

    #[test]
    fn typed_text_never_shows_in_debug_output() {
        let answer = Answer {
            version: VERSION,
            id: "x".into(),
            reply: Reply::Typed {
                text: SecretString::new("hunter2-secret".into()),
            },
        };
        let shown = format!("{answer:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("Typed(<hidden>)"));
    }

    #[test]
    fn only_requests_made_of_drawable_text_pass() {
        let mut request = approval();
        assert!(request.is_drawable());
        if let Dialog::Approval { details, .. } = &mut request.dialog {
            details.push(("Program".into(), "p\u{430}ypal".into()));
        }
        assert!(!request.is_drawable());
        let mut request = approval();
        request.title = "line\nbreak".into();
        assert!(!request.is_drawable());
    }
}
