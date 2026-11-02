//! Parsing `.env` files for imports. The agent reads the files itself
//! ([`Request::ImportFrom`](crate::protocol::Request::ImportFrom)); GNOME
//! Keyring is read by [`keyring`](crate::keyring).

use crate::protocol::SecretString;
use crate::util::is_valid_env_name;

use crate::ui::ApprovalRequest;

/// The most entries one import request may hold; the agent refuses more.
pub const MAX_ENTRIES: usize = 100;

/// Where the values of an import come from, as its dialog says.
pub enum Source<'a> {
    /// The requester supplies them (the `import` request).
    Requester,
    /// The agent reads them from GNOME Keyring: for each entry, its name and
    /// the item it comes from ([`keyring::describe_item`](crate::keyring::describe_item)).
    Keyring(&'a [(String, String)]),
    /// The agent reads them from this `.env` file.
    Dotenv(&'a str),
}

/// The approval dialog of an import of `new` and `existing` entries (in
/// that order for a keyring import's rows), as the agent shows it — and as
/// clients estimate it to size their batches.
pub fn approval(
    source: &Source<'_>,
    new: &[&str],
    existing: &[&str],
    replace: bool,
    requester: &str,
) -> ApprovalRequest {
    let n = new.len() + existing.len();
    let list = |names: &[&str]| {
        if names.is_empty() {
            "(none)".to_string()
        } else {
            names.join(", ")
        }
    };
    let mut details: Vec<(String, String)> = Vec::new();
    let (summary, explanation) = match source {
        Source::Requester => {
            details.push(("New entries".into(), list(new)));
            (
                format!("Import {n} secrets?"),
                "The program that asked supplied these names and values. Check the names \
                 before you allow it.",
            )
        }
        Source::Dotenv(path) => {
            details.push(("Read from".into(), path.to_string()));
            details.push(("New entries".into(), list(new)));
            (
                format!("Import {n} secrets from a .env file?"),
                "The agent reads the values itself, from the file below; the program that \
                 asked chose the variables and their names. Check the names before you allow \
                 it.",
            )
        }
        Source::Keyring(rows) => {
            details.push(("Read from".into(), "GNOME Keyring".into()));
            // One row per entry, its name as content: the entry, then the
            // item its value comes from.
            for (at, (name, item)) in rows.iter().enumerate() {
                details.push((format!("Entry {}", at + 1), format!("{name} ← {item}")));
            }
            (
                format!("Import {n} secrets from GNOME Keyring?"),
                "The agent reads each value itself, from the keyring item shown after the \
                 entry's name; the program that asked chose the items and the names. Check \
                 that each item is the one you mean before you allow it.",
            )
        }
    };
    if !existing.is_empty() {
        let label = if replace {
            "Will be replaced"
        } else {
            "Already exist (skipped)"
        };
        details.push((label.into(), list(existing)));
    }
    details.push(("Requested by (unverified)".into(), requester.to_string()));
    ApprovalRequest {
        title: "Rusthorse — import secrets".into(),
        summary,
        explanation: explanation.into(),
        command: None,
        details,
        facts: Vec::new(),
        warnings: Vec::new(),
        can_remember: false,
    }
}

/// One entry to import, as a client plans the batches: its name, and for a
/// keyring item what the dialog shows for it.
pub struct Planned {
    /// The entry name.
    pub name: String,
    /// The keyring item, as [`keyring::describe_item`](crate::keyring::describe_item) shows it.
    pub item: Option<String>,
}

/// The longest requester chain the agent can show: eight processes whose
/// 15-byte names are all invalid UTF-8 (each byte then shown as a 8-
/// character `\u{fffd}`) and the longest process ids.
fn requester_room() -> String {
    vec![format!("{}[4194304]", "\u{FFFD}".repeat(15)); 8].join(" ← ")
}

/// Whether the agent shows its dialogs with a program whose height it must
/// limit (zenity), from what `status` reports in `dialogs`: the path of
/// `rusthorse-dialog`, which scrolls, means no; anything else — zenity,
/// unknown — yes.
pub fn dialogs_limit_height(dialogs: Option<&str>) -> bool {
    !dialogs.is_some_and(|d| d.starts_with('/'))
}

/// Whether the dialog of an import of `entries` fits: at most
/// [`MAX_ENTRIES`], its text within
/// [`MAX_DIALOG_CHARS`](crate::ui::MAX_DIALOG_CHARS) and, when
/// `limit_height` (zenity), within the screen's height. Assumes the worst:
/// every entry exists (its name is shown twice) and the longest requester
/// chain.
pub fn fits(entries: &[&Planned], dotenv: Option<&str>, limit_height: bool) -> bool {
    if entries.len() > MAX_ENTRIES {
        return false;
    }
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    let rows: Vec<(String, String)> = entries
        .iter()
        .map(|e| (e.name.clone(), e.item.clone().unwrap_or_default()))
        .collect();
    let source = match dotenv {
        Some(path) => Source::Dotenv(path),
        None => Source::Keyring(&rows),
    };
    let request = approval(&source, &[], &names, true, &requester_room());
    crate::ui::approval_text(&request).chars().count() <= crate::ui::MAX_DIALOG_CHARS
        && !(limit_height && crate::ui::approval_too_tall(&request).is_some())
}

/// How many of `entries`, in order, go into each batch of an import, so that
/// each batch's dialog [`fits`] (`limit_height`: see [`dialogs_limit_height`]). An entry whose dialog does not fit even
/// alone gets a batch of its own (the agent then refuses it, saying why).
/// `dotenv` is the file of a `.env` import; `None` for a keyring import.
pub fn batch_sizes(entries: &[Planned], dotenv: Option<&str>, limit_height: bool) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut batch: Vec<&Planned> = Vec::new();
    for entry in entries {
        batch.push(entry);
        if batch.len() > 1 && !fits(&batch, dotenv, limit_height) {
            batch.pop();
            sizes.push(batch.len());
            batch = vec![entry];
        }
    }
    if !batch.is_empty() {
        sizes.push(batch.len());
    }
    sizes
}

/// Parse a `.env` file in the one dialect that the common `.env` libraries —
/// python-dotenv and Node's dotenv — both read alike, so that what is
/// imported is what a program that uses the file through them would read,
/// and nothing of a value can be taken for a name. (Docker's `--env-file`
/// keeps quotes as part of the value, and shells do not take spaces around
/// `=`: files written for them may be read differently.)
///
/// - blank lines and `#` comment lines;
/// - `NAME=value` lines, with an optional `export ` and spaces around `=`;
///   `NAME` is a variable name (letters, digits, `_`; not starting with a
///   digit);
/// - a value on one line: either in single, double or back quotes, with
///   neither that quote nor a backslash inside, then only spaces or a `#`
///   comment; or without quotes, where a `#` is allowed only after a space
///   (a comment, cut off) and spaces at the ends are trimmed.
///
/// Anything else refuses the whole file — a value over several lines, a
/// backslash in quotes, text after a closing quote, a `#` without a space
/// before it in an unquoted value, a line that is not `NAME=value` but holds
/// a quote — because the readers disagree on it, or because reading on
/// could take part of a value for more lines. Errors name the line, never
/// its text. Lines that are not `NAME=value` and hold no quote are skipped,
/// as are empty values.
pub fn parse_dotenv(text: &str) -> Result<Vec<(String, SecretString)>, String> {
    let mut pairs = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let binding = line
            .strip_prefix("export")
            .filter(|rest| rest.starts_with([' ', '\t']))
            .map_or(line, str::trim_start);
        let length = binding
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(binding.len());
        let (name, rest) = binding.split_at(length);
        let value = rest
            .trim_start()
            .strip_prefix('=')
            .filter(|_| is_valid_env_name(name));
        let Some(value) = value else {
            if line.contains(['"', '\'', '`']) {
                return Err(format!(
                    "line {number}: not a NAME=value line, and it holds a quote"
                ));
            }
            continue;
        };
        let value = value.trim();
        let parsed = match value.chars().next() {
            Some(quote @ ('"' | '\'' | '`')) => {
                let inner = &value[1..];
                let Some(end) = inner.find(quote) else {
                    return Err(format!(
                        "line {number}: a quoted value that does not end on its line (Rusthorse \
                         reads one-line values only)"
                    ));
                };
                let content = &inner[..end];
                let after = inner[end + 1..].trim();
                if content.contains('\\') {
                    return Err(format!(
                        "line {number}: a backslash in a quoted value, which .env readers do not \
                         all read alike"
                    ));
                }
                if !(after.is_empty() || after.starts_with('#')) {
                    return Err(format!("line {number}: text after a quoted value"));
                }
                content.to_string()
            }
            _ => match value.find('#') {
                None => value.to_string(),
                Some(at) if value[..at].ends_with([' ', '\t']) => {
                    value[..at].trim_end().to_string()
                }
                Some(_) => {
                    return Err(format!(
                        "line {number}: a # in a value without quotes, which .env readers do not \
                         all read alike (put the value in quotes)"
                    ));
                }
            },
        };
        if !parsed.is_empty() {
            pairs.push((name.to_string(), SecretString::new(parsed)));
        }
    }
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planned(name: String, item: Option<&str>) -> Planned {
        Planned {
            name,
            item: item.map(String::from),
        }
    }

    #[test]
    fn every_batch_dialog_fits_and_batches_are_as_large_as_that_allows() {
        assert!(batch_sizes(&[], None, true).is_empty());
        for (dotenv, item) in [
            (Some("/home/me/project/.env"), None),
            (None, Some("segredo: FAKE [aplicacao=segredo, nome=FAKE]")),
            (None, Some("FAKE")),
        ] {
            let entries: Vec<Planned> = (0..120)
                .map(|i| planned(format!("FAKE_VARIABLE_WITH_A_LONGER_NAME_{i:03}"), item))
                .collect();
            for limit_height in [true, false] {
                let sizes = batch_sizes(&entries, dotenv, limit_height);
                assert_eq!(sizes.iter().sum::<usize>(), 120);
                assert!(sizes.len() > 1, "{sizes:?}");
                let mut at = 0;
                for (i, size) in sizes.iter().enumerate() {
                    let batch: Vec<&Planned> = entries[at..at + size].iter().collect();
                    assert!(
                        fits(&batch, dotenv, limit_height),
                        "{dotenv:?} {item:?} {i}"
                    );
                    // As large as allowed: one more would not fit.
                    if let Some(next) = entries.get(at + size) {
                        let mut more = batch.clone();
                        more.push(next);
                        assert!(
                            !fits(&more, dotenv, limit_height),
                            "{dotenv:?} {item:?} {i}"
                        );
                    }
                    at += size;
                }
            }
        }
        // The room kept for the requester covers the longest chain the agent
        // can describe: eight processes with 15 bytes of invalid UTF-8 for a
        // name and the largest pid.
        let worst = crate::peer::Peer {
            uid: 1000,
            pid: 4_194_304,
            chain: (0..8)
                .map(|_| crate::peer::ProcessInfo {
                    pid: 4_194_304,
                    name: String::from_utf8_lossy(&[0xff; 15]).into_owned(),
                })
                .collect(),
        };
        let keyring: Vec<Planned> = (0..80)
            .map(|i| planned(format!("FAKE_{i}"), Some("segredo: FAKE [nome=FAKE]")))
            .collect();
        let sizes = batch_sizes(&keyring, None, true);
        let names: Vec<String> = keyring.iter().map(|e| e.name.clone()).collect();
        let mut at = 0;
        for size in sizes {
            let rows: Vec<(String, String)> = keyring[at..at + size]
                .iter()
                .map(|e| (e.name.clone(), e.item.clone().unwrap_or_default()))
                .collect();
            let existing: Vec<&str> = names[at..at + size].iter().map(String::as_str).collect();
            let request = approval(
                &Source::Keyring(&rows),
                &[],
                &existing,
                true,
                &worst.describe(),
            );
            assert!(
                crate::ui::approval_text(&request).chars().count() <= crate::ui::MAX_DIALOG_CHARS
            );
            assert!(
                crate::ui::approval_too_tall(&request).is_none(),
                "batch at {at}"
            );
            at += size;
        }
        // Never more than the agent takes in one request.
        let tiny: Vec<Planned> = (0..250).map(|i| planned(format!("X{i}"), None)).collect();
        let sizes = batch_sizes(&tiny, Some("/e"), false);
        assert!(sizes.iter().all(|&n| n <= MAX_ENTRIES), "{sizes:?}");
        assert_eq!(sizes.iter().sum::<usize>(), 250);
        // An entry too long for any dialog goes alone.
        let long = vec![planned("X".repeat(100), Some(&"Y".repeat(5000)))];
        assert_eq!(batch_sizes(&long, None, true), [1]);
        // rusthorse-dialog (a path) scrolls; zenity and unknown do not.
        assert!(!dialogs_limit_height(Some("/usr/bin/rusthorse-dialog")));
        assert!(dialogs_limit_height(Some("zenity")));
        assert!(dialogs_limit_height(None));
    }

    #[test]
    fn the_common_dialect_is_read_as_every_reader_reads_it() {
        let text = "# a comment with \"quotes\"\n\
                    A=\"x y\" # comment\n\
                    B='it is'\n\
                    C=`back`\n\
                    export D = plain # comment\n\
                    E=a\"b'c\n\
                    F=\"\"\n\
                    G=no-comment\n\
                    bare words are skipped\n";
        let pairs: Vec<(String, String)> = parse_dotenv(text)
            .expect("parse")
            .into_iter()
            .map(|(n, v)| (n, v.to_string()))
            .collect();
        let expected = [
            ("A", "x y"),
            ("B", "it is"),
            ("C", "back"),
            ("D", "plain"),
            ("E", "a\"b'c"),
            ("G", "no-comment"),
        ];
        assert_eq!(pairs, expected.map(|(n, v)| (n.to_string(), v.to_string())));
    }

    #[test]
    fn what_the_readers_disagree_on_refuses_the_file_and_shows_nothing_of_it() {
        for (text, error) in [
            // A value over several lines (a PEM key): its lines are never
            // taken for names.
            (
                "PRIVATE_KEY=\"-----BEGIN-----\nFAKE_MATERIAL=x\n-----END-----\"\n",
                "line 1: a quoted value that does not end on its line",
            ),
            // A backslash before a quote, read as an escape by some.
            (
                "K='FAKE_A\\'\nFAKE_B=x\n'\n",
                "line 1: a backslash in a quoted value",
            ),
            (
                "K=\"FAKE\\\\\"\n# note \"\nN=x\n",
                "line 1: a backslash in a quoted value",
            ),
            ("K=`FAKE\\n`\n", "line 1: a backslash in a quoted value"),
            (
                "K=\"FAKE_A\" trailing\n",
                "line 1: text after a quoted value",
            ),
            ("K=FAKE#cut\n", "line 1: a # in a value without quotes"),
            // Node's `NAME: value`, also with `=` in its value.
            (
                "KEY: \"start=value\nFAKE_PRIVATE=x\nend=tail\"\nNORMAL=x\n",
                "line 1: not a NAME=value line, and it holds a quote",
            ),
            (
                "my-key=\"FAKE\nHIDDEN=x\n\"\n",
                "line 1: not a NAME=value line",
            ),
        ] {
            let refused = parse_dotenv(text).expect_err(text);
            assert!(refused.starts_with(error), "{text:?}: {refused}");
            assert!(!refused.contains("FAKE"), "{refused}");
        }
    }

    #[test]
    fn dotenv_parsing() {
        let text = "\
# comment
OPENAI_API_KEY=sk-abc
export TOKEN=\"quoted value\"
SINGLE='x y'
EMPTY=
bad-name=1
  SPACED = trimmed
NOEQUALS
";
        let pairs: Vec<(String, String)> = parse_dotenv(text)
            .expect("parse")
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("OPENAI_API_KEY".into(), "sk-abc".into()),
                ("TOKEN".into(), "quoted value".into()),
                ("SINGLE".into(), "x y".into()),
                ("SPACED".into(), "trimmed".into()),
            ]
        );
    }
}
