//! Parsing `.env` files for imports. The agent reads the files itself
//! ([`Request::ImportFrom`](crate::protocol::Request::ImportFrom)); GNOME
//! Keyring is read by [`keyring`](crate::keyring).

use crate::protocol::SecretString;

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

/// What a `.env` file holds, as [`parse_dotenv`] reads it.
pub struct Dotenv {
    /// The variables with a value, in the file's order.
    pub pairs: Vec<(String, SecretString)>,
    /// The variables with an empty value: they cannot be imported.
    pub empty: Vec<String>,
}

/// Parse a `.env` file in a small dialect, chosen so that python-dotenv and
/// Node's dotenv read every file Rusthorse accepts as Rusthorse does — the
/// same names, the same values — and so that nothing of a value can be taken
/// for a name. (Docker's `--env-file` keeps quotes as part of the value, and
/// shells take no spaces around `=`: files written for them may differ.)
///
/// - Lines end with LF or CRLF. The only blanks are spaces and tabs.
/// - A line is blank, a comment (`#` first), or `NAME=value`, with an
///   optional `export ` before it and blanks around `=`. `NAME` is made of
///   ASCII letters, digits, `_`, `.` and `-` (whether the vault takes it is
///   decided when importing).
/// - A value is on one line: in single or double quotes, with neither that
///   quote nor a backslash inside, followed only by blanks or a `#`
///   comment; or unquoted, not starting with a back quote, where a `#` after
///   a blank starts a comment and blanks at both ends are dropped.
///
/// Every other file is refused as a whole, naming the line and never its
/// text: a byte-order mark, a lone carriage return, a control character,
/// any other blank or line separator, a value over several lines, a
/// backslash in quotes, a value in back quotes, a `#` without a blank before
/// it in an unquoted value, a `${…}` in a value (python-dotenv replaces it),
/// a name set twice, the name `__proto__` (Node's dotenv drops it), and any
/// line that is not one of the three above. Nothing is skipped without a
/// word: the whole file is checked before any name is given, so a file with
/// an error starts no import. (An import then saves batch by batch: batches
/// allowed before one that is denied or fails stay saved.)
pub fn parse_dotenv(text: &str) -> Result<Dotenv, String> {
    let mut parsed = Dotenv {
        pairs: Vec::new(),
        empty: Vec::new(),
    };
    let segments: Vec<&str> = text.split('\n').collect();
    // Where each name was first set: a name set twice refuses the file.
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (index, raw) in segments.iter().enumerate() {
        let number = index + 1;
        // A carriage return ends a line only before a line feed (CRLF).
        let line = if index + 1 < segments.len() {
            raw.strip_suffix('\r').unwrap_or(raw)
        } else {
            raw
        };
        if let Some(c) = line.chars().find(|&c| {
            c == '\u{FEFF}'
                || (c.is_control() && c != '\t')
                || (c.is_whitespace() && c != ' ' && c != '\t')
        }) {
            return Err(format!(
                "line {number}: a character that .env readers do not all read alike ({})",
                match c {
                    '\r' => "a carriage return without a line feed".to_string(),
                    '\u{FEFF}' => "a byte-order mark".to_string(),
                    c => format!("U+{:04X}", u32::from(c)),
                }
            ));
        }
        let line = line.trim_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let unsupported =
            || format!("line {number}: not a NAME=value line in the form Rusthorse reads");
        let binding = line
            .strip_prefix("export")
            .filter(|rest| rest.starts_with([' ', '\t']))
            .map_or(line, |rest| rest.trim_start_matches([' ', '\t']));
        let length = binding
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
            .unwrap_or(binding.len());
        let (name, rest) = binding.split_at(length);
        let Some(value) = rest
            .trim_start_matches([' ', '\t'])
            .strip_prefix('=')
            .filter(|_| !name.is_empty())
        else {
            return Err(unsupported());
        };
        // Node's dotenv drops this name (it is an object's prototype).
        if name == "__proto__" {
            return Err(format!(
                "line {number}: the name __proto__, which Node's dotenv drops"
            ));
        }
        if let Some(first) = seen.insert(name.to_string(), number) {
            return Err(format!(
                "line {number}: {name} is set again (also on line {first}); which one counts \
                 differs between programs"
            ));
        }
        let value = value.trim_matches([' ', '\t']);
        let value = match value.chars().next() {
            Some('`') => {
                return Err(format!(
                    "line {number}: a value in back quotes, which python-dotenv keeps and Node's \
                     dotenv takes off"
                ));
            }
            Some(quote @ ('"' | '\'')) => {
                let inner = &value[1..];
                let Some(end) = inner.find(quote) else {
                    return Err(format!(
                        "line {number}: a quoted value that does not end on its line (Rusthorse \
                         reads one-line values only)"
                    ));
                };
                let content = &inner[..end];
                let after = inner[end + 1..].trim_start_matches([' ', '\t']);
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
                    value[..at].trim_end_matches([' ', '\t']).to_string()
                }
                Some(_) => {
                    return Err(format!(
                        "line {number}: a # in a value without quotes, which .env readers do not \
                         all read alike (put the value in quotes)"
                    ));
                }
            },
        };
        // python-dotenv replaces `${NAME}` by default; Node's dotenv does not.
        if value.contains("${") {
            return Err(format!(
                "line {number}: a ${{…}} in a value, which python-dotenv replaces and Node's \
                 dotenv does not"
            ));
        }
        if value.is_empty() {
            parsed.empty.push(name.to_string());
        } else {
            parsed
                .pairs
                .push((name.to_string(), SecretString::new(value)));
        }
    }
    Ok(parsed)
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
        let mut worst = crate::peer::Peer::agent();
        worst.uid = 1000;
        worst.pid = 4_194_304;
        worst.chain = (0..8)
            .map(|_| crate::peer::ProcessInfo {
                pid: 4_194_304,
                name: String::from_utf8_lossy(&[0xff; 15]).into_owned(),
            })
            .collect();
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

    fn values(text: &str) -> Vec<(String, String)> {
        parse_dotenv(text)
            .expect("parse")
            .pairs
            .into_iter()
            .map(|(n, v)| (n, v.to_string()))
            .collect()
    }

    #[test]
    fn the_dialect_is_read_as_both_libraries_read_it() {
        let text = "# a comment with \"quotes\" and = signs\r\n\
                    A=\"x y\" # comment\n\
                    B='it is'\n\
                    C=mid`back`quotes\n\
                    export D = plain # comment\n\
                    E=a\"b'c\n\
                    \tF.dotted-name=\"  inner  \"\n\
                    G=no-comment\r\n\
                    H=p\u{e4}ss\n";
        let expected = [
            ("A", "x y"),
            ("B", "it is"),
            ("C", "mid`back`quotes"),
            ("D", "plain"),
            ("E", "a\"b'c"),
            ("F.dotted-name", "  inner  "),
            ("G", "no-comment"),
            ("H", "p\u{e4}ss"),
        ];
        assert_eq!(
            values(text),
            expected.map(|(n, v)| (n.to_string(), v.to_string()))
        );
    }

    #[test]
    fn empty_values_are_reported_not_skipped() {
        let parsed = parse_dotenv("A=\nB=''\nC=x # c\nD=\"\" # quoted empty\n").expect("parse");
        assert_eq!(parsed.empty, ["A", "B", "D"]);
        assert_eq!(parsed.pairs.len(), 1);
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
            ("K=`FAKE`\n", "line 1: a value in back quotes"),
            (
                "K=\"FAKE_A\" trailing\n",
                "line 1: text after a quoted value",
            ),
            ("K=FAKE#cut\n", "line 1: a # in a value without quotes"),
            // Node reads "" and python-dotenv "# FAKE".
            ("K= # FAKE\n", "line 1: a # in a value without quotes"),
            // Lines that are not NAME=value, quoted or not: Node's
            // `NAME: value`, a bare word, a name with other characters.
            (
                "KEY: \"start=value\nFAKE_PRIVATE=x\nend=tail\"\nNORMAL=x\n",
                "line 1: not a NAME=value line",
            ),
            ("NAME: FAKE\nX=ok\n", "line 1: not a NAME=value line"),
            ("X=ok\nFAKE words\n", "line 2: not a NAME=value line"),
            ("my key=FAKE\n", "line 1: not a NAME=value line"),
            // Characters the readers treat differently: a byte-order mark
            // (in front or before a quote), a lone carriage return (a line
            // break for both libraries), other blanks and separators.
            ("\u{FEFF}K=FAKE\n", "line 1: a character"),
            (
                "KEY=\u{FEFF}\"start\nFAKE_PRIVATE_MATERIAL==\nend=tail\"\nNORMAL=x\n",
                "line 1: a character",
            ),
            (
                "# comment\rKEY=\"start\nFAKE_PRIVATE_MATERIAL==\nend=tail\"\nNORMAL=x\n",
                "line 1: a character",
            ),
            ("A=one\rB=FAKE\n", "line 1: a character"),
            ("K=FAKE\u{A0}x\n", "line 1: a character"),
            ("K=FAKE\u{2028}X=y\n", "line 1: a character"),
            ("K=FAKE\u{85}\n", "line 1: a character"),
            ("K=FAKE\u{1}\n", "line 1: a character"),
            // A carriage return at the very end, without a line feed.
            ("K=FAKE\r", "line 1: a character"),
            // Interpolation, in every form python-dotenv expands.
            ("PART=x\nKEY=${PART}-FAKE\n", "line 2: a ${…} in a value"),
            ("KEY='${PART}FAKE'\n", "line 1: a ${…} in a value"),
            ("KEY=\"${PART:-FAKE}\"\n", "line 1: a ${…} in a value"),
            // A name set twice, also once empty.
            (
                "DUP=\nDUP=FAKE\n",
                "line 2: DUP is set again (also on line 1)",
            ),
            ("__proto__=FAKE\n", "line 1: the name __proto__"),
        ] {
            let Err(refused) = parse_dotenv(text) else {
                panic!("accepted: {text:?}");
            };
            assert!(refused.starts_with(error), "{text:?}: {refused}");
            assert!(!refused.contains("FAKE"), "{refused}");
        }
    }
}
