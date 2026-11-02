//! Parsing `.env` files for imports. The agent reads the files itself
//! ([`Request::ImportFrom`](crate::protocol::Request::ImportFrom)); GNOME
//! Keyring is read by [`keyring`](crate::keyring).

use crate::protocol::SecretString;
use crate::util::is_valid_env_name;

use crate::ui::ApprovalRequest;

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

/// A requester chain as long as one the agent may show (eight processes
/// with long names), so that batches leave room for the real one.
fn requester_room() -> String {
    ["rusthorse-manager[4194304]"; 8].join(" ← ")
}

/// Whether the dialog of an import of `entries` fits: its text within
/// [`MAX_DIALOG_CHARS`](crate::ui::MAX_DIALOG_CHARS) and, as zenity shows
/// it, within the screen's height. Assumes the worst: every entry exists
/// (its name is shown twice) and a long requester chain.
pub fn fits(entries: &[&Planned], dotenv: Option<&str>) -> bool {
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
        && crate::ui::approval_too_tall(&request).is_none()
}

/// How many of `entries`, in order, go into each batch of an import, so that
/// each batch's dialog [`fits`]. An entry whose dialog does not fit even
/// alone gets a batch of its own (the agent then refuses it, saying why).
/// `dotenv` is the file of a `.env` import; `None` for a keyring import.
pub fn batch_sizes(entries: &[Planned], dotenv: Option<&str>) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut batch: Vec<&Planned> = Vec::new();
    for entry in entries {
        batch.push(entry);
        if batch.len() > 1 && !fits(&batch, dotenv) {
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

/// Parse a `.env` file, as python-dotenv and Node's dotenv read it:
///
/// - `NAME=value` lines, an optional `export ` before the name, `#` comment
///   lines, spaces around `=`;
/// - a value in single, double or back quotes may span lines, up to its
///   closing quote; a quote with a backslash before it does not close (as
///   both libraries read it), and after the closing quote only spaces and a
///   `#` comment may follow;
/// - escapes are decoded as python-dotenv does: `\\`, `\'`, `\"`, `\n`,
///   `\r`, `\t`, `\a`, `\b`, `\f`, `\v` in double quotes, `\\` and `\'` in
///   single quotes, none in back quotes;
/// - an unquoted value ends at a ` #` comment, and its spaces are trimmed.
///
/// Names that are not valid variable names, and empty values, are skipped.
///
/// The file is refused as a whole — rather than read line by line, which
/// would take the rest of a value for more `NAME=value` lines and return
/// pieces of it as names — when a quote is never closed, when text follows a
/// closing quote, or when a line that is not a `NAME=value` line holds a
/// quote character. Errors name the line, never its text.
pub fn parse_dotenv(text: &str) -> Result<Vec<(String, SecretString)>, String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut pairs = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let number = index + 1;
        let line = lines[index].trim_start();
        index += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((name, value)) = line.split_once('=') else {
            // Not a binding (Node's `NAME: value`, say): harmless unless it
            // could open a quoted value in some dialect.
            if line.contains(['"', '\'', '`']) {
                return Err(format!(
                    "line {number}: a line that is not NAME=value holds a quote"
                ));
            }
            continue;
        };
        let name = name.trim();
        let value = value.trim_start();
        let parsed = match value.chars().next() {
            Some(quote @ ('"' | '\'' | '`')) => {
                // The quoted text, over as many lines as it takes.
                let mut rest = value[1..].to_string();
                let (content, after) = loop {
                    if let Some(end) = closing(&rest, quote) {
                        let after = rest[end + 1..].to_string();
                        rest.truncate(end);
                        break (rest, after);
                    }
                    let Some(next) = lines.get(index) else {
                        return Err(format!("line {number}: a quoted value is not closed"));
                    };
                    index += 1;
                    rest.push('\n');
                    rest.push_str(next);
                };
                let after = after.trim();
                if !(after.is_empty() || after.starts_with('#')) {
                    return Err(format!(
                        "line {number}: text after the end of a quoted value"
                    ));
                }
                unescape(&content, quote)
            }
            _ => {
                // An unquoted value ends at a comment.
                let end = value
                    .char_indices()
                    .find(|&(at, c)| c == '#' && value[..at].ends_with([' ', '\t']))
                    .map_or(value.len(), |(at, _)| at);
                value[..end].trim_end().to_string()
            }
        };
        if is_valid_env_name(name) && !parsed.is_empty() {
            pairs.push((name.to_string(), SecretString::new(parsed)));
        }
    }
    Ok(pairs)
}

/// The position of the first `quote` in `text` without a backslash before
/// it — what closes a quoted value for python-dotenv and Node's dotenv.
fn closing(text: &str, quote: char) -> Option<usize> {
    let mut previous = None;
    for (at, c) in text.char_indices() {
        if c == quote && previous != Some('\\') {
            return Some(at);
        }
        previous = Some(c);
    }
    None
}

/// The escapes python-dotenv decodes in a quoted value.
fn unescape(content: &str, quote: char) -> String {
    if quote == '`' {
        return content.to_string();
    }
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let decoded = match (quote, chars.peek().copied()) {
            (_, Some('\\')) => Some('\\'),
            (_, Some('\'')) => Some('\''),
            ('"', Some('"')) => Some('"'),
            ('"', Some('n')) => Some('\n'),
            ('"', Some('r')) => Some('\r'),
            ('"', Some('t')) => Some('\t'),
            ('"', Some('a')) => Some('\u{7}'),
            ('"', Some('b')) => Some('\u{8}'),
            ('"', Some('f')) => Some('\u{c}'),
            ('"', Some('v')) => Some('\u{b}'),
            _ => None,
        };
        match decoded {
            Some(d) => {
                chars.next();
                out.push(d);
            }
            None => out.push(c),
        }
    }
    out
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
        assert!(batch_sizes(&[], None).is_empty());
        for (dotenv, item) in [
            (Some("/home/me/project/.env"), None),
            (None, Some("segredo: FAKE [aplicacao=segredo, nome=FAKE]")),
            (None, Some("FAKE")),
        ] {
            let entries: Vec<Planned> = (0..60)
                .map(|i| planned(format!("FAKE_VARIABLE_WITH_A_LONGER_NAME_{i:03}"), item))
                .collect();
            let sizes = batch_sizes(&entries, dotenv);
            assert_eq!(sizes.iter().sum::<usize>(), 60);
            assert!(sizes.len() > 1, "{sizes:?}");
            let mut at = 0;
            for (i, size) in sizes.iter().enumerate() {
                let batch: Vec<&Planned> = entries[at..at + size].iter().collect();
                assert!(fits(&batch, dotenv), "{dotenv:?} {item:?} batch {i}");
                // As large as allowed: one more would not fit.
                if let Some(next) = entries.get(at + size) {
                    let mut more = batch.clone();
                    more.push(next);
                    assert!(!fits(&more, dotenv), "{dotenv:?} {item:?} batch {i}");
                }
                at += size;
            }
        }
        // An entry too long for any dialog goes alone.
        let long = vec![planned("X".repeat(100), Some(&"Y".repeat(5000)))];
        assert_eq!(batch_sizes(&long, None), [1]);
    }

    fn names(text: &str) -> Vec<String> {
        parse_dotenv(text)
            .expect("parse")
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    }

    #[test]
    fn a_value_over_several_lines_is_one_value_and_never_names() {
        let text = "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\n\
                    FAKE_PRIVATE_KEY_MATERIAL==\n\
                    OTHER=looks-like-a-line\n\
                    -----END PRIVATE KEY-----\" # a comment\n\
                    NORMAL=x\n";
        let pairs = parse_dotenv(text).expect("parse");
        assert_eq!(names(text), ["PRIVATE_KEY", "NORMAL"]);
        assert_eq!(
            pairs[0].1.as_str(),
            "-----BEGIN PRIVATE KEY-----\nFAKE_PRIVATE_KEY_MATERIAL==\n\
             OTHER=looks-like-a-line\n-----END PRIVATE KEY-----"
        );
    }

    #[test]
    fn a_quote_with_a_backslash_before_it_does_not_close() {
        // As python-dotenv and Node's dotenv read it: the value goes on.
        for quote in ['\'', '"', '`'] {
            let text = format!(
                "KEY={quote}start\\{quote}\nFAKE_PRIVATE_MATERIAL==\nend{quote}\nNORMAL=x\n"
            );
            assert_eq!(names(&text), ["KEY", "NORMAL"], "{quote}");
        }
        // Two backslashes before the quote: still not a close.
        assert_eq!(names("K='a\\\\'\nX=1\nb'\n"), ["K"]);
        // Values of other forms: comments, escapes, back quotes, export.
        let text = "A=\"x\" # c\nB='y z'\nC=\"say \\\"hi\\\"\\n\"\n\
                    D='it\\'s'\nE=`raw \\n`\nexport F = plain # note\nG=a#b\n";
        let values: Vec<String> = parse_dotenv(text)
            .expect("parse")
            .into_iter()
            .map(|(_, v)| v.to_string())
            .collect();
        assert_eq!(
            values,
            [
                "x",
                "y z",
                "say \"hi\"\n",
                "it's",
                "raw \\n",
                "plain",
                "a#b"
            ]
        );
    }

    #[test]
    fn what_could_hide_a_value_refuses_the_file_without_showing_it() {
        for (text, error) in [
            (
                "OK=1\nKEY=\"FAKE_SECRET_START\nFAKE_NAME_LOOKING=part\n",
                "line 2: a quoted value is not closed",
            ),
            (
                "K=\"FAKE_A\nFAKE_B\" trailing\n",
                "line 1: text after the end of a quoted value",
            ),
            // Node's `NAME: value` form, opening a quote.
            (
                "KEY: \"FAKE_START\nFAKE_LOOKS=like a name\n\"\n",
                "line 1: a line that is not NAME=value holds a quote",
            ),
            // A quote closed only by a backslash-quote, which the dialects
            // read either way.
            (
                "K='FAKE_A\\'\nFAKE_B=x\n",
                "line 1: a quoted value is not closed",
            ),
        ] {
            assert_eq!(parse_dotenv(text).expect_err("refused"), error, "{text:?}");
        }
        // A value whose name is not allowed is still read as a whole.
        assert_eq!(names("my-key=\"FAKE\nHIDDEN=x\n\"\nOK=1\n"), ["OK"]);
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
