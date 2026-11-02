//! Parsing `.env` files for imports. The agent reads the files itself
//! ([`Request::ImportFrom`](crate::protocol::Request::ImportFrom)); GNOME
//! Keyring is read by [`keyring`](crate::keyring).

use crate::protocol::SecretString;
use crate::util::is_valid_env_name;

/// Most entries sent to the agent in one batch (each batch is one approval).
pub const BATCH: usize = 50;
/// Most lines the entry names of one batch may take in the approval dialog,
/// counting each name as if it started a line, so that the dialog lists all
/// of them and still fits on the screen (see `ui::approval_height`).
pub const BATCH_LINES: usize = 24;

/// How many of `names`, in order, go into each batch of an import: at most
/// [`BATCH`] names, and at most [`BATCH_LINES`] lines of them in the dialog.
pub fn batch_sizes<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<usize> {
    let mut sizes: Vec<usize> = Vec::new();
    let mut lines = 0;
    for name in names {
        let cost = crate::ui::mono_lines(&format!("{name}, "));
        match sizes.last_mut() {
            Some(size) if *size < BATCH && lines + cost <= BATCH_LINES => {
                lines += cost;
                *size += 1;
            }
            _ => {
                lines = cost;
                sizes.push(1);
            }
        }
    }
    sizes
}

/// Parse a `.env` file: `NAME=value` lines, optional `export ` prefix, `#`
/// comments, and single or double quotes around the value. A quoted value
/// may go on over several lines (a PEM key, say), up to its closing quote;
/// after a closing quote, only a `#` comment may follow. Lines with invalid
/// names or empty values are skipped.
///
/// A quote that is never closed refuses the whole file: going on line by
/// line would read the rest of the value as more `NAME=value` lines, and
/// return pieces of it as names. The error names the line, never its text.
pub fn parse_dotenv(text: &str) -> Result<Vec<(String, SecretString)>, String> {
    let mut pairs = Vec::new();
    let mut lines = text.lines().enumerate();
    while let Some((index, line)) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        let quote = value.chars().next().filter(|c| *c == '"' || *c == '\'');
        let value = match quote {
            None => value.to_string(),
            Some(quote) => {
                let inner = &value[1..];
                match closing(inner, quote) {
                    Some(end) if after_value(&inner[end + 1..]) => inner[..end].to_string(),
                    // Something other than a comment after the closing quote:
                    // the value is the text as written.
                    Some(_) => value.to_string(),
                    None => {
                        let mut joined = inner.to_string();
                        loop {
                            let Some((_, next)) = lines.next() else {
                                return Err(format!(
                                    "line {}: a quoted value is not closed",
                                    index + 1
                                ));
                            };
                            joined.push('\n');
                            match closing(next, quote) {
                                Some(end) if after_value(&next[end + 1..]) => {
                                    joined.push_str(&next[..end]);
                                    break;
                                }
                                Some(_) => {
                                    return Err(format!(
                                        "line {}: text after the end of a quoted value",
                                        index + 1
                                    ));
                                }
                                None => joined.push_str(next),
                            }
                        }
                        joined
                    }
                }
            }
        };
        if is_valid_env_name(name) && !value.is_empty() {
            pairs.push((name.to_string(), SecretString::new(value)));
        }
    }
    Ok(pairs)
}

/// The position of the first `quote` in `text` that is not escaped with a
/// backslash (only `"` can be escaped).
fn closing(text: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        match c {
            '\\' if quote == '"' && !escaped => escaped = true,
            c if c == quote && !escaped => return Some(at),
            _ => escaped = false,
        }
    }
    None
}

/// What may follow a closing quote: nothing, or a comment.
fn after_value(rest: &str) -> bool {
    let rest = rest.trim();
    rest.is_empty() || rest.starts_with('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches_hold_at_most_twenty_four_lines_of_names() {
        assert!(batch_sizes([]).is_empty());
        // Each name counts as a line of its own.
        let short: Vec<String> = (0..60).map(|i| format!("K{i}")).collect();
        assert_eq!(batch_sizes(short.iter().map(String::as_str)), [24, 24, 12]);
        let long: Vec<String> = (0..30)
            .map(|i| format!("{}{i:03}", "X".repeat(70)))
            .collect();
        let sizes = batch_sizes(long.iter().map(String::as_str));
        assert_eq!(sizes.iter().sum::<usize>(), 30);
        assert!(sizes.len() > 1, "{sizes:?}");
    }

    #[test]
    fn a_value_over_several_lines_is_one_value_and_never_names() {
        let text = "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\n\
                    FAKE_PRIVATE_KEY_MATERIAL==\n\
                    OTHER=looks-like-a-line\n\
                    -----END PRIVATE KEY-----\" # a comment\n\
                    NORMAL=x\n";
        let pairs = parse_dotenv(text).expect("parse");
        let names: Vec<&str> = pairs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["PRIVATE_KEY", "NORMAL"]);
        assert_eq!(
            pairs[0].1.as_str(),
            "-----BEGIN PRIVATE KEY-----\nFAKE_PRIVATE_KEY_MATERIAL==\n\
             OTHER=looks-like-a-line\n-----END PRIVATE KEY-----"
        );
        // Single-line forms, comments after the value, escaped quotes.
        let pairs = parse_dotenv("A=\"x\" # c\nB='y z'\nC=\"say \\\"hi\\\"\"\n").expect("parse");
        let values: Vec<String> = pairs.iter().map(|(_, v)| v.to_string()).collect();
        assert_eq!(values, ["x", "y z", "say \\\"hi\\\""]);
    }

    #[test]
    fn an_unclosed_quote_refuses_the_file_without_showing_it() {
        let text = "OK=1\nKEY=\"FAKE_SECRET_START\nFAKE_NAME_LOOKING=part\n";
        let error = parse_dotenv(text).expect_err("refused");
        assert_eq!(error, "line 2: a quoted value is not closed");
        let error = parse_dotenv("K=\"FAKE_A\nFAKE_B\" trailing\n").expect_err("refused");
        assert_eq!(error, "line 1: text after the end of a quoted value");
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
