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

/// Parse a `.env` file: `NAME=value` lines, optional `export ` prefix,
/// `#` comments, and matching single or double quotes around the value.
/// Lines with invalid names or empty values are skipped.
pub fn parse_dotenv(text: &str) -> Vec<(String, SecretString)> {
    let mut pairs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let mut value = value.trim();
        if value.len() >= 2 {
            let bytes = value.as_bytes();
            let (first, last) = (bytes[0], bytes[value.len() - 1]);
            if first == last && (first == b'"' || first == b'\'') {
                value = &value[1..value.len() - 1];
            }
        }
        if is_valid_env_name(name) && !value.is_empty() {
            pairs.push((name.to_string(), SecretString::new(value.to_string())));
        }
    }
    pairs
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
