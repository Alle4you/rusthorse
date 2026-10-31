//! Small helpers shared by the CLI and the agent.

use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use nix::unistd::getuid;

/// Create `path` (and missing parents) with mode `0700`, and make sure it is
/// owned by the current user and not accessible to anyone else.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    if meta.uid() != getuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not owned by the current user", path.display()),
        ));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Whether `name` is a portable environment variable name (`[A-Za-z_][A-Za-z0-9_]*`).
pub fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse a human duration such as `90s`, `15m`, `2h` or `0` (meaning "never").
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    if text == "0" {
        return Ok(Duration::ZERO);
    }
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("{text:?}: missing unit (use s, m or h, e.g. 15m)"))?;
    let (number, unit) = text.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("{text:?}: expected a number followed by s, m or h"))?;
    let seconds = match unit {
        "s" => number,
        "m" => number.saturating_mul(60),
        "h" => number.saturating_mul(3600),
        _ => return Err(format!("{text:?}: unknown unit {unit:?} (use s, m or h)")),
    };
    Ok(Duration::from_secs(seconds))
}

/// Format a duration compactly (`45s`, `15m`, `1h30m`).
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    match (secs / 3600, (secs % 3600) / 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, 0) => format!("{m}m"),
        (0, m, s) => format!("{m}m{s}s"),
        (h, 0, _) => format!("{h}h"),
        (h, m, _) => format!("{h}h{m}m"),
    }
}

/// Quote a single argument for display in a POSIX shell.
pub fn shell_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

/// Quote a command line for display.
pub fn shell_join<S: AsRef<str>>(argv: &[S]) -> String {
    argv.iter()
        .map(|a| shell_quote(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Make text safe to show in a dialog: control characters (including newlines
/// and Unicode bidirectional overrides) become visible escapes so that a
/// requester cannot forge extra lines or reorder what the human reads.
pub fn visible(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || is_format_char(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// Unicode "format" characters that change how text is displayed without being
/// visible themselves (bidi overrides and isolates, zero-width characters).
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{FEFF}'
    )
}

/// Shorten `text` to at most `max` characters, marking the cut.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_names() {
        assert!(is_valid_env_name("OPENAI_API_KEY"));
        assert!(is_valid_env_name("_x1"));
        assert!(!is_valid_env_name("1X"));
        assert!(!is_valid_env_name("A-B"));
        assert!(!is_valid_env_name(""));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
        assert!(parse_duration("15").is_err());
        assert!(parse_duration("m").is_err());
        assert!(parse_duration("5d").is_err());
        assert_eq!(format_duration(Duration::from_secs(5400)), "1h30m");
        assert_eq!(format_duration(Duration::from_secs(600)), "10m");
    }

    #[test]
    fn quoting() {
        assert_eq!(
            shell_join(&["echo", "a b", "it's"]),
            r"echo 'a b' 'it'\''s'"
        );
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("--flag=x/y"), "--flag=x/y");
    }

    #[test]
    fn visible_escapes_control_and_bidi() {
        assert_eq!(visible("a\nb"), "a\\u{a}b");
        assert_eq!(visible("x\u{202E}y"), "x\\u{202e}y");
        assert_eq!(visible("plain ção"), "plain ção");
    }

    #[test]
    fn truncation() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
    }
}
