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

/// Device and inode of the file at `path` (symlinks followed), which identify
/// a file independently of its name.
pub fn file_identity(path: &Path) -> io::Result<(u64, u64)> {
    let meta = std::fs::metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

/// Whether `path` no longer names the file whose identity is `running`:
/// `Some(true)` if it names another file or nothing, `Some(false)` if it still
/// names that file, and `None` if that cannot be told — the identity is
/// unknown, or the path cannot be examined (no permission, an I/O error).
pub fn replaced(path: &Path, running: Option<(u64, u64)>) -> Option<bool> {
    let running = running?;
    match file_identity(path) {
        Ok(now) => Some(now != running),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Some(true)
        }
        Err(_) => None,
    }
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

/// How many combining marks in a row are shown as they are; more are escaped.
/// Two cover real text (Vietnamese stacks two); more only pile up into marks
/// that cover the lines above and below.
const MAX_COMBINING_MARKS: usize = 2;

/// Make text safe to show in a dialog: every character that would not appear
/// as itself becomes a visible `\u{…}` escape, so that a requester cannot
/// forge extra lines, reorder, hide or blur what the human reads. That is
/// control characters (including newlines), line and paragraph separators,
/// bidirectional controls, invisible characters, spaces other than the plain
/// space, and combining marks stacked more than two deep.
pub fn visible(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut marks = 0;
    for c in text.chars() {
        marks = if is_combining_mark(c) { marks + 1 } else { 0 };
        if c.is_control() || is_invisible_or_layout(c) || marks > MAX_COMBINING_MARKS {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// Characters that are not shown as themselves: Unicode's
/// Default_Ignorable_Code_Point set (zero-width characters, bidirectional
/// controls, variation selectors, tags, fillers), the other format (Cf)
/// characters, the line and paragraph separators, and spaces that look like
/// a plain space but are not one.
fn is_invisible_or_layout(c: char) -> bool {
    matches!(c,
        // Default_Ignorable_Code_Point (Unicode 15).
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}'..='\u{1160}'
        | '\u{17B4}'..='\u{17B5}' | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{3164}'
        // Not Default_Ignorable, but drawn as nothing at all.
        | '\u{2800}'
        | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}' | '\u{FFF0}'..='\u{FFF8}'
        | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}'
        // Other format characters.
        | '\u{0600}'..='\u{0605}' | '\u{06DD}' | '\u{070F}' | '\u{0890}'..='\u{0891}'
        | '\u{08E2}' | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}'
        | '\u{13430}'..='\u{1343F}'
        // Line and paragraph separators: real line breaks for the renderer.
        | '\u{2028}' | '\u{2029}'
        // Spaces other than U+0020.
        | '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}'
        | '\u{3000}'
    )
}

/// Combining marks of the blocks where they are commonly stacked.
fn is_combining_mark(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036F}' | '\u{0483}'..='\u{0489}' | '\u{0591}'..='\u{05BD}'
        | '\u{05BF}' | '\u{05C1}'..='\u{05C2}' | '\u{05C4}'..='\u{05C5}' | '\u{05C7}'
        | '\u{0610}'..='\u{061A}' | '\u{064B}'..='\u{065F}' | '\u{0670}'
        | '\u{06D6}'..='\u{06DC}' | '\u{06DF}'..='\u{06E4}' | '\u{06E7}'..='\u{06E8}'
        | '\u{06EA}'..='\u{06ED}' | '\u{1AB0}'..='\u{1AFF}' | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20FF}' | '\u{FE20}'..='\u{FE2F}'
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
    fn replaced_files_are_told_apart_by_identity_not_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A name that happens to end like the kernel's marker is not a sign.
        let path = dir.path().join("agent (deleted)");
        std::fs::write(&path, b"one").expect("write");
        let running = file_identity(&path).ok();
        assert_eq!(replaced(&path, running), Some(false));
        // Replaced by another file under the same name.
        let new = dir.path().join("new");
        std::fs::write(&new, b"two").expect("write");
        std::fs::rename(&new, &path).expect("rename");
        assert_eq!(replaced(&path, running), Some(true));
        // Removed.
        std::fs::remove_file(&path).expect("remove");
        assert_eq!(replaced(&path, running), Some(true));
        // Unknown identity: no claim.
        assert_eq!(replaced(&path, None), None);
    }

    #[test]
    fn a_path_that_cannot_be_examined_is_not_called_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let closed = dir.path().join("closed");
        std::fs::create_dir(&closed).expect("mkdir");
        let path = closed.join("agent");
        std::fs::write(&path, b"one").expect("write");
        let running = file_identity(&path).ok();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let examinable = std::fs::metadata(&path).is_ok(); // root ignores the mode
        let verdict = replaced(&path, running);
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        if !examinable {
            assert_eq!(verdict, None, "no permission is not a replacement");
        }
    }

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
    fn visible_escapes_what_would_not_show_as_itself() {
        // Line and paragraph separators would be real line breaks.
        assert_eq!(visible("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c");
        // Invisible characters: variation selector, tag, soft hyphen, filler.
        assert_eq!(
            visible("a\u{FE0F}b\u{E0041}c\u{AD}d\u{3164}e"),
            "a\\u{fe0f}b\\u{e0041}c\\u{ad}d\\u{3164}e"
        );
        // Spaces that look like a plain one.
        assert_eq!(
            visible("a\u{A0}b\u{2002}c\u{3000}d"),
            "a\\u{a0}b\\u{2002}c\\u{3000}d"
        );
        assert_eq!(visible("a b"), "a b");
        assert_eq!(visible("a\u{2800}b"), "a\\u{2800}b");
        // Up to two combining marks stay (Vietnamese "ệ"); a pile does not.
        assert_eq!(visible("e\u{323}\u{302}"), "e\u{323}\u{302}");
        assert_eq!(
            visible("e\u{301}\u{301}\u{301}\u{301}x\u{301}"),
            "e\u{301}\u{301}\\u{301}\\u{301}x\u{301}"
        );
    }

    #[test]
    fn truncation() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
    }
}
