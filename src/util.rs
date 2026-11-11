//! Small helpers shared by the CLI and the agent.

use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::unistd::getuid;

/// Create `path` (and missing parents) with mode `0700`, and make sure it is
/// owned by the current user and not accessible to anyone else.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    make_private_dir(path, &mut Vec::new())
}

/// [`ensure_private_dir`], which also adds to `made` the directories that
/// were missing, parents first, each as soon as it is made — so that a
/// failure further on loses none. Each was made then, by this call or by
/// another program meanwhile, and its name is in its parent, which must be
/// synced for that name to survive a crash.
pub fn make_private_dir(path: &Path, made: &mut Vec<PathBuf>) -> io::Result<()> {
    make_dirs(path, made)?;
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

/// Sync the directory that holds each directory in `made` (as
/// [`make_private_dir`] and [`make_dirs`] list them), so that their names
/// survive a crash: a file synced into a directory just made is lost with
/// that directory's name. As for the vault's saves, any error is a failure.
/// Each is opened as a directory only: what another program may have put
/// in its place, a FIFO above all, fails at once instead of being opened.
pub fn sync_parents(made: &[PathBuf]) -> io::Result<()> {
    for dir in made {
        let parent = dir
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY)
            .open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("cannot sync the directory {}: {e}", parent.display()),
                )
            })?;
    }
    Ok(())
}

/// Create `path` and its missing parents with mode `0700`, as
/// `DirBuilder::recursive` does, adding to `made` each one that was missing,
/// parents first, each as soon as it is made. Existing directories are left
/// as they are.
pub fn make_dirs(path: &Path, made: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {
            made.push(path.to_path_buf());
            return Ok(());
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) if path.is_dir() => return Ok(()),
        Err(e) => return Err(e),
    }
    match path.parent() {
        Some(parent) => make_dirs(parent, made)?,
        None => {
            return Err(io::Error::other(format!(
                "cannot create {}",
                path.display()
            )));
        }
    }
    match builder.create(path) {
        Ok(()) => {}
        // Missing a moment ago: another program made it meanwhile.
        Err(_) if path.is_dir() => {}
        Err(e) => return Err(e),
    }
    made.push(path.to_path_buf());
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

    /// What [`make_private_dir`] says it made, and whether it succeeded.
    fn made(path: &Path) -> (Vec<PathBuf>, bool) {
        let mut made = Vec::new();
        let done = make_private_dir(path, &mut made).is_ok();
        (made, done)
    }

    #[test]
    fn a_private_directory_says_which_directories_it_made() {
        let dir = tempfile::tempdir().expect("tempdir");
        let deep = dir.path().join("a").join("b").join("c");
        let (list, done) = made(&deep);
        assert!(done);
        assert_eq!(
            list,
            [
                dir.path().join("a"),
                dir.path().join("a/b"),
                dir.path().join("a/b/c"),
            ]
        );
        for path in &list {
            let mode = std::fs::metadata(path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", path.display());
        }
        // Once there, none is made again; one missing below them is.
        assert_eq!(made(&deep), (vec![], true));
        let below = deep.join("d");
        assert_eq!(made(&below), (vec![below], true));
        // A file in the way is not a directory.
        let file = dir.path().join("file");
        std::fs::write(&file, b"").expect("write");
        assert_eq!(made(&file.join("x")), (vec![], false));
        assert_eq!(made(&file), (vec![], false));
    }

    #[test]
    fn the_directories_made_before_a_failure_are_still_listed() {
        let dir = tempfile::tempdir().expect("tempdir");
        // `a` is made, then a name too long for any directory is refused.
        let long = "x".repeat(256);
        let (list, done) = made(&dir.path().join("a").join(&long));
        assert!(!done);
        assert_eq!(list, [dir.path().join("a")]);
    }

    #[test]
    fn the_directory_holding_each_one_made_is_synced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (list, done) = made(&dir.path().join("a").join("b"));
        assert!(done);
        sync_parents(&list).expect("sync");
        // A relative name is in the current directory.
        sync_parents(&[PathBuf::from("relative")]).expect("sync .");
        // One that cannot be opened is an error that names it.
        let gone = dir.path().join("gone");
        let why = sync_parents(&[gone.join("x")]).expect_err("missing");
        assert_eq!(why.kind(), io::ErrorKind::NotFound);
        assert!(
            why.to_string()
                .contains(&format!("cannot sync the directory {}", gone.display())),
            "{why}"
        );
        // Each one: a failure after one that succeeds is still a failure.
        sync_parents(&[list[0].clone(), gone.join("x")]).expect_err("the second");
        // What another program put in a parent's place is not opened: a
        // FIFO, which would wait for a writer, fails at once.
        let fifo = dir.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
        let (tx, rx) = std::sync::mpsc::channel();
        let made = fifo.join("x");
        std::thread::spawn(move || {
            let _ = tx.send(sync_parents(&[made]).map_err(|e| e.kind()));
        });
        let synced = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO waited for a writer");
        assert_eq!(synced, Err(io::ErrorKind::NotADirectory));
    }

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
