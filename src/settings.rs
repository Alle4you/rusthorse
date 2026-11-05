//! The agent's settings ([ADR 0007, section 3](https://github.com/Alle4you/rusthorse/blob/main/docs/adr/0007-visual-manager.md#3-persistent-agent-configuration-m2)):
//! five options the human administers — the idle lock, remembered
//! approvals, the dialog timeout, and locking on suspend and on screen lock —
//! their bounds, the file that keeps them (`agent.toml`), and where each
//! value in effect comes from.
//!
//! Precedence: the default, then the file, then an explicit flag of
//! `rusthorse agent`. The agent reads the file when it starts, and rewrites
//! it when the human approves a change (`configure`). Any program of the
//! user can edit the file too (threat model L1): what guards a change made
//! through the protocol is the agent's dialog, not the file's mode.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::util::parse_duration;

/// The longest the vault may stay unlocked without use, when it locks by
/// itself.
pub const MAX_IDLE: Duration = Duration::from_secs(24 * 3600);
/// The longest an approval may be remembered.
pub const MAX_REMEMBER: Duration = Duration::from_secs(8 * 3600);
/// The shortest time a dialog waits for an answer.
pub const MIN_DIALOG: Duration = Duration::from_secs(15);
/// The longest time a dialog waits for an answer. One dialog ends well
/// before the manager stops waiting for the agent (ten minutes); a request
/// that waits behind other dialogs, or asks for the master password first,
/// can still take longer.
pub const MAX_DIALOG: Duration = Duration::from_secs(5 * 60);
/// The largest settings file the agent reads.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// A setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    /// Lock the vault after this much time without use; zero never does.
    IdleTimeout,
    /// How long "Allow for …" lasts in `run` dialogs; zero does not offer it.
    Remember,
    /// How long a dialog waits for an answer.
    DialogTimeout,
    /// Lock when the computer is about to sleep.
    LockOnSuspend,
    /// Lock when the session is locked or its screensaver starts.
    LockOnScreenLock,
}

impl Key {
    /// Every setting, in the order shown.
    pub const ALL: [Key; 5] = [
        Key::IdleTimeout,
        Key::Remember,
        Key::DialogTimeout,
        Key::LockOnSuspend,
        Key::LockOnScreenLock,
    ];

    /// Its name in the file, and in the audit log.
    pub fn name(self) -> &'static str {
        match self {
            Key::IdleTimeout => "idle_timeout",
            Key::Remember => "remember",
            Key::DialogTimeout => "dialog_timeout",
            Key::LockOnSuspend => "lock_on_suspend",
            Key::LockOnScreenLock => "lock_on_screen_lock",
        }
    }

    /// The flag of `rusthorse agent` that sets it.
    pub fn flag(self) -> &'static str {
        match self {
            Key::IdleTimeout => "--idle-timeout",
            Key::Remember => "--remember",
            Key::DialogTimeout => "--dialog-timeout",
            Key::LockOnSuspend => "--no-lock-on-suspend",
            Key::LockOnScreenLock => "--no-lock-on-screen-lock",
        }
    }

    /// Its name for people, as the agent's dialog shows it.
    pub fn label(self) -> &'static str {
        match self {
            Key::IdleTimeout => "Lock after inactivity",
            Key::Remember => "Remembered approvals",
            Key::DialogTimeout => "Dialog timeout",
            Key::LockOnSuspend => "Lock on suspend",
            Key::LockOnScreenLock => "Lock on screen lock",
        }
    }

    /// The values it takes.
    pub fn allowed(self) -> &'static str {
        match self {
            Key::IdleTimeout => "0 (never), or 1s to 24h",
            Key::Remember => "0 (off), or 1s to 8h",
            Key::DialogTimeout => "15s to 5m",
            Key::LockOnSuspend | Key::LockOnScreenLock => "true or false",
        }
    }

    /// Whether its value is a duration (else on or off).
    pub fn is_duration(self) -> bool {
        matches!(self, Key::IdleTimeout | Key::Remember | Key::DialogTimeout)
    }
}

/// A setting's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// For [`Key::IdleTimeout`], [`Key::Remember`], [`Key::DialogTimeout`].
    Duration(Duration),
    /// For [`Key::LockOnSuspend`], [`Key::LockOnScreenLock`].
    Switch(bool),
}

/// A duration as the file, the flags and the audit log write it: `0`, or a
/// whole number of hours, minutes or seconds (`8h`, `90m`, `45s`) — what
/// [`parse_duration`] reads back.
pub fn duration_text(duration: Duration) -> String {
    match duration.as_secs() {
        0 => "0".into(),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// A duration for people, every part of it: `45s`, `15m`, `1h30m`, `1h59s`
/// — never rounded, so that a dialog shows exactly what is approved.
pub fn exact_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let mut text = String::new();
    for (count, unit) in [(h, "h"), (m, "m"), (s, "s")] {
        if count > 0 {
            text.push_str(&format!("{count}{unit}"));
        }
    }
    if text.is_empty() {
        text.push_str("0s");
    }
    text
}

impl Value {
    /// As the file and the audit log write it.
    pub fn text(self) -> String {
        match self {
            Value::Duration(d) => duration_text(d),
            Value::Switch(on) => on.to_string(),
        }
    }

    /// As people read it, for `key`: `15m`, `never`, `off`, `on`.
    pub fn describe(self, key: Key) -> String {
        match self {
            Value::Duration(d) if d.is_zero() && key == Key::IdleTimeout => "never".into(),
            Value::Duration(d) if d.is_zero() => "off".into(),
            Value::Duration(d) => exact_duration(d),
            Value::Switch(true) => "on".into(),
            Value::Switch(false) => "off".into(),
        }
    }
}

/// Whether `value` is allowed for `key`: of its kind, and within its bounds.
pub fn check(key: Key, value: Value) -> Result<(), String> {
    let within = match (key, value) {
        (Key::IdleTimeout, Value::Duration(d)) => {
            d.is_zero() || (d >= Duration::from_secs(1) && d <= MAX_IDLE)
        }
        (Key::Remember, Value::Duration(d)) => {
            d.is_zero() || (d >= Duration::from_secs(1) && d <= MAX_REMEMBER)
        }
        (Key::DialogTimeout, Value::Duration(d)) => d >= MIN_DIALOG && d <= MAX_DIALOG,
        (Key::LockOnSuspend | Key::LockOnScreenLock, Value::Switch(_)) => true,
        _ => false,
    };
    if within {
        Ok(())
    } else {
        Err(format!(
            "{} cannot be {} (allowed: {})",
            key.name(),
            value.text(),
            key.allowed()
        ))
    }
}

/// What the dialog says when changing `key` from `old` to `new` protects
/// less, or `None` when it does not: remembering turned on or longer, the
/// idle lock longer or off, a lock on suspend or screen lock turned off, a
/// longer dialog timeout.
pub fn weakens(key: Key, old: Value, new: Value) -> Option<&'static str> {
    use Value::{Duration as D, Switch as S};
    match (key, old, new) {
        (Key::IdleTimeout, D(o), D(n)) if n.is_zero() && !o.is_zero() => {
            Some("The vault will no longer lock by itself when it is not used.")
        }
        (Key::IdleTimeout, D(o), D(n)) if !o.is_zero() && n > o => {
            Some("The vault will stay unlocked longer without use.")
        }
        (Key::Remember, D(o), D(n)) if o.is_zero() && !n.is_zero() => Some(
            "Run dialogs will offer “Allow for …”, which lets identical requests run without \
             asking for that long.",
        ),
        (Key::Remember, D(o), D(n)) if n > o => Some("Approvals you remember will last longer."),
        (Key::DialogTimeout, D(o), D(n)) if n > o => {
            Some("Dialogs will wait longer for an answer.")
        }
        (Key::LockOnSuspend, S(true), S(false)) => {
            Some("The vault will no longer lock when the computer suspends.")
        }
        (Key::LockOnScreenLock, S(true), S(false)) => {
            Some("The vault will no longer lock when the screen locks.")
        }
        _ => None,
    }
}

/// The five settings in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// See [`Key::IdleTimeout`].
    pub idle_timeout: Duration,
    /// See [`Key::Remember`].
    pub remember: Duration,
    /// See [`Key::DialogTimeout`].
    pub dialog_timeout: Duration,
    /// See [`Key::LockOnSuspend`].
    pub lock_on_suspend: bool,
    /// See [`Key::LockOnScreenLock`].
    pub lock_on_screen_lock: bool,
}

impl Default for Settings {
    /// The defaults: lock after 15 minutes without use, remember nothing,
    /// dialogs wait 2 minutes, lock on suspend and on screen lock.
    fn default() -> Self {
        Settings {
            idle_timeout: Duration::from_secs(15 * 60),
            remember: Duration::ZERO,
            dialog_timeout: Duration::from_secs(2 * 60),
            lock_on_suspend: true,
            lock_on_screen_lock: true,
        }
    }
}

impl Settings {
    /// The value of `key`.
    pub fn get(&self, key: Key) -> Value {
        match key {
            Key::IdleTimeout => Value::Duration(self.idle_timeout),
            Key::Remember => Value::Duration(self.remember),
            Key::DialogTimeout => Value::Duration(self.dialog_timeout),
            Key::LockOnSuspend => Value::Switch(self.lock_on_suspend),
            Key::LockOnScreenLock => Value::Switch(self.lock_on_screen_lock),
        }
    }

    /// These settings with `layer`'s values in place of theirs.
    pub fn with(mut self, layer: &Layer) -> Settings {
        for (key, value) in layer.iter() {
            match (key, value) {
                (Key::IdleTimeout, Value::Duration(d)) => self.idle_timeout = d,
                (Key::Remember, Value::Duration(d)) => self.remember = d,
                (Key::DialogTimeout, Value::Duration(d)) => self.dialog_timeout = d,
                (Key::LockOnSuspend, Value::Switch(on)) => self.lock_on_suspend = on,
                (Key::LockOnScreenLock, Value::Switch(on)) => self.lock_on_screen_lock = on,
                // A layer holds only checked values (`Layer::set`).
                _ => {}
            }
        }
        self
    }
}

/// Settings given in one place — the file, the flags, a change: each may be
/// absent. Every value in it is allowed ([`check`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer(BTreeMap<Key, Value>);

impl Layer {
    /// The value it gives `key`, if any.
    pub fn get(&self, key: Key) -> Option<Value> {
        self.0.get(&key).copied()
    }

    /// Give `key` this value, if it is allowed.
    pub fn set(&mut self, key: Key, value: Value) -> Result<(), String> {
        check(key, value)?;
        self.0.insert(key, value);
        Ok(())
    }

    /// Whether it gives no value.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Its values, in the order of [`Key::ALL`].
    pub fn iter(&self) -> impl Iterator<Item = (Key, Value)> + '_ {
        self.0.iter().map(|(k, v)| (*k, *v))
    }

    /// This layer with `other`'s values in place of its own.
    pub fn with(&self, other: &Layer) -> Layer {
        let mut merged = self.clone();
        merged.0.extend(other.iter());
        merged
    }
}

/// Where a setting in effect comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Neither the file nor a flag gives it.
    Default,
    /// The settings file.
    File,
    /// An explicit flag of `rusthorse agent`, which wins over the file.
    Flag,
}

/// The settings file, what it holds, and what explicit flags set: what the
/// settings in effect are made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sources {
    /// The settings file (absolute).
    pub path: PathBuf,
    /// What the file holds.
    pub file: Layer,
    /// What explicit flags set.
    pub flags: Layer,
}

impl Sources {
    /// The settings in effect: the defaults, then the file, then the flags.
    pub fn effective(&self) -> Settings {
        Settings::default().with(&self.file).with(&self.flags)
    }

    /// Where the value of `key` in effect comes from.
    pub fn source(&self, key: Key) -> Source {
        if self.flags.get(key).is_some() {
            Source::Flag
        } else if self.file.get(key).is_some() {
            Source::File
        } else {
            Source::Default
        }
    }
}

/// Check that nobody but the user and root can remove, rename or replace
/// what is at `path`. The path is walked as the system resolves it, one
/// name at a time, following each link: every directory it goes through
/// must belong to the user or to root and be writable by neither its group
/// nor others unless it has the sticky bit (as `/tmp`, where others cannot
/// remove what they do not own), and every link must belong to the user or
/// to root (in a sticky directory, its owner could replace it). Once a
/// walk has passed, nobody else can change a directory on the way, nor
/// put another in its place, nor change a link it followed.
///
/// What it does with a name that is missing, and with the last name,
/// depends on `how` ([`Walk`]). It returns, for [`Walk::Read`], the device
/// and inode of the file the path leads to, or `None` when it leads to
/// nothing.
fn check_directories(path: &Path, how: Walk) -> Result<Option<(u64, u64)>, String> {
    walk(path, nix::unistd::getuid().as_raw(), how)
}

/// What a walk of the settings path is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Walk {
    /// Reading the file: a missing name means there is no file; a link
    /// at the end is followed to the file.
    Read,
    /// Before making the missing directories: a missing name ends the walk
    /// (what is missing is made in a directory checked); a link at the end
    /// is not followed — the new file replaces it.
    BeforeCreate,
    /// Before writing: every directory must exist (one gone or not made
    /// fails the walk); the file may be missing; a link at the end is not
    /// followed.
    BeforeWrite,
}

/// [`check_directories`] for the user `me` (tests pretend to be another).
fn walk(path: &Path, me: u32, how: Walk) -> Result<Option<(u64, u64)>, String> {
    use std::ffi::OsString;
    use std::path::Component;
    let at = path.display();
    let owned = |uid: u32| uid == me || uid == 0;
    let check = |dir: &Path| -> Result<(), String> {
        let meta = std::fs::symlink_metadata(dir).map_err(|e| {
            format!(
                "cannot examine {} for the settings file {at}: {e}",
                dir.display()
            )
        })?;
        if !owned(meta.uid()) {
            return Err(format!(
                "the settings file {at} is under {}, which belongs to another user, who could \
                 remove or replace it; choose another file with --config",
                dir.display()
            ));
        }
        if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
            return Err(format!(
                "the settings file {at} is under {}, which its group or others can change: they \
                 could remove or replace the file; make it private (chmod go-w {}) or choose \
                 another file with --config",
                dir.display(),
                dir.display()
            ));
        }
        Ok(())
    };
    // Reading, a directory or link someone else could change matters only
    // if the path leads to a file: with none there, the defaults apply (a
    // save would have been refused there). The first such problem is kept
    // until then; otherwise it fails the walk at once.
    let mut problem: Option<String> = None;
    let mut guard = |result: Result<(), String>| -> Result<(), String> {
        match result {
            Err(e) if how == Walk::Read => {
                problem.get_or_insert(e);
                Ok(())
            }
            other => other,
        }
    };
    // The names still to walk, in order; `None` stands for `..`.
    fn names(path: &Path) -> Vec<Option<OsString>> {
        path.components()
            .filter_map(|c| match c {
                Component::Normal(name) => Some(Some(name.to_os_string())),
                Component::ParentDir => Some(None),
                _ => None,
            })
            .collect()
    }
    let absolute = std::path::absolute(path)
        .map_err(|e| format!("cannot resolve the settings file {at}: {e}"))?;
    let mut pending: std::collections::VecDeque<Option<OsString>> = names(&absolute).into();
    let mut dir = PathBuf::from("/");
    guard(check(&dir))?;
    let mut links = 0;
    while let Some(name) = pending.pop_front() {
        let Some(name) = name else {
            dir.pop();
            guard(check(&dir))?;
            continue;
        };
        let next = dir.join(&name);
        let meta = match std::fs::symlink_metadata(&next) {
            Ok(meta) => meta,
            // The file itself, not made yet.
            Err(e) if e.kind() == io::ErrorKind::NotFound && pending.is_empty() => return Ok(None),
            // A directory that does not exist (yet, or any more): no file
            // to read, or the rest to be made in `dir`, which is checked —
            // but before writing, every directory must be there.
            Err(e) if e.kind() == io::ErrorKind::NotFound && how != Walk::BeforeWrite => {
                return Ok(None);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(format!(
                    "the settings file {at} goes through {}, which does not exist",
                    next.display()
                ));
            }
            Err(e) => {
                return Err(format!(
                    "cannot examine {} for the settings file {at}: {e}",
                    next.display()
                ));
            }
        };
        if meta.file_type().is_symlink() {
            links += 1;
            if links > 40 {
                return Err(format!(
                    "the settings file {at} goes through too many links"
                ));
            }
            if !owned(meta.uid()) {
                guard(Err(format!(
                    "the settings file {at} goes through the link {}, which belongs to another \
                     user, who could change where it leads; choose another file with --config",
                    next.display()
                )))?;
            }
            if pending.is_empty() && how != Walk::Read {
                // The file's own name: the new file replaces the link.
                return Ok(None);
            }
            let target = std::fs::read_link(&next).map_err(|e| {
                format!(
                    "cannot read the link {} for the settings file {at}: {e}",
                    next.display()
                )
            })?;
            if target.is_absolute() {
                dir = PathBuf::from("/");
                guard(check(&dir))?;
            }
            for name in names(&target).into_iter().rev() {
                pending.push_front(name);
            }
            continue;
        }
        if pending.is_empty() {
            if how != Walk::Read && meta.is_dir() {
                return Err(format!("the settings file {at} is a directory"));
            }
            // The file itself: `load` checks the one it opens is this one,
            // and its owner and mode.
            return match problem {
                Some(problem) => Err(problem),
                None => Ok(Some((meta.dev(), meta.ino()))),
            };
        }
        if !meta.is_dir() {
            return Err(format!(
                "the settings file {at} goes through {}, which is not a directory",
                next.display()
            ));
        }
        dir = next;
        guard(check(&dir))?;
    }
    // The path leads to a directory (`/`, `child/..`, a link to `.`): not a
    // file — reading refuses it as such, a save cannot replace it.
    if how != Walk::Read {
        return Err(format!("the settings file {at} is a directory"));
    }
    if let Some(problem) = problem {
        return Err(problem);
    }
    let meta = std::fs::metadata(&dir)
        .map_err(|e| format!("cannot examine the settings file {at}: {e}"))?;
    Ok(Some((meta.dev(), meta.ino())))
}

/// Read the settings file at `path`. A missing file gives nothing — the
/// agent cannot tell a file never written from one removed, but it writes
/// the file only where nobody else can remove it ([`save`]). A file that is
/// not a regular file, not the user's, writable by its group or by others —
/// the agent cannot tell whether the group is the user's alone; a umask of
/// `002` makes new files group-writable, and the error says to `chmod 600` —
/// under a directory that others can change (`check_directories`), larger
/// than 64 KiB, not TOML, with an unknown key, a value of the wrong type or
/// out of bounds, is refused, saying why.
pub fn load(path: &Path) -> Result<Layer, String> {
    let at = path.display();
    // The path first; then the file it leads to must be the one opened.
    let Some(walked) = check_directories(path, Walk::Read)? else {
        return Ok(Layer::default());
    };
    #[cfg(test)]
    hook("load_before_open");
    let changed = || format!("the settings file {at} changed while it was read; start again");
    // Opening does not wait: a FIFO would block.
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(changed()),
        Err(e) => return Err(format!("cannot read the settings file {at}: {e}")),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot read the settings file {at}: {e}"))?;
    if (meta.dev(), meta.ino()) != walked {
        return Err(changed());
    }
    if !meta.is_file() {
        return Err(format!("the settings file {at} is not a regular file"));
    }
    if meta.uid() != nix::unistd::getuid().as_raw() {
        return Err(format!("the settings file {at} is not owned by you"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "the settings file {at} can be changed by its group or by others; make it private: \
             chmod 600 {at}"
        ));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!(
            "the settings file {at} is larger than {} KiB",
            MAX_FILE_BYTES / 1024
        ));
    }
    let mut text = String::new();
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read the settings file {at}: {e}"))?;
    parse(&text).map_err(|e| format!("the settings file {at}: {e}"))
}

/// Read the text of a settings file: TOML with the settings' names as keys,
/// each optional; durations as strings, as the flags take them (`"15m"`).
pub fn parse(text: &str) -> Result<Layer, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Raw {
        idle_timeout: Option<String>,
        remember: Option<String>,
        dialog_timeout: Option<String>,
        lock_on_suspend: Option<bool>,
        lock_on_screen_lock: Option<bool>,
    }
    let raw: Raw = toml::from_str(text).map_err(|e| e.message().to_string())?;
    let mut layer = Layer::default();
    for (key, text) in [
        (Key::IdleTimeout, raw.idle_timeout),
        (Key::Remember, raw.remember),
        (Key::DialogTimeout, raw.dialog_timeout),
    ] {
        if let Some(text) = text {
            let duration = parse_duration(&text)
                .map_err(|e| format!("{}: {e} (allowed: {})", key.name(), key.allowed()))?;
            layer.set(key, Value::Duration(duration))?;
        }
    }
    for (key, on) in [
        (Key::LockOnSuspend, raw.lock_on_suspend),
        (Key::LockOnScreenLock, raw.lock_on_screen_lock),
    ] {
        if let Some(on) = on {
            layer.set(key, Value::Switch(on))?;
        }
    }
    Ok(layer)
}

/// The text the agent writes for `layer`.
pub fn render(layer: &Layer) -> String {
    let mut text = String::from(
        "# Settings of the Rusthorse agent (docs/cli.md). The agent rewrites this\n\
         # file when you change a setting in the manager, without comments; edits\n\
         # by hand take effect when the agent starts again.\n",
    );
    for (key, value) in layer.iter() {
        match value {
            Value::Duration(d) => {
                text.push_str(&format!("{} = \"{}\"\n", key.name(), duration_text(d)));
            }
            Value::Switch(on) => text.push_str(&format!("{} = {on}\n", key.name())),
        }
    }
    text
}

/// For tests: what to do, once, at a point of [`save`].
#[cfg(test)]
type Hooks = Vec<(&'static str, Box<dyn FnOnce()>)>;

#[cfg(test)]
thread_local! {
    /// For tests: what to do, once, at a point of [`save`]
    /// (`before_create`, `after_create`, `after_check`), as another user
    /// could meanwhile.
    static HOOKS: std::cell::RefCell<Hooks> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Run the hook set for `point`, if any.
#[cfg(test)]
fn hook(point: &str) {
    let found = HOOKS.with(|hooks| {
        let mut hooks = hooks.borrow_mut();
        let at = hooks.iter().position(|(p, _)| *p == point)?;
        Some(hooks.remove(at).1)
    });
    if let Some(run) = found {
        run();
    }
}

/// A save of the settings file that failed.
#[derive(Debug)]
pub struct SaveError {
    /// Whether the new file had already replaced the old one: it then holds
    /// the new settings, which may not survive a crash.
    pub replaced: bool,
    /// What failed.
    pub error: io::Error,
}

/// Write `layer` to the settings file at `path`, so that the file holds
/// either the old settings or the new ones, never part of them: a private
/// temporary file in the same directory, written and synced, renamed over
/// `path` — a link there is replaced, not followed — and the directory
/// synced. Missing directories are created `0700`; existing ones are left
/// as they are, and must be such that nobody but the user and root can
/// remove or replace the file (`check_directories`): else nothing is
/// written.
pub fn save(path: &Path, layer: &Layer) -> Result<(), SaveError> {
    let before = |error: io::Error| SaveError {
        replaced: false,
        error,
    };
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| before(io::Error::other("the settings file has no directory")))?;
    check_directories(path, Walk::BeforeCreate).map_err(|e| before(io::Error::other(e)))?;
    #[cfg(test)]
    hook("before_create");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(before)?;
    #[cfg(test)]
    hook("after_create");
    // Again, strictly, now that every directory exists: one made meanwhile
    // by someone else (under a sticky directory), one reached only through a
    // directory just made (`missing/..`), or one that went away, is refused.
    // Once it passes, nobody else can change the directories on the way.
    check_directories(path, Walk::BeforeWrite).map_err(|e| before(io::Error::other(e)))?;
    #[cfg(test)]
    hook("after_check");
    let word = getrandom::u64().map_err(|e| before(io::Error::other(e)))?;
    let temp = dir.join(format!(".agent-settings.{word:016x}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(before)?;
    let written = file
        .write_all(render(layer).as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written.and_then(|()| std::fs::rename(&temp, path)) {
        let _ = std::fs::remove_file(&temp);
        return Err(before(e));
    }
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|error| SaveError {
            replaced: true,
            error,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A temporary directory only its owner can change, whatever the umask
    /// (the settings file must not be where others could remove it).
    fn private_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        dir
    }

    fn secs(s: u64) -> Value {
        Value::Duration(Duration::from_secs(s))
    }

    #[test]
    fn bounds_are_checked_for_every_setting() {
        for (key, allowed, refused) in [
            (
                Key::IdleTimeout,
                vec![secs(0), secs(1), secs(15 * 60), secs(24 * 3600)],
                vec![secs(24 * 3600 + 1), Value::Switch(true)],
            ),
            (
                Key::Remember,
                vec![secs(0), secs(1), secs(8 * 3600)],
                vec![secs(8 * 3600 + 1), Value::Switch(false)],
            ),
            (
                Key::DialogTimeout,
                vec![secs(15), secs(120), secs(300)],
                vec![secs(0), secs(14), secs(301), Value::Switch(true)],
            ),
            (
                Key::LockOnSuspend,
                vec![Value::Switch(true), Value::Switch(false)],
                vec![secs(1)],
            ),
            (
                Key::LockOnScreenLock,
                vec![Value::Switch(true), Value::Switch(false)],
                vec![secs(0)],
            ),
        ] {
            for value in allowed {
                assert_eq!(check(key, value), Ok(()), "{key:?} {value:?}");
            }
            for value in refused {
                let why = check(key, value).expect_err("refused");
                assert!(
                    why.contains(key.name()) && why.contains(key.allowed()),
                    "{why}"
                );
            }
        }
        // Less than a second is not a whole second: refused, not rounded.
        assert!(
            check(
                Key::IdleTimeout,
                Value::Duration(Duration::from_millis(500))
            )
            .is_err()
        );
        assert!(check(Key::Remember, Value::Duration(Duration::from_millis(1))).is_err());
    }

    #[test]
    fn changes_that_protect_less_are_named() {
        let warned = |key, old, new| weakens(key, old, new).is_some();
        // The idle lock: off, or longer.
        assert!(warned(Key::IdleTimeout, secs(900), secs(0)));
        assert!(warned(Key::IdleTimeout, secs(900), secs(901)));
        assert!(!warned(Key::IdleTimeout, secs(900), secs(60)));
        assert!(!warned(Key::IdleTimeout, secs(0), secs(60)));
        // Remembering: on, or longer.
        assert!(warned(Key::Remember, secs(0), secs(60)));
        assert!(warned(Key::Remember, secs(60), secs(3600)));
        assert!(!warned(Key::Remember, secs(3600), secs(60)));
        assert!(!warned(Key::Remember, secs(60), secs(0)));
        // Dialogs: longer.
        assert!(warned(Key::DialogTimeout, secs(120), secs(300)));
        assert!(!warned(Key::DialogTimeout, secs(120), secs(30)));
        // Locks: off.
        for key in [Key::LockOnSuspend, Key::LockOnScreenLock] {
            assert!(warned(key, Value::Switch(true), Value::Switch(false)));
            assert!(!warned(key, Value::Switch(false), Value::Switch(true)));
        }
    }

    #[test]
    fn durations_are_written_as_they_are_read() {
        for (secs, text) in [
            (0, "0"),
            (1, "1s"),
            (59, "59s"),
            (60, "1m"),
            (90, "90s"),
            (5400, "90m"),
            (3600, "1h"),
            (8 * 3600, "8h"),
            (3661, "3661s"),
        ] {
            let d = Duration::from_secs(secs);
            assert_eq!(duration_text(d), text);
            assert_eq!(parse_duration(text), Ok(d));
        }
        assert_eq!(secs(0).describe(Key::IdleTimeout), "never");
        assert_eq!(secs(0).describe(Key::Remember), "off");
        assert_eq!(secs(5400).describe(Key::Remember), "1h30m");
        // Never rounded: what is approved is what is shown.
        assert_eq!(secs(3659).describe(Key::Remember), "1h59s");
        assert_eq!(secs(3661).describe(Key::IdleTimeout), "1h1m1s");
        assert_eq!(secs(86399).describe(Key::IdleTimeout), "23h59m59s");
        assert_eq!(exact_duration(Duration::ZERO), "0s");
        assert_eq!(Value::Switch(true).describe(Key::LockOnSuspend), "on");
        assert_eq!(Value::Switch(false).describe(Key::LockOnSuspend), "off");
    }

    #[test]
    fn the_file_is_read_and_written_back_alike() {
        let layer = parse(
            "# a comment\nidle_timeout = \"5m\"\nremember = \"0\"\n\nlock_on_suspend = false\n",
        )
        .expect("parse");
        assert_eq!(layer.get(Key::IdleTimeout), Some(secs(300)));
        assert_eq!(layer.get(Key::Remember), Some(secs(0)));
        assert_eq!(layer.get(Key::DialogTimeout), None);
        assert_eq!(layer.get(Key::LockOnSuspend), Some(Value::Switch(false)));
        assert_eq!(layer.get(Key::LockOnScreenLock), None);
        let text = render(&layer);
        assert!(
            text.ends_with("idle_timeout = \"5m\"\nremember = \"0\"\nlock_on_suspend = false\n"),
            "{text}"
        );
        assert_eq!(parse(&text), Ok(layer));
        assert_eq!(parse(""), Ok(Layer::default()));
        assert_eq!(parse(&render(&Layer::default())), Ok(Layer::default()));
    }

    #[test]
    fn a_wrong_file_is_refused_saying_why() {
        for (text, says) in [
            ("idle_timeout = \"30h\"", "idle_timeout cannot be 30h"),
            ("remember = \"9h\"", "remember cannot be 9h"),
            ("dialog_timeout = \"10s\"", "dialog_timeout cannot be 10s"),
            ("dialog_timeout = \"2 minutes\"", "dialog_timeout: "),
            ("idle_timeout = 900", "invalid type"),
            ("lock_on_suspend = \"no\"", "invalid type"),
            ("idle = \"5m\"", "unknown field `idle`"),
            ("[agent]\nidle_timeout = \"5m\"", "unknown field `agent`"),
            (
                "idle_timeout = \"5m\"\nidle_timeout = \"6m\"",
                "duplicate key",
            ),
            ("idle_timeout = ", "string"),
        ] {
            let why = parse(text).expect_err(text);
            assert!(why.contains(says), "{text:?}: {why}");
        }
    }

    #[test]
    fn the_effective_settings_come_from_the_flags_then_the_file_then_the_defaults() {
        let mut file = Layer::default();
        file.set(Key::IdleTimeout, secs(300)).expect("set");
        file.set(Key::Remember, secs(3600)).expect("set");
        let mut flags = Layer::default();
        flags.set(Key::Remember, secs(0)).expect("set");
        flags
            .set(Key::LockOnSuspend, Value::Switch(false))
            .expect("set");
        let sources = Sources {
            path: PathBuf::from("/fake/agent.toml"),
            file,
            flags,
        };
        assert_eq!(
            sources.effective(),
            Settings {
                idle_timeout: Duration::from_secs(300),
                remember: Duration::ZERO,
                dialog_timeout: Duration::from_secs(120),
                lock_on_suspend: false,
                lock_on_screen_lock: true,
            }
        );
        let from: Vec<Source> = Key::ALL.iter().map(|k| sources.source(*k)).collect();
        assert_eq!(
            from,
            [
                Source::File,
                Source::Flag,
                Source::Default,
                Source::Flag,
                Source::Default
            ]
        );
        for key in Key::ALL {
            assert_eq!(
                Settings::default().with(&Layer::default()).get(key),
                Settings::default().get(key)
            );
        }
        assert!(Layer::default().set(Key::DialogTimeout, secs(1)).is_err());
    }

    #[test]
    fn loading_refuses_what_it_should_not_trust() {
        let dir = private_tempdir();
        let path = dir.path().join("agent.toml");
        // Missing: the defaults.
        assert_eq!(load(&path), Ok(Layer::default()));
        std::fs::write(&path, "remember = \"1h\"\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(
            load(&path).expect("load").get(Key::Remember),
            Some(secs(3600))
        );
        // Writable by its group — even the user's primary group, which
        // need not be the user's alone — or by others: refused, saying how
        // to fix it.
        for mode in [0o664, 0o620, 0o646] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let why = load(&path).expect_err("refused");
            assert!(
                why.contains("can be changed by its group or by others")
                    && why.contains(&format!("chmod 600 {}", path.display())),
                "{why}"
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::fs::write(&path, format!("# {}\n", "x".repeat(70 * 1024))).expect("write");
        assert!(
            load(&path)
                .expect_err("too large")
                .contains("larger than 64 KiB")
        );
        std::fs::write(&path, "remember = \"9h\"\n").expect("write");
        let why = load(&path).expect_err("out of bounds");
        assert!(
            why.contains(&path.display().to_string()) && why.contains("remember"),
            "{why}"
        );
        // Not a regular file: a directory, a FIFO (without waiting for a
        // writer).
        assert!(
            load(dir.path())
                .expect_err("dir")
                .contains("not a regular file")
        );
        let fifo = dir.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(load(&fifo));
        });
        let read = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO waited for a writer");
        assert!(read.expect_err("fifo").contains("not a regular file"));
    }

    /// A link that belongs to another user, who could change where it leads:
    /// refused. Shown by pretending to be another user, for a link of ours
    /// in `/tmp` (root's, sticky) that leads to `/`.
    #[test]
    fn a_link_of_another_user_is_refused() {
        let me = nix::unistd::getuid();
        let tmp = Path::new("/tmp");
        let sticky = std::fs::metadata(tmp).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o1000 != 0);
        if me.is_root() || !sticky {
            eprintln!("skipped: needs a non-root user and a sticky /tmp of root's");
            return;
        }
        struct Gone(PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let link = Gone(tmp.join(format!(
            "rusthorse-test-link-{:016x}",
            getrandom::u64().expect("random")
        )));
        std::os::unix::fs::symlink("/", &link.0).expect("symlink");
        // Read through it: a file of root's, reached as its owner or not.
        let path = link.0.join("etc").join("passwd");
        assert!(
            walk(&path, me.as_raw(), Walk::Read)
                .expect("ours")
                .is_some()
        );
        let why = walk(&path, me.as_raw() + 1, Walk::Read).expect_err("another user's link");
        assert!(why.contains("goes through the link"), "{why}");
        // To nothing: no file, the defaults; a save there is refused.
        let none = link.0.join("nonexistent-rusthorse").join("agent.toml");
        assert_eq!(walk(&none, me.as_raw() + 1, Walk::Read), Ok(None));
        for how in [Walk::BeforeCreate, Walk::BeforeWrite] {
            let why = walk(&none, me.as_raw() + 1, how).expect_err("another user's link");
            assert!(why.contains("goes through the link"), "{how:?}: {why}");
        }
        // As the file's own name too, whether it is read or replaced.
        for how in [Walk::Read, Walk::BeforeCreate, Walk::BeforeWrite] {
            let why = walk(&link.0, me.as_raw() + 1, how).expect_err("another user's link");
            assert!(why.contains("goes through the link"), "{how:?}: {why}");
        }
    }

    /// The file read is the one the walk found: replaced, or its directory
    /// put aside, between the walk and the opening, it is refused. (After a
    /// walk that passed, only the user or root could do either; this keeps
    /// what is read and what was checked the same file even then.)
    #[test]
    fn the_file_read_is_the_one_checked() {
        let dir = private_tempdir();
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, "idle_timeout = \"5m\"\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(
            load(&path).expect("load").get(Key::IdleTimeout),
            Some(secs(300))
        );
        let swapped = path.clone();
        HOOKS.with(|hooks| {
            hooks.borrow_mut().push((
                "load_before_open",
                Box::new(move || {
                    // Another file put in its place (a new inode: removing
                    // the old one first could let the new one reuse its
                    // number).
                    let other = swapped.with_extension("new");
                    std::fs::write(&other, "idle_timeout = \"0\"\n").expect("write");
                    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600))
                        .expect("chmod");
                    std::fs::rename(&other, &swapped).expect("rename");
                }),
            ))
        });
        let why = load(&path).expect_err("swapped");
        assert!(why.contains("changed while it was read"), "{why}");
        // Its directory put aside: the file is not there when opened.
        let inner = dir.path().join("inner");
        std::fs::create_dir(&inner).expect("mkdir");
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::write(inner.join("agent.toml"), "").expect("write");
        std::fs::set_permissions(
            inner.join("agent.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");
        let (from, to) = (inner.clone(), dir.path().join("aside"));
        HOOKS.with(|hooks| {
            hooks.borrow_mut().push((
                "load_before_open",
                Box::new(move || std::fs::rename(&from, &to).expect("put aside")),
            ))
        });
        let why = load(&inner.join("agent.toml")).expect_err("put aside");
        assert!(why.contains("changed while it was read"), "{why}");
    }

    /// A path that leads to a directory is not a settings file: refused,
    /// never taken for a missing file.
    #[test]
    fn a_directory_is_not_a_settings_file() {
        let dir = private_tempdir();
        let child = dir.path().join("child");
        std::fs::create_dir(&child).expect("mkdir");
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let dot = dir.path().join("dot");
        std::os::unix::fs::symlink(".", &dot).expect("symlink");
        let root = dir.path().join("root");
        std::os::unix::fs::symlink("/", &root).expect("symlink");
        for path in [
            PathBuf::from("/"),
            child.join(".."),
            child.clone(),
            dot.clone(),
            root.clone(),
        ] {
            let why = load(&path).expect_err("a directory");
            assert!(
                why.contains("not a regular file"),
                "{}: {why}",
                path.display()
            );
        }
        let layer = Layer::default();
        // (A link as the file's own name is replaced by a save, whatever
        // it leads to.)
        for path in [child.join(".."), dir.path().join(".")] {
            let why = save(&path, &layer).expect_err("a directory");
            assert!(
                why.error.to_string().contains("is a directory"),
                "{}: {}",
                path.display(),
                why.error
            );
        }
    }

    #[test]
    fn saving_replaces_the_file_whole_and_privately() {
        let dir = private_tempdir();
        let path = dir
            .path()
            .join("config")
            .join("rusthorse")
            .join("agent.toml");
        let mut layer = Layer::default();
        layer.set(Key::IdleTimeout, secs(60)).expect("set");
        save(&path, &layer).expect("save");
        assert_eq!(load(&path), Ok(layer.clone()));
        let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        // Directories it made are private; one that was there is left as it
        // was.
        assert_eq!(mode(path.parent().expect("dir")), 0o700);
        assert_eq!(mode(&dir.path().join("config")), 0o700);
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).expect("mkdir");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        save(&shared.join("agent.toml"), &layer).expect("save");
        assert_eq!(mode(&shared), 0o755);
        assert_eq!(mode(&shared.join("agent.toml")), 0o600);
        // A second save replaces the first; no temporary file stays.
        layer
            .set(Key::LockOnScreenLock, Value::Switch(false))
            .expect("set");
        save(&path, &layer).expect("save");
        assert_eq!(load(&path), Ok(layer.clone()));
        let names: Vec<_> = std::fs::read_dir(path.parent().expect("dir"))
            .expect("list")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, ["agent.toml"]);
        // A link at the path is replaced, not written through.
        let elsewhere = dir.path().join("elsewhere.toml");
        std::fs::write(&elsewhere, "").expect("write");
        std::fs::remove_file(&path).expect("remove");
        std::os::unix::fs::symlink(&elsewhere, &path).expect("symlink");
        save(&path, &layer).expect("save");
        assert!(std::fs::symlink_metadata(&path).expect("meta").is_file());
        assert_eq!(std::fs::read_to_string(&elsewhere).expect("read"), "");
        // A directory that others can change: they could remove the file,
        // and the agent would start with the defaults. Not written there,
        // and a file there is not read; a sticky directory is fine.
        let open = dir.path().join("open");
        std::fs::create_dir(&open).expect("mkdir");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o770)).expect("chmod");
        let failed = save(&open.join("rusthorse").join("agent.toml"), &layer).expect_err("open");
        assert!(!failed.replaced);
        assert!(
            failed
                .error
                .to_string()
                .contains("its group or others can change"),
            "{}",
            failed.error
        );
        assert!(!open.join("rusthorse").exists());
        std::fs::write(open.join("agent.toml"), "").expect("write");
        std::fs::set_permissions(
            open.join("agent.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");
        let why = load(&open.join("agent.toml")).expect_err("open dir");
        assert!(why.contains("chmod go-w"), "{why}");
        // No file there: the defaults, as for any missing file (a save
        // there is refused, above).
        assert_eq!(load(&open.join("none.toml")), Ok(Layer::default()));
        assert_eq!(
            load(&open.join("missing").join("agent.toml")),
            Ok(Layer::default())
        );
        // Reached through a link in a private directory, to a private
        // directory inside the open one: the directories above where the
        // link leads count too.
        let inner = open.join("inner");
        std::fs::create_dir(&inner).expect("mkdir");
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&inner, &link).expect("symlink");
        let why = save(&link.join("agent.toml"), &layer).expect_err("through the link");
        assert!(
            why.error.to_string().contains(&open.display().to_string()),
            "{}",
            why.error
        );
        assert!(!inner.join("agent.toml").exists());
        std::fs::write(inner.join("agent.toml"), "").expect("write");
        std::fs::set_permissions(
            inner.join("agent.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");
        assert!(load(&link.join("agent.toml")).is_err());
        // A chain of links through the open directory, between private
        // ones: neither the path as written nor where it ends shows it.
        let target = dir.path().join("target");
        std::fs::create_dir(&target).expect("mkdir");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::os::unix::fs::symlink(&target, open.join("bounce")).expect("symlink");
        let chain = dir.path().join("chain");
        std::os::unix::fs::symlink(open.join("bounce"), &chain).expect("symlink");
        let why = save(&chain.join("agent.toml"), &layer).expect_err("through the chain");
        assert!(
            why.error.to_string().contains(&open.display().to_string()),
            "{}",
            why.error
        );
        std::fs::write(target.join("agent.toml"), "").expect("write");
        std::fs::set_permissions(
            target.join("agent.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");
        assert!(load(&chain.join("agent.toml")).is_err());
        // The same target through a relative link in a private directory,
        // with `..` in it: accepted.
        std::os::unix::fs::symlink("../target", dir.path().join("config").join("up"))
            .expect("symlink");
        assert_eq!(
            load(&dir.path().join("config").join("up").join("agent.toml")),
            Ok(Layer::default())
        );
        save(
            &dir.path().join("config").join("up").join("agent.toml"),
            &layer,
        )
        .expect("save");
        // A missing directory, then `..` into the open one: only known once
        // the missing one is made — walked again then, and refused.
        let why = save(
            &dir.path()
                .join("missing")
                .join("..")
                .join("open")
                .join("agent.toml"),
            &layer,
        )
        .expect_err("missing/..");
        assert!(
            why.error.to_string().contains(&open.display().to_string()),
            "{}",
            why.error
        );
        assert_eq!(
            std::fs::read_to_string(open.join("agent.toml")).expect("read"),
            "",
            "written"
        );
        // A missing directory made meanwhile by someone else, writable by
        // all: refused, nothing written in it.
        let late = dir.path().join("late");
        let made = late.clone();
        HOOKS.with(|hooks| {
            hooks.borrow_mut().push((
                "before_create",
                Box::new(move || {
                    std::fs::create_dir(&made).expect("mkdir");
                    std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o777))
                        .expect("chmod");
                }),
            ))
        });
        let why = save(&late.join("agent.toml"), &layer).expect_err("made meanwhile");
        assert!(
            why.error
                .to_string()
                .contains("its group or others can change"),
            "{}",
            why.error
        );
        assert_eq!(std::fs::read_dir(&late).expect("list").count(), 0);
        // The same, put aside while the agent looks and back before it
        // writes: the directory must be there when it looks.
        let (made, aside, back, back_to) = (
            dir.path().join("later"),
            dir.path().join("parked"),
            dir.path().join("parked"),
            dir.path().join("later"),
        );
        let (moved, moved_to) = (made.clone(), aside.clone());
        HOOKS.with(|hooks| {
            let mut hooks = hooks.borrow_mut();
            hooks.push((
                "before_create",
                Box::new(move || {
                    std::fs::create_dir(&made).expect("mkdir");
                    std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o777))
                        .expect("chmod");
                }),
            ));
            hooks.push((
                "after_create",
                Box::new(move || std::fs::rename(&moved, &moved_to).expect("put aside")),
            ));
            hooks.push((
                "after_check",
                Box::new(move || std::fs::rename(&back, &back_to).expect("put back")),
            ));
        });
        let later = dir.path().join("later");
        let why = save(&later.join("agent.toml"), &layer).expect_err("put aside meanwhile");
        assert!(
            why.error.to_string().contains("does not exist"),
            "{}",
            why.error
        );
        HOOKS.with(|hooks| hooks.borrow_mut().clear());
        assert!(!later.exists() || std::fs::read_dir(&later).expect("list").count() == 0);
        assert!(!aside.join("agent.toml").exists());
        // Before writing, every directory must be there; before making
        // them, or to read, a missing one means nothing there.
        let absent = dir.path().join("absent").join("agent.toml");
        let me = nix::unistd::getuid().as_raw();
        assert_eq!(walk(&absent, me, Walk::BeforeCreate), Ok(None));
        assert_eq!(walk(&absent, me, Walk::Read), Ok(None));
        assert!(
            walk(&absent, me, Walk::BeforeWrite)
                .expect_err("strict")
                .contains("does not exist")
        );
        assert_eq!(
            walk(&dir.path().join("agent.toml"), me, Walk::BeforeWrite),
            Ok(None)
        );
        // A link as the file's own name, leading nowhere: there is no file
        // to read, and a save replaces the link, not what it leads to.
        let config = dir.path().join("config");
        let dangling = config.join("dangling.toml");
        std::os::unix::fs::symlink("absent/agent.toml", &dangling).expect("symlink");
        assert_eq!(load(&dangling), Ok(Layer::default()));
        save(&dangling, &layer).expect("replace the link");
        assert!(
            std::fs::symlink_metadata(&dangling)
                .expect("meta")
                .is_file()
        );
        assert!(!config.join("absent").exists());
        assert_eq!(load(&dangling), Ok(layer.clone()));
        // Sticky: others cannot remove what they do not own.
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777)).expect("chmod");
        assert_eq!(load(&open.join("agent.toml")), Ok(Layer::default()));
        save(&open.join("agent.toml"), &layer).expect("sticky");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        // A directory that cannot be written: nothing replaced, nothing left.
        if !nix::unistd::getuid().is_root() {
            let parent = path.parent().expect("dir");
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o500))
                .expect("chmod");
            let failed = save(&path, &Layer::default()).expect_err("read-only");
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
            assert!(!failed.replaced);
            assert_eq!(load(&path), Ok(layer));
        }
    }
}
