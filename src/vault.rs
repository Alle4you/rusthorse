//! The encrypted vault: a KeePass KDBX4 file.
//!
//! Field mapping (also documented in `docs/architecture.md`):
//!
//! | Rusthorse  | KDBX field  | Protected |
//! |------------|-------------|-----------|
//! | name       | `Title`     | no        |
//! | username   | `UserName`  | no        |
//! | value      | `Password`  | yes       |
//! | url        | `URL`       | no        |
//! | notes      | `Notes`     | yes       |
//! | host       | `Host`      | no        |
//! | port       | `Port`      | no        |
//! | tags       | `Tags`      | —         |
//!
//! Entries in the recycle bin are ignored. Files written by Rusthorse open in
//! KeePassXC and other KDBX4 clients.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use keepass::config::{DatabaseConfig, DatabaseVersion, KdfConfig};
use keepass::db::{EntryId, GroupId, Times, fields};
use keepass::error::{DatabaseKeyError, DatabaseOpenError, DatabaseSaveError};
use keepass::{Database, DatabaseKey};

use crate::protocol::{EntryChanges, EntryFields, EntryInfo, Field, NewEntry, SecretString};
use crate::util::ensure_private_dir;

/// Custom KDBX field holding the host name or IP address.
pub const FIELD_HOST: &str = "Host";
/// Custom KDBX field holding the port.
pub const FIELD_PORT: &str = "Port";

/// Shown instead of a title that the KeePass file marks as protected.
pub const PROTECTED_TITLE: &str = "[protected title]";

/// Vault files larger than this are refused before anything is decrypted.
pub const MAX_VAULT_BYTES: u64 = 128 * 1024 * 1024;

const KNOWN_FIELDS: [&str; 7] = [
    fields::TITLE,
    fields::USERNAME,
    fields::PASSWORD,
    fields::URL,
    fields::NOTES,
    FIELD_HOST,
    FIELD_PORT,
];

/// Errors from vault operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// No entry has that name.
    #[error("no entry named {0:?}")]
    NotFound(String),
    /// Several entries have that name.
    #[error("{name:?} matches several entries ({}); use the Group/Name path", paths.join(", "))]
    Ambiguous {
        /// The name that was looked up.
        name: String,
        /// Paths of the matching entries.
        paths: Vec<String>,
    },
    /// An entry with that name already exists.
    #[error("an entry named {0:?} already exists")]
    AlreadyExists(String),
    /// The master password is wrong.
    #[error("wrong master password")]
    WrongPassword,
    /// Another program modified the file since it was loaded.
    #[error("the vault file was changed by another program; lock and unlock to reload it")]
    ChangedOnDisk,
    /// The vault file does not exist.
    #[error("no vault at {0}; create one with `rusthorse init`")]
    Missing(PathBuf),
    /// The vault file already exists.
    #[error("a vault already exists at {0}")]
    Exists(PathBuf),
    /// The entry data is invalid.
    #[error("{0}")]
    Invalid(String),
    /// The file is not a readable KDBX database.
    #[error("cannot open the vault: {0}")]
    Open(#[source] DatabaseOpenError),
    /// The database could not be serialized.
    #[error("cannot save the vault: {0}")]
    Save(#[source] DatabaseSaveError),
    /// The new file replaced the vault, but its directory could not be
    /// synced: the change is visible, but may not survive a crash or a power
    /// loss. The save is neither confirmed nor undone.
    #[error(
        "the vault file was replaced, but syncing its directory failed ({0}); the change is in \
         place but may not survive a crash or power loss"
    )]
    NotDurable(#[source] std::io::Error),
    /// File system error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Argon2id parameters used when creating a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in bytes.
    pub memory_bytes: u64,
    /// Number of passes.
    pub iterations: u64,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl KdfParams {
    /// Defaults for new vaults: Argon2id with 64 MiB, 20 passes, 2 lanes.
    /// KeePassXC also uses 64 MiB and aims at about one second per unlock;
    /// these settings take about 0.8 s on a 2020s desktop CPU (measure with
    /// the ignored `default_kdf_timing` test).
    pub const DEFAULT: Self = Self {
        memory_bytes: 64 * 1024 * 1024,
        iterations: 20,
        parallelism: 2,
    };

    /// Deliberately weak parameters for tests. Never use for real data.
    pub const INSECURE_FOR_TESTS: Self = Self {
        memory_bytes: 1024 * 1024,
        iterations: 1,
        parallelism: 1,
    };

    fn database_config(self) -> DatabaseConfig {
        let mut config = DatabaseConfig::default();
        let version = match config.kdf_config {
            KdfConfig::Argon2 { version, .. } | KdfConfig::Argon2id { version, .. } => version,
            // The crate's default is Argon2; this arm only exists for exhaustiveness.
            _ => unreachable!("keepass default KDF is Argon2"),
        };
        config.kdf_config = KdfConfig::Argon2id {
            iterations: self.iterations,
            memory: self.memory_bytes,
            parallelism: self.parallelism,
            version,
        };
        config
    }
}

/// What the file looked like when it was loaded, to detect outside changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl Fingerprint {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        }
    }
}

/// A test hook run during a save.
#[cfg(test)]
type SaveHook = Box<dyn FnOnce(&Path) + Send>;

/// An unlocked vault.
pub struct Vault {
    db: Database,
    path: PathBuf,
    password: SecretString,
    fingerprint: Option<Fingerprint>,
    /// Remove `<name>.bak` after the next successful save (it is encrypted
    /// with a password that is no longer current).
    discard_backup: bool,
    /// Why that removal failed, if it did (see [`Vault::take_cleanup_error`]).
    cleanup_error: Option<String>,
    /// Test hook: runs after the new file is written, before it replaces the
    /// old one (simulates another program saving at that moment).
    #[cfg(test)]
    before_rename: Option<SaveHook>,
    /// Test hook: runs on a backup copy before it is verified (simulates
    /// corruption on the way to the disk).
    #[cfg(test)]
    before_verify: Option<SaveHook>,
    /// Test hook: make deleting the old-password backup fail.
    #[cfg(test)]
    fail_cleanup: bool,
    /// Test hook: make syncing the directory fail after the rename.
    #[cfg(test)]
    fail_dir_sync: bool,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Create a new, empty vault file. Fails if `path` already exists.
    pub fn create(
        path: &Path,
        password: SecretString,
        kdf: KdfParams,
    ) -> Result<Vault, VaultError> {
        if fs::symlink_metadata(path).is_ok() {
            return Err(VaultError::Exists(path.to_path_buf()));
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            ensure_private_dir(dir)?;
        }
        let mut db = Database::with_config(kdf.database_config());
        db.root_mut().name = "Rusthorse".to_string();
        let mut vault = Vault {
            db,
            path: path.to_path_buf(),
            password,
            fingerprint: None,
            discard_backup: false,
            cleanup_error: None,
            #[cfg(test)]
            before_rename: None,
            #[cfg(test)]
            before_verify: None,
            #[cfg(test)]
            fail_cleanup: false,
            #[cfg(test)]
            fail_dir_sync: false,
        };
        vault.write_file(false)?;
        Ok(vault)
    }

    /// Open and decrypt an existing vault.
    pub fn open(path: &Path, password: SecretString) -> Result<Vault, VaultError> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(VaultError::Missing(path.to_path_buf()));
            }
            Err(e) => return Err(e.into()),
        };
        let meta = file.metadata()?;
        if meta.len() > MAX_VAULT_BYTES {
            return Err(VaultError::Invalid(format!(
                "{} is larger than {} MiB; refusing to load it",
                path.display(),
                MAX_VAULT_BYTES / (1024 * 1024)
            )));
        }
        let fingerprint = Fingerprint::of(&meta);
        let db = Database::open(&mut file, DatabaseKey::new().with_password(&password)).map_err(
            |e| match e {
                DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey) => VaultError::WrongPassword,
                other => VaultError::Open(other),
            },
        )?;
        Ok(Vault {
            db,
            path: path.to_path_buf(),
            password,
            fingerprint: Some(fingerprint),
            discard_backup: false,
            cleanup_error: None,
            #[cfg(test)]
            before_rename: None,
            #[cfg(test)]
            before_verify: None,
            #[cfg(test)]
            fail_cleanup: false,
            #[cfg(test)]
            fail_dir_sync: false,
        })
    }

    /// The vault file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether `candidate` is the current master password (compared in
    /// constant time).
    pub fn password_matches(&self, candidate: &str) -> bool {
        let (a, b) = (self.password.as_bytes(), candidate.as_bytes());
        let mut diff = a.len() ^ b.len();
        for i in 0..a.len().max(b.len()) {
            diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
        }
        diff == 0
    }

    /// Why deleting the old-password backup after a password change failed,
    /// if it did. The password change itself is saved either way.
    pub fn take_cleanup_error(&mut self) -> Option<String> {
        self.cleanup_error.take()
    }

    /// Test hook: make the next saves fail after replacing the file, at the
    /// directory sync (see [`VaultError::NotDurable`]).
    #[cfg(test)]
    pub(crate) fn fail_directory_sync(&mut self) {
        self.fail_dir_sync = true;
    }

    /// Use `new` as the master password from the next save on. That save
    /// also removes `<name>.bak`, which is encrypted with the old password.
    pub fn change_password(&mut self, new: SecretString) {
        self.password = new;
        self.discard_backup = true;
    }

    /// Write the vault back to disk, atomically, keeping the previous file as
    /// `<name>.bak`. Refuses if another program changed the file meanwhile.
    pub fn save(&mut self) -> Result<(), VaultError> {
        self.write_file(true)
    }

    fn write_file(&mut self, check_unchanged: bool) -> Result<(), VaultError> {
        if !matches!(self.db.config.version, DatabaseVersion::KDB4(_)) {
            return Err(VaultError::Invalid(
                "this vault uses an older KeePass format (KDBX3 or earlier); Rusthorse can read \
                 it but only writes KDBX4. Convert it once in KeePassXC (Database → Database \
                 Settings → Encryption → Database format: KDBX 4) and try again"
                    .into(),
            ));
        }
        if check_unchanged {
            let current = fs::metadata(&self.path).ok().map(|m| Fingerprint::of(&m));
            if current != self.fingerprint {
                return Err(VaultError::ChangedOnDisk);
            }
        }
        let dir = match self.path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let name = self
            .path
            .file_name()
            .ok_or_else(|| VaultError::Invalid("the vault path has no file name".into()))?
            .to_string_lossy()
            .into_owned();
        let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));

        let result = (|| -> Result<Fingerprint, VaultError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            self.db
                .save(&mut file, DatabaseKey::new().with_password(&self.password))
                .map_err(VaultError::Save)?;
            file.flush()?;
            file.sync_all()?;
            Ok(Fingerprint::of(&file.metadata()?))
        })();
        let written = match result {
            Ok(fingerprint) => fingerprint,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        #[cfg(test)]
        if let Some(hook) = self.before_rename.take() {
            hook(&self.path);
        }
        // Check again right before replacing the file: serializing and the
        // KDF take a while, and another program may have saved meanwhile.
        // This narrows the window; it cannot close it against writers that do
        // not cooperate (see docs/threat-model.md, L15).
        if check_unchanged {
            let current = fs::metadata(&self.path).ok().map(|m| Fingerprint::of(&m));
            if current != self.fingerprint {
                let _ = fs::remove_file(&tmp);
                return Err(VaultError::ChangedOnDisk);
            }
        }

        if self.fingerprint.is_some() {
            let backup = dir.join(format!("{name}.bak"));
            let _ = fs::remove_file(&backup);
            if let Err(e) = fs::hard_link(&self.path, &backup) {
                let _ = fs::remove_file(&tmp);
                return Err(e.into());
            }
        }
        if let Err(e) = fs::rename(&tmp, &self.path) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        // From here on the new file is in place: a failure no longer means
        // "not saved". The renamed file is the one we wrote (same inode),
        // whatever the path points to by now.
        self.fingerprint = Some(written);
        #[cfg(test)]
        let synced = if self.fail_dir_sync {
            Err(std::io::Error::other("injected directory sync failure"))
        } else {
            File::open(&dir).and_then(|d| d.sync_all())
        };
        #[cfg(not(test))]
        let synced = File::open(&dir).and_then(|d| d.sync_all());
        if let Err(e) = synced {
            // Deleting an old-password `.bak` waits for a save that is
            // confirmed: after a crash, that file may be the only copy.
            return Err(VaultError::NotDurable(e));
        }
        if self.discard_backup {
            let backup = dir.join(format!("{name}.bak"));
            #[cfg(test)]
            let removed = if self.fail_cleanup {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            } else {
                fs::remove_file(&backup)
            };
            #[cfg(not(test))]
            let removed = fs::remove_file(&backup);
            self.cleanup_error = match removed {
                Ok(()) => File::open(&dir).and_then(|d| d.sync_all()).err().map(|e| {
                    format!(
                        "{}: deleted, but the directory was not synced: {e}",
                        backup.display()
                    )
                }),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => Some(format!("{}: {e}", backup.display())),
            };
            self.discard_backup = false;
        }
        Ok(())
    }

    fn recycle_bin(&self) -> Option<GroupId> {
        self.db.recycle_bin().map(|g| g.id())
    }

    /// Group names from the root (excluded) down to `group`.
    fn group_path(&self, group: GroupId) -> Vec<String> {
        let mut names = Vec::new();
        let mut current = Some(group);
        while let Some(id) = current {
            let Some(g) = self.db.group(id) else { break };
            current = g.parent().map(|p| p.id());
            if current.is_some() {
                names.push(g.name.clone());
            }
        }
        names.reverse();
        names
    }

    fn in_recycle_bin(&self, group: GroupId) -> bool {
        let Some(bin) = self.recycle_bin() else {
            return false;
        };
        let mut current = Some(group);
        while let Some(id) = current {
            if id == bin {
                return true;
            }
            current = self.db.group(id).and_then(|g| g.parent().map(|p| p.id()));
        }
        false
    }

    /// Live entries (outside the recycle bin) as (id, title, group path).
    fn entries(&self) -> Vec<(EntryId, String, Vec<String>)> {
        self.db
            .iter_all_entries()
            .filter_map(|e| {
                let group = e.parent().id();
                if self.in_recycle_bin(group) {
                    return None;
                }
                // A protected title is treated as secret: it is neither shown
                // nor matched by name (the entry is still reachable by UUID).
                let title = match e.fields.get(fields::TITLE) {
                    Some(v) if !v.is_protected() => v.get().clone(),
                    _ => String::new(),
                };
                Some((e.id(), title, self.group_path(group)))
            })
            .collect()
    }

    /// Find an entry by title or by `Group/Sub/Title` path. A name that
    /// matches more than one entry — including a title that looks like the
    /// path of another entry — is ambiguous.
    pub fn find(&self, name: &str) -> Result<EntryId, VaultError> {
        let entries = self.entries();
        // An entry's UUID always identifies it unambiguously.
        if let Some((id, _, _)) = entries.iter().find(|(id, _, _)| id.to_string() == name) {
            return Ok(*id);
        }
        let matches: Vec<&(EntryId, String, Vec<String>)> = entries
            .iter()
            .filter(|(_, title, group)| {
                !title.is_empty()
                    && (title == name || (name.contains('/') && display_path(group, title) == name))
            })
            .collect();
        match matches.as_slice() {
            [] => Err(VaultError::NotFound(name.to_string())),
            [(id, _, _)] => Ok(*id),
            many => Err(VaultError::Ambiguous {
                name: name.to_string(),
                paths: many
                    .iter()
                    .map(|(_, title, group)| display_path(group, title))
                    .collect(),
            }),
        }
    }

    /// Whether `name` resolves to an existing entry (ambiguity counts as yes).
    pub fn contains(&self, name: &str) -> bool {
        !matches!(self.find(name), Err(VaultError::NotFound(_)))
    }

    /// Metadata for one entry.
    pub fn info(&self, id: EntryId) -> EntryInfo {
        let entry = self
            .db
            .entry(id)
            .expect("entry id comes from this database");
        let mut protected_fields = Vec::new();
        // A field the KeePass file marks as protected is treated as secret,
        // whatever its name: only its existence is reported.
        let mut text = |key: &str| {
            let value = entry.fields.get(key)?;
            if value.get().is_empty() {
                return None;
            }
            if value.is_protected() {
                protected_fields.push(key.to_string());
                return None;
            }
            Some(value.get().clone())
        };
        let username = text(fields::USERNAME);
        let url = text(fields::URL);
        let host = text(FIELD_HOST);
        let port = text(FIELD_PORT).and_then(|p| p.trim().parse().ok());
        let name = match entry.fields.get(fields::TITLE) {
            Some(v) if v.is_protected() => {
                protected_fields.insert(0, fields::TITLE.to_string());
                PROTECTED_TITLE.to_string()
            }
            Some(v) => v.get().clone(),
            None => String::new(),
        };
        let group = self.group_path(entry.parent().id());
        let mut other_fields: Vec<String> = entry
            .fields
            .keys()
            .filter(|k| !KNOWN_FIELDS.contains(&k.as_str()))
            .cloned()
            .collect();
        other_fields.sort();
        EntryInfo {
            id: id.to_string(),
            name,
            group: (!group.is_empty()).then(|| group.join("/")),
            fields: EntryFields {
                username,
                url,
                host,
                port,
                tags: entry.tags.clone(),
            },
            protected_fields,
            has_password: entry.get_password().is_some_and(|p| !p.is_empty()),
            has_notes: entry.get(fields::NOTES).is_some_and(|n| !n.is_empty()),
            other_fields,
            modified: entry.times.last_modification.map(|t| {
                t.and_utc()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            }),
        }
    }

    /// All live entries, sorted by group and name.
    pub fn list(&self) -> Vec<EntryInfo> {
        let mut infos: Vec<EntryInfo> = self
            .entries()
            .into_iter()
            .map(|(id, _, _)| self.info(id))
            .collect();
        infos.sort_by(|a, b| (&a.group, &a.name).cmp(&(&b.group, &b.name)));
        infos
    }

    /// The entry's notes, if it has any.
    pub fn notes(&self, id: EntryId) -> Option<SecretString> {
        let entry = self.db.entry(id)?;
        entry
            .get(fields::NOTES)
            .filter(|n| !n.is_empty())
            .map(|n| SecretString::new(n.to_string()))
    }

    /// Copy the vault file, as it is on disk (encrypted), to `dest`, which
    /// must not exist; then decrypt the copy with the current master password
    /// to prove it is a usable backup. Returns the number of entries in it.
    pub fn backup_to(&mut self, dest: &Path) -> Result<usize, VaultError> {
        let current = fs::metadata(&self.path).ok().map(|m| Fingerprint::of(&m));
        if current != self.fingerprint {
            return Err(VaultError::ChangedOnDisk);
        }
        let bytes = fs::read(&self.path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dest)
            .map_err(|e| {
                VaultError::Invalid(if e.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "{} already exists; a backup never replaces a file, so choose a new name",
                        dest.display()
                    )
                } else {
                    format!("cannot create the backup file {}: {e}", dest.display())
                })
            })?;
        let written = (|| -> Result<(), VaultError> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            if let Some(dir) = dest.parent().filter(|d| !d.as_os_str().is_empty()) {
                File::open(dir)?.sync_all()?;
            }
            Ok(())
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(dest);
            return Err(e);
        }
        #[cfg(test)]
        if let Some(hook) = self.before_verify.take() {
            hook(dest);
        }
        let copy = Vault::open(dest, self.password.clone()).map_err(|e| {
            VaultError::Invalid(format!(
                "the backup at {} was written but does not open ({e}); do not rely on it",
                dest.display()
            ))
        })?;
        Ok(copy.entries().len())
    }

    /// The entry's password, if it has a non-empty one.
    pub fn secret(&self, id: EntryId) -> Option<SecretString> {
        let entry = self.db.entry(id)?;
        entry
            .get_password()
            .filter(|p| !p.is_empty())
            .map(|p| SecretString::new(p.to_string()))
    }

    /// Create an entry, or overwrite an existing one when `replace` is set.
    /// Returns `true` when an existing entry was replaced.
    pub fn add(
        &mut self,
        new: &NewEntry,
        value: &SecretString,
        replace: bool,
    ) -> Result<bool, VaultError> {
        validate_name(&new.name)?;
        validate_fields(&new.fields)?;
        match self.find(&new.name) {
            Ok(id) if replace => {
                let mut entry = self
                    .db
                    .entry_mut(id)
                    .expect("entry id comes from this database");
                let mut tracked = entry.track_changes();
                write_fields(&mut tracked, new, value);
                tracked.times.last_modification = Some(Times::now());
                Ok(true)
            }
            Ok(_) => Err(VaultError::AlreadyExists(new.name.clone())),
            Err(VaultError::NotFound(_)) => {
                let group = self.ensure_group(new.group.as_deref())?;
                let mut parent = self
                    .db
                    .group_mut(group)
                    .expect("group id comes from this database");
                let mut entry = parent.add_entry();
                write_fields(&mut entry, new, value);
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Apply `changes` to an entry, recording the previous state in the
    /// entry's KeePass history. `new_value` replaces the password.
    pub fn edit(
        &mut self,
        id: EntryId,
        changes: &EntryChanges,
        new_value: Option<&SecretString>,
    ) -> Result<(), VaultError> {
        if let Some(name) = &changes.rename {
            validate_name(name)?;
            match self.find(name) {
                Ok(other) if other != id => return Err(VaultError::AlreadyExists(name.clone())),
                Err(VaultError::Ambiguous { .. }) => {
                    return Err(VaultError::AlreadyExists(name.clone()));
                }
                _ => {}
            }
        }
        validate_fields(&EntryFields {
            url: changes.url.clone(),
            host: changes.host.clone(),
            username: changes.username.clone(),
            ..EntryFields::default()
        })?;

        let mut entry = self
            .db
            .entry_mut(id)
            .expect("entry id comes from this database");
        let mut e = entry.track_changes();
        if let Some(name) = &changes.rename {
            e.set_unprotected(fields::TITLE, name.as_str());
        }
        for field in &changes.clear {
            let key = match field {
                Field::Username => fields::USERNAME,
                Field::Url => fields::URL,
                Field::Host => FIELD_HOST,
                Field::Port => FIELD_PORT,
                Field::Notes => fields::NOTES,
            };
            e.fields.remove(key);
        }
        set_text(&mut e, fields::USERNAME, changes.username.as_deref());
        set_text(&mut e, fields::URL, changes.url.as_deref());
        set_text(&mut e, FIELD_HOST, changes.host.as_deref());
        if let Some(port) = changes.port {
            e.set_unprotected(FIELD_PORT, port.to_string());
        }
        match changes.notes.as_deref() {
            Some("") => {
                e.fields.remove(fields::NOTES);
            }
            Some(notes) => e.set_protected(fields::NOTES, notes),
            None => {}
        }
        for tag in &changes.add_tags {
            if !e.tags.contains(tag) {
                e.tags.push(tag.clone());
            }
        }
        e.tags.retain(|t| !changes.remove_tags.contains(t));
        if let Some(value) = new_value {
            e.set_protected(fields::PASSWORD, value.as_str());
        }
        e.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// Run `f`, undoing every change it made to the database if it fails, so
    /// that a batch is applied completely or not at all.
    pub fn transaction<R, E>(
        &mut self,
        f: impl FnOnce(&mut Vault) -> Result<R, E>,
    ) -> Result<R, E> {
        let before = self.db.clone();
        match f(self) {
            Ok(result) => Ok(result),
            Err(e) => {
                self.db = before;
                Err(e)
            }
        }
    }

    /// Delete an entry permanently, recording the deletion (KeePass
    /// `DeletedObjects`) so that synchronizing with an older copy does not
    /// bring it back.
    pub fn remove(&mut self, id: EntryId) {
        if let Some(mut entry) = self.db.entry_mut(id) {
            entry.track_changes().remove();
        }
    }

    /// The group at `path` (`A/B/C`), created if missing. `None` is the root.
    fn ensure_group(&mut self, path: Option<&str>) -> Result<GroupId, VaultError> {
        let mut current = self.db.root().id();
        let Some(path) = path else {
            return Ok(current);
        };
        for component in path.split('/').map(str::trim).filter(|c| !c.is_empty()) {
            validate_name(component)?;
            let existing = self.db.group(current).and_then(|g| {
                g.groups()
                    .find(|child| child.name == component)
                    .map(|c| c.id())
            });
            current = match existing {
                Some(id) => id,
                None => {
                    let mut parent = self
                        .db
                        .group_mut(current)
                        .expect("group id comes from this database");
                    let mut child = parent.add_group();
                    child.name = component.to_string();
                    child.id()
                }
            };
        }
        Ok(current)
    }
}

fn display_path(group: &[String], title: &str) -> String {
    if group.is_empty() {
        title.to_string()
    } else {
        format!("{}/{}", group.join("/"), title)
    }
}

/// Names must be non-empty, trimmed, reasonably short and free of control or
/// invisible formatting characters (they are shown in approval dialogs).
pub fn validate_name(name: &str) -> Result<(), VaultError> {
    if name.trim().is_empty() {
        return Err(VaultError::Invalid("the name must not be empty".into()));
    }
    if name.trim() != name {
        return Err(VaultError::Invalid(
            "the name must not start or end with spaces".into(),
        ));
    }
    if name.chars().count() > 128 {
        return Err(VaultError::Invalid(
            "the name must be at most 128 characters".into(),
        ));
    }
    if name.contains('/') {
        return Err(VaultError::Invalid(
            "the name must not contain '/' (it separates groups in paths)".into(),
        ));
    }
    if crate::util::visible(name) != name {
        return Err(VaultError::Invalid(
            "the name must not contain control or invisible formatting characters".into(),
        ));
    }
    Ok(())
}

fn validate_fields(fields: &EntryFields) -> Result<(), VaultError> {
    for (label, value) in [
        ("username", &fields.username),
        ("url", &fields.url),
        ("host", &fields.host),
    ] {
        if let Some(v) = value
            && crate::util::visible(v) != *v
        {
            return Err(VaultError::Invalid(format!(
                "the {label} must not contain control or invisible formatting characters"
            )));
        }
    }
    for tag in &fields.tags {
        validate_name(tag).map_err(|e| VaultError::Invalid(format!("tag {tag:?}: {e}")))?;
    }
    Ok(())
}

fn set_text(entry: &mut keepass::db::Entry, key: &str, value: Option<&str>) {
    match value {
        Some(v) if !v.is_empty() => entry.set_unprotected(key, v),
        Some(_) => {
            entry.fields.remove(key);
        }
        None => {}
    }
}

fn write_fields(entry: &mut keepass::db::Entry, new: &NewEntry, value: &SecretString) {
    entry.set_unprotected(fields::TITLE, new.name.as_str());
    entry.set_protected(fields::PASSWORD, value.as_str());
    for key in [
        fields::USERNAME,
        fields::URL,
        FIELD_HOST,
        FIELD_PORT,
        fields::NOTES,
    ] {
        entry.fields.remove(key);
    }
    set_text(entry, fields::USERNAME, new.fields.username.as_deref());
    set_text(entry, fields::URL, new.fields.url.as_deref());
    set_text(entry, FIELD_HOST, new.fields.host.as_deref());
    if let Some(port) = new.fields.port {
        entry.set_unprotected(FIELD_PORT, port.to_string());
    }
    if let Some(notes) = new.notes.as_deref().filter(|n| !n.is_empty()) {
        entry.set_protected(fields::NOTES, notes);
    }
    entry.tags = new.fields.tags.clone();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_string())
    }

    fn entry(name: &str) -> NewEntry {
        NewEntry {
            name: name.into(),
            fields: EntryFields {
                username: Some("admin".into()),
                url: Some("https://192.168.1.1/".into()),
                host: Some("192.168.1.1".into()),
                port: Some(443),
                tags: vec!["network".into()],
            },
            notes: Some("rack 2".into()),
            ..NewEntry::default()
        }
    }

    fn new_vault(dir: &tempfile::TempDir) -> (Vault, PathBuf) {
        let path = dir.path().join("sub").join("vault.kdbx");
        let vault = Vault::create(
            &path,
            secret("correct horse"),
            KdfParams::INSECURE_FOR_TESTS,
        )
        .expect("create");
        (vault, path)
    }

    #[test]
    fn create_add_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, path) = new_vault(&dir);
        assert!(
            !vault
                .add(&entry("router"), &secret("s3cret!"), false)
                .expect("add")
        );
        vault.save().expect("save");

        let reopened = Vault::open(&path, secret("correct horse")).expect("open");
        let id = reopened.find("router").expect("find");
        let info = reopened.info(id);
        assert_eq!(info.fields.username.as_deref(), Some("admin"));
        assert_eq!(info.fields.host.as_deref(), Some("192.168.1.1"));
        assert_eq!(info.fields.port, Some(443));
        assert_eq!(info.fields.tags, vec!["network".to_string()]);
        assert!(info.has_password && info.has_notes);
        assert_eq!(
            reopened.secret(id).as_deref().map(String::as_str),
            Some("s3cret!")
        );
        assert!(dir.path().join("sub").join("vault.kdbx.bak").exists());
    }

    #[test]
    fn wrong_password_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, path) = new_vault(&dir);
        assert!(matches!(
            Vault::open(&path, secret("nope")),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn duplicates_and_replace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        vault.add(&entry("a"), &secret("one1"), false).expect("add");
        assert!(matches!(
            vault.add(&entry("a"), &secret("two2"), false),
            Err(VaultError::AlreadyExists(_))
        ));
        assert!(
            vault
                .add(&entry("a"), &secret("two2"), true)
                .expect("replace")
        );
        let id = vault.find("a").expect("find");
        assert_eq!(
            vault.secret(id).as_deref().map(String::as_str),
            Some("two2")
        );
    }

    #[test]
    fn groups_and_ambiguity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        let mut one = entry("db");
        one.group = Some("Work/Servers".into());
        let mut two = entry("db");
        two.group = Some("Home".into());
        vault.add(&one, &secret("aaaa"), false).expect("add one");
        // Same title in another group: `add` sees the existing name.
        assert!(matches!(
            vault.add(&two, &secret("bbbb"), false),
            Err(VaultError::AlreadyExists(_))
        ));
        assert_eq!(
            vault.info(vault.find("db").expect("find")).group.as_deref(),
            Some("Work/Servers")
        );
        assert!(vault.find("Work/Servers/db").is_ok());
    }

    #[test]
    fn edit_records_history_and_changes_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        vault
            .add(&entry("router"), &secret("old-value"), false)
            .expect("add");
        let id = vault.find("router").expect("find");
        let changes = EntryChanges {
            rename: Some("core-router".into()),
            host: Some("10.0.0.1".into()),
            clear: vec![Field::Url],
            add_tags: vec!["prod".into()],
            remove_tags: vec!["network".into()],
            ..EntryChanges::default()
        };
        vault
            .edit(id, &changes, Some(&secret("new-value")))
            .expect("edit");
        let info = vault.info(vault.find("core-router").expect("find renamed"));
        assert_eq!(info.fields.host.as_deref(), Some("10.0.0.1"));
        assert_eq!(info.fields.url, None);
        assert_eq!(info.fields.tags, vec!["prod".to_string()]);
        let history = vault
            .db
            .entry(id)
            .and_then(|e| e.history.clone())
            .expect("history");
        assert_eq!(history.get_entries().len(), 1);
    }

    #[test]
    fn outside_changes_block_saving() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, path) = new_vault(&dir);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let bytes = fs::read(&path).expect("read");
        fs::write(&path, bytes).expect("rewrite");
        vault.add(&entry("x"), &secret("abcd"), false).expect("add");
        assert!(matches!(vault.save(), Err(VaultError::ChangedOnDisk)));
    }

    #[test]
    fn a_save_by_another_program_during_our_save_is_not_overwritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, path) = new_vault(&dir);
        vault
            .add(&entry("ours"), &secret("abcd"), false)
            .expect("add");
        vault.before_rename = Some(Box::new(|path: &Path| {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let bytes = fs::read(path).expect("read");
            fs::write(path, bytes).expect("another program saves");
        }));
        assert!(matches!(vault.save(), Err(VaultError::ChangedOnDisk)));
        // Our temporary file was cleaned up.
        let leftovers = fs::read_dir(path.parent().expect("dir"))
            .expect("list")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn changing_the_password_reencrypts_and_drops_the_old_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, path) = new_vault(&dir);
        vault.add(&entry("x"), &secret("abcd"), false).expect("add");
        vault.save().expect("save");
        let backup = dir.path().join("sub").join("vault.kdbx.bak");
        assert!(backup.exists());
        assert!(vault.password_matches("correct horse"));
        assert!(!vault.password_matches("correct hors"));
        vault.change_password(secret("new passphrase here"));
        vault.save().expect("save with the new password");
        assert!(
            !backup.exists(),
            "the backup encrypted with the old password remains"
        );
        assert!(matches!(
            Vault::open(&path, secret("correct horse")),
            Err(VaultError::WrongPassword)
        ));
        let reopened = Vault::open(&path, secret("new passphrase here")).expect("open");
        assert!(reopened.find("x").is_ok());
    }

    #[test]
    fn a_backup_that_does_not_open_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        vault.add(&entry("x"), &secret("abcd"), false).expect("add");
        vault.save().expect("save");
        let dest = dir.path().join("copy.kdbx");
        vault.before_verify = Some(Box::new(|path: &Path| {
            let mut bytes = fs::read(path).expect("read");
            let middle = bytes.len() / 2;
            bytes[middle] ^= 0xff;
            fs::write(path, bytes).expect("corrupt");
        }));
        assert!(matches!(
            vault.backup_to(&dest),
            Err(VaultError::Invalid(_))
        ));
    }

    #[test]
    fn a_failed_cleanup_after_a_password_change_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, path) = new_vault(&dir);
        vault.add(&entry("x"), &secret("abcd"), false).expect("add");
        vault.save().expect("save");
        vault.fail_cleanup = true;
        vault.change_password(secret("another passphrase"));
        vault.save().expect("the password change itself is saved");
        let problem = vault.take_cleanup_error().expect("the failure is reported");
        assert!(problem.contains("vault.kdbx.bak"), "{problem}");
        assert!(Vault::open(&path, secret("another passphrase")).is_ok());
    }

    #[test]
    fn a_backup_never_replaces_a_file_and_says_what_to_do() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.kdbx");
        let mut vault = Vault::create(
            &path,
            SecretString::new("correct horse".into()),
            KdfParams::INSECURE_FOR_TESTS,
        )
        .expect("create");
        let taken = dir.path().join("taken.kdbx");
        fs::write(&taken, b"keep me").expect("write");
        let err = vault.backup_to(&taken).expect_err("replaced").to_string();
        assert!(
            err.contains("already exists") && err.contains("choose a new name"),
            "{err}"
        );
        assert_eq!(fs::read(&taken).expect("read"), b"keep me");
        let nowhere = dir.path().join("no-such-dir").join("backup.kdbx");
        let err = vault.backup_to(&nowhere).expect_err("created").to_string();
        assert!(err.starts_with("cannot create the backup file"), "{err}");
    }

    #[test]
    fn a_failed_directory_sync_is_not_reported_as_unsaved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, path) = new_vault(&dir);
        vault
            .add(&entry("old"), &secret("abcd"), false)
            .expect("add");
        vault.save().expect("save");
        vault.change_password(secret("another passphrase"));
        vault
            .add(&entry("new"), &secret("efgh"), false)
            .expect("add");
        vault.fail_dir_sync = true;
        assert!(matches!(vault.save(), Err(VaultError::NotDurable(_))));
        // The change is on disk, and the vault knows it is: no false
        // "changed by another program" on the next save.
        let reopened = Vault::open(&path, secret("another passphrase")).expect("new file");
        assert!(reopened.find("new").is_ok());
        // The old-password copy is kept until a save is confirmed.
        let backup = path.with_file_name("vault.kdbx.bak");
        assert!(Vault::open(&backup, secret("correct horse")).is_ok());
        vault.fail_dir_sync = false;
        vault.save().expect("the next save works");
        assert!(vault.take_cleanup_error().is_none());
        assert!(
            !backup.exists(),
            "the old-password copy is deleted once confirmed"
        );
    }

    #[test]
    fn names_are_validated() {
        assert!(validate_name("GitHub token").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(" x").is_err());
        assert!(validate_name("a\nb").is_err());
        assert!(validate_name("evil\u{202E}txt").is_err());
    }

    #[test]
    fn protected_metadata_is_not_disclosed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        vault
            .add(&entry("signed"), &secret("abcd"), false)
            .expect("add");
        let id = vault.find("signed").expect("find");
        // As if another KeePass client had marked these fields protected.
        {
            let mut e = vault.db.entry_mut(id).expect("entry");
            e.set_protected(fields::URL, "https://x.example/?sig=SECRET");
            e.set_protected(fields::USERNAME, "hidden-user");
        }
        let info = vault.info(id);
        assert_eq!(info.fields.url, None);
        assert_eq!(info.fields.username, None);
        assert_eq!(info.protected_fields, vec!["UserName", "URL"]);
        let listed = serde_json::to_string(&vault.list()).expect("json");
        assert!(!listed.contains("SECRET") && !listed.contains("hidden-user"));
    }

    #[test]
    fn a_title_that_looks_like_a_path_is_ambiguous() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        let mut inner = entry("API");
        inner.group = Some("Prod".into());
        vault.add(&inner, &secret("aaaa"), false).expect("add");
        // Titles with '/' cannot be created any more...
        assert!(matches!(
            vault.add(&entry("Prod/API"), &secret("bbbb"), false),
            Err(VaultError::Invalid(_))
        ));
        // ...but a file edited elsewhere may contain one.
        vault
            .db
            .root_mut()
            .add_entry()
            .set_unprotected(fields::TITLE, "Prod/API");
        assert!(matches!(
            vault.find("Prod/API"),
            Err(VaultError::Ambiguous { .. })
        ));
    }

    #[test]
    fn removal_is_recorded_for_synchronization() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        vault
            .add(&entry("gone"), &secret("abcd"), false)
            .expect("add");
        let id = vault.find("gone").expect("find");
        vault.remove(id);
        assert!(vault.db.deleted_objects.contains_key(&id.uuid()));
    }

    #[test]
    fn oversized_files_are_refused_before_decryption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("big.kdbx");
        let file = File::create(&path).expect("create");
        file.set_len(MAX_VAULT_BYTES + 1).expect("sparse file");
        assert!(matches!(
            Vault::open(&path, secret("x")),
            Err(VaultError::Invalid(_))
        ));
    }

    #[test]
    fn protected_titles_are_hidden_and_only_reachable_by_uuid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        vault
            .add(&entry("visible"), &secret("abcd"), false)
            .expect("add");
        let id = vault.find("visible").expect("find");
        vault
            .db
            .entry_mut(id)
            .expect("entry")
            .set_protected(fields::TITLE, "SECRET-TITLE");
        let info = vault.info(id);
        assert_eq!(info.name, PROTECTED_TITLE);
        assert_eq!(
            info.protected_fields.first().map(String::as_str),
            Some("Title")
        );
        assert!(
            !serde_json::to_string(&vault.list())
                .expect("json")
                .contains("SECRET-TITLE")
        );
        assert!(matches!(
            vault.find("SECRET-TITLE"),
            Err(VaultError::NotFound(_))
        ));
        assert_eq!(vault.find(&id.to_string()).expect("by uuid"), id);
    }

    #[test]
    fn failed_transactions_leave_no_trace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        let result: Result<(), VaultError> = vault.transaction(|v| {
            v.add(&entry("PARTIAL"), &secret("abcd"), false)?;
            let mut bad = entry("INVALID");
            bad.fields.url = Some("https://x\nAllow".into());
            v.add(&bad, &secret("abcd"), false)?;
            Ok(())
        });
        assert!(result.is_err());
        assert!(matches!(
            vault.find("PARTIAL"),
            Err(VaultError::NotFound(_))
        ));
    }

    #[test]
    fn remove_deletes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut vault, _) = new_vault(&dir);
        vault
            .add(&entry("gone"), &secret("abcd"), false)
            .expect("add");
        let id = vault.find("gone").expect("find");
        vault.remove(id);
        assert!(matches!(vault.find("gone"), Err(VaultError::NotFound(_))));
    }
}

#[cfg(test)]
mod timing {
    use super::*;

    /// `cargo test --release -- --ignored --nocapture default_kdf_timing`
    #[test]
    #[ignore = "measures the real KDF cost; run explicitly"]
    fn default_kdf_timing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.kdbx");
        let password = || SecretString::new("timing password".to_string());
        let started = std::time::Instant::now();
        Vault::create(&path, password(), KdfParams::DEFAULT).expect("create");
        let created = started.elapsed();
        let started = std::time::Instant::now();
        Vault::open(&path, password()).expect("open");
        println!("create: {created:?}, open: {:?}", started.elapsed());
    }
}
