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

/// An unlocked vault.
pub struct Vault {
    db: Database,
    path: PathBuf,
    password: SecretString,
    fingerprint: Option<Fingerprint>,
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
        let fingerprint = Fingerprint::of(&file.metadata()?);
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
        })
    }

    /// The vault file path.
    pub fn path(&self) -> &Path {
        &self.path
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

        let result = (|| -> Result<(), VaultError> {
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
            Ok(())
        })();
        if let Err(e) = result {
            let _ = fs::remove_file(&tmp);
            return Err(e);
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
        File::open(&dir)?.sync_all()?;
        self.fingerprint = Some(Fingerprint::of(&fs::metadata(&self.path)?));
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
                let title = e.get_title().unwrap_or_default().to_string();
                Some((e.id(), title, self.group_path(group)))
            })
            .collect()
    }

    /// Find an entry by name, or by `Group/Sub/Name` path when the plain name
    /// does not match.
    pub fn find(&self, name: &str) -> Result<EntryId, VaultError> {
        let entries = self.entries();
        let mut matches: Vec<&(EntryId, String, Vec<String>)> = entries
            .iter()
            .filter(|(_, title, _)| title == name)
            .collect();
        if matches.is_empty() && name.contains('/') {
            matches = entries
                .iter()
                .filter(|(_, title, group)| display_path(group, title) == name)
                .collect();
        }
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
        let text = |key: &str| entry.get(key).filter(|v| !v.is_empty()).map(str::to_string);
        let group = self.group_path(entry.parent().id());
        let mut other_fields: Vec<String> = entry
            .fields
            .keys()
            .filter(|k| !KNOWN_FIELDS.contains(&k.as_str()))
            .cloned()
            .collect();
        other_fields.sort();
        EntryInfo {
            name: entry.get_title().unwrap_or_default().to_string(),
            group: (!group.is_empty()).then(|| group.join("/")),
            fields: EntryFields {
                username: text(fields::USERNAME),
                url: text(fields::URL),
                host: text(FIELD_HOST),
                port: entry.get(FIELD_PORT).and_then(|p| p.trim().parse().ok()),
                tags: entry.tags.clone(),
            },
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

    /// Delete an entry permanently.
    pub fn remove(&mut self, id: EntryId) {
        if let Some(entry) = self.db.entry_mut(id) {
            entry.remove();
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
    fn names_are_validated() {
        assert!(validate_name("GitHub token").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(" x").is_err());
        assert!(validate_name("a\nb").is_err());
        assert!(validate_name("evil\u{202E}txt").is_err());
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
