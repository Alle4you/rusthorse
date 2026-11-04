//! A vault created by KeePassXC must survive Rusthorse's edits: entries,
//! fields, history and groups that Rusthorse did not touch stay exactly as
//! they were, and the file still opens with the keepass reader afterwards.
//!
//! The fixtures are a real KDBX 4.1 file written by KeePassXC 2.7.12, and a
//! KDBX 4.0 file that KeePassXC 2.7.6 saved (see tests/fixtures/NOTICE.md).

use std::path::PathBuf;

use keepass::{Database, DatabaseKey};
use rusthorse::protocol::{EntryChanges, EntryFields, NewEntry, SecretString};
use rusthorse::vault::{KdfParams, Vault};

const FIXTURE: &str = "tests/fixtures/keepassxc-2.7.12-kdbx41.kdbx";
/// Saved as KDBX 4.0 by KeePassXC 2.7.6, which writes 4.0 when nothing in
/// the file needs 4.1.
const FIXTURE_KDBX40: &str = "tests/fixtures/keepassxc-2.7.6-kdbx40.kdbx";
const PASSWORD: &str = "demopass";

/// The KDBX version in a file's header: major and minor.
fn kdbx_version(path: &PathBuf) -> (u16, u16) {
    let head = std::fs::read(path).expect("read");
    let minor = u16::from_le_bytes([head[8], head[9]]);
    let major = u16::from_le_bytes([head[10], head[11]]);
    (major, minor)
}

fn copy_fixture(dir: &tempfile::TempDir) -> PathBuf {
    let path = dir.path().join("vault.kdbx");
    std::fs::copy(FIXTURE, &path).expect("copy fixture");
    path
}

fn raw(path: &PathBuf) -> Database {
    Database::open(
        &mut std::fs::File::open(path).expect("open"),
        DatabaseKey::new().with_password(PASSWORD),
    )
    .expect("decrypt")
}

/// Where phase 1 of the credential broker stored an entry's profile (ADR
/// 0013). Rusthorse no longer reads it: it is a custom field like any other.
const PHASE_1_PROFILE: &str = "Rusthorse.Broker";

/// A profile as phase 1 stored it.
const STORED_PROFILE: &str = r#"{"version":1,"preset":"openai-compatible","revision":1,"origin":"https://api.deepseek.com","base_path":"/v1","automatic_locks":"continue","max_lifetime_minutes":720,"max_requests":200}"#;

/// The field `key` of the entry `id` as a KeePass reader sees it: its text,
/// and whether it is protected.
fn field(db: &Database, id: keepass::db::EntryId, key: &str) -> Option<(String, bool)> {
    db.entry(id)
        .expect("the entry")
        .fields
        .get(key)
        .map(|value| (value.get().clone(), value.is_protected()))
}

#[test]
fn rusthorse_edits_preserve_everything_else_in_a_keepassxc_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = copy_fixture(&dir);
    let before = raw(&path);

    let mut vault = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("open");
    let listed = vault.list();
    assert!(!listed.is_empty(), "the fixture has entries");
    let edited = listed[0].id.clone();

    // One edit to an existing entry, one new entry.
    let id = vault.find(&edited).expect("find by uuid");
    vault
        .edit(
            id,
            &EntryChanges {
                host: Some("10.9.8.7".into()),
                add_tags: vec!["rusthorse".into()],
                ..EntryChanges::default()
            },
            None,
        )
        .expect("edit");
    vault
        .add(
            &NewEntry {
                name: "ADDED_BY_RUSTHORSE".into(),
                fields: EntryFields {
                    url: Some("https://example.com".into()),
                    ..EntryFields::default()
                },
                ..NewEntry::default()
            },
            &SecretString::new("added-value".into()),
            false,
        )
        .expect("add");
    vault.save().expect("save");

    let after = raw(&path);
    assert_eq!(after.num_entries(), before.num_entries() + 1);
    assert_eq!(after.num_groups(), before.num_groups());
    assert_eq!(after.meta, before.meta, "database metadata changed");

    // Every entry Rusthorse did not touch is identical, history included.
    for entry in before.iter_all_entries() {
        let other = after.entry(entry.id()).expect("entry kept");
        if entry.id().to_string() == edited {
            assert_eq!(other.get("Host"), Some("10.9.8.7"));
            assert!(other.tags.contains(&"rusthorse".to_string()));
            // The previous state went into the entry's history.
            let old_len = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
            let new_len = other.history.as_ref().map_or(0, |h| h.get_entries().len());
            assert_eq!(new_len, old_len + 1);
            for (key, value) in &entry.fields {
                if key != "Host" {
                    assert_eq!(other.fields.get(key), Some(value), "field {key} changed");
                }
            }
        } else {
            assert_eq!(*entry, *other, "an untouched entry changed: {}", entry.id());
        }
    }

    // And Rusthorse reads its own result.
    let reopened = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("reopen");
    assert!(reopened.find("ADDED_BY_RUSTHORSE").is_ok());
}

/// A profile stored by phase 1 of the credential broker (ADR 0013, scope
/// amendment) is an ordinary custom field: in a KeePassXC vault, Rusthorse
/// lists it by name only and keeps it byte for byte, protected or not,
/// through its edits of the entry — a rename, a new user name, host, tag and
/// value — and its save; nothing else changes on the way.
#[test]
fn a_phase_1_profile_is_kept_byte_for_byte_through_rusthorses_edits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = copy_fixture(&dir);
    // Two entries of the KeePassXC vault (outside its recycle bin) get the
    // field, as phase 1 stored it and as another client may have protected
    // it.
    let listed: Vec<String> = Vault::open(&path, SecretString::new(PASSWORD.into()))
        .expect("open")
        .list()
        .into_iter()
        .map(|info| info.id)
        .take(2)
        .collect();
    assert_eq!(listed.len(), 2, "the fixture has two entries");
    let mut db = raw(&path);
    let ids: Vec<keepass::db::EntryId> = listed
        .iter()
        .map(|uuid| {
            db.iter_all_entries()
                .find(|e| e.id().to_string() == *uuid)
                .map(|e| e.id())
                .expect("the entry")
        })
        .collect();
    db.entry_mut(ids[0])
        .expect("entry")
        .set_unprotected(PHASE_1_PROFILE, STORED_PROFILE);
    db.entry_mut(ids[1])
        .expect("entry")
        .set_protected(PHASE_1_PROFILE, STORED_PROFILE);
    let mut file = std::fs::File::create(&path).expect("rewrite");
    db.save(&mut file, DatabaseKey::new().with_password(PASSWORD))
        .expect("save as another client");
    drop(file);
    let before = raw(&path);
    let stored = [
        Some((STORED_PROFILE.to_string(), false)),
        Some((STORED_PROFILE.to_string(), true)),
    ];
    for (id, stored) in ids.iter().zip(&stored) {
        assert_eq!(&field(&before, *id, PHASE_1_PROFILE), stored);
    }

    // Rusthorse lists it by name, never its value, and changes the entries.
    let mut vault = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("open");
    for id in &ids {
        let info = vault.info(vault.find(&id.to_string()).expect("find by uuid"));
        assert!(
            info.other_fields.iter().any(|f| f == PHASE_1_PROFILE),
            "{:?}",
            info.other_fields
        );
        assert!(!info.protected_fields.iter().any(|f| f == PHASE_1_PROFILE));
        let json = serde_json::to_string(&info).expect("json");
        assert!(
            !json.contains("deepseek") && !json.contains("preset"),
            "{json}"
        );
    }
    let first = vault.find(&ids[0].to_string()).expect("find");
    vault
        .edit(
            first,
            &EntryChanges {
                rename: Some("RENAMED_BY_RUSTHORSE".into()),
                username: Some("me".into()),
                host: Some("10.9.8.7".into()),
                add_tags: vec!["rusthorse".into()],
                ..EntryChanges::default()
            },
            Some(&SecretString::new("a-new-fake-value".into())),
        )
        .expect("edit");
    let second = vault.find(&ids[1].to_string()).expect("find");
    vault
        .edit(
            second,
            &EntryChanges {
                port: Some(2222),
                add_tags: vec!["rusthorse".into()],
                ..EntryChanges::default()
            },
            None,
        )
        .expect("edit");
    vault.save().expect("save");

    // The field is as it was, byte for byte, its protection included; the
    // edits took; every other field of the two entries, every other entry
    // and the database's metadata are as they were.
    let after = raw(&path);
    for (id, stored) in ids.iter().zip(&stored) {
        assert_eq!(&field(&after, *id, PHASE_1_PROFILE), stored);
    }
    let edited = after.entry(ids[0]).expect("entry");
    assert_eq!(edited.get_title(), Some("RENAMED_BY_RUSTHORSE"));
    assert_eq!(edited.get_username(), Some("me"));
    assert_eq!(edited.get("Host"), Some("10.9.8.7"));
    assert_eq!(edited.get_password(), Some("a-new-fake-value"));
    assert_eq!(
        after.entry(ids[1]).expect("entry").get("Port"),
        Some("2222")
    );
    let changed: [&[&str]; 2] = [&["Title", "UserName", "Password", "Host"], &["Port"]];
    for (id, changed) in ids.iter().zip(changed) {
        let old = before.entry(*id).expect("entry");
        let new = after.entry(*id).expect("entry");
        for (key, value) in &old.fields {
            if !changed.contains(&key.as_str()) {
                assert_eq!(new.fields.get(key), Some(value), "field {key} changed");
            }
        }
        assert_eq!(
            new.fields.len(),
            old.fields.len()
                + changed
                    .iter()
                    .filter(|k| !old.fields.contains_key(**k))
                    .count()
        );
        assert!(new.tags.contains(&"rusthorse".to_string()));
    }
    for entry in before.iter_all_entries() {
        if !ids.contains(&entry.id()) {
            let other = after.entry(entry.id()).expect("entry kept");
            assert_eq!(*entry, *other, "an untouched entry changed: {}", entry.id());
        }
    }
    assert_eq!(after.meta, before.meta, "database metadata changed");
}

/// A profile stored by phase 1 survives Rusthorse and KeePassXC itself
/// saving the file (ADR 0013, scope amendment): in a vault written through
/// the library, with the field on one entry, Rusthorse edits that entry,
/// then `keepassxc-cli` another, then Rusthorse again, each saving the file;
/// the field reads back byte for byte, unprotected, and Rusthorse lists it
/// by name only.
///
/// It needs `keepassxc-cli`, so it is ignored by default: run `cargo test
/// --test keepassxc_compat -- --ignored` where it is installed. The program
/// opens nothing of the user's: only this test's file, with its settings in
/// the test's own directory and the (fake) password on its standard input.
#[test]
#[ignore = "needs keepassxc-cli: run with --ignored where it is installed"]
fn a_phase_1_profile_survives_rusthorse_and_keepassxc_cli_saving_the_vault() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.kdbx");
    let password = "a fake test passphrase";
    let mut vault = Vault::create(
        &path,
        SecretString::new(password.into()),
        KdfParams::INSECURE_FOR_TESTS,
    )
    .expect("create");
    for name in ["KEY", "OTHER"] {
        let entry = NewEntry {
            name: name.into(),
            ..NewEntry::default()
        };
        let value = SecretString::new(format!("sk-ant-test-0000FAKE0000{name}-0000"));
        vault.add(&entry, &value, false).expect("add");
    }
    vault.save().expect("save");
    drop(vault);
    let open = || {
        Database::open(
            &mut std::fs::File::open(&path).expect("open"),
            DatabaseKey::new().with_password(password),
        )
        .expect("decrypt")
    };
    let by_title = |db: &Database, title: &str| {
        db.iter_all_entries()
            .find(|e| e.get_title() == Some(title))
            .map(|e| e.id())
            .unwrap_or_else(|| panic!("no entry {title}"))
    };
    // The field, as phase 1 stored it.
    let mut db = open();
    let key = by_title(&db, "KEY");
    db.entry_mut(key)
        .expect("entry")
        .set_unprotected(PHASE_1_PROFILE, STORED_PROFILE);
    let mut file = std::fs::File::create(&path).expect("rewrite");
    db.save(&mut file, DatabaseKey::new().with_password(password))
        .expect("save");
    drop(file);
    let stored = Some((STORED_PROFILE.to_string(), false));

    // Rusthorse changes that entry and saves the file.
    let mut vault = Vault::open(&path, SecretString::new(password.into())).expect("open");
    let id = vault.find("KEY").expect("find");
    assert_eq!(vault.info(id).other_fields, [PHASE_1_PROFILE]);
    let changes = EntryChanges {
        username: Some("changed-by-rusthorse".into()),
        add_tags: vec!["rusthorse".into()],
        ..EntryChanges::default()
    };
    vault.edit(id, &changes, None).expect("edit");
    vault.save().expect("save");
    drop(vault);
    assert_eq!(field(&open(), key, PHASE_1_PROFILE), stored);

    // KeePassXC changes the other entry and saves the file.
    let home = dir.path().join("home");
    std::fs::create_dir(&home).expect("a home for keepassxc-cli");
    let mut child = Command::new("keepassxc-cli")
        .args(["edit", "--quiet", "--username", "changed-by-keepassxc"])
        .arg(&path)
        .arg("OTHER")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("QT_QPA_PLATFORM", "offscreen")
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keepassxc-cli");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{password}\n").as_bytes())
        .expect("the password");
    let output = child.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "keepassxc-cli failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    // Read by another reader: both changes are there, and the field is as
    // it was, unprotected.
    let db = open();
    let other = by_title(&db, "OTHER");
    assert_eq!(
        db.entry(other).expect("entry").get_username(),
        Some("changed-by-keepassxc")
    );
    assert_eq!(
        db.entry(key).expect("entry").get_username(),
        Some("changed-by-rusthorse")
    );
    assert_eq!(field(&db, key, PHASE_1_PROFILE), stored);
    // And Rusthorse still lists it by name only.
    let mut vault = Vault::open(&path, SecretString::new(password.into())).expect("reopen");
    let id = vault.find("KEY").expect("find");
    let info = vault.info(id);
    assert_eq!(info.other_fields, [PHASE_1_PROFILE]);
    assert!(
        info.protected_fields.is_empty(),
        "{:?}",
        info.protected_fields
    );
    // KeePassXC may have written KDBX 4.0, as it does when nothing in the
    // file needs 4.1: Rusthorse saves it again all the same, and the field
    // is still as it was.
    let changes = EntryChanges {
        username: Some("changed-by-rusthorse-again".into()),
        ..EntryChanges::default()
    };
    vault.edit(id, &changes, None).expect("edit");
    vault.save().expect("save after keepassxc-cli");
    drop(vault);
    assert_eq!(kdbx_version(&path), (4, 1));
    assert_eq!(field(&open(), key, PHASE_1_PROFILE), stored);
}

/// A vault that KeePassXC saved as KDBX 4.0 is written back as KDBX 4.1,
/// the version Rusthorse writes, with everything in it kept: Rusthorse
/// edits it like any other vault, and KeePassXC reads the result.
#[test]
fn a_kdbx_4_0_vault_is_written_back_as_kdbx_4_1() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.kdbx");
    std::fs::copy(FIXTURE_KDBX40, &path).expect("copy fixture");
    assert_eq!(kdbx_version(&path), (4, 0));
    let before = raw(&path);

    let mut vault = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("open");
    let id = vault.find("API_KEY").expect("find");
    let changes = EntryChanges {
        username: Some("edited-by-rusthorse".into()),
        ..EntryChanges::default()
    };
    vault.edit(id, &changes, None).expect("edit");
    vault.save().expect("a KDBX 4.0 vault is saved");
    drop(vault);
    assert_eq!(kdbx_version(&path), (4, 1));

    // Everything else as it was; the edited entry changed only where asked.
    let after = raw(&path);
    for title in ["API_KEY", "OTHER"] {
        let find = |db: &Database| {
            db.iter_all_entries()
                .find(|e| e.get_title() == Some(title))
                .map(|e| {
                    (
                        e.get_username().map(str::to_string),
                        e.get_url().map(str::to_string),
                        e.get_password().map(str::to_string),
                    )
                })
                .unwrap_or_else(|| panic!("no entry {title}"))
        };
        let (username, url, password) = find(&before);
        let (username_after, url_after, password_after) = find(&after);
        assert_eq!((url_after, password_after), (url, password), "{title}");
        if title == "API_KEY" {
            assert_eq!(username_after.as_deref(), Some("edited-by-rusthorse"));
        } else {
            assert_eq!(username_after, username, "{title}");
        }
    }
    let reopened = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("reopen");
    assert_eq!(reopened.list().len(), 2);
}

#[test]
fn a_keepassxc_vault_can_be_backed_up_and_its_password_changed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = copy_fixture(&dir);
    let mut vault = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("open");
    let entries = vault.list().len();

    let backup = dir.path().join("backup.kdbx");
    assert_eq!(vault.backup_to(&backup).expect("backup"), entries);

    vault.change_password(SecretString::new("a new passphrase".into()));
    vault.save().expect("save");
    assert!(Vault::open(&path, SecretString::new(PASSWORD.into())).is_err());
    let reopened = Vault::open(&path, SecretString::new("a new passphrase".into())).expect("new");
    assert_eq!(reopened.list().len(), entries);
    // The earlier backup still opens with the old password.
    assert!(Vault::open(&backup, SecretString::new(PASSWORD.into())).is_ok());
}
