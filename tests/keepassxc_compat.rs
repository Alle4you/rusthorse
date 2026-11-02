//! A vault created by KeePassXC must survive Rusthorse's edits: entries,
//! fields, history and groups that Rusthorse did not touch stay exactly as
//! they were, and the file still opens with the keepass reader afterwards.
//!
//! The fixture is a real KDBX 4.1 file written by KeePassXC 2.7.12 (see
//! tests/fixtures/NOTICE.md).

use std::path::PathBuf;

use keepass::{Database, DatabaseKey};
use rusthorse::broker_profile::{Preset, ProfileRequest};
use rusthorse::protocol::{EntryChanges, EntryFields, NewEntry, SecretString};
use rusthorse::vault::{FIELD_BROKER, Vault};

const FIXTURE: &str = "tests/fixtures/keepassxc-2.7.12-kdbx41.kdbx";
const PASSWORD: &str = "demopass";

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

/// A broker profile (ADR 0013) is one plain custom field that another KDBX
/// client keeps as it is: set by Rusthorse in a KeePassXC vault, read and
/// saved again by another client, it is still usable, and nothing else
/// changed on the way.
#[test]
fn a_broker_profile_survives_a_round_trip_through_a_keepassxc_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = copy_fixture(&dir);
    let before = raw(&path);

    let mut vault = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("open");
    let edited = vault.list()[0].id.clone();
    let id = vault.find(&edited).expect("find by uuid");
    let request = ProfileRequest {
        origin: Some("https://api.deepseek.com".into()),
        max_requests: Some(200),
        ..ProfileRequest::new(Preset::OpenaiCompatible)
    };
    let profile = request.resolve().expect("profile");
    vault
        .edit(
            id,
            &EntryChanges {
                broker: Some(request),
                ..EntryChanges::default()
            },
            None,
        )
        .expect("edit");
    vault.save().expect("save");

    // Another client sees one more field, unprotected, holding the stored
    // form; every other field of the entry, and every other entry, is as
    // it was.
    let after = raw(&path);
    let old = before
        .iter_all_entries()
        .find(|e| e.id().to_string() == edited)
        .expect("the edited entry");
    let new = after.entry(old.id()).expect("entry kept");
    let field = new.fields.get(FIELD_BROKER).expect("the profile's field");
    assert!(!field.is_protected());
    assert_eq!(field.get(), &profile.to_stored());
    assert_eq!(new.fields.len(), old.fields.len() + 1);
    for (key, value) in &old.fields {
        assert_eq!(new.fields.get(key), Some(value), "field {key} changed");
    }
    assert_eq!(new.tags, old.tags);
    for entry in before.iter_all_entries() {
        if entry.id() != old.id() {
            let other = after.entry(entry.id()).expect("entry kept");
            assert_eq!(*entry, *other, "an untouched entry changed: {}", entry.id());
        }
    }
    assert_eq!(after.meta, before.meta, "database metadata changed");

    // Saved again by that client, the profile is still usable.
    let mut file = std::fs::File::create(&path).expect("rewrite");
    after
        .save(&mut file, DatabaseKey::new().with_password(PASSWORD))
        .expect("save as another client");
    drop(file);
    let reopened = Vault::open(&path, SecretString::new(PASSWORD.into())).expect("reopen");
    let info = reopened.info(reopened.find(&edited).expect("find"));
    assert_eq!(info.broker, Some(profile));
    assert!(!info.other_fields.iter().any(|f| f == FIELD_BROKER));
    assert!(!info.protected_fields.iter().any(|f| f == FIELD_BROKER));
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
