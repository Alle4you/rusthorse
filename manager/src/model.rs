//! Metadata-only form and search logic. Never stores a revealed value.

use rusthorse::generate::Spec;
use rusthorse::protocol::{
    EntryChanges, EntryFields, EntryInfo, Field, NewEntry, Request, ValueChange,
};

#[derive(Clone, Default)]
pub(crate) struct Form {
    pub name: String,
    pub group: String,
    pub username: String,
    pub url: String,
    pub host: String,
    pub port: String,
    pub tags: String,
}

impl Form {
    pub fn from_entry(entry: &EntryInfo) -> Self {
        Self {
            name: entry.name.clone(),
            group: entry.group.clone().unwrap_or_default(),
            username: entry.fields.username.clone().unwrap_or_default(),
            url: entry.fields.url.clone().unwrap_or_default(),
            host: entry.fields.host.clone().unwrap_or_default(),
            port: entry.fields.port.map(|p| p.to_string()).unwrap_or_default(),
            tags: entry.fields.tags.join(", "),
        }
    }

    pub fn request(&self, old: Option<&EntryInfo>, value: ValueMode) -> Result<Request, String> {
        for text in [
            &self.name,
            &self.group,
            &self.username,
            &self.url,
            &self.host,
            &self.tags,
        ] {
            if text.chars().count() > 1000 {
                return Err("Each field must be at most 1000 characters.".into());
            }
        }
        let port = if self.port.trim().is_empty() {
            None
        } else {
            Some(
                self.port
                    .parse::<u16>()
                    .map_err(|_| "Port must be an integer from 0 to 65535.")?,
            )
        };
        let tags: Vec<String> = self
            .tags
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect();
        let Some(old) = old else {
            rusthorse::vault::validate_name(&self.name).map_err(|e| e.to_string())?;
            return Ok(Request::Add {
                entry: NewEntry {
                    name: self.name.clone(),
                    group: (!self.group.is_empty()).then(|| self.group.clone()),
                    fields: EntryFields {
                        username: nonempty(&self.username),
                        url: nonempty(&self.url),
                        host: nonempty(&self.host),
                        port,
                        tags,
                    },
                    notes: None,
                },
                value: None,
                generate: matches!(value, ValueMode::Generate).then(Spec::default),
                replace: false,
            });
        };
        let before = Self::from_entry(old);
        if self.group != before.group {
            return Err("Moving an existing entry to another group is not supported yet.".into());
        }
        let mut changes = EntryChanges::default();
        if self.name != before.name {
            editable(old, "Title")?;
            rusthorse::vault::validate_name(&self.name).map_err(|e| e.to_string())?;
            changes.rename = Some(self.name.clone());
        }
        for (current, previous, protected, field, dest) in [
            (
                &self.username,
                &before.username,
                "UserName",
                Field::Username,
                &mut changes.username,
            ),
            (&self.url, &before.url, "URL", Field::Url, &mut changes.url),
            (
                &self.host,
                &before.host,
                "Host",
                Field::Host,
                &mut changes.host,
            ),
        ] {
            if current != previous {
                editable(old, protected)?;
                if current.is_empty() {
                    changes.clear.push(field);
                } else {
                    *dest = Some(current.clone());
                }
            }
        }
        if self.port != before.port {
            editable(old, "Port")?;
            if let Some(port) = port {
                changes.port = Some(port);
            } else {
                changes.clear.push(Field::Port);
            }
        }
        // Do not split/join untouched legacy tags (a tag can contain a comma).
        if self.tags != before.tags {
            changes.add_tags = tags
                .iter()
                .filter(|t| !old.fields.tags.contains(t))
                .cloned()
                .collect();
            changes.remove_tags = old
                .fields
                .tags
                .iter()
                .filter(|t| !tags.contains(t))
                .cloned()
                .collect();
        }
        changes.value = match value {
            ValueMode::Keep => None,
            ValueMode::Prompt => Some(ValueChange::Prompt),
            ValueMode::Generate => Some(ValueChange::Generate(Spec::default())),
        };
        if changes.is_empty() {
            return Err("Nothing changed.".into());
        }
        Ok(Request::Edit {
            name: old.id.clone(),
            changes,
        })
    }
}

fn nonempty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

fn editable(entry: &EntryInfo, field: &str) -> Result<(), String> {
    if entry.protected_fields.iter().any(|f| f == field) {
        Err(format!(
            "{field} is protected; edit it in KeePassXC using the documented handoff procedure."
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ValueMode {
    Keep,
    Prompt,
    Generate,
}

pub(crate) fn matches(entry: &EntryInfo, query: &str, group: Option<&str>) -> bool {
    if group.is_some_and(|g| entry.group.as_deref().unwrap_or_default() != g) {
        return false;
    }
    let query = query.to_lowercase();
    [
        &entry.name,
        &entry.id,
        entry.group.as_deref().unwrap_or_default(),
        entry.fields.username.as_deref().unwrap_or_default(),
        entry.fields.url.as_deref().unwrap_or_default(),
        entry.fields.host.as_deref().unwrap_or_default(),
    ]
    .into_iter()
    .any(|s| s.to_lowercase().contains(&query))
        || entry
            .fields
            .tags
            .iter()
            .any(|s| s.to_lowercase().contains(&query))
}

/// The command that gives an entry's value to a program. The entry is named
/// by its UUID, which no rename or duplicate title can make ambiguous; the
/// variable is the entry's name when that is a valid variable name.
pub(crate) fn snippet(entry: &EntryInfo) -> String {
    let var = if is_variable_name(&entry.name) {
        entry.name.as_str()
    } else {
        "SECRET"
    };
    format!(
        "rusthorse run {} -- your-command",
        rusthorse::util::shell_quote(&format!("{var}={}", entry.id))
    )
}

fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// The second line of an entry in the list: who and where.
pub(crate) fn summary(entry: &EntryInfo) -> String {
    let place = entry
        .fields
        .host
        .as_deref()
        .or(entry.fields.url.as_deref())
        .unwrap_or_default();
    match (entry.fields.username.as_deref().unwrap_or_default(), place) {
        ("", "") => "No login or address".into(),
        (user, "") => user.into(),
        ("", place) => place.into(),
        (user, place) => format!("{user} · {place}"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn entry() -> EntryInfo {
        EntryInfo {
            id: "11111111-2222-3333-4444-555555555555".into(),
            name: "FAKE_KEY".into(),
            group: Some("AI".into()),
            fields: EntryFields {
                username: Some("demo".into()),
                tags: vec!["a,b".into()],
                ..Default::default()
            },
            protected_fields: vec!["URL".into()],
            has_password: true,
            has_notes: true,
            other_fields: vec![],
            modified: None,
        }
    }

    #[test]
    fn new_values_are_typed_or_generated_only_by_the_agent() {
        let form = Form {
            name: "FAKE".into(),
            group: "Test".into(),
            ..Default::default()
        };
        for (mode, generated) in [(ValueMode::Prompt, false), (ValueMode::Generate, true)] {
            let Request::Add {
                entry,
                value,
                generate,
                replace,
            } = form.request(None, mode).expect("add")
            else {
                panic!("not add")
            };
            assert_eq!(entry.group.as_deref(), Some("Test"));
            assert!(entry.notes.is_none() && value.is_none() && !replace);
            assert_eq!(generate.is_some(), generated);
        }
    }

    #[test]
    fn edits_target_uuid_and_preserve_withheld_and_untouched_fields() {
        let entry = entry();
        let mut form = Form::from_entry(&entry);
        form.name = "RENAMED".into();
        form.username.clear();
        let Request::Edit { name, changes } =
            form.request(Some(&entry), ValueMode::Keep).expect("edit")
        else {
            panic!("not edit")
        };
        assert_eq!(name, entry.id);
        assert_eq!(changes.rename.as_deref(), Some("RENAMED"));
        assert_eq!(changes.clear, [Field::Username]);
        assert!(changes.url.is_none() && changes.notes.is_none() && changes.value.is_none());
        assert!(changes.add_tags.is_empty() && changes.remove_tags.is_empty());
        form.url = "https://example.invalid".into();
        assert!(form.request(Some(&entry), ValueMode::Keep).is_err());
    }

    #[test]
    fn invalid_ports_no_changes_and_group_moves_do_not_send() {
        let entry = entry();
        let mut form = Form::from_entry(&entry);
        assert!(form.request(Some(&entry), ValueMode::Keep).is_err());
        form.port = "65536".into();
        assert!(form.request(Some(&entry), ValueMode::Generate).is_err());
        form.port.clear();
        form.group = "Other".into();
        assert!(form.request(Some(&entry), ValueMode::Prompt).is_err());
    }

    #[test]
    fn search_and_group_filter_combine() {
        let entry = entry();
        assert!(matches(&entry, "dEmO", Some("AI")));
        assert!(!matches(&entry, "FAKE", Some("Other")));
        assert!(matches(&entry, "a,b", None));
        assert!(!matches(&entry, "not present", None));
    }

    #[test]
    fn summaries_show_login_and_address() {
        let mut entry = entry();
        assert_eq!(summary(&entry), "demo");
        entry.fields.host = Some("10.0.0.1".into());
        assert_eq!(summary(&entry), "demo · 10.0.0.1");
        entry.fields.username = None;
        assert_eq!(summary(&entry), "10.0.0.1");
        entry.fields.host = None;
        assert_eq!(summary(&entry), "No login or address");
    }

    #[test]
    fn command_snippet_never_uses_the_title_as_shell_code() {
        let mut entry = entry();
        assert_eq!(
            snippet(&entry),
            "rusthorse run FAKE_KEY=11111111-2222-3333-4444-555555555555 -- your-command"
        );
        for name in ["$(touch /tmp/no); 'fake'", "9LIVES", "with space", "", "ÇA"] {
            entry.name = name.into();
            assert_eq!(
                snippet(&entry),
                "rusthorse run SECRET=11111111-2222-3333-4444-555555555555 -- your-command",
                "{name}"
            );
        }
        entry.id = "a'$(echo fake)".into();
        assert!(snippet(&entry).contains("'SECRET=a'\\''$(echo fake)'"));
    }
}
