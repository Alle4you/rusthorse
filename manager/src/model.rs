//! Metadata-only form and search logic. Never stores a revealed value.

use rusthorse::generate::Spec;
use rusthorse::protocol::{
    EntryChanges, EntryFields, EntryInfo, EntryKind, Field, NewEntry, Request, ValueChange,
};

#[derive(Clone, Default)]
pub(crate) struct Form {
    /// `None`: no particular kind ("Other").
    pub kind: Option<EntryKind>,
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
            kind: entry.fields.kind,
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
                        kind: self.kind,
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
        let mut changes = EntryChanges::default();
        if self.name != before.name {
            editable(old, "Title")?;
            rusthorse::vault::validate_name(&self.name).map_err(|e| e.to_string())?;
            changes.rename = Some(self.name.clone());
        }
        // Untouched, the row is no move: a group of another client keeps
        // its exact name (` Work `, or a `/` in it). Edited, the row is read
        // as the agent reads a path; spaces around a `/` or a doubled `/`
        // that lead back to the same text are no move. The empty path is the
        // top level. (The agent decides by the group itself, not its text.)
        let group = group_path(&self.group);
        if self.group != before.group && group != before.group {
            for component in group.split('/').filter(|c| !c.is_empty()) {
                rusthorse::vault::validate_name(component).map_err(|e| format!("Group: {e}"))?;
            }
            changes.group = Some(group);
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
        if self.kind != before.kind {
            editable(old, "Kind")?;
            match self.kind {
                Some(kind) => changes.kind = Some(kind),
                None => changes.clear.push(Field::Kind),
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
        changes.value = value.change();
        if changes.is_empty() {
            return Err("Nothing changed.".into());
        }
        Ok(Request::Edit {
            name: old.id.clone(),
            changes,
        })
    }
}

/// Whether a form offers `field` for an entry of `kind` (`None`: every
/// field). A field that has a value is shown whatever this says: a kind
/// never hides data.
pub(crate) fn offers(kind: Option<EntryKind>, field: Field) -> bool {
    !matches!(
        (kind, field),
        (
            Some(EntryKind::ApiKey | EntryKind::Login),
            Field::Host | Field::Port
        ) | (Some(EntryKind::Server), Field::Url)
            | (Some(EntryKind::Device), Field::Port)
    )
}

/// Whether the form shows the row of `field`: when the kind offers it, and
/// always when the row has text or the file withholds the field (its row is
/// empty, but the field exists and the row says it is protected).
pub(crate) fn shows(kind: Option<EntryKind>, field: Field, has_text: bool, withheld: bool) -> bool {
    offers(kind, field) || has_text || withheld
}

/// The choices of the form's Kind row, in order: "Other" first.
pub(crate) const KIND_CHOICES: [Option<EntryKind>; 5] = [
    None,
    Some(EntryKind::ApiKey),
    Some(EntryKind::Login),
    Some(EntryKind::Server),
    Some(EntryKind::Device),
];

/// How a kind is named in the form and the details.
pub(crate) fn kind_label(kind: Option<EntryKind>) -> &'static str {
    kind.map_or("Other", EntryKind::label)
}

/// A group path as the agent reads it: each component trimmed, empty ones
/// dropped, joined with `/`. The top level is the empty path.
fn group_path(text: &str) -> String {
    text.split('/')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect::<Vec<_>>()
        .join("/")
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

impl ValueMode {
    /// The change of value this choice asks the agent for.
    pub(crate) fn change(self) -> Option<ValueChange> {
        match self {
            ValueMode::Keep => None,
            ValueMode::Prompt => Some(ValueChange::Prompt),
            ValueMode::Generate => Some(ValueChange::Generate(Spec::default())),
        }
    }
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
///
/// For an API key with an endpoint, the command also gets the endpoint in a
/// variable of its own ([`url_variable`]): it is not a secret.
pub(crate) fn snippet(entry: &EntryInfo) -> String {
    let var = if is_variable_name(&entry.name) {
        entry.name.as_str()
    } else {
        "SECRET"
    };
    let quote = rusthorse::util::shell_quote;
    let secret = quote(&format!("{var}={}", entry.id));
    if entry.fields.kind == Some(EntryKind::ApiKey) && entry.fields.url.is_some() {
        // One option per line, joined by the shell's line continuation, so
        // that it reads well and still pastes as one command.
        let url = quote(&format!("{}={}", url_variable(var), entry.id));
        format!("rusthorse run {secret} \\\n  --url {url} \\\n  -- your-command")
    } else {
        format!("rusthorse run {secret} -- your-command")
    }
}

/// The variable that gets an API key's endpoint: `OPENAI_API_KEY` →
/// `OPENAI_BASE_URL` (what the OpenAI and Anthropic libraries read),
/// `GITHUB_TOKEN` → `GITHUB_BASE_URL`, anything else → `NAME_URL`.
pub(crate) fn url_variable(var: &str) -> String {
    for suffix in ["_API_KEY", "_API_TOKEN", "_TOKEN", "_KEY"] {
        if let Some(stem) = var.strip_suffix(suffix)
            && !stem.is_empty()
        {
            return format!("{stem}_BASE_URL");
        }
    }
    format!("{var}_URL")
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
        assert!(changes.group.is_none(), "the entry stays in its group");
        assert!(changes.url.is_none() && changes.notes.is_none() && changes.value.is_none());
        assert!(changes.add_tags.is_empty() && changes.remove_tags.is_empty());
        form.url = "https://example.invalid".into();
        assert!(form.request(Some(&entry), ValueMode::Keep).is_err());
    }

    #[test]
    fn invalid_ports_and_no_changes_do_not_send() {
        let entry = entry();
        let mut form = Form::from_entry(&entry);
        assert!(form.request(Some(&entry), ValueMode::Keep).is_err());
        form.port = "65536".into();
        assert!(form.request(Some(&entry), ValueMode::Generate).is_err());
    }

    /// The change an edit form sends, or its error.
    fn changes(form: &Form, entry: &EntryInfo) -> Result<EntryChanges, String> {
        match form.request(Some(entry), ValueMode::Keep)? {
            Request::Edit { name, changes } => {
                assert_eq!(name, entry.id);
                Ok(changes)
            }
            _ => panic!("not edit"),
        }
    }

    #[test]
    fn group_moves_send_the_path_as_the_agent_reads_it() {
        let entry = entry();
        let mut form = Form::from_entry(&entry);
        for (typed, sent) in [
            ("Work/Servers", "Work/Servers"),
            (" Work / Servers/ ", "Work/Servers"),
            ("//Work//Servers", "Work/Servers"),
            ("Prod", "Prod"),
        ] {
            form.group = typed.into();
            let changes = changes(&form, &entry).expect(typed);
            assert_eq!(changes.group.as_deref(), Some(sent), "{typed:?}");
            // Only the group moves: no rename, nothing cleared or set.
            assert!(
                changes.rename.is_none() && changes.clear.is_empty(),
                "{typed:?}"
            );
            assert!(changes.username.is_none() && changes.value.is_none());
            assert!(changes.add_tags.is_empty() && changes.remove_tags.is_empty());
        }
    }

    #[test]
    fn emptying_the_group_moves_to_the_top_level() {
        let entry = entry();
        let mut form = Form::from_entry(&entry);
        for typed in ["", "  ", "/", " / "] {
            form.group = typed.into();
            let changes = changes(&form, &entry).expect(typed);
            assert_eq!(changes.group.as_deref(), Some(""), "{typed:?}");
        }
        // An entry at the top level moves into a group, and stays where it
        // is when the row is left empty.
        let mut top = entry.clone();
        top.group = None;
        let mut form = Form::from_entry(&top);
        assert_eq!(form.group, "");
        assert_eq!(
            changes(&form, &top).expect_err("no move"),
            "Nothing changed."
        );
        form.group = " / ".into();
        assert_eq!(
            changes(&form, &top).expect_err("no move"),
            "Nothing changed."
        );
        form.group = "AI".into();
        assert_eq!(
            changes(&form, &top).expect("move").group.as_deref(),
            Some("AI")
        );
    }

    #[test]
    fn a_group_with_spaces_from_another_client_can_be_left_or_changed() {
        let mut entry = entry();
        entry.group = Some(" Work ".into());
        // Left as it is: another change does not move the entry.
        let mut form = Form::from_entry(&entry);
        form.port = "22".into();
        let sent = changes(&form, &entry).expect("edit");
        assert!(sent.group.is_none());
        // Changed to `Work`, which is another group: a move.
        let mut form = Form::from_entry(&entry);
        form.group = "Work".into();
        let sent = changes(&form, &entry).expect("edit");
        assert_eq!(sent.group.as_deref(), Some("Work"));
    }

    #[test]
    fn the_same_group_written_differently_is_no_move() {
        let mut entry = entry();
        entry.group = Some("Work/Servers".into());
        let mut form = Form::from_entry(&entry);
        for typed in [" Work / Servers ", "Work//Servers/", "/Work/Servers"] {
            form.group = typed.into();
            let error = changes(&form, &entry).expect_err(typed);
            assert_eq!(error, "Nothing changed.", "{typed:?}");
        }
        // Another change is sent without a move.
        form.port = "22".into();
        let changes = changes(&form, &entry).expect("edit");
        assert_eq!(changes.port, Some(22));
        assert!(changes.group.is_none());
    }

    #[test]
    fn invalid_group_names_are_refused_before_sending() {
        let entry = entry();
        let mut form = Form::from_entry(&entry);
        let long = "g".repeat(129);
        for typed in [
            "Work/Bad\u{200b}Name".to_string(),
            "Work/Tab\there".to_string(),
            format!("Work/{long}"),
        ] {
            form.group = typed.clone();
            let error = changes(&form, &entry).expect_err(&typed);
            assert!(error.starts_with("Group: the name must"), "{error}");
        }
        // 128 characters is a valid group name.
        form.group = format!("Work/{}", "g".repeat(128));
        assert!(changes(&form, &entry).is_ok());
    }

    #[test]
    fn a_rename_and_a_move_go_together() {
        let entry = entry();
        let mut form = Form::from_entry(&entry);
        form.name = "RENAMED".into();
        form.group = " Prod / Keys ".into();
        let changes = changes(&form, &entry).expect("edit");
        assert_eq!(changes.rename.as_deref(), Some("RENAMED"));
        assert_eq!(changes.group.as_deref(), Some("Prod/Keys"));
        // An invalid name stops the whole edit, the move with it.
        form.name = "Bad/Name".into();
        assert!(form.request(Some(&entry), ValueMode::Keep).is_err());
        // And an invalid group stops the rename.
        form.name = "RENAMED".into();
        form.group = "Prod/\u{202e}Keys".into();
        assert!(form.request(Some(&entry), ValueMode::Keep).is_err());
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
    fn kinds_are_sent_and_taken_away() {
        let mut form = Form {
            kind: Some(EntryKind::ApiKey),
            name: "FAKE".into(),
            ..Default::default()
        };
        let Request::Add { entry: new, .. } = form.request(None, ValueMode::Prompt).expect("add")
        else {
            panic!("not add")
        };
        assert_eq!(new.fields.kind, Some(EntryKind::ApiKey));

        let mut entry = entry();
        entry.fields.kind = Some(EntryKind::Login);
        form = Form::from_entry(&entry);
        form.kind = Some(EntryKind::Device);
        let Request::Edit { changes, .. } =
            form.request(Some(&entry), ValueMode::Keep).expect("edit")
        else {
            panic!("not edit")
        };
        assert_eq!(changes.kind, Some(EntryKind::Device));
        assert!(changes.clear.is_empty());
        form.kind = None;
        let Request::Edit { changes, .. } =
            form.request(Some(&entry), ValueMode::Keep).expect("edit")
        else {
            panic!("not edit")
        };
        assert_eq!(changes.kind, None);
        assert_eq!(changes.clear, [Field::Kind]);
        // A kind the file marks as protected is withheld, so not editable.
        entry.fields.kind = None;
        entry.protected_fields.push("Kind".into());
        form = Form::from_entry(&entry);
        form.kind = Some(EntryKind::ApiKey);
        assert!(form.request(Some(&entry), ValueMode::Keep).is_err());
    }

    #[test]
    fn each_kind_offers_its_fields() {
        use Field::{Host, Port, Url, Username};
        let offered = |kind| {
            [Username, Url, Host, Port]
                .into_iter()
                .filter(|f| offers(kind, *f))
                .collect::<Vec<_>>()
        };
        assert_eq!(offered(None), [Username, Url, Host, Port]);
        assert_eq!(offered(Some(EntryKind::ApiKey)), [Username, Url]);
        assert_eq!(offered(Some(EntryKind::Login)), [Username, Url]);
        assert_eq!(offered(Some(EntryKind::Server)), [Username, Host, Port]);
        assert_eq!(offered(Some(EntryKind::Device)), [Username, Url, Host]);
        assert_eq!(KIND_CHOICES.len(), EntryKind::ALL.len() + 1);
        // A kind never hides a row with text, nor one the file withholds.
        let api = Some(EntryKind::ApiKey);
        assert!(!shows(api, Host, false, false));
        assert!(shows(api, Host, true, false));
        assert!(shows(api, Host, false, true));
    }

    #[test]
    fn an_api_key_snippet_also_passes_the_endpoint() {
        let mut entry = entry();
        entry.name = "OPENAI_API_KEY".into();
        entry.fields.kind = Some(EntryKind::ApiKey);
        // No endpoint (here the URL is withheld): nothing to pass.
        assert!(!snippet(&entry).contains("--url"));
        entry.fields.url = Some("https://api.example.invalid/v1".into());
        assert_eq!(
            snippet(&entry),
            "rusthorse run OPENAI_API_KEY=11111111-2222-3333-4444-555555555555 \\\n  \
             --url OPENAI_BASE_URL=11111111-2222-3333-4444-555555555555 \\\n  \
             -- your-command"
        );
        // The shell reads the three lines as one command with these words.
        let script = snippet(&entry).replacen("rusthorse run", "printf '%s\\n'", 1);
        let words = std::process::Command::new("sh")
            .args(["-c", &script])
            .output()
            .expect("sh");
        assert!(words.status.success());
        assert_eq!(
            String::from_utf8_lossy(&words.stdout),
            "OPENAI_API_KEY=11111111-2222-3333-4444-555555555555\n--url\n\
             OPENAI_BASE_URL=11111111-2222-3333-4444-555555555555\n--\nyour-command\n"
        );
        // Other kinds keep the plain snippet.
        entry.fields.kind = Some(EntryKind::Login);
        assert!(!snippet(&entry).contains("--url"));
        for (var, url) in [
            ("OPENAI_API_KEY", "OPENAI_BASE_URL"),
            ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"),
            ("GITHUB_TOKEN", "GITHUB_BASE_URL"),
            ("STRIPE_KEY", "STRIPE_BASE_URL"),
            ("SECRET", "SECRET_URL"),
            ("_KEY", "_KEY_URL"),
        ] {
            assert_eq!(url_variable(var), url);
        }
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
