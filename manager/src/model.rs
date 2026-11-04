//! Metadata-only form and search logic. Never stores a revealed value.

use std::time::Duration;

use rusthorse::broker_profile::{AutomaticLocks, BrokerProfile, Preset};
use rusthorse::generate::Spec;
use rusthorse::protocol::{
    EntryChanges, EntryFields, EntryInfo, EntryKind, Field, GrantInfo, NewEntry, Request,
    ValueChange,
};
use rusthorse::vault::FIELD_BROKER;

#[derive(Clone, Default)]
pub(crate) struct Form {
    /// `None`: no particular kind ("Other").
    pub kind: Option<EntryKind>,
    pub name: String,
    pub group: String,
    /// Whether the human chose another group in the form's list. `None`:
    /// decided by comparing `group` with the entry's group as text.
    pub group_edited: Option<bool>,
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
            group_edited: None,
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
            for component in group_path(&self.group).split('/').filter(|c| !c.is_empty()) {
                rusthorse::vault::validate_name(component).map_err(|e| format!("Group: {e}"))?;
            }
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
        // its exact name (` Work `, or a `/` in it). Edited, the row is sent
        // as the agent reads a path (the empty path is the top level), and
        // the agent decides by the group itself whether it is a move: text
        // alone cannot tell a group named `Work/Servers` from `Work` →
        // `Servers`.
        let group = group_path(&self.group);
        if self.group_edited.unwrap_or(self.group != before.group) {
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
/// The groups an entry form offers: every group that holds an entry, and the
/// groups above it (`home` for `home/routers`), sorted; the top level is not
/// one of them. Paths as the agent shows them (names joined by `/`).
pub(crate) fn group_choices(entries: &[EntryInfo]) -> Vec<String> {
    let mut groups = std::collections::BTreeSet::new();
    for path in entries.iter().filter_map(|e| e.group.as_deref()) {
        let parts: Vec<&str> = path.split('/').collect();
        for end in 1..=parts.len() {
            groups.insert(parts[..end].join("/"));
        }
    }
    groups.into_iter().collect()
}

/// A typed group path as the agent reads it: each part trimmed, empty parts
/// left out, joined by `/`; empty is the top level.
pub(crate) fn group_path(text: &str) -> String {
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

/// The command that gives an entry to a program. The entry is named by its
/// UUID, which no rename or duplicate title can make ambiguous.
///
/// An entry with a usable broker profile (ADR 0013) is given through the
/// credential broker: the command gets a temporary token and the broker's
/// address, in the variables its preset's clients read
/// ([`broker_variables`]), never the value. Any other entry is given by
/// value, in a variable named after the entry when that is a valid variable
/// name; for an API key with an endpoint, the command also gets the
/// endpoint in a variable of its own ([`url_variable`]): it is not a secret.
pub(crate) fn snippet(entry: &EntryInfo) -> String {
    let quote = rusthorse::util::shell_quote;
    // One option per line, joined by the shell's line continuation, so that
    // it reads well and still pastes as one command.
    if let Some(profile) = &entry.broker {
        let (token, url) = broker_variables(profile.preset);
        let token = quote(&format!("{token}={}", entry.id));
        let url = quote(&format!("{url}={}", entry.id));
        return format!(
            "rusthorse run \\\n  --broker {token} \\\n  --url {url} \\\n  -- your-command"
        );
    }
    let var = if is_variable_name(&entry.name) {
        entry.name.as_str()
    } else {
        "SECRET"
    };
    let secret = quote(&format!("{var}={}", entry.id));
    if entry.fields.kind == Some(EntryKind::ApiKey) && entry.fields.url.is_some() {
        let url = quote(&format!("{}={}", url_variable(var), entry.id));
        format!("rusthorse run {secret} \\\n  --url {url} \\\n  -- your-command")
    } else {
        format!("rusthorse run {secret} -- your-command")
    }
}

/// The variables that get the token and the broker's address in a command
/// given an entry through the broker: those its preset's libraries read, as
/// the recipes of `rusthorse guide ai` bind them. The Anthropic libraries
/// take their key from `ANTHROPIC_API_KEY`, so the token goes there and
/// `run` replaces whatever key that variable held in the environment (the
/// `anthropic` preset takes the token as `x-api-key` or as `Authorization:
/// Bearer`, however a library sends it); they read `ANTHROPIC_BASE_URL`. A
/// library that also sends `ANTHROPIC_AUTH_TOKEN`, when the environment
/// sets it, presents something other than the token and is refused, which
/// the note says ([`broker_snippet_note`]), with Claude Code's own recipe.
/// The OpenAI libraries read `OPENAI_API_KEY` and `OPENAI_BASE_URL`.
pub(crate) fn broker_variables(preset: Preset) -> (&'static str, &'static str) {
    match preset {
        Preset::Anthropic => ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"),
        Preset::Openai | Preset::OpenaiCompatible => ("OPENAI_API_KEY", "OPENAI_BASE_URL"),
    }
}

/// What the explanation of a command through the broker adds for a
/// preset, if anything. For `anthropic`: the command suits the Anthropic
/// libraries, which must not find another credential in
/// `ANTHROPIC_AUTH_TOKEN`; and Claude Code, which reads the token from
/// `ANTHROPIC_AUTH_TOKEN` and must not find a key in `ANTHROPIC_API_KEY`,
/// has a recipe of its own in `rusthorse guide ai`.
pub(crate) fn broker_snippet_note(preset: Preset) -> Option<&'static str> {
    match preset {
        Preset::Anthropic => Some(
            "This command suits the Anthropic libraries. Unset ANTHROPIC_AUTH_TOKEN if your environment sets it: a library that sends it as well presents something other than the token, and the broker refuses the request. Claude Code has a recipe of its own in rusthorse guide ai: the token in ANTHROPIC_AUTH_TOKEN, with ANTHROPIC_API_KEY unset.",
        ),
        Preset::Openai | Preset::OpenaiCompatible => None,
    }
}

/// An entry's broker profile (ADR 0013) as the agent reports it: a usable
/// one in [`EntryInfo::broker`], a protected one among the protected
/// fields, one this Rusthorse cannot read among the other fields.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Profile<'a> {
    /// Commands can get a grant for the entry.
    Usable(&'a BrokerProfile),
    /// The file marks the profile as protected: it is withheld like a
    /// secret, and cannot be used.
    Protected,
    /// The stored profile cannot be read, so it cannot be used.
    Unusable,
    /// The entry has no profile.
    Absent,
}

/// What the agent reports about `entry`'s broker profile.
pub(crate) fn profile(entry: &EntryInfo) -> Profile<'_> {
    let named = |fields: &[String]| fields.iter().any(|f| f == FIELD_BROKER);
    match &entry.broker {
        Some(profile) => Profile::Usable(profile),
        None if named(&entry.protected_fields) => Profile::Protected,
        None if named(&entry.other_fields) => Profile::Unusable,
        None => Profile::Absent,
    }
}

/// The rows an entry's details show for a usable profile: its preset and
/// the revision of it the human approved, then what approval dialogs show
/// ([`BrokerProfile::describe`]).
pub(crate) fn profile_facts(profile: &BrokerProfile) -> Vec<(String, String)> {
    let mut facts = vec![(
        "Preset".to_string(),
        format!(
            "{} ({}), revision {}",
            profile.preset.label(),
            profile.preset,
            profile.revision
        ),
    )];
    facts.extend(profile.describe());
    facts
}

/// The label of the fact that says whether a grant's destination answered
/// requests with `401 Unauthorized`; every grant has it.
pub(crate) const KEY_REFUSED: &str = "Key refused";

/// How the grants page shows one grant of the credential broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantRow {
    /// The grant's ID, which a revocation names.
    pub id: String,
    /// Whether revoking it would end anything: a revoked grant is listed
    /// until its command ends, but has ended already.
    pub revocable: bool,
    /// Whether its destination answered some of its requests with `401
    /// Unauthorized`, as last listed: the page draws that fact
    /// ([`KEY_REFUSED`]) as a warning.
    pub key_refused: bool,
    /// Label and value pairs, in the order shown.
    pub facts: Vec<(&'static str, String)>,
}

impl GrantRow {
    /// The row for `grant`. A [`GrantInfo`] holds no token, so neither does
    /// the row.
    pub(crate) fn new(grant: &GrantInfo) -> Self {
        Self::of(grant, false)
    }

    /// The row for a grant the agent listed before and lists no more: it has
    /// ended. The page keeps it in its place while it is shown, so that no
    /// other grant's button moves under the pointer, with what was last
    /// listed. The same facts as [`GrantRow::new`], in the same order.
    pub(crate) fn ended(grant: &GrantInfo) -> Self {
        Self::of(grant, true)
    }

    fn of(grant: &GrantInfo, gone: bool) -> Self {
        let revoked = grant.state == "revoked";
        let used = match grant.max_requests {
            Some(limit) => format!("{} of {limit}", grant.requests),
            None => format!("{} (no limit)", grant.requests),
        };
        Self {
            id: grant.id.clone(),
            revocable: !revoked && !gone,
            key_refused: grant.unauthorized.is_some_and(|n| n > 0),
            facts: vec![
                ("Entry", grant.entry.clone()),
                (
                    "Destination",
                    format!("{} ({})", grant.destination, grant.preset.label()),
                ),
                ("Command", grant.command.clone()),
                // Process names, which any program chooses: labelled as the
                // agent's dialogs label them.
                ("Requested by (unverified)", grant.requester.clone()),
                ("Token variable", grant.var.clone()),
                (
                    "State",
                    if gone {
                        "Ended: the agent no longer lists it".to_string()
                    } else {
                        grant_state(&grant.state)
                    },
                ),
                ("Started", grant.started.clone()),
                (
                    "Ends",
                    if revoked || gone {
                        "It has ended.".to_string()
                    } else {
                        ends_in(grant.ends_in_secs)
                    },
                ),
                (
                    "Requests",
                    if gone {
                        format!("{used} when last listed")
                    } else {
                        format!("{used}; {} in flight", grant.in_flight)
                    },
                ),
                // Always there, whatever the count: the page then sets its
                // text in place.
                (
                    KEY_REFUSED,
                    key_refused_text(grant.unauthorized, revoked || gone, gone),
                ),
                (
                    "Automatic locks",
                    match grant.automatic_locks {
                        AutomaticLocks::End => {
                            "End it: the screen locking, suspend and the idle timeout".to_string()
                        }
                        AutomaticLocks::Continue => {
                            "Do not end it: it keeps working while the screen or the vault is locked".to_string()
                        }
                    },
                ),
                ("ID", grant.id.clone()),
            ],
        }
    }
}

/// What a grant's [`KEY_REFUSED`] fact says: how many of its requests the
/// destination answered with `401 Unauthorized` — it did not accept the
/// value the broker sent from the entry — and what to do about it. The
/// agent counts only requests the broker forwarded: the broker's own `401`,
/// for a request without the grant's token, never reaches the destination.
/// `unauthorized` is `None` from an agent that does not count them; `ended`
/// says that the grant has ended already, so that a change of the value no
/// longer ends it; `gone`, that the count is the one last listed.
fn key_refused_text(unauthorized: Option<u64>, ended: bool, gone: bool) -> String {
    let requests = match unauthorized {
        None => return "Not reported".into(),
        Some(0) if gone => return "No, when last listed".into(),
        Some(0) => return "No".into(),
        Some(1) => "1 request".to_string(),
        Some(n) => format!("{n} requests"),
    };
    format!(
        "{requests} answered 401 Unauthorized{}: the destination did not accept the entry's value. If it is wrong, revoked, or not of the kind the destination expects, replace it with Change the value… in the entry's details{}",
        if gone { " when last listed" } else { "" },
        if ended {
            "."
        } else {
            "; that ends this grant."
        },
    )
}

/// A grant's state for people; a state this build does not know is shown
/// as the agent wrote it. The agent of phase 1 also lists a grant as
/// `starting` while the run it belongs to is prepared, before it admits
/// anything.
fn grant_state(state: &str) -> String {
    match state {
        "starting" => "Starting: its run is being prepared; no request is admitted yet".into(),
        "active" => "Active".into(),
        "exhausted" => {
            "Exhausted: its request limit is reached; requests already admitted finish".into()
        }
        "revoked" => "Revoked: its broker refuses every request until the command ends".into(),
        other => other.into(),
    }
}

/// When a grant ends at the latest: when its maximum lifetime passes, `secs`
/// from now. In whole minutes, rounded up so that "at the latest" stays
/// true (and a page refreshed every few seconds does not change all the
/// time).
fn ends_in(secs: u64) -> String {
    match secs.div_ceil(60) {
        0 => "now".into(),
        minutes => format!(
            "in {} at the latest",
            rusthorse::util::format_duration(Duration::from_secs(minutes.saturating_mul(60)))
        ),
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
            broker: None,
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
        // Edited to ` / `, the row is sent; the agent finds the entry
        // already at the top level and drops the move.
        form.group = " / ".into();
        assert_eq!(
            changes(&form, &top).expect("sent").group.as_deref(),
            Some("")
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
    fn a_new_entry_with_an_invalid_group_is_refused_before_sending() {
        let form = Form {
            name: "FAKE".into(),
            group: "Work/Bad\u{200b}Name".into(),
            ..Default::default()
        };
        let error = form.request(None, ValueMode::Prompt).expect_err("refused");
        assert!(error.starts_with("Group: "), "{error}");
    }

    #[test]
    fn the_form_offers_every_group_and_the_groups_above_it() {
        let mut entries = Vec::new();
        for group in [
            Some("home/routers"),
            Some("home/firewalls"),
            Some("AI"),
            None,
            Some("AI"),
        ] {
            let mut e = entry();
            e.group = group.map(str::to_string);
            entries.push(e);
        }
        assert_eq!(
            group_choices(&entries),
            ["AI", "home", "home/firewalls", "home/routers"]
        );
        assert!(group_choices(&[]).is_empty());
    }

    #[test]
    fn a_group_chosen_in_the_list_is_sent_even_when_it_reads_the_same() {
        // The entry is in a group of another client named `Work/Servers`;
        // the human chose "New group…" and typed `Work/Servers`, meaning the
        // nested groups: sent, for the agent to decide by the group itself.
        let mut entry = entry();
        entry.group = Some("Work/Servers".into());
        let mut form = Form::from_entry(&entry);
        form.group_edited = Some(true);
        let sent = changes(&form, &entry).expect("sent");
        assert_eq!(sent.group.as_deref(), Some("Work/Servers"));
        // Not chosen: not sent, whatever the text.
        form.group = "Elsewhere".into();
        form.group_edited = Some(false);
        assert_eq!(
            changes(&form, &entry).expect_err("untouched"),
            "Nothing changed."
        );
    }

    #[test]
    fn an_edited_group_row_is_sent_for_the_agent_to_decide() {
        // The entry is in a group whose path reads `Work/Servers`: it may be
        // the nested `Work` → `Servers`, or one group of another client
        // with a `/` in its name. Text alone cannot tell, so an edited row
        // is sent, normalized, and the agent compares the groups themselves
        // (and drops a move to the group the entry is in).
        let mut entry = entry();
        entry.group = Some("Work/Servers".into());
        let mut form = Form::from_entry(&entry);
        for typed in [" Work / Servers ", "Work//Servers/", "/Work/Servers"] {
            form.group = typed.into();
            let sent = changes(&form, &entry).expect(typed);
            assert_eq!(sent.group.as_deref(), Some("Work/Servers"), "{typed:?}");
        }
        // Left as it is, the row is not sent, with or without other changes.
        let mut form = Form::from_entry(&entry);
        assert_eq!(
            changes(&form, &entry).expect_err("untouched"),
            "Nothing changed."
        );
        form.port = "22".into();
        let sent = changes(&form, &entry).expect("edit");
        assert_eq!(sent.port, Some(22));
        assert!(sent.group.is_none());
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

    /// A usable broker profile of `preset`, with the defaults of its latest
    /// revision.
    pub fn usable(preset: Preset) -> BrokerProfile {
        let mut request = rusthorse::broker_profile::ProfileRequest::new(preset);
        if preset == Preset::OpenaiCompatible {
            request.origin = Some("https://api.deepseek.example".into());
        }
        request.resolve().expect("a valid profile")
    }

    #[test]
    fn an_entry_with_a_usable_profile_is_given_through_the_broker() {
        let mut entry = entry();
        entry.name = "ANTHROPIC_API_KEY".into();
        entry.fields.kind = Some(EntryKind::ApiKey);
        entry.fields.url = Some("https://api.anthropic.com".into());
        entry.broker = Some(usable(Preset::Anthropic));
        // The token in the variable the Anthropic libraries take their key
        // from: `run` replaces any key the environment holds there.
        assert_eq!(
            snippet(&entry),
            "rusthorse run \\\n  \
             --broker ANTHROPIC_API_KEY=11111111-2222-3333-4444-555555555555 \\\n  \
             --url ANTHROPIC_BASE_URL=11111111-2222-3333-4444-555555555555 \\\n  \
             -- your-command"
        );
        // The shell reads the four lines as one command with these words.
        let script = snippet(&entry).replacen("rusthorse run", "printf '%s\\n'", 1);
        let words = std::process::Command::new("sh")
            .args(["-c", &script])
            .output()
            .expect("sh");
        assert!(words.status.success());
        assert_eq!(
            String::from_utf8_lossy(&words.stdout),
            "--broker\nANTHROPIC_API_KEY=11111111-2222-3333-4444-555555555555\n--url\n\
             ANTHROPIC_BASE_URL=11111111-2222-3333-4444-555555555555\n--\nyour-command\n"
        );
        // The variables are those the preset's clients read, whatever the
        // entry is called, and whatever its kind.
        for (preset, token, url) in [
            (Preset::Openai, "OPENAI_API_KEY", "OPENAI_BASE_URL"),
            (
                Preset::OpenaiCompatible,
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
            ),
        ] {
            entry.name = "with space".into();
            entry.fields.kind = None;
            entry.broker = Some(usable(preset));
            let text = snippet(&entry);
            assert!(
                text.starts_with(&format!(
                    "rusthorse run \\\n  --broker {token}={} ",
                    entry.id
                )),
                "{text}"
            );
            assert!(
                text.contains(&format!("--url {url}={} ", entry.id)),
                "{text}"
            );
        }
        // The entry's UUID is quoted for the shell like any other.
        entry.id = "a'$(echo fake)".into();
        let text = snippet(&entry);
        assert!(
            text.contains("--broker 'OPENAI_API_KEY=a'\\''$(echo fake)'"),
            "{text}"
        );
        assert!(
            text.contains("--url 'OPENAI_BASE_URL=a'\\''$(echo fake)'"),
            "{text}"
        );
    }

    /// `rusthorse guide ai`, the guide for AI agents, whose recipes the
    /// commands through the broker and their note follow.
    const AI_GUIDE: &str = include_str!("../../src/guide/ai.md");

    #[test]
    fn commands_through_the_broker_follow_the_guide_for_ai_agents() {
        // The guide's commands for the libraries bind the same variables.
        let (token, url) = broker_variables(Preset::Anthropic);
        assert!(
            AI_GUIDE.contains(&format!(
                "--broker {token}=anthropic --url {url}=anthropic -- python app.py"
            )),
            "{token}, {url}"
        );
        let (token, url) = broker_variables(Preset::Openai);
        assert!(
            AI_GUIDE.contains(&format!(
                "--broker {token} --url {url}={token} -- python app.py"
            )),
            "{token}, {url}"
        );
        assert_eq!(
            broker_variables(Preset::OpenaiCompatible),
            broker_variables(Preset::Openai)
        );
        // The note says what would compete with the token in the
        // libraries' command, and that Claude Code's is the guide's own: where,
        // and how it differs, as the guide does.
        let note = broker_snippet_note(Preset::Anthropic).expect("a note for Anthropic");
        for said in [
            "Unset ANTHROPIC_AUTH_TOKEN if your environment sets it",
            "the broker refuses the request",
            "rusthorse guide ai",
            "the token in ANTHROPIC_AUTH_TOKEN, with ANTHROPIC_API_KEY unset",
        ] {
            assert!(note.contains(said), "{said}: {note}");
        }
        assert!(AI_GUIDE.contains("### Claude Code through the broker"));
        assert!(AI_GUIDE.contains(
            "env -u ANTHROPIC_API_KEY CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 rusthorse run --no-redact \\\n  \
             --broker ANTHROPIC_AUTH_TOKEN=anthropic --url ANTHROPIC_BASE_URL=anthropic -- claude"
        ));
        assert_eq!(broker_snippet_note(Preset::Openai), None);
        assert_eq!(broker_snippet_note(Preset::OpenaiCompatible), None);
    }

    #[test]
    fn an_entry_without_a_usable_profile_keeps_the_snippet_by_value() {
        let mut entry = entry();
        entry.name = "OPENAI_API_KEY".into();
        let by_value = "rusthorse run OPENAI_API_KEY=11111111-2222-3333-4444-555555555555 \
                        -- your-command";
        assert_eq!(profile(&entry), Profile::Absent);
        assert_eq!(snippet(&entry), by_value);
        // Protected, or unreadable: the agent cannot use it either.
        entry.protected_fields.push(FIELD_BROKER.into());
        assert_eq!(profile(&entry), Profile::Protected);
        assert_eq!(snippet(&entry), by_value);
        entry.protected_fields.retain(|f| f != FIELD_BROKER);
        entry.other_fields.push(FIELD_BROKER.into());
        assert_eq!(profile(&entry), Profile::Unusable);
        assert_eq!(snippet(&entry), by_value);
        // Fields of other names say nothing about the profile.
        entry.other_fields = vec!["Rusthorse.Other".into(), "Broker".into()];
        entry.protected_fields = vec!["rusthorse.broker".into()];
        assert_eq!(profile(&entry), Profile::Absent);
        // The agent reports a usable one in `broker`.
        let anthropic = usable(Preset::Anthropic);
        entry.broker = Some(anthropic.clone());
        assert_eq!(profile(&entry), Profile::Usable(&anthropic));
        assert!(snippet(&entry).starts_with("rusthorse run \\\n  --broker "));
    }

    #[test]
    fn the_details_describe_the_whole_profile() {
        let anthropic = usable(Preset::Anthropic);
        let facts = profile_facts(&anthropic);
        assert_eq!(
            facts[0],
            (
                "Preset".to_string(),
                "Anthropic (anthropic), revision 1".to_string()
            )
        );
        // Then exactly what an approval dialog shows.
        assert_eq!(facts[1..], anthropic.describe()[..]);
        let labels: Vec<&str> = facts.iter().map(|(label, _)| label.as_str()).collect();
        assert_eq!(
            labels,
            ["Preset", "Destination", "Allows", "Ends", "Requests"]
        );
        let compatible = profile_facts(&usable(Preset::OpenaiCompatible));
        assert_eq!(
            compatible[0].1,
            "OpenAI-compatible (openai-compatible), revision 1"
        );
        assert_eq!(compatible[1].1, "https://api.deepseek.example/v1");
    }

    /// A grant as a current agent of protocol 8 lists it: its destination
    /// answered none of its requests with `401 Unauthorized`.
    pub fn grant(id: &str, state: &str) -> GrantInfo {
        GrantInfo {
            id: id.into(),
            entry: "AI/ANTHROPIC_API_KEY (11111111)".into(),
            var: "ANTHROPIC_AUTH_TOKEN".into(),
            destination: "https://api.anthropic.com".into(),
            preset: Preset::Anthropic,
            command: "claude --print hello".into(),
            requester: "bash ← claude".into(),
            state: state.into(),
            started: "2026-11-02T10:15:00-03:00".into(),
            ends_in_secs: 11 * 3600 + 42 * 60 + 30,
            requests: 3,
            max_requests: None,
            in_flight: 1,
            unauthorized: Some(0),
            automatic_locks: AutomaticLocks::Continue,
        }
    }

    #[test]
    fn grants_are_described_field_by_field() {
        let row = GrantRow::new(&grant("g0123456789abcdef", "active"));
        assert_eq!(row.id, "g0123456789abcdef");
        assert!(row.revocable);
        assert!(!row.key_refused);
        let facts: Vec<(&str, &str)> = row.facts.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(
            facts,
            [
                ("Entry", "AI/ANTHROPIC_API_KEY (11111111)"),
                ("Destination", "https://api.anthropic.com (Anthropic)"),
                ("Command", "claude --print hello"),
                ("Requested by (unverified)", "bash ← claude"),
                ("Token variable", "ANTHROPIC_AUTH_TOKEN"),
                ("State", "Active"),
                ("Started", "2026-11-02T10:15:00-03:00"),
                // 11h42m30s: rounded up, so that it is at the latest.
                ("Ends", "in 11h43m at the latest"),
                ("Requests", "3 (no limit); 1 in flight"),
                ("Key refused", "No"),
                (
                    "Automatic locks",
                    "Do not end it: it keeps working while the screen or the vault is locked"
                ),
                ("ID", "g0123456789abcdef"),
            ]
        );
        // A limit, the automatic locks ending it, the last minutes.
        let mut limited = grant("g1", "exhausted");
        limited.max_requests = Some(3);
        limited.in_flight = 0;
        limited.automatic_locks = AutomaticLocks::End;
        limited.ends_in_secs = 59;
        let row = GrantRow::new(&limited);
        assert!(row.revocable, "an exhausted grant has not ended");
        let fact = |row: &GrantRow, key: &str| {
            row.facts
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("no {key}"))
        };
        assert_eq!(fact(&row, "Requests"), "3 of 3; 0 in flight");
        assert_eq!(fact(&row, "Ends"), "in 1m at the latest");
        assert!(fact(&row, "State").starts_with("Exhausted: "));
        assert!(fact(&row, "Automatic locks").starts_with("End it: "));
        // Never earlier than it says: a second past a minute is a minute
        // more.
        for (secs, ends) in [
            (0, "now"),
            (1, "in 1m at the latest"),
            (60, "in 1m at the latest"),
            (61, "in 2m at the latest"),
            (3600, "in 1h at the latest"),
            (3601, "in 1h1m at the latest"),
            (24 * 3600, "in 24h at the latest"),
        ] {
            limited.ends_in_secs = secs;
            assert_eq!(fact(&GrantRow::new(&limited), "Ends"), ends, "{secs}");
        }
        // Whatever an agent sends, the page draws it rather than panic.
        limited.ends_in_secs = u64::MAX;
        assert!(fact(&GrantRow::new(&limited), "Ends").ends_with("h at the latest"));
        // A revoked grant is listed until its command ends; there is
        // nothing left to revoke.
        let row = GrantRow::new(&grant("g2", "revoked"));
        assert!(!row.revocable);
        assert_eq!(fact(&row, "Ends"), "It has ended.");
        assert!(fact(&row, "State").starts_with("Revoked: "));
        // A grant whose run is being prepared can be revoked: that ends it
        // before it admits anything.
        let row = GrantRow::new(&grant("g3", "starting"));
        assert!(row.revocable);
        assert_eq!(
            fact(&row, "State"),
            "Starting: its run is being prepared; no request is admitted yet"
        );
        // A state of a newer agent is shown as it is, and can be revoked.
        let row = GrantRow::new(&grant("g4", "paused"));
        assert!(row.revocable);
        assert_eq!(fact(&row, "State"), "paused");
    }

    #[test]
    fn a_grant_says_how_many_requests_its_destination_answered_401() {
        let keys = |row: &GrantRow| row.facts.iter().map(|(k, _)| *k).collect::<Vec<_>>();
        let refused = |row: &GrantRow| {
            row.facts
                .iter()
                .find(|(k, _)| *k == "Key refused")
                .map(|(_, v)| v.clone())
                .expect("the fact")
        };
        let mut listed = grant("g0123456789abcdef", "active");
        // Every grant has it, right after its requests, whatever the count:
        // the page sets its text in place.
        let reference = keys(&GrantRow::new(&listed));
        let at = reference
            .iter()
            .position(|k| *k == "Requests")
            .expect("requests");
        assert_eq!(reference[at + 1], "Key refused");
        // Said in full once: what to do, and that it ends the grant.
        listed.unauthorized = Some(1);
        assert_eq!(
            refused(&GrantRow::new(&listed)),
            "1 request answered 401 Unauthorized: the destination did not accept the entry's value. If it is wrong, revoked, or not of the kind the destination expects, replace it with Change the value… in the entry's details; that ends this grant."
        );
        let advice = "the destination did not accept the entry's value. If it is wrong, revoked, or not of the kind the destination expects, replace it with Change the value… in the entry's details";
        for (count, now, ended, warned) in [
            // An agent that does not count them.
            (
                None,
                "Not reported".to_string(),
                "Not reported".to_string(),
                false,
            ),
            (Some(0), "No".into(), "No, when last listed".into(), false),
            (
                Some(1),
                format!("1 request answered 401 Unauthorized: {advice}; that ends this grant."),
                format!("1 request answered 401 Unauthorized when last listed: {advice}."),
                true,
            ),
            (
                Some(3),
                format!("3 requests answered 401 Unauthorized: {advice}; that ends this grant."),
                format!("3 requests answered 401 Unauthorized when last listed: {advice}."),
                true,
            ),
        ] {
            listed.unauthorized = count;
            let (row, gone) = (GrantRow::new(&listed), GrantRow::ended(&listed));
            assert_eq!(refused(&row), now, "{count:?}");
            assert_eq!(row.key_refused, warned, "{count:?}");
            // Ended, the grant keeps the count last listed, and says so.
            assert_eq!(refused(&gone), ended, "{count:?}");
            assert_eq!(gone.key_refused, warned, "{count:?}");
            assert_eq!(keys(&row), reference, "{count:?}");
            assert_eq!(keys(&gone), reference, "{count:?}");
            for r in [&row, &gone] {
                assert!(r.facts.iter().all(|(_, v)| !v.contains('\n')), "{r:?}");
            }
        }
        // A revoked grant has ended already: a change of the value does not
        // end it.
        listed.state = "revoked".into();
        listed.unauthorized = Some(2);
        let row = GrantRow::new(&listed);
        assert_eq!(
            refused(&row),
            format!("2 requests answered 401 Unauthorized: {advice}.")
        );
        assert!(row.key_refused);
        assert_eq!(keys(&row), reference);
    }

    #[test]
    fn a_grant_no_longer_listed_is_shown_as_ended_in_the_same_rows() {
        let mut listed = grant("g0123456789abcdef", "active");
        listed.max_requests = Some(10);
        let keys = |row: &GrantRow| row.facts.iter().map(|(k, _)| *k).collect::<Vec<_>>();
        let fact = |row: &GrantRow, key: &str| {
            row.facts
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("no {key}"))
        };
        for state in ["active", "exhausted", "revoked", "starting", "paused"] {
            listed.state = state.into();
            let (now, ended) = (GrantRow::new(&listed), GrantRow::ended(&listed));
            // The same rows, in the same order: the page sets their texts
            // in place.
            assert_eq!(keys(&ended), keys(&now), "{state}");
            assert!(!ended.revocable, "{state}");
            assert_eq!(ended.id, now.id);
            assert_eq!(fact(&ended, "State"), "Ended: the agent no longer lists it");
            assert_eq!(fact(&ended, "Ends"), "It has ended.");
            // Its counts are those last listed; nothing is said of requests
            // in flight, which the agent no longer reports.
            assert_eq!(fact(&ended, "Requests"), "3 of 10 when last listed");
            for key in ["Entry", "Destination", "Command", "Started", "ID"] {
                assert_eq!(fact(&ended, key), fact(&now, key), "{key}");
            }
        }
    }

    #[test]
    fn editing_an_entry_with_a_profile_never_touches_the_profile() {
        let mut entry = entry();
        entry.broker = Some(usable(Preset::Anthropic));
        let mut form = Form::from_entry(&entry);
        form.name = "RENAMED".into();
        form.tags = String::new();
        let sent = changes(&form, &entry).expect("edit");
        // A plain edit: one that sets or clears a profile is a broker_edit,
        // which this app never sends.
        assert!(!sent.touches_broker());
        assert!(sent.broker.is_none() && !sent.clear.contains(&Field::Broker));
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
