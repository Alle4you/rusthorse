//! Importing from GNOME Keyring or a `.env` file (ADR 0012): the windows
//! that choose what to import, and the batches sent to the agent. This app
//! sees names, labels and attributes only; the agent reads the values.

use std::collections::{BTreeSet, HashSet, VecDeque};

use rusthorse::protocol::{ImportSource, KeyringItem, KeyringPick};

use super::*;

/// One thing that can be imported, as the window shows it.
struct Candidate {
    /// What the row shows: a keyring item's label, or a variable's name.
    title: String,
    /// Under the title: a keyring item's attributes.
    subtitle: String,
    /// The keyring item's object path; `None` for a `.env` variable.
    id: Option<String>,
    /// Its attributes (keyring), from which a name can come.
    attributes: std::collections::BTreeMap<String, String>,
    locked: bool,
    check: gtk::CheckButton,
    row: adw::ActionRow,
    status: gtk::Label,
}

/// Where the names come from.
enum Naming {
    /// Keyring: the label, or the attribute in the dropdown (`keys[i - 1]`).
    Keyring {
        from: gtk::DropDown,
        keys: Vec<String>,
    },
    /// `.env`: the variable's name, after the prefix.
    Dotenv { prefix: adw::EntryRow },
}

impl Naming {
    fn name(&self, c: &Candidate) -> Option<String> {
        match self {
            Naming::Keyring { from, keys } => match from.selected() {
                0 => Some(c.title.clone()),
                i => c.attributes.get(&keys[i as usize - 1]).cloned(),
            },
            Naming::Dotenv { prefix } => {
                Some(format!("{}{}", prefix.text().to_uppercase(), c.title))
            }
        }
    }
}

/// Batches of `ImportFrom` requests waiting to be sent, one at a time.
pub(super) struct Batches {
    pub rest: VecDeque<Request>,
    /// The number of the batch being sent, from 1.
    pub index: usize,
    pub total: usize,
    /// The agent's summary of each batch done.
    pub done: Vec<String>,
}

impl Manager {
    /// Import & backup → From GNOME Keyring…: the agent asks the human
    /// before it lists the keyring's items to this app.
    pub(super) fn import_keyring(self: &Rc<Self>) {
        if self.needs_open_vault() {
            return;
        }
        self.submit(Request::KeyringItems, Pending::KeyringItems);
    }

    /// Import & backup → From a .env file…: choose the file, then the agent
    /// asks before it shows the names in it to this app.
    pub(super) fn import_dotenv(self: &Rc<Self>) {
        if self.needs_open_vault() {
            return;
        }
        let dialog = gtk::FileDialog::builder()
            .title("Import from a .env file")
            .modal(true)
            .build();
        let weak = Rc::downgrade(self);
        dialog.open(Some(&self.window), gio::Cancellable::NONE, move |result| {
            let Some(s) = weak.upgrade() else { return };
            let Ok(file) = result else { return };
            let Some(path) = file.path().and_then(|p| p.to_str().map(String::from)) else {
                s.feedback(
                    "Rusthorse imports only from a local file with a UTF-8 path.",
                    true,
                );
                return;
            };
            s.submit(
                Request::DotenvNames { path: path.clone() },
                Pending::DotenvNames { path },
            );
        });
    }

    /// The window shows which names exist only when the vault is open.
    fn needs_open_vault(&self) -> bool {
        let open = self
            .status
            .borrow()
            .as_ref()
            .is_some_and(|s| s.vault_exists && !s.locked);
        if !open {
            self.feedback(
                "Unlock the vault first: the import window marks the names that already exist.",
                true,
            );
        }
        !open
    }

    /// Choose keyring items to import.
    pub(super) fn pick_keyring(self: &Rc<Self>, items: Vec<KeyringItem>) {
        if items.is_empty() {
            self.feedback("GNOME Keyring has no items.", false);
            return;
        }
        let keys: Vec<String> = items
            .iter()
            .flat_map(|i| i.attributes.keys().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut labels = vec!["Label".to_string()];
        labels.extend(
            keys.iter()
                .map(|k| format!("Attribute {}", rusthorse::ui::dialog_text(k))),
        );
        let from =
            gtk::DropDown::from_strings(&labels.iter().map(String::as_str).collect::<Vec<_>>());
        let candidates = items
            .into_iter()
            .map(|item| {
                let subtitle = item
                    .attributes
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                candidate(
                    item.label,
                    subtitle,
                    Some(item.id),
                    item.attributes,
                    item.locked,
                )
            })
            .collect();
        self.pick(
            "Import from GNOME Keyring",
            "Tick the items to import, and choose where their names come from. The agent reads their secrets itself when you import; this window sees only labels and attributes. Locked items cannot be imported: unlock the keyring first.",
            candidates,
            Naming::Keyring { from, keys },
            None,
        );
    }

    /// Choose `.env` variables to import.
    pub(super) fn pick_dotenv(self: &Rc<Self>, path: String, names: Vec<String>) {
        if names.is_empty() {
            self.feedback("The file has no NAME=value lines.", false);
            return;
        }
        let prefix = adw::EntryRow::builder()
            .title("Prefix for every name (optional)")
            .use_markup(false)
            .build();
        let candidates = names
            .into_iter()
            .map(|name| candidate(name, String::new(), None, Default::default(), false))
            .collect();
        self.pick(
            "Import from a .env file",
            "Tick the variables to import. The agent reads their values itself when you import; this window sees only their names.",
            candidates,
            Naming::Dotenv { prefix },
            Some(path),
        );
    }

    /// The window that chooses what to import, for either source.
    fn pick(
        self: &Rc<Self>,
        title: &str,
        explanation: &str,
        candidates: Vec<Candidate>,
        naming: Naming,
        path: Option<String>,
    ) {
        let existing: HashSet<String> = self
            .entries
            .borrow()
            .iter()
            .map(|e| e.name.clone())
            .collect();
        let window = adw::Window::builder()
            .title(title)
            .transient_for(&self.window)
            .modal(true)
            .destroy_with_parent(true)
            .default_width(720)
            .default_height(640)
            .build();
        let body = column(12);

        let options = group("Import", Some(explanation));
        if let Some(path) = &path {
            options.add(&fact_row("File", path));
        }
        match &naming {
            Naming::Keyring { from, .. } => {
                options.add(&key_row("Names from", from));
            }
            Naming::Dotenv { prefix } => options.add(prefix),
        }
        let tag = adw::EntryRow::builder()
            .title("Tag for the new entries (optional)")
            .use_markup(false)
            .text("imported")
            .build();
        options.add(&tag);
        let replace = adw::SwitchRow::builder()
            .title("Replace entries that already exist")
            .build();
        options.add(&replace);
        body.append(&options);

        let search = gtk::SearchEntry::builder()
            .placeholder_text("Filter")
            .build();
        let tools = row_box(6);
        search.set_hexpand(true);
        tools.append(&search);
        let all = gtk::Button::with_label("Tick shown");
        let none = gtk::Button::with_label("Untick all");
        tools.append(&all);
        tools.append(&none);
        body.append(&tools);

        let list = gtk::ListBox::new();
        list.add_css_class("boxed-list");
        list.set_selection_mode(gtk::SelectionMode::None);
        for c in &candidates {
            list.append(&c.row);
        }
        let summary = styled("", &["dim-label"]);
        let content = column(12);
        content.append(&body);
        content.append(&list);
        content.append(&summary);
        margins(&content, 18, 24);

        let header = adw::HeaderBar::builder()
            .show_end_title_buttons(false)
            .show_start_title_buttons(false)
            .build();
        let cancel = gtk::Button::with_label("Cancel");
        header.pack_start(&cancel);
        let go = gtk::Button::with_label("Import");
        go.add_css_class("suggested-action");
        go.set_sensitive(false);
        header.pack_end(&go);
        let view = adw::ToolbarView::new();
        view.add_top_bar(&header);
        view.set_content(Some(&scrolled(&content)));
        window.set_content(Some(&view));

        let state = Rc::new((candidates, naming, existing));
        // Recompute every row's name and status, and what Import would do.
        // The rows' and the options' handlers keep this closure; it keeps
        // only weak references — to the state that holds those widgets, and
        // to the widgets whose handlers hold the state — or they would keep
        // each other alive after the window is gone.
        let refresh = {
            let state = Rc::downgrade(&state);
            let (summary, go, replace) = (summary.downgrade(), go.downgrade(), replace.downgrade());
            move || {
                let (Some(state), Some(summary), Some(go), Some(replace)) = (
                    state.upgrade(),
                    summary.upgrade(),
                    go.upgrade(),
                    replace.upgrade(),
                ) else {
                    return;
                };
                let (candidates, naming, existing) = &*state;
                let names: Vec<Option<String>> =
                    candidates.iter().map(|c| naming.name(c)).collect();
                let mut ticked = HashSet::new();
                let mut repeated = HashSet::new();
                for (c, name) in candidates.iter().zip(&names) {
                    if c.check.is_active()
                        && let Some(name) = name
                        && !ticked.insert(name.clone())
                    {
                        repeated.insert(name.clone());
                    }
                }
                let (mut chosen, mut new, mut exists, mut blocked) = (0, 0, 0, 0);
                for (c, name) in candidates.iter().zip(&names) {
                    let problem = match name {
                        _ if c.locked => Some("locked".to_string()),
                        None => Some("no such attribute".to_string()),
                        Some(n) if rusthorse::vault::validate_name(n).is_err() => {
                            Some(format!("{n} — name not allowed"))
                        }
                        Some(n) if c.check.is_active() && repeated.contains(n) => {
                            Some(format!("{n} — repeated"))
                        }
                        _ => None,
                    };
                    let text = match (&problem, name) {
                        (Some(p), _) => p.clone(),
                        (None, Some(n)) if existing.contains(n) => format!(
                            "{n} — exists, {}",
                            if replace.is_active() {
                                "replaced"
                            } else {
                                "skipped"
                            }
                        ),
                        (None, Some(n)) => format!("{n} — new"),
                        (None, None) => String::new(),
                    };
                    c.status.set_text(&rusthorse::ui::dialog_text(&text));
                    c.check.set_sensitive(!c.locked);
                    if c.check.is_active() {
                        chosen += 1;
                        if problem.is_some() {
                            blocked += 1;
                        } else if name.as_ref().is_some_and(|n| existing.contains(n)) {
                            exists += 1;
                        } else {
                            new += 1;
                        }
                    }
                }
                summary.set_text(&if blocked > 0 {
                    format!("{chosen} ticked; {blocked} cannot be imported as they are: untick them or change their names.")
                } else {
                    format!("{chosen} ticked: {new} new, {exists} existing.")
                });
                go.set_label(&format!("Import {chosen}"));
                go.set_sensitive(chosen > 0 && blocked == 0);
            }
        };
        let refresh = Rc::new(refresh);
        refresh();
        for c in &state.0 {
            let r = Rc::clone(&refresh);
            c.check.connect_toggled(move |_| r());
        }
        {
            let r = Rc::clone(&refresh);
            replace.connect_active_notify(move |_| r());
        }
        match &state.1 {
            Naming::Keyring { from, .. } => {
                let r = Rc::clone(&refresh);
                from.connect_selected_notify(move |_| r());
            }
            Naming::Dotenv { prefix } => {
                let r = Rc::clone(&refresh);
                prefix.connect_changed(move |_| r());
            }
        }
        {
            let state = Rc::clone(&state);
            // Filtering a short list needs no delay: on every change.
            search.connect_changed(move |search| {
                let wanted = search.text().to_lowercase();
                for c in &state.0 {
                    let shown = wanted.is_empty()
                        || c.title.to_lowercase().contains(&wanted)
                        || c.subtitle.to_lowercase().contains(&wanted);
                    c.row.set_visible(shown);
                }
            });
        }
        {
            let state = Rc::clone(&state);
            all.connect_clicked(move |_| {
                for c in &state.0 {
                    if c.row.is_visible() && !c.locked {
                        c.check.set_active(true);
                    }
                }
            });
        }
        {
            let state = Rc::clone(&state);
            none.connect_clicked(move |_| {
                for c in &state.0 {
                    c.check.set_active(false);
                }
            });
        }
        let w = window.downgrade();
        cancel.connect_clicked(move |_| {
            if let Some(w) = w.upgrade() {
                w.close();
            }
        });
        let weak = Rc::downgrade(self);
        let w = window.downgrade();
        go.connect_clicked(move |_| {
            let Some(s) = weak.upgrade() else { return };
            if s.job.borrow().is_some() {
                return;
            }
            let (candidates, naming, _) = &*state;
            let chosen: Vec<(&Candidate, String)> = candidates
                .iter()
                .filter(|c| c.check.is_active())
                .filter_map(|c| naming.name(c).map(|n| (c, n)))
                .collect();
            let tags: Vec<String> = Some(tag.text().trim().to_string())
                .filter(|t| !t.is_empty())
                .into_iter()
                .collect();
            // Batches whose dialogs fit, estimated as the agent builds them.
            let planned: Vec<rusthorse::import::Planned> = chosen
                .iter()
                .map(|(c, n)| rusthorse::import::Planned {
                    name: n.clone(),
                    item: c.id.as_ref().map(|id| {
                        rusthorse::keyring::describe_item(&KeyringItem {
                            id: id.clone(),
                            label: c.title.clone(),
                            attributes: c.attributes.clone(),
                            locked: c.locked,
                        })
                    }),
                })
                .collect();
            let sizes = rusthorse::import::batch_sizes(&planned, path.as_deref());
            let mut rest = chosen.into_iter();
            let requests: VecDeque<Request> = sizes
                .into_iter()
                .map(|size| {
                    let batch: Vec<(&Candidate, String)> = rest.by_ref().take(size).collect();
                    let source = match (naming, &path) {
                        (Naming::Dotenv { prefix }, Some(path)) => ImportSource::Dotenv {
                            path: path.clone(),
                            prefix: Some(prefix.text().to_uppercase()).filter(|p| !p.is_empty()),
                            names: batch.into_iter().map(|(_, n)| n).collect(),
                        },
                        _ => ImportSource::Keyring {
                            items: batch
                                .into_iter()
                                .map(|(c, name)| KeyringPick {
                                    id: c.id.clone().unwrap_or_default(),
                                    name,
                                })
                                .collect(),
                        },
                    };
                    Request::ImportFrom {
                        source,
                        tags: tags.clone(),
                        replace: replace.is_active(),
                    }
                })
                .collect();
            if let Some(w) = w.upgrade() {
                w.close();
            }
            s.send_batches(Batches {
                total: requests.len(),
                rest: requests,
                index: 0,
                done: Vec::new(),
            });
        });
        window.present();
        *self.editor.borrow_mut() = Some(window);
    }

    /// Send the next batch, or say what was imported.
    pub(super) fn send_batches(self: &Rc<Self>, mut batches: Batches) {
        match batches.rest.pop_front() {
            Some(request) => {
                batches.index += 1;
                self.submit(request, Pending::Import(batches));
            }
            None => {
                self.feedback(&format!("Imported. {}", batches.done.join("; ")), false);
                self.refresh();
            }
        }
    }

    /// The agent answered a batch.
    pub(super) fn after_batch(
        self: &Rc<Self>,
        answer: Result<Response, Failure>,
        mut batches: Batches,
    ) {
        let (i, n) = (batches.index, batches.total);
        let before = if i == 1 {
            "no batch before it was imported".to_string()
        } else {
            format!("batches 1 to {} were imported", i - 1)
        };
        match answer {
            Ok(Response::Ok { message }) => {
                batches.done.push(message);
                self.send_batches(batches);
            }
            Err(failure) if failure.uncertain => {
                self.feedback(
                    &format!(
                        "Batch {i} of {n} may or may not have been imported ({}); {before}, later ones were not. Look at the entries before importing again.",
                        failure.message
                    ),
                    true,
                );
                self.refresh();
            }
            Err(failure) => {
                self.feedback(
                    &format!(
                        "Stopped at batch {i} of {n}: {}. {before}; batch {i} and later ones were not.",
                        failure.message
                    ),
                    true,
                );
                self.refresh();
            }
            Ok(_) => {
                self.feedback(
                    &format!(
                        "Batch {i} of {n}: unexpected answer; {before}. Look at the entries before importing again."
                    ),
                    true,
                );
                self.refresh();
            }
        }
    }
}

fn candidate(
    title: String,
    subtitle: String,
    id: Option<String>,
    attributes: std::collections::BTreeMap<String, String>,
    locked: bool,
) -> Candidate {
    let check = gtk::CheckButton::new();
    check.set_valign(gtk::Align::Center);
    let row = adw::ActionRow::builder()
        .title(rusthorse::ui::dialog_text(&title))
        .use_markup(false)
        .build();
    if !subtitle.is_empty() {
        row.set_subtitle(&rusthorse::ui::dialog_text(&subtitle));
    }
    row.add_prefix(&check);
    row.set_activatable_widget(Some(&check));
    let status = styled("", &["caption"]);
    status.set_wrap(false);
    status.set_ellipsize(pango::EllipsizeMode::Middle);
    status.set_max_width_chars(36);
    row.add_suffix(&status);
    Candidate {
        title,
        subtitle,
        id,
        attributes,
        locked,
        check,
        row,
        status,
    }
}
