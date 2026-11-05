//! The main window. The agent is the only approval authority: every action
//! that touches a value or changes the vault is a request the agent may ask
//! the human about in its own dialog.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use gtk::{gio, glib, pango};
use rusthorse::audit::{self, AuditEvent, PageRead};
use rusthorse::protocol::{
    EntryChanges, EntryInfo, EntryKind, Field, GrantInfo, Request, Response, RevealPurpose,
    SecretString, SettingsInfo, StatusInfo,
};
use rusthorse::settings::{Key, Source};

use crate::connection::{Failure, Job};
use crate::model::{
    self, Chosen, Form, GrantRow, HISTORY_FILTERS, HistoryCounts, HistoryFilter, HistoryRow, Tone,
    ValueMode,
};

/// How long a shown value stays on screen.
const REVEAL_SECONDS: u64 = 30;
/// How often the status is polled while nothing else is pending.
const POLL_SECONDS: u32 = 5;
/// How long Start agent waits for `systemctl --user start`.
#[cfg(not(test))]
const START_AGENT_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const START_AGENT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a listing of the grants or a revocation may take in all, from
/// reaching the agent to its answer ([`Job::with_limit`]): the agent asks the
/// human nothing for them, and a revocation waits about a second at most
/// for its brokers to confirm (ADR 0013). One without an answer by then is
/// reported, and the page can be used again.
#[cfg(not(test))]
const GRANTS_LIMIT: Duration = Duration::from_secs(30);
#[cfg(test)]
const GRANTS_LIMIT: Duration = Duration::from_secs(3);

enum Pending {
    Status {
        list: bool,
    },
    List,
    Change,
    Reveal {
        title: String,
        notes: bool,
    },
    Copy {
        title: String,
    },
    /// The keyring's items, to choose what to import.
    KeyringItems,
    /// The names in this `.env` file, to choose what to import.
    DotenvNames {
        path: String,
    },
    /// A batch of an import, and the batches after it.
    Import(import_window::Batches),
}

#[path = "import_window.rs"]
mod import_window;

pub(crate) struct Manager {
    pub window: adw::ApplicationWindow,
    socket: PathBuf,
    entries: RefCell<Vec<EntryInfo>>,
    /// The group of each row in `rows`, in order, for the group headers.
    row_groups: RefCell<Vec<String>>,
    selected: RefCell<Option<String>>,
    status: RefCell<Option<StatusInfo>>,
    /// The request the human started; the controls wait for it.
    job: RefCell<Option<(Job, Pending)>>,
    /// A background status check; never blocks the controls, and runs while
    /// a request waits for the human too.
    poll: RefCell<Option<Job>>,
    /// Bumped when a request of the human's starts or ends. A status check
    /// started under an older value may describe a state that request
    /// changed, so it is ignored.
    epoch: Cell<u64>,
    /// `epoch` when the running status check started.
    poll_epoch: Cell<u64>,
    /// A status check saw the vault locked (or the agent gone) while the
    /// current request was waiting: a value, a list or an "unlocked" status
    /// it returns is older than that lock and is not used.
    lock_seen: Cell<bool>,
    closed: Cell<bool>,
    filling: Cell<bool>,
    search: gtk::SearchEntry,
    groups: gtk::DropDown,
    group_names: RefCell<Vec<String>>,
    rows: gtk::ListBox,
    detail: gtk::Box,
    status_page: gtk::Box,
    pill: gtk::Label,
    lock: gtk::Button,
    lock_hint: gtk::Label,
    message: gtk::Label,
    waiting: gtk::Box,
    actions: RefCell<Vec<gtk::Button>>,
    revealed: RefCell<Option<adw::Window>>,
    editor: RefCell<Option<adw::Window>>,
    /// The last status check found nothing listening on the socket.
    agent_down: Cell<bool>,
    /// `systemctl --user start` is running.
    starting: Cell<bool>,
    /// The pages; the grants page is listed while it is the one shown.
    stack: gtk::Stack,
    /// The grants page (ADR 0013): the note shown while the vault is
    /// locked, the line that sums up the list or says why there is none,
    /// the grants, and Revoke all.
    grants_locked: adw::PreferencesGroup,
    grants_summary: gtk::Label,
    grants_list: gtk::Box,
    revoke_all: gtk::Button,
    /// The grants shown, in the order shown ([`GrantSlot`]).
    grant_slots: RefCell<Vec<GrantSlot>>,
    /// The last listing failed: the page says why in place of the list.
    grants_failed: Cell<bool>,
    /// A listing of the grants, in the background, and `grants_epoch` when
    /// it started.
    grants_job: RefCell<Option<(Job, u64)>>,
    /// A revocation: one at a time, beside the human's request. It asks
    /// nothing, so a dialog the agent shows meanwhile does not hold it back.
    revoke_job: RefCell<Option<Job>>,
    /// Bumped when a revocation or a request of the human's ends: a listing
    /// started under another value may have been made before what it did,
    /// and show as active a grant that has ended since, so it is done
    /// again. (One answered before such an end shows what was true then.)
    grants_epoch: Cell<u64>,
    /// The history page: the audit log, read from the file the agent names
    /// in its status, and shown only while the vault is unlocked — it names
    /// entries and the commands that used them.
    history_file: gtk::Label,
    history_summary: gtk::Label,
    history_filter: gtk::DropDown,
    history_refresh: gtk::Button,
    history_list: gtk::ListBox,
    history_more: gtk::Button,
    /// What was read of the log.
    history: RefCell<History>,
    /// A page of the log being read, on a thread of its own: a file read,
    /// not a request to the agent, so it waits for nothing else.
    history_job: RefCell<Option<HistoryJob>>,
    /// Lock now was sent, and no status has been applied since: until one
    /// says otherwise, the vault counts as locked here, so that the history
    /// it cleared is not read again meanwhile.
    lock_sent: Cell<bool>,
    /// For tests: the next page read waits, once read, until this receives
    /// something (or its sender goes) before it is handed over.
    #[cfg(test)]
    history_gate: RefCell<Option<mpsc::Receiver<()>>>,
    /// The Settings page's rows (ADR 0007, section 3).
    settings: SettingsRows,
    /// The settings the rows were last set from, as the agent reported
    /// them; `None` when it reports none. The rows are set again only when
    /// the agent reports something else, so that a status check does not
    /// undo what the human is choosing.
    settings_shown: RefCell<Option<SettingsInfo>>,
    /// The rows are being set from a report, not by the human.
    settings_filling: Cell<bool>,
}

/// The rows of the Settings page: one per setting, and Apply and Revert.
struct SettingsRows {
    note: gtk::Label,
    file: gtk::Label,
    idle: adw::ComboRow,
    remember: adw::ComboRow,
    dialog: adw::ComboRow,
    suspend: adw::SwitchRow,
    screen: adw::SwitchRow,
    apply: gtk::Button,
    revert: gtk::Button,
    /// The seconds each duration row offers, in its order.
    choices: RefCell<[Vec<u64>; 3]>,
}

impl SettingsRows {
    fn durations(&self) -> [(&adw::ComboRow, Key); 3] {
        [
            (&self.idle, Key::IdleTimeout),
            (&self.remember, Key::Remember),
            (&self.dialog, Key::DialogTimeout),
        ]
    }

    /// What the rows hold now.
    fn chosen(&self) -> Option<Chosen> {
        let choices = self.choices.borrow();
        let secs = |i: usize, row: &adw::ComboRow| choices[i].get(row.selected() as usize).copied();
        Some(Chosen {
            idle_timeout_secs: secs(0, &self.idle)?,
            remember_secs: secs(1, &self.remember)?,
            dialog_timeout_secs: secs(2, &self.dialog)?,
            lock_on_suspend: self.suspend.is_active(),
            lock_on_screen_lock: self.screen.is_active(),
        })
    }
}

/// What the history page has read of the audit log since it was last
/// cleared.
#[derive(Default)]
struct History {
    /// A page was read, or the reading failed: the page does not read
    /// again by itself.
    loaded: bool,
    /// The file the records come from.
    path: Option<PathBuf>,
    /// Newest first.
    records: Vec<AuditEvent>,
    unreadable: usize,
    older: Option<audit::Cursor>,
    too_long: bool,
    /// The file changed under the last page read.
    changed: bool,
    /// Why the log could not be read.
    problem: Option<String>,
}

/// A page of the audit log being read.
struct HistoryJob {
    result: mpsc::Receiver<std::io::Result<PageRead>>,
    path: PathBuf,
    /// Older records, after those read.
    older: bool,
}

/// Plain text: never markup, and drawn through the same character filter
/// as the agent's dialogs.
fn label(text: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(rusthorse::ui::dialog_text(text))
        .use_markup(false)
        .xalign(0.0)
        .wrap(true)
        .wrap_mode(pango::WrapMode::WordChar)
        .attributes(&no_hyphens())
        .build()
}

/// Text attributes that stop Pango from drawing a hyphen where it breaks a
/// word: a value, a URL or a command must look exactly as it is.
fn no_hyphens() -> pango::AttrList {
    let list = pango::AttrList::new();
    list.insert(pango::AttrInt::new_insert_hyphens(false));
    list
}

fn styled(text: &str, classes: &[&str]) -> gtk::Label {
    let l = label(text);
    for c in classes {
        l.add_css_class(c);
    }
    l
}

fn column(spacing: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Vertical, spacing)
}

fn row_box(spacing: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Horizontal, spacing)
}

fn margins(widget: &impl IsA<gtk::Widget>, top: i32, side: i32) {
    widget.set_margin_top(top);
    widget.set_margin_bottom(top);
    widget.set_margin_start(side);
    widget.set_margin_end(side);
}

fn clear(container: &gtk::Box) {
    while let Some(child) = container.first_child() {
        container.remove(&child);
    }
}

fn scrolled(child: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    gtk::ScrolledWindow::builder()
        .child(child)
        .hexpand(true)
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build()
}

/// A page body: scrolls, and keeps its content at a readable width.
fn page(content: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    let clamp = adw::Clamp::builder()
        .maximum_size(760)
        .child(content)
        .build();
    margins(&clamp, 24, 24);
    scrolled(&clamp)
}

fn group(title: &str, description: Option<&str>) -> adw::PreferencesGroup {
    let g = adw::PreferencesGroup::builder().title(title).build();
    if let Some(d) = description {
        g.set_description(Some(d));
    }
    g
}

/// Width of the sidebar; the entry list is 340 and the details take the rest,
/// as in the approved prototype (`docs/design/manager/`).
const SIDEBAR_WIDTH: i32 = 230;

/// Width of the key column in key/value rows, so that values line up (as in
/// the prototype; longer keys wrap).
const KEY_WIDTH: i32 = 120;

/// A boxed row laid out as a key on the left and its content on the right.
fn key_row(key: &str, content: &impl IsA<gtk::Widget>) -> adw::PreferencesRow {
    let line = row_box(12);
    margins(&line, 12, 16);
    let k = styled(key, &["dim-label"]);
    k.set_width_request(KEY_WIDTH);
    k.set_valign(gtk::Align::Center);
    line.append(&k);
    line.append(content);
    let row = adw::PreferencesRow::builder()
        .title(key)
        .activatable(false)
        .child(&line)
        .build();
    // Screen readers name the row by its key, as they did the action rows
    // these replaced; its content says what it holds.
    row.upcast_ref::<gtk::Widget>()
        .update_relation(&[gtk::accessible::Relation::LabelledBy(&[k.upcast_ref()])]);
    row
}

/// A row showing metadata as plain, selectable text, through the dialogs'
/// filter.
fn fact_row(key: &str, value: &str) -> adw::PreferencesRow {
    fact_parts(key, value).0
}

/// A [`fact_row`], and the label that holds its value.
fn fact_parts(key: &str, value: &str) -> (adw::PreferencesRow, gtk::Label) {
    let v = label(value);
    v.set_selectable(true);
    v.set_hexpand(true);
    v.set_valign(gtk::Align::Center);
    (key_row(key, &v), v)
}

/// Set a [`label`]'s text, through the same filter, unless it shows that
/// text already: a label set anew loses its selection.
fn set_plain(label: &gtk::Label, text: &str) {
    let text = rusthorse::ui::dialog_text(text);
    if label.text() != text {
        label.set_text(&text);
    }
}

/// One grant on the grants page. Its group, its Revoke button and its rows
/// are kept from one listing to the next, and only the texts that changed
/// are set again: a refresh does not put another grant's button under the
/// pointer, and keeps a selection and the keyboard focus.
struct GrantSlot {
    id: String,
    group: adw::PreferencesGroup,
    revoke: gtk::Button,
    /// Each fact's key, row and value, in the order shown.
    rows: Vec<(&'static str, adw::PreferencesRow, gtk::Label)>,
    /// What the agent listed for it last.
    last: GrantInfo,
    /// Whether the last listing named it. A grant the agent no longer lists
    /// has ended; it keeps its place while the page is shown.
    listed: bool,
    /// Whether revoking it would end anything.
    revocable: bool,
}

impl GrantSlot {
    /// Show `row`: in the rows there are, when they hold the same facts.
    fn show(&mut self, row: &GrantRow) {
        let same = self
            .rows
            .iter()
            .map(|(key, ..)| *key)
            .eq(row.facts.iter().map(|(key, _)| *key));
        if same {
            for ((_, _, value), (_, text)) in self.rows.iter().zip(&row.facts) {
                set_plain(value, text);
            }
        } else {
            for (_, r, _) in self.rows.drain(..) {
                self.group.remove(&r);
            }
            for (key, text) in &row.facts {
                let (r, value) = fact_parts(key, text);
                self.group.add(&r);
                self.rows.push((key, r, value));
            }
        }
        // Requests the destination answered with 401: their count is drawn
        // as a warning while there are some, in the same label.
        for (key, _, value) in &self.rows {
            if *key == model::KEY_REFUSED {
                if row.key_refused {
                    value.add_css_class("warning");
                } else {
                    value.remove_css_class("warning");
                }
            }
        }
        self.revocable = row.revocable;
    }

    /// The agent lists it: show what it says now.
    fn listed(&mut self, grant: &GrantInfo) {
        self.show(&GrantRow::new(grant));
        self.last = grant.clone();
        self.listed = true;
        self.group.remove_css_class("dim-label");
    }

    /// The agent lists it no more: it has ended.
    fn ended(&mut self) {
        let row = GrantRow::ended(&self.last);
        self.show(&row);
        self.listed = false;
        self.group.add_css_class("dim-label");
    }
}

/// One record on the history page: its time, action and outcome, then
/// each fact on a line of its own, as plain text through the dialogs'
/// filter (any program of the user can write the log).
fn history_row(row: &HistoryRow) -> gtk::ListBoxRow {
    let body = column(4);
    margins(&body, 10, 14);
    let head = row_box(10);
    let time = styled(&row.time, &["caption", "monospace", "dim-label"]);
    time.set_selectable(true);
    head.append(&time);
    let action = styled(&row.action, &["heading"]);
    action.set_selectable(true);
    head.append(&action);
    let outcome = styled(&row.outcome, &[]);
    outcome.set_selectable(true);
    outcome.set_hexpand(true);
    match row.tone {
        Tone::Allowed => outcome.add_css_class("success"),
        Tone::Refused => outcome.add_css_class("warning"),
        Tone::Plain => {}
    }
    head.append(&outcome);
    body.append(&head);
    // Keys in a column of their own, so that the values line up.
    let facts = gtk::Grid::builder()
        .column_spacing(12)
        .row_spacing(2)
        .build();
    for (at, (key, text)) in (0..).zip(&row.facts) {
        let k = styled(key, &["caption", "dim-label"]);
        k.set_wrap(false);
        k.set_valign(gtk::Align::Start);
        facts.attach(&k, 0, at, 1, 1);
        let v = styled(text, &["caption"]);
        v.set_selectable(true);
        v.set_hexpand(true);
        facts.attach(&v, 1, at, 1, 1);
    }
    body.append(&facts);
    let r = gtk::ListBoxRow::builder()
        .activatable(false)
        .selectable(false)
        .child(&body)
        .build();
    r.set_widget_name("history-record");
    r
}

fn button(text: &str, icon: Option<&str>) -> gtk::Button {
    let Some(icon) = icon else {
        return gtk::Button::with_label(text);
    };
    let b = gtk::Button::new();
    b.set_child(Some(
        &adw::ButtonContent::builder()
            .label(text)
            .icon_name(icon)
            .use_underline(false)
            .build(),
    ));
    b
}

impl Manager {
    pub fn new(app: &adw::Application, socket: PathBuf) -> Rc<Self> {
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Rusthorse")
            .default_width(1240)
            .default_height(780)
            .build();

        // Sidebar: identity, navigation, and the lock.
        let sidebar = column(12);
        margins(&sidebar, 14, 12);
        let brand = row_box(10);
        let icon_bytes = glib::Bytes::from_static(include_bytes!(
            "../../data/icons/hicolor/scalable/apps/io.github.alle4you.Rusthorse.svg"
        ));
        let image = gtk::Image::from_gicon(&gio::BytesIcon::new(&icon_bytes));
        image.set_pixel_size(36);
        brand.append(&image);
        let name = styled("Rusthorse", &["heading"]);
        name.set_valign(gtk::Align::Center);
        name.set_hexpand(true);
        brand.append(&name);
        let pill = styled("Connecting…", &["caption", "pill-label"]);
        pill.set_valign(gtk::Align::Center);
        pill.set_wrap(false);
        brand.append(&pill);
        sidebar.append(&brand);
        let nav = gtk::ListBox::new();
        nav.add_css_class("navigation-sidebar");
        nav.set_vexpand(true);
        sidebar.append(&nav);
        let lock_hint = styled("", &["caption", "dim-label"]);
        lock_hint.set_xalign(0.5);
        sidebar.append(&lock_hint);
        let lock = button("Unlock", None);
        sidebar.append(&lock);

        let stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .hexpand(true)
            .vexpand(true)
            .build();

        // Entries: list on the left, details on the right.
        let entries_page = gtk::Paned::new(gtk::Orientation::Horizontal);
        entries_page.set_position(340);
        // A wider window widens the details, not the list.
        entries_page.set_resize_start_child(false);
        entries_page.set_shrink_start_child(false);
        entries_page.set_shrink_end_child(false);
        let left = column(10);
        margins(&left, 12, 12);
        // The narrowest the list gets when the window is narrow; it starts
        // at 340.
        left.set_width_request(260);
        let search = gtk::SearchEntry::builder()
            .placeholder_text("Search names, logins, hosts, tags")
            .build();
        left.append(&search);
        let groups = gtk::DropDown::from_strings(&["All groups"]);
        left.append(&groups);
        let rows = gtk::ListBox::new();
        rows.add_css_class("navigation-sidebar");
        left.append(&scrolled(&rows));
        let detail = column(18);
        entries_page.set_start_child(Some(&left));
        entries_page.set_end_child(Some(&page(&detail)));
        let status_page = column(18);

        // Grants of the credential broker (ADR 0013). They need no unlocked
        // vault: grants can outlive an automatic lock.
        let grants_page = column(24);
        let grants_locked = group(
            "The vault is locked",
            Some(
                "Unless its run asked otherwise (rusthorse run --broker-locks end), a grant is not ended by the automatic locks — the screen locking, suspend, the idle timeout — and keeps working while the vault is locked, until it ends. Grants are listed here, and you can revoke them.",
            ),
        );
        grants_locked.set_visible(false);
        grants_page.append(&grants_locked);
        let grants_group = group(
            "Grants of the credential broker",
            Some(
                "A command started with rusthorse run --broker gets a temporary token for each entry it uses that way, never the entry's value. The broker puts the value where the command puts its token, in a request header, only in requests to the grant's approved origin — the one the agent's dialog showed you — at any path there. A grant ends when its command ends or its lifetime passes, or earlier: when you revoke it, on Lock now, when its entry changes, on an automatic lock if its run asked for that, and in a few other cases, such as a failed save. Revoking ends it at once and closes its open requests, though one already sent may still take effect; the command keeps running, without that access. Refreshed every five seconds while shown; a grant that ends meanwhile keeps its place, marked as ended, until you leave the page.",
            ),
        );
        let revoke_all = button("Revoke all", None);
        revoke_all.set_widget_name("revoke-all");
        revoke_all.add_css_class("destructive-action");
        revoke_all.set_valign(gtk::Align::Center);
        revoke_all.set_tooltip_text(Some(
            "End every grant now: their tokens stop working and their open requests are closed.",
        ));
        revoke_all.set_sensitive(false);
        grants_group.set_header_suffix(Some(&revoke_all));
        let grants_summary = styled("", &["dim-label"]);
        grants_group.add(&grants_summary);
        grants_page.append(&grants_group);
        let grants_list = column(18);
        grants_page.append(&grants_list);

        // History: the agent's audit log, read from the file its status
        // names, as rusthorse audit reads it. Only while the vault is
        // unlocked: the log names entries and the commands that used them.
        let history_page = column(18);
        let history_group = group(
            "Audit log",
            Some(
                "What the agent records: approvals and denials, unlocks and locks, the commands it started and how they ended, the credential broker's grants and requests. Values are never recorded. Any program of yours can write to this file, so it is a record, not proof. Times are when a record was written, after you answered for an approval, by the system clock. Shown only while the vault is unlocked: the log names your entries and the commands that used them.",
            ),
        );
        let history_filter = gtk::DropDown::from_strings(&HISTORY_FILTERS.map(|(_, label)| label));
        history_filter.set_valign(gtk::Align::Center);
        history_filter.set_tooltip_text(Some("Which of the records read are shown"));
        let history_refresh = button("Refresh", Some("view-refresh-symbolic"));
        history_refresh.set_widget_name("history-refresh");
        history_refresh.set_valign(gtk::Align::Center);
        history_refresh.set_tooltip_text(Some("Read the newest records again"));
        let history_controls = row_box(8);
        history_controls.append(&history_filter);
        history_controls.append(&history_refresh);
        history_group.set_header_suffix(Some(&history_controls));
        let history_summary = styled("", &["dim-label"]);
        history_group.add(&history_summary);
        let history_file = styled("", &["caption", "dim-label"]);
        history_file.set_selectable(true);
        history_group.add(&history_file);
        history_page.append(&history_group);
        let history_list = gtk::ListBox::new();
        history_list.add_css_class("boxed-list");
        history_list.set_selection_mode(gtk::SelectionMode::None);
        history_list.set_visible(false);
        history_page.append(&history_list);
        let history_more = button("Load older", None);
        history_more.set_widget_name("history-more");
        history_more.set_halign(gtk::Align::Center);
        history_more.set_visible(false);
        history_page.append(&history_more);

        let pages: Vec<(&str, &str, &str, gtk::Widget)> = vec![
            (
                "entries",
                "Entries",
                "dialog-password-symbolic",
                entries_page.upcast(),
            ),
            (
                "grants",
                "Grants",
                "channel-secure-symbolic",
                page(&grants_page).upcast(),
            ),
            (
                "approvals",
                "Remembered approvals",
                "emblem-ok-symbolic",
                Self::planned_page(
                    "emblem-ok-symbolic",
                    "Remembered approvals",
                    "Listing and revoking single remembered approvals comes in a later version. The Status page shows how many there are; Lock now forgets all of them (commands already running are not stopped).",
                ),
            ),
            (
                "history",
                "History",
                "document-open-recent-symbolic",
                page(&history_page).upcast(),
            ),
            (
                "data",
                "Import & backup",
                "drive-harddisk-symbolic",
                gtk::Box::new(gtk::Orientation::Vertical, 0).upcast(),
            ),
            (
                "settings",
                "Settings",
                "preferences-system-symbolic",
                gtk::Box::new(gtk::Orientation::Vertical, 0).upcast(),
            ),
            (
                "status",
                "Status",
                "network-transmit-receive-symbolic",
                page(&status_page).upcast(),
            ),
            (
                "help",
                "Help",
                "help-browser-symbolic",
                gtk::Box::new(gtk::Orientation::Vertical, 0).upcast(),
            ),
            (
                "about",
                "About",
                "help-about-symbolic",
                Self::about_page(&icon_bytes),
            ),
        ];

        // Import & backup.
        let data = column(24);
        let backup_group = group(
            "Backup",
            Some(
                "A copy of the encrypted vault file, checked by the agent: it must open with the current master password. Keep copies somewhere else too.",
            ),
        );
        let backup = button("Create verified backup…", Some("document-save-symbolic"));
        backup.set_halign(gtk::Align::Start);
        backup_group.add(&backup);
        data.append(&backup_group);
        let import_group = group(
            "Import",
            Some(
                "Move secrets into Rusthorse from GNOME Keyring (for example those of a tool that keeps API keys there) or from a .env file. The agent reads the values itself; this app sees only names. Start with one, check that it works, then import the rest. The originals stay where they were — and while they are there, any program of your session can still read them: delete them once every entry works.",
            ),
        );
        let import_keyring = button("From GNOME Keyring…", Some("dialog-password-symbolic"));
        let import_dotenv = button("From a .env file…", Some("document-open-symbolic"));
        let import_buttons = row_box(12);
        import_buttons.append(&import_keyring);
        import_buttons.append(&import_dotenv);
        import_group.add(&import_buttons);
        data.append(&import_group);
        let later = group(
            "Restore",
            Some(
                "Restoring a backup comes in a later version; meanwhile, follow the restore steps in the installation guide. To look at the vault in KeePassXC, open a backup copy, never the live file.",
            ),
        );
        data.append(&later);

        // Settings: the agent's (ADR 0007, section 3).
        let settings = column(24);
        let policy = group(
            "Agent settings",
            Some(
                "The agent applies a change at once, after you approve it in its own dialog, saves it in its settings file, and forgets remembered approvals. Settings are changed only while the vault is unlocked. Any program of yours can also edit that file and restart the agent: the dialog guards changes made here, not the file. Closing this app does not lock the vault.",
            ),
        );
        let settings_note = styled("", &["dim-label"]);
        policy.add(&settings_note);
        let settings_file = styled("", &["caption", "dim-label"]);
        settings_file.set_selectable(true);
        policy.add(&settings_file);
        let combo = |title: &str, name: &str| {
            let row = adw::ComboRow::builder()
                .title(title)
                .use_markup(false)
                .use_subtitle(false)
                .build();
            row.set_widget_name(name);
            row
        };
        let switch = |title: &str, name: &str| {
            let row = adw::SwitchRow::builder()
                .title(title)
                .use_markup(false)
                .build();
            row.set_widget_name(name);
            row
        };
        let settings_rows = SettingsRows {
            note: settings_note,
            file: settings_file,
            idle: combo(Key::IdleTimeout.label(), "setting-idle"),
            remember: combo(Key::Remember.label(), "setting-remember"),
            dialog: combo(Key::DialogTimeout.label(), "setting-dialog"),
            suspend: switch(Key::LockOnSuspend.label(), "setting-suspend"),
            screen: switch(Key::LockOnScreenLock.label(), "setting-screen"),
            apply: button("Apply…", None),
            revert: button("Revert", None),
            choices: RefCell::new([vec![], vec![], vec![]]),
        };
        for (row, _) in settings_rows.durations() {
            policy.add(row);
        }
        policy.add(&settings_rows.suspend);
        policy.add(&settings_rows.screen);
        settings_rows.apply.set_widget_name("settings-apply");
        settings_rows.apply.add_css_class("suggested-action");
        settings_rows.apply.set_tooltip_text(Some(
            "Ask the agent to change the settings: it shows each old and new value in its own dialog.",
        ));
        settings_rows.revert.set_widget_name("settings-revert");
        let settings_buttons = row_box(12);
        settings_buttons.set_halign(gtk::Align::End);
        settings_buttons.append(&settings_rows.revert);
        settings_buttons.append(&settings_rows.apply);
        policy.add(&settings_buttons);
        settings.append(&policy);
        let password_group = group(
            "Master password",
            Some(
                "The agent asks for the current and the new password in its own dialogs. This app never receives them.",
            ),
        );
        let passwd = button("Change master password…", Some("dialog-password-symbolic"));
        passwd.set_halign(gtk::Align::Start);
        password_group.add(&passwd);
        settings.append(&password_group);

        // Help.
        let help = column(24);
        for (title, text) in [
            (
                "How it works",
                "Rusthorse keeps your secrets in a KeePass file that only the agent opens. This app shows names, logins, URLs, hosts and tags — never a value unless you approve it in the agent's dialog. Selecting an entry fetches nothing secret.",
            ),
            (
                "Show and Copy",
                "Show asks the agent, then displays the value in a window that hides after 30 seconds or when it loses focus; you can copy it from there. Copy asks the agent, then puts the value on the clipboard like any copied text: it stays there until you copy something else, and a clipboard history may keep it even after that. Other programs of your desktop session can read the clipboard. Paste it only where it belongs, never into a chat with an AI.",
            ),
            (
                "Use it from a command",
                "An entry's details hold two commands to copy. The first gives the command the secret in its environment after your approval; its output is redacted. The second is a template to fill in, through the credential broker: the command gets a temporary token instead, and the broker puts the key only in its requests to the origin you name and approve. Either is the way to give an AI agent a secret without showing it.",
            ),
            (
                "Grants of the credential broker",
                "A command started with rusthorse run --broker names, for each entry it uses that way, where the key goes, and the agent's dialog shows you that origin to approve. After your approval the command gets a temporary token for a grant, never the value, and the broker puts the value only in its requests to that origin, at any path there. The Grants page lists the grants in use and revokes them, also while the vault is locked.",
            ),
            (
                "History",
                "The History page shows what the agent recorded in its audit log, newest first: approvals and denials, unlocks and locks, the commands it started and how they ended, the broker's grants and requests. Values are never recorded. It reads the file the agent names, only while the vault is unlocked, and forgets it when the vault locks. Any program of yours can write to that file: it is a record, not proof.",
            ),
            (
                "If something is uncertain",
                "When the app says an outcome is unknown, the change may have happened: refresh and look before trying again. Closing this app does not cancel a dialog the agent already shows; answer it there.",
            ),
            (
                "More",
                "Guides: docs/manager.md, docs/getting-started.md, docs/threat-model.md in the source tree. Report security problems privately as SECURITY.md describes.",
            ),
        ] {
            let g = group(title, None);
            let body = label(text);
            body.add_css_class("body");
            g.add(&body);
            help.append(&g);
        }

        for (id, title, icon, widget) in pages {
            let widget = match id {
                "data" => page(&data).upcast(),
                "settings" => page(&settings).upcast(),
                "help" => page(&help).upcast(),
                _ => widget,
            };
            stack.add_titled(&widget, Some(id), title);
            let item = row_box(12);
            margins(&item, 6, 6);
            item.append(&gtk::Image::from_icon_name(icon));
            item.append(&label(title));
            let row = gtk::ListBoxRow::new();
            row.set_widget_name(id);
            row.set_child(Some(&item));
            nav.append(&row);
        }
        nav.select_row(nav.row_at_index(0).as_ref());
        let stack_ref = stack.clone();
        nav.connect_row_selected(move |_, row| {
            if let Some(row) = row {
                stack_ref.set_visible_child_name(&row.widget_name());
            }
        });

        // Content column: header bar, pages, status bar.
        let content = column(0);
        let header = adw::HeaderBar::builder()
            .show_start_title_buttons(false)
            .build();
        header.set_title_widget(Some(&adw::WindowTitle::new("Entries", "")));
        let refresh = gtk::Button::from_icon_name("view-refresh-symbolic");
        refresh.set_tooltip_text(Some("Refresh"));
        header.pack_start(&refresh);
        let add = button("New entry", Some("list-add-symbolic"));
        add.add_css_class("suggested-action");
        header.pack_end(&add);
        content.append(&header);
        content.append(&stack);
        let bar = row_box(10);
        margins(&bar, 8, 16);
        let waiting = row_box(8);
        let spinner = gtk::Spinner::new();
        spinner.set_spinning(true);
        waiting.append(&spinner);
        waiting.append(&styled(
            "Waiting for the agent — a password or approval dialog may be open.",
            &["dim-label"],
        ));
        waiting.set_visible(false);
        bar.append(&waiting);
        let message = label("");
        message.set_hexpand(true);
        bar.append(&message);
        content.append(&bar);
        let title = header
            .title_widget()
            .and_downcast::<adw::WindowTitle>()
            .expect("title");
        stack.connect_visible_child_name_notify(move |s| {
            if let Some(name) = s.visible_child_name()
                && let Some(page) = s.child_by_name(&name)
            {
                title.set_title(&s.page(&page).title().unwrap_or_default());
            }
        });

        let split = row_box(0);
        let side = column(0);
        side.add_css_class("background");
        // Fixed width. Set explicitly, because the brand label's hexpand
        // would otherwise propagate up and give the sidebar half of any spare
        // width, squeezing the details.
        side.set_width_request(SIDEBAR_WIDTH);
        side.set_hexpand(false);
        let side_header = adw::HeaderBar::builder()
            .show_end_title_buttons(false)
            .title_widget(&gtk::Label::new(None))
            .build();
        side.append(&side_header);
        side.append(&sidebar);
        sidebar.set_vexpand(true);
        split.append(&side);
        split.append(&gtk::Separator::new(gtk::Orientation::Vertical));
        content.set_hexpand(true);
        split.append(&content);
        window.set_content(Some(&split));

        let manager = Rc::new(Self {
            window,
            socket,
            entries: RefCell::new(vec![]),
            row_groups: RefCell::new(vec![]),
            selected: RefCell::new(None),
            status: RefCell::new(None),
            job: RefCell::new(None),
            poll: RefCell::new(None),
            epoch: Cell::new(0),
            poll_epoch: Cell::new(0),
            lock_seen: Cell::new(false),
            closed: Cell::new(false),
            filling: Cell::new(false),
            search,
            groups,
            group_names: RefCell::new(vec![]),
            rows,
            detail,
            status_page,
            pill,
            lock,
            lock_hint,
            message,
            waiting,
            actions: RefCell::new(vec![]),
            revealed: RefCell::new(None),
            editor: RefCell::new(None),
            agent_down: Cell::new(false),
            starting: Cell::new(false),
            stack: stack.clone(),
            grants_locked,
            grants_summary,
            grants_list,
            revoke_all,
            grant_slots: RefCell::new(vec![]),
            grants_failed: Cell::new(false),
            grants_job: RefCell::new(None),
            revoke_job: RefCell::new(None),
            grants_epoch: Cell::new(0),
            history_file,
            history_summary,
            history_filter,
            history_refresh,
            history_list,
            history_more,
            history: RefCell::new(History::default()),
            history_job: RefCell::new(None),
            lock_sent: Cell::new(false),
            #[cfg(test)]
            history_gate: RefCell::new(None),
            settings: settings_rows,
            settings_shown: RefCell::new(None),
            settings_filling: Cell::new(false),
        });
        manager.actions.replace(vec![
            refresh.clone(),
            add.clone(),
            manager.lock.clone(),
            backup.clone(),
            passwd.clone(),
            import_keyring.clone(),
            import_dotenv.clone(),
        ]);
        manager.connect_button(&import_keyring, |s| s.import_keyring());
        manager.connect_button(&import_dotenv, |s| s.import_dotenv());
        manager.show_detail();
        manager.connect_button(&refresh, |s| s.refresh());
        manager.connect_button(&add, |s| s.edit(None));
        manager.connect_button(&manager.lock, |s| s.toggle_lock());
        manager.connect_button(&passwd, |s| {
            s.submit(Request::ChangePassword, Pending::Change)
        });
        manager.connect_button(&backup, |s| s.backup());
        // Not `connect_button`: a revocation does not wait for the human's
        // request (see `revoke`).
        let weak = Rc::downgrade(&manager);
        manager.revoke_all.connect_clicked(move |_| {
            if let Some(s) = weak.upgrade() {
                s.revoke(None);
            }
        });
        // The grants are listed when their page is shown, and every few
        // seconds while it is (see the timer below). Those that ended while
        // it was shown go when it is left. The history is read when its page
        // is first shown with the vault unlocked, and then on Refresh.
        let weak = Rc::downgrade(&manager);
        manager.stack.connect_visible_child_name_notify(move |_| {
            if let Some(s) = weak.upgrade() {
                if s.showing_grants() {
                    s.list_grants();
                } else {
                    s.forget_ended_grants();
                }
                if s.showing_history() && !s.history.borrow().loaded {
                    s.read_history(false);
                }
            }
        });
        // Not `connect_button`: reading the log waits for no request.
        let weak = Rc::downgrade(&manager);
        manager.history_refresh.connect_clicked(move |_| {
            if let Some(s) = weak.upgrade() {
                s.read_history(false);
            }
        });
        let weak = Rc::downgrade(&manager);
        manager.history_more.connect_clicked(move |_| {
            if let Some(s) = weak.upgrade() {
                s.read_history(true);
            }
        });
        let weak = Rc::downgrade(&manager);
        manager.history_filter.connect_selected_notify(move |_| {
            if let Some(s) = weak.upgrade() {
                s.paint_history_rows();
            }
        });
        manager.clear_history();
        // The Settings page: a choice the human makes enables Apply and
        // Revert; Apply asks the agent.
        for (row, _) in manager.settings.durations() {
            let weak = Rc::downgrade(&manager);
            row.connect_selected_notify(move |_| {
                if let Some(s) = weak.upgrade() {
                    s.paint_settings_controls();
                }
            });
        }
        for row in [&manager.settings.suspend, &manager.settings.screen] {
            let weak = Rc::downgrade(&manager);
            row.connect_active_notify(move |_| {
                if let Some(s) = weak.upgrade() {
                    s.paint_settings_controls();
                }
            });
        }
        manager.connect_button(&manager.settings.apply, |s| s.apply_settings());
        let weak = Rc::downgrade(&manager);
        manager.settings.revert.connect_clicked(move |_| {
            if let Some(s) = weak.upgrade() {
                let shown = s.settings_shown.borrow().clone();
                s.fill_settings(shown.as_ref());
            }
        });
        manager.paint_settings(None);
        let weak = Rc::downgrade(&manager);
        manager.rows.set_header_func(move |row, before| {
            let Some(s) = weak.upgrade() else { return };
            let groups = s.row_groups.borrow();
            let this = groups.get(row.index() as usize);
            let previous = before.and_then(|b| groups.get(b.index() as usize));
            if this.is_some() && this != previous {
                let name = this.map(String::as_str).unwrap_or_default();
                let header = styled(
                    if name.is_empty() { "No group" } else { name },
                    &["caption-heading", "dim-label"],
                );
                header.set_margin_top(12);
                header.set_margin_bottom(4);
                header.set_margin_start(8);
                row.set_header(Some(&header));
            } else {
                row.set_header(None::<&gtk::Widget>);
            }
        });
        let weak = Rc::downgrade(&manager);
        manager.search.connect_search_changed(move |_| {
            if let Some(s) = weak.upgrade() {
                s.populate_rows();
            }
        });
        let weak = Rc::downgrade(&manager);
        manager.groups.connect_selected_notify(move |_| {
            if let Some(s) = weak.upgrade()
                && !s.filling.get()
            {
                s.populate_rows();
            }
        });
        let weak = Rc::downgrade(&manager);
        manager.rows.connect_row_selected(move |_, row| {
            if let Some(s) = weak.upgrade()
                && !s.filling.get()
            {
                s.hide_revealed();
                *s.selected.borrow_mut() = row.map(|r| r.widget_name().to_string());
                s.show_detail();
            }
        });
        let weak = Rc::downgrade(&manager);
        manager.window.connect_close_request(move |_| {
            if let Some(s) = weak.upgrade() {
                s.shutdown();
            }
            glib::Propagation::Proceed
        });
        let weak = Rc::downgrade(&manager);
        glib::timeout_add_local(Duration::from_millis(50), move || {
            let Some(s) = weak.upgrade().filter(|s| !s.closed.get()) else {
                return glib::ControlFlow::Break;
            };
            s.receive();
            glib::ControlFlow::Continue
        });
        let weak = Rc::downgrade(&manager);
        glib::timeout_add_seconds_local(POLL_SECONDS, move || {
            let Some(s) = weak.upgrade().filter(|s| !s.closed.get()) else {
                return glib::ControlFlow::Break;
            };
            s.poll_status();
            if s.showing_grants() {
                s.list_grants();
            }
            glib::ControlFlow::Continue
        });
        manager
    }

    /// Forget what is shown and stop talking to the agent. Called when the
    /// window closes and when the application shuts down.
    pub fn shutdown(&self) {
        self.closed.set(true);
        self.job.borrow_mut().take();
        self.poll.borrow_mut().take();
        self.grants_job.borrow_mut().take();
        self.revoke_job.borrow_mut().take();
        self.history_job.borrow_mut().take();
        self.hide_revealed();
        if let Some(editor) = self.editor.borrow_mut().take() {
            editor.close();
        }
        self.clear_entries();
    }

    fn planned_page(icon: &str, title: &str, text: &str) -> gtk::Widget {
        // StatusPage descriptions are markup: these texts are fixed and
        // contain no markup characters.
        adw::StatusPage::builder()
            .icon_name(icon)
            .title(title)
            .description(text)
            .build()
            .upcast()
    }

    fn about_page(icon_bytes: &glib::Bytes) -> gtk::Widget {
        let about = column(10);
        about.set_valign(gtk::Align::Center);
        let image = gtk::Image::from_gicon(&gio::BytesIcon::new(icon_bytes));
        image.set_pixel_size(128);
        about.append(&image);
        for (text, classes) in [
            ("Rusthorse", &["title-1"][..]),
            (
                concat!("Version ", env!("CARGO_PKG_VERSION")),
                &["dim-label"][..],
            ),
            (
                "A local secrets vault whose secrets you use with your approval.",
                &[][..],
            ),
            (
                "GNU General Public License, version 3 or later.",
                &["caption", "dim-label"][..],
            ),
        ] {
            let l = styled(text, classes);
            l.set_xalign(0.5);
            l.set_justify(gtk::Justification::Center);
            about.append(&l);
        }
        page(&about).upcast()
    }

    fn connect_button(self: &Rc<Self>, button: &gtk::Button, action: impl Fn(&Rc<Self>) + 'static) {
        let weak = Rc::downgrade(self);
        button.connect_clicked(move |_| {
            if let Some(s) = weak.upgrade()
                && s.job.borrow().is_none()
            {
                action(&s);
            }
        });
    }

    pub fn refresh(self: &Rc<Self>) {
        self.submit(Request::Status, Pending::Status { list: true });
    }

    fn toggle_lock(self: &Rc<Self>) {
        if self.agent_down.get() {
            self.start_agent();
            return;
        }
        if self
            .status
            .borrow()
            .as_ref()
            .is_some_and(|s| !s.vault_exists)
        {
            self.create_vault();
            return;
        }
        let locked = self.status.borrow().as_ref().is_none_or(|s| s.locked);
        if locked {
            self.submit(Request::Unlock, Pending::Change);
        } else {
            self.lock_sent.set(true);
            self.hide_revealed();
            self.clear_entries();
            self.submit(Request::Lock, Pending::Change);
        }
    }

    /// Ask the agent to create the vault. The agent, not this app, asks for
    /// the master password: this app never sees it.
    fn create_vault(self: &Rc<Self>) {
        self.submit(Request::CreateVault, Pending::Change);
    }

    /// Ask systemd to start the agent's service. The agent must not be a
    /// child of this app (or of any program an AI controls): started by
    /// systemd, it runs outside their process trees, as at login.
    fn start_agent(self: &Rc<Self>) {
        if self.starting.get() || self.job.borrow().is_some() {
            return;
        }
        let started = gio::Subprocess::newv(
            &[
                std::ffi::OsStr::new("systemctl"),
                std::ffi::OsStr::new("--user"),
                std::ffi::OsStr::new("start"),
                std::ffi::OsStr::new("rusthorse-agent.service"),
            ],
            gio::SubprocessFlags::STDOUT_SILENCE | gio::SubprocessFlags::STDERR_PIPE,
        );
        let process = match started {
            Ok(process) => process,
            Err(e) => {
                self.feedback(
                    &format!(
                        "Cannot run systemctl: {e}. Start the agent as the installation guide says."
                    ),
                    true,
                );
                return;
            }
        };
        self.starting.set(true);
        self.set_busy(true);
        self.feedback("Starting the agent…", false);
        // systemctl normally answers at once; one that hangs is stopped.
        let late = Rc::new(Cell::new(false));
        {
            let (late, process) = (Rc::clone(&late), process.clone());
            glib::timeout_add_local_once(START_AGENT_TIMEOUT, move || {
                if process.identifier().is_some() {
                    late.set(true);
                    process.force_exit();
                }
            });
        }
        let weak = Rc::downgrade(self);
        let waited = process.clone();
        process.communicate_utf8_async(None, gio::Cancellable::NONE, move |result| {
            let Some(s) = weak.upgrade() else { return };
            s.starting.set(false);
            s.set_busy(false);
            if late.get() {
                s.feedback(
                    &format!(
                        "systemctl did not finish within {} seconds and was stopped; try again, or start the agent as the installation guide says.",
                        START_AGENT_TIMEOUT.as_secs()
                    ),
                    true,
                );
                return;
            }
            match result {
                Ok(_) if waited.is_successful() => {
                    s.feedback("The agent was started.", false);
                    s.refresh();
                    // The agent needs a moment to listen on its socket.
                    let weak = Rc::downgrade(&s);
                    glib::timeout_add_local_once(Duration::from_millis(500), move || {
                        if let Some(s) = weak.upgrade()
                            && s.agent_down.get()
                        {
                            s.refresh();
                        }
                    });
                }
                Ok((_, stderr)) => {
                    let why = stderr.map(|e| e.trim().to_string()).unwrap_or_default();
                    s.feedback(
                        &format!(
                            "The agent could not be started ({}). Install it as the installation guide says.",
                            if why.is_empty() { "systemctl failed" } else { why.as_str() }
                        ),
                        true,
                    );
                }
                Err(e) => s.feedback(&format!("Cannot run systemctl: {e}."), true),
            }
        });
    }

    /// Check the status in the background, also while a request waits for
    /// the human, so that a lock made elsewhere is seen meanwhile.
    fn poll_status(&self) {
        if self.closed.get() || self.poll.borrow().is_some() {
            return;
        }
        if let Ok(job) = Job::start(self.socket.clone(), Request::Status) {
            self.poll_epoch.set(self.epoch.get());
            *self.poll.borrow_mut() = Some(job);
        }
    }

    /// Whether the grants page is the one shown.
    fn showing_grants(&self) -> bool {
        self.stack.visible_child_name().as_deref() == Some("grants")
    }

    /// List the grants in the background; never blocks the controls, and
    /// needs no unlocked vault. A listing already under way is not doubled:
    /// its result follows, or a new listing if that result is stale.
    fn list_grants(self: &Rc<Self>) {
        if self.closed.get() || self.grants_job.borrow().is_some() {
            return;
        }
        match Job::with_limit(self.socket.clone(), Request::Grants, GRANTS_LIMIT) {
            Ok(job) => *self.grants_job.borrow_mut() = Some((job, self.grants_epoch.get())),
            Err(e) => self.paint_grants(Err(e)),
        }
    }

    /// Something that can end grants is over: a listing under way may have
    /// been made before it, and is not shown.
    fn grants_changed(&self) {
        self.grants_epoch.set(self.grants_epoch.get() + 1);
    }

    /// Revoke one grant, or every grant (`None`). Like Lock now, it needs no
    /// approval. It does not wait for the human's request either: a dialog
    /// the agent shows meanwhile does not hold back a revocation, which
    /// only takes away. One at a time.
    fn revoke(self: &Rc<Self>, id: Option<String>) {
        if self.closed.get() || self.revoke_job.borrow().is_some() {
            return;
        }
        match Job::with_limit(
            self.socket.clone(),
            Request::RevokeGrant { id },
            GRANTS_LIMIT,
        ) {
            Ok(job) => {
                *self.revoke_job.borrow_mut() = Some(job);
                self.message.set_text("");
                self.update_revoke_buttons();
            }
            Err(e) => self.feedback(&e, true),
        }
    }

    /// The agent answered a revocation: say what it did, and list again.
    fn after_revoke(self: &Rc<Self>, answer: Result<Response, Failure>) {
        self.grants_changed();
        match answer {
            Ok(Response::Ok { message }) => self.feedback(&message, false),
            Ok(_) => self.feedback("Unexpected answer. Refresh and look before retrying.", true),
            Err(failure) => self.feedback(&failure.text(), true),
        }
        self.update_revoke_buttons();
        self.list_grants();
        self.poll_status();
    }

    /// Make the Revoke buttons usable when there is something to revoke and
    /// no revocation under way. Revoke all also stays usable when the grants
    /// could not be listed: it may work all the same, and only takes away.
    fn update_revoke_buttons(&self) {
        let idle = self.revoke_job.borrow().is_none();
        let mut any = false;
        for slot in self.grant_slots.borrow().iter() {
            slot.revoke.set_sensitive(idle && slot.revocable);
            any |= slot.revocable;
        }
        self.revoke_all
            .set_sensitive(idle && (any || self.grants_failed.get()));
    }

    /// Show the grants listed, or why they could not be listed (in place of
    /// the list, which may be out of date then).
    ///
    /// Each grant keeps its place: its group and its Revoke button stay
    /// from one listing to the next, and only the texts that changed are
    /// set again ([`GrantSlot`]). A new grant comes last. A grant the agent
    /// no longer lists has ended: while the page is shown it stays where it
    /// was, marked so — collapsing it would move the grants below it, and
    /// put another grant's Revoke button under the pointer. It goes when the
    /// page is left.
    fn paint_grants(self: &Rc<Self>, listed: Result<Vec<GrantInfo>, String>) {
        let grants = match listed {
            Ok(grants) => grants,
            Err(why) => {
                for slot in self.grant_slots.take() {
                    self.grants_list.remove(&slot.group);
                }
                self.grants_failed.set(true);
                self.grants_summary
                    .set_text(&rusthorse::ui::dialog_text(&why));
                self.grants_summary.add_css_class("error");
                self.update_revoke_buttons();
                return;
            }
        };
        self.grants_failed.set(false);
        self.grants_summary.remove_css_class("error");
        let mut slots = self.grant_slots.take();
        // Which slots this listing names; a slot is matched once, so that
        // an ID listed twice keeps two places.
        let mut named = vec![false; slots.len()];
        for grant in &grants {
            match (0..slots.len()).find(|&i| !named[i] && slots[i].id == grant.id) {
                Some(i) => {
                    slots[i].listed(grant);
                    named[i] = true;
                }
                None => {
                    let slot = self.grant_slot(grant);
                    self.grants_list.append(&slot.group);
                    slots.push(slot);
                    named.push(true);
                }
            }
        }
        let shown = self.showing_grants();
        let mut kept = Vec::with_capacity(slots.len());
        for (mut slot, named) in slots.into_iter().zip(named) {
            if !named {
                if !shown {
                    self.grants_list.remove(&slot.group);
                    continue;
                }
                slot.ended();
            }
            kept.push(slot);
        }
        *self.grant_slots.borrow_mut() = kept;
        self.paint_grants_summary();
        self.update_revoke_buttons();
    }

    /// The group of a grant the page did not show yet.
    fn grant_slot(self: &Rc<Self>, grant: &GrantInfo) -> GrantSlot {
        // A group's title is markup: only an ID of the exact form of one
        // goes there. Everything else from the agent is drawn as plain
        // text, through the dialogs' filter.
        let title = if rusthorse::broker_protocol::is_well_formed_grant_id(&grant.id) {
            format!("Grant {}", grant.id)
        } else {
            "Grant".to_string()
        };
        let g = group(&title, None);
        let revoke = button("Revoke", None);
        revoke.set_widget_name(&format!("revoke-{}", grant.id));
        revoke.add_css_class("destructive-action");
        revoke.set_valign(gtk::Align::Center);
        revoke.set_tooltip_text(Some(
            "End this grant now: its token stops working and its open requests are closed.",
        ));
        revoke.update_property(&[gtk::accessible::Property::Label(&format!(
            "Revoke grant {}",
            rusthorse::ui::dialog_text(&grant.id)
        ))]);
        let id = grant.id.clone();
        let weak = Rc::downgrade(self);
        revoke.connect_clicked(move |_| {
            if let Some(s) = weak.upgrade() {
                s.revoke(Some(id.clone()));
            }
        });
        g.set_header_suffix(Some(&revoke));
        let mut slot = GrantSlot {
            id: grant.id.clone(),
            group: g,
            revoke,
            rows: vec![],
            last: grant.clone(),
            listed: true,
            revocable: false,
        };
        slot.listed(grant);
        slot
    }

    /// The line above the grants: how many are listed, and how many of
    /// those shown have ended since the page was opened. Kept short once
    /// there is a grant to show, whatever the counts: a line more would move
    /// the grants below.
    fn paint_grants_summary(&self) {
        let slots = self.grant_slots.borrow();
        let listed = slots.iter().filter(|s| s.listed).count();
        let ended = slots.len() - listed;
        self.grants_summary.set_text(&match (listed, ended) {
            (0, 0) => "No grants. A command started with rusthorse run --broker gets one for each entry it uses through the broker, until it ends.".to_string(),
            (0, m) => format!("No grants now; {m} ended while this page was shown."),
            (1, 0) => "1 grant.".to_string(),
            (n, 0) => format!("{n} grants, oldest first."),
            (1, m) => format!("1 grant; {m} more ended while this page was shown."),
            (n, m) => {
                format!("{n} grants, oldest first; {m} more ended while this page was shown.")
            }
        });
    }

    /// The grants page was left: the grants that ended while it was shown
    /// go, now that nothing can move under the pointer.
    fn forget_ended_grants(&self) {
        let mut slots = self.grant_slots.borrow_mut();
        let before = slots.len();
        slots.retain(|slot| {
            if !slot.listed {
                self.grants_list.remove(&slot.group);
            }
            slot.listed
        });
        let changed = slots.len() != before;
        drop(slots);
        if changed {
            self.paint_grants_summary();
        }
    }

    /// Show the settings the agent reports — the rows set again only when
    /// they differ from what was last shown, so that a status check does not
    /// undo a choice under way — or that it reports none.
    fn paint_settings(&self, info: Option<&SettingsInfo>) {
        if self.settings_shown.borrow().as_ref() != info {
            *self.settings_shown.borrow_mut() = info.cloned();
            self.fill_settings(info);
        }
        self.paint_settings_controls();
    }

    /// Set the rows from `info`: each value, offered among the usual ones,
    /// and where it comes from; a row a flag fixes cannot be changed here.
    fn fill_settings(&self, info: Option<&SettingsInfo>) {
        let rows = &self.settings;
        let reported = info.is_some();
        for (row, _) in rows.durations() {
            row.set_visible(reported);
        }
        rows.suspend.set_visible(reported);
        rows.screen.set_visible(reported);
        rows.apply.set_visible(reported);
        rows.revert.set_visible(reported);
        let Some(info) = info else {
            set_plain(&rows.file, "");
            return;
        };
        self.settings_filling.set(true);
        set_plain(&rows.file, &format!("Saved in {}", info.file));
        let mut choices = rows.choices.borrow_mut();
        for (i, ((row, key), setting)) in rows
            .durations()
            .into_iter()
            .zip([
                &info.idle_timeout_secs,
                &info.remember_secs,
                &info.dialog_timeout_secs,
            ])
            .enumerate()
        {
            let offered = model::duration_choices(key, setting.value);
            let labels: Vec<&str> = offered.iter().map(|(_, l)| l.as_str()).collect();
            row.set_model(Some(&gtk::StringList::new(&labels)));
            choices[i] = offered.iter().map(|(s, _)| *s).collect();
            let at = choices[i]
                .iter()
                .position(|s| *s == setting.value)
                .unwrap_or(0);
            row.set_selected(at as u32);
            row.set_subtitle(&rusthorse::ui::dialog_text(&model::setting_source(
                key,
                setting.source,
            )));
            row.set_sensitive(setting.source != Source::Flag);
        }
        drop(choices);
        for (row, key, setting) in [
            (&rows.suspend, Key::LockOnSuspend, &info.lock_on_suspend),
            (
                &rows.screen,
                Key::LockOnScreenLock,
                &info.lock_on_screen_lock,
            ),
        ] {
            row.set_active(setting.value);
            row.set_subtitle(&rusthorse::ui::dialog_text(&model::setting_source(
                key,
                setting.source,
            )));
            row.set_sensitive(setting.source != Source::Flag);
        }
        self.settings_filling.set(false);
        self.paint_settings_controls();
    }

    /// The change the rows hold, if any, against the settings shown.
    fn settings_change(&self) -> Option<rusthorse::protocol::SettingsChange> {
        let shown = self.settings_shown.borrow();
        self.settings.chosen()?.change(shown.as_ref()?)
    }

    /// The note, and whether Apply and Revert can be used: Apply needs a
    /// change, the vault unlocked, and no request under way.
    fn paint_settings_controls(&self) {
        if self.settings_filling.get() {
            return;
        }
        let rows = &self.settings;
        let reported = self.settings_shown.borrow().is_some();
        let unlocked = self.vault_unlocked();
        let changed = self.settings_change().is_some();
        let idle = self.job.borrow().is_none();
        rows.apply
            .set_sensitive(reported && unlocked && changed && idle);
        rows.revert.set_sensitive(reported && changed && idle);
        let note = if self.status.borrow().is_none() {
            "Not available while the agent cannot be reached."
        } else if !reported {
            "The agent does not report its settings: it predates them, or it was started without a settings file. Restart it after an upgrade."
        } else if !unlocked {
            "Unlock the vault to change settings. Until then they are shown as they are."
        } else if changed {
            "Apply asks the agent; nothing changes until you approve in its dialog."
        } else {
            "Choose new values, then Apply."
        };
        set_plain(&rows.note, note);
    }

    /// Ask the agent to change the settings the rows changed. The agent
    /// shows the change in its own dialog; until the human approves there,
    /// nothing changes.
    fn apply_settings(self: &Rc<Self>) {
        if !self.vault_unlocked() {
            return;
        }
        if let Some(change) = self.settings_change() {
            self.submit(Request::Configure { settings: change }, Pending::Change);
        }
    }

    /// Whether the history page is the one shown.
    fn showing_history(&self) -> bool {
        self.stack.visible_child_name().as_deref() == Some("history")
    }

    /// Whether the last status said the vault is unlocked, and Lock now
    /// was not sent since.
    fn vault_unlocked(&self) -> bool {
        !self.lock_sent.get()
            && self
                .status
                .borrow()
                .as_ref()
                .is_some_and(|s| s.vault_exists && !s.locked)
    }

    /// Read a page of the audit log on a thread of its own: the newest
    /// records, or with `older`, those before the records read. Only while
    /// the vault is unlocked, from the file the agent's status names. One
    /// page at a time.
    fn read_history(self: &Rc<Self>, older: bool) {
        if self.closed.get() || self.history_job.borrow().is_some() {
            return;
        }
        if !self.vault_unlocked() {
            self.paint_history_status();
            return;
        }
        let path = PathBuf::from(
            self.status
                .borrow()
                .as_ref()
                .map(|s| s.audit_log.clone())
                .unwrap_or_default(),
        );
        let problem = if path.as_os_str().is_empty() {
            Some("The agent did not say where it writes its audit log.".to_string())
        } else if !path.is_absolute() {
            Some(format!(
                "The agent writes its audit log at a relative path, {}, which this app cannot locate.",
                path.display()
            ))
        } else {
            None
        };
        if let Some(problem) = problem {
            self.paint_history_rows_of(History {
                loaded: true,
                problem: Some(problem),
                ..History::default()
            });
            return;
        }
        // Older records come from the file the others came from; if the
        // agent names another, read it from its end.
        let cursor = {
            let history = self.history.borrow();
            match &history.older {
                Some(cursor) if older && history.path.as_ref() == Some(&path) => {
                    Some(cursor.clone())
                }
                _ if older && history.path.as_ref() == Some(&path) => return,
                _ => None,
            }
        };
        let older = cursor.is_some();
        let (tx, result) = mpsc::sync_channel(1);
        let reading = path.clone();
        #[cfg(test)]
        let gate = self.history_gate.borrow_mut().take();
        let started = std::thread::Builder::new()
            .name("manager-history".into())
            .spawn(move || {
                let read = audit::read_page(&reading, cursor.as_ref());
                #[cfg(test)]
                if let Some(gate) = gate {
                    let _ = gate.recv();
                }
                let _ = tx.send(read);
            });
        match started {
            Ok(_) => {
                *self.history_job.borrow_mut() = Some(HistoryJob {
                    result,
                    path,
                    older,
                });
                self.paint_history_status();
            }
            Err(e) => self.after_history(
                &HistoryJob {
                    result,
                    path,
                    older,
                },
                Err(format!("cannot start reading it: {e}")),
            ),
        }
    }

    /// Show a page read, or why it was not.
    fn after_history(&self, job: &HistoryJob, read: Result<PageRead, String>) {
        let mut history = std::mem::take(&mut *self.history.borrow_mut());
        if !job.older {
            history = History {
                path: Some(job.path.clone()),
                ..History::default()
            };
        }
        history.loaded = true;
        match read {
            Ok(PageRead::Page(page)) => {
                history.problem = None;
                history.changed = false;
                history.unreadable += page.unreadable;
                history.older = page.older;
                history.too_long = page.too_long;
                let from = history.records.len();
                history.records.extend(page.records);
                if job.older {
                    *self.history.borrow_mut() = history;
                    self.append_history_rows(from);
                    self.paint_history_status();
                    return;
                }
            }
            Ok(PageRead::Changed) => {
                history.changed = true;
                history.older = None;
            }
            Err(e) => {
                history.problem = Some(format!(
                    "Cannot read the audit log at {}: {e}.",
                    job.path.display()
                ));
            }
        }
        if job.older {
            *self.history.borrow_mut() = history;
            self.paint_history_status();
        } else {
            self.paint_history_rows_of(history);
        }
    }

    /// Forget what was read of the log, and say that the page shows it only
    /// while the vault is unlocked. A page being read is not shown.
    fn clear_history(&self) {
        self.history_job.borrow_mut().take();
        self.paint_history_rows_of(History::default());
    }

    /// Show `history` from its first record.
    fn paint_history_rows_of(&self, history: History) {
        *self.history.borrow_mut() = history;
        self.paint_history_rows();
    }

    /// Show the records read that the filter picks, from the first.
    fn paint_history_rows(&self) {
        while let Some(row) = self.history_list.first_child() {
            self.history_list.remove(&row);
        }
        self.append_history_rows(0);
        self.paint_history_status();
    }

    /// The filter chosen.
    fn history_filter(&self) -> HistoryFilter {
        HISTORY_FILTERS
            .get(self.history_filter.selected() as usize)
            .map_or(HistoryFilter::All, |(filter, _)| *filter)
    }

    /// Add the rows of the records read from the `from`th on, that the
    /// filter picks.
    fn append_history_rows(&self, from: usize) {
        let filter = self.history_filter();
        for event in self.history.borrow().records.iter().skip(from) {
            if filter.matches(event) {
                self.history_list
                    .append(&history_row(&HistoryRow::new(event)));
            }
        }
    }

    /// The summary, the file, and which controls are offered.
    fn paint_history_status(&self) {
        let unlocked = self.vault_unlocked();
        let reading = self.history_job.borrow().is_some();
        let history = self.history.borrow();
        let filter = self.history_filter();
        let shown = history
            .records
            .iter()
            .filter(|event| filter.matches(event))
            .count();
        self.history_refresh.set_sensitive(unlocked && !reading);
        self.history_filter.set_sensitive(unlocked);
        self.history_list.set_visible(unlocked && shown > 0);
        // A changed file has no older records to read: Refresh reads it.
        self.history_more
            .set_visible(unlocked && history.older.is_some());
        self.history_more.set_sensitive(!reading);
        set_plain(
            &self.history_file,
            &match (&history.path, unlocked) {
                (Some(path), true) => format!("Read from {}", path.display()),
                _ => String::new(),
            },
        );
        self.history_summary.remove_css_class("error");
        let text = if !unlocked {
            "Unlock the vault to see the history.".to_string()
        } else if let Some(problem) = &history.problem {
            self.history_summary.add_css_class("error");
            problem.clone()
        } else if reading && !history.loaded {
            "Reading the audit log…".to_string()
        } else if !history.loaded {
            String::new()
        } else {
            model::history_summary(HistoryCounts {
                read: history.records.len(),
                shown,
                unreadable: history.unreadable,
                more: history.older.is_some(),
                too_long: history.too_long,
                changed: history.changed,
            })
        };
        set_plain(&self.history_summary, &text);
    }

    fn submit(self: &Rc<Self>, request: Request, purpose: Pending) {
        if self.closed.get() || self.job.borrow().is_some() {
            return;
        }
        self.epoch.set(self.epoch.get() + 1);
        self.lock_seen.set(false);
        if !matches!(request, Request::Status | Request::List) {
            self.hide_revealed();
            // A new action: the last one's message is stale. A status check
            // or a list — also the one that follows a change — keeps it, so
            // that what a change reported stays readable.
            self.message.set_text("");
        }
        match Job::start(self.socket.clone(), request) {
            Ok(job) => {
                *self.job.borrow_mut() = Some((job, purpose));
                self.set_busy(true);
            }
            Err(e) => self.feedback(&e, true),
        }
    }

    fn set_busy(&self, busy: bool) {
        for b in self.actions.borrow().iter() {
            b.set_sensitive(!busy);
        }
        self.detail.set_sensitive(!busy);
        self.waiting.set_visible(busy);
        self.paint_settings_controls();
    }

    fn feedback(&self, text: &str, problem: bool) {
        self.message.set_text(&rusthorse::ui::dialog_text(text));
        if problem {
            self.message.add_css_class("error");
        } else {
            self.message.remove_css_class("error");
        }
    }

    fn receive(self: &Rc<Self>) {
        let polled = self
            .poll
            .borrow()
            .as_ref()
            .and_then(|job| match job.result.try_recv() {
                Ok(answer) => Some(answer),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(Err(Failure::lost())),
            });
        if let Some(answer) = polled {
            self.poll.borrow_mut().take();
            // A request started or ended since this check began: its own
            // result is newer.
            let fresh = self.poll_epoch.get() == self.epoch.get();
            let pending = self.job.borrow().is_some();
            match answer {
                _ if !fresh => {}
                Ok(Response::Status(info)) if info.locked => {
                    // Locked elsewhere, maybe while a dialog is open: forget
                    // what is shown now, and any value to come.
                    self.lock_seen.set(pending);
                    self.apply_status(info, false);
                }
                Ok(Response::Status(info)) => {
                    if !pending {
                        self.apply_status(info, false);
                    }
                }
                Ok(_) => {}
                Err(failure) => {
                    self.lock_seen.set(pending);
                    self.unreachable(&failure);
                }
            }
        }

        let listed = self
            .grants_job
            .borrow()
            .as_ref()
            .and_then(|(job, _)| answer_of(job));
        if let Some(answer) = listed {
            let started = self.grants_job.borrow_mut().take().map(|(_, epoch)| epoch);
            if started != Some(self.grants_epoch.get()) {
                // A revocation or a request of the human's ended meanwhile:
                // the list may have been made before it, and show as active
                // a grant that has ended since. List again rather than show
                // it.
                if self.showing_grants() {
                    self.list_grants();
                }
            } else {
                self.paint_grants(match answer {
                    Ok(Response::Grants { grants }) => Ok(grants),
                    Ok(_) => Err("The agent returned an unexpected kind of answer.".into()),
                    Err(failure) => Err(failure.text()),
                });
            }
        }
        let read = self
            .history_job
            .borrow()
            .as_ref()
            .and_then(|job| match job.result.try_recv() {
                Ok(read) => Some(read.map_err(|e| e.to_string())),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    Some(Err("the reading stopped unexpectedly".into()))
                }
            });
        if let Some(read) = read {
            // Taken first: showing it looks at whether a page is being read.
            let job = self.history_job.borrow_mut().take();
            if let Some(job) = job {
                self.after_history(&job, read);
            }
        }
        let revoked = self.revoke_job.borrow().as_ref().and_then(answer_of);
        if let Some(answer) = revoked {
            self.revoke_job.borrow_mut().take();
            self.after_revoke(answer);
        }

        let answer = {
            let job = self.job.borrow();
            let Some((job, _)) = job.as_ref() else { return };
            match job.result.try_recv() {
                Ok(answer) => Some(answer),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(Err(Failure::lost())),
            }
        };
        let Some(answer) = answer else { return };
        let Some((_, purpose)) = self.job.borrow_mut().take() else {
            return;
        };
        self.epoch.set(self.epoch.get() + 1);
        self.set_busy(false);
        // It may have ended grants (Lock now ends them all, a change ends
        // its entry's).
        self.grants_changed();
        if self.showing_grants() {
            self.list_grants();
        }
        let purpose = match purpose {
            Pending::Import(batches) => {
                self.after_batch(answer, batches);
                return;
            }
            other => other,
        };
        match answer {
            Err(failure) => {
                self.feedback(&failure.text(), true);
                if matches!(purpose, Pending::Status { .. }) {
                    self.unreachable(&failure);
                } else {
                    // Keep what is on screen; a status check tells whether
                    // the vault was locked meanwhile.
                    self.poll_status();
                }
            }
            // An answer that describes the vault as open, read before a lock
            // this window has since seen, must not undo that lock on screen
            // (nor list again, which would ask for the password): ask anew.
            Ok(Response::Status(info)) if self.lock_seen.get() && !info.locked => {
                drop(info);
                self.refresh();
            }
            Ok(Response::Entries { entries }) if self.lock_seen.get() => {
                drop(entries);
                self.refresh();
            }
            Ok(Response::Status(info)) => {
                let list = matches!(purpose, Pending::Status { list: true });
                self.apply_status(info, list);
            }
            Ok(Response::Entries { entries }) => {
                *self.entries.borrow_mut() = entries;
                self.populate_groups();
                self.populate_rows();
            }
            Ok(Response::Ok { message }) => {
                self.feedback(&message, false);
                self.refresh();
            }
            Ok(Response::Secret { value }) if self.lock_seen.get() => {
                drop(value);
                self.feedback(
                    "The vault was locked while the agent was asking you, so the value was neither shown nor copied.",
                    true,
                );
            }
            Ok(Response::KeyringItems { items }) => self.pick_keyring(items),
            Ok(Response::Names { names, empty }) => match purpose {
                Pending::DotenvNames { path } => self.pick_dotenv(path, names, empty),
                _ => self.feedback("Unexpected answer. Refresh and look before retrying.", true),
            },
            Ok(Response::Secret { value }) => match purpose {
                Pending::Reveal { title, notes } => self.show_secret(&title, notes, value),
                Pending::Copy { title } => self.put_on_clipboard(&title, &value),
                _ => self.feedback("Unexpected answer. Refresh and look before retrying.", true),
            },
            Ok(_) => self.feedback("Unexpected answer. Refresh and look before retrying.", true),
        }
    }

    fn unreachable(self: &Rc<Self>, failure: &Failure) {
        self.status.borrow_mut().take();
        self.lock_sent.set(false);
        self.paint_settings(None);
        // Whether the vault is locked is not known now.
        self.grants_locked.set_visible(false);
        self.agent_down.set(failure.not_running);
        self.pill.set_text(if failure.not_running {
            "Not running"
        } else {
            "Unavailable"
        });
        self.pill.remove_css_class("success");
        self.pill.add_css_class("warning");
        self.lock.set_label(if failure.not_running {
            "Start agent"
        } else {
            "Unlock"
        });
        self.lock_hint.set_text("");
        clear(&self.status_page);
        let g = group("Agent", None);
        g.add(&label(&failure.text()));
        self.status_page.append(&g);
        const DOWN: &str = "The agent is not running";
        const DOWN_TEXT: &str = "The agent keeps your vault and asks you before every use of a \
             secret. It is a service of your session, which systemd starts when you log in. \
             Start it now to continue.";
        // The status is checked every few seconds: keep the page as it is.
        if failure.not_running && self.showing_first_step(DOWN, DOWN_TEXT) {
            return;
        }
        self.hide_revealed();
        self.clear_entries();
        if failure.not_running {
            self.paint_first_step(DOWN, DOWN_TEXT, "Start agent", Self::start_agent);
        }
    }

    /// Whether the detail pane already shows this first step.
    fn showing_first_step(&self, title: &str, description: &str) -> bool {
        self.detail
            .first_child()
            .and_then(|w| w.downcast::<adw::StatusPage>().ok())
            .is_some_and(|page| {
                page.title() == title && page.description().as_deref() == Some(description)
            })
    }

    /// The detail pane when there is nothing to show yet: what to do next,
    /// and a button that does it. `description` is markup.
    fn paint_first_step(
        self: &Rc<Self>,
        title: &str,
        description: &str,
        action_label: &str,
        action: fn(&Rc<Manager>),
    ) {
        clear(&self.detail);
        let page = adw::StatusPage::builder()
            .icon_name("dialog-password-symbolic")
            .title(title)
            .build();
        page.set_description(Some(description));
        let go = button(action_label, None);
        go.add_css_class("suggested-action");
        go.add_css_class("pill");
        go.set_halign(gtk::Align::Center);
        page.set_child(Some(&go));
        let weak = Rc::downgrade(self);
        go.connect_clicked(move |_| {
            if let Some(s) = weak.upgrade()
                && s.job.borrow().is_none()
            {
                action(&s);
            }
        });
        self.detail.append(&page);
    }

    fn apply_status(self: &Rc<Self>, info: StatusInfo, list: bool) {
        self.agent_down.set(false);
        self.lock_sent.set(false);
        // The grants page says when the vault is locked: grants can outlive
        // an automatic lock, and are listed and revoked all the same.
        self.grants_locked
            .set_visible(info.vault_exists && info.locked);
        if !info.vault_exists {
            // First start: no vault yet. Creating it is the next step.
            self.pill.set_text("No vault");
            self.pill.remove_css_class("success");
            self.pill.add_css_class("warning");
            self.lock.set_label("Create vault…");
            self.lock_hint.set_text("");
            self.paint_status(&info);
            let description = format!(
                "Rusthorse keeps your secrets in one encrypted KeePass file:\n<tt>{}</tt>\n\n\
                 The agent asks you to choose its master password in a window of its own; this \
                 app never sees it. A forgotten master password cannot be recovered.",
                rusthorse::ui::markup_text(&info.vault)
            );
            *self.status.borrow_mut() = Some(info);
            const CREATE: &str = "Create your vault";
            if self.showing_first_step(CREATE, &description) {
                return;
            }
            self.hide_revealed();
            self.clear_entries();
            self.paint_first_step(CREATE, &description, "Create vault…", Self::create_vault);
            return;
        }
        let was_locked = self.status.borrow().as_ref().is_none_or(|s| s.locked);
        let locked = info.locked;
        self.pill
            .set_text(if locked { "Locked" } else { "Unlocked" });
        self.pill
            .remove_css_class(if locked { "success" } else { "warning" });
        self.pill
            .add_css_class(if locked { "warning" } else { "success" });
        self.lock
            .set_label(if locked { "Unlock" } else { "Lock now" });
        self.lock_hint
            .set_text(&match (locked, info.locks_in_secs) {
                (true, _) => "Values are encrypted on disk.".to_string(),
                (false, Some(s)) => format!("Locks itself in {} min", s.div_ceil(60)),
                (false, None) => "Auto-lock is off".to_string(),
            });
        self.paint_status(&info);
        self.paint_settings(info.settings.as_ref());
        *self.status.borrow_mut() = Some(info);
        self.paint_settings_controls();
        if locked {
            self.hide_revealed();
            self.clear_entries();
        } else {
            if list || was_locked {
                // Unlocked here or elsewhere (the CLI): listing asks nothing.
                self.submit(Request::List, Pending::List);
            }
            if self.showing_history() && !self.history.borrow().loaded {
                self.read_history(false);
            }
        }
    }

    fn paint_status(&self, info: &StatusInfo) {
        clear(&self.status_page);
        let agent = group(
            "Agent",
            Some(
                "Checked every five seconds. This is not rusthorse doctor: file permissions, the service and desktop isolation are not checked here.",
            ),
        );
        for (key, value) in [
            (
                "State",
                if info.locked {
                    "Locked".to_string()
                } else {
                    match info.locks_in_secs {
                        Some(s) => format!("Unlocked; locks itself in {s} seconds without use"),
                        None => "Unlocked; auto-lock is off".to_string(),
                    }
                },
            ),
            (
                "Version and protocol",
                format!(
                    "{} (protocol {})",
                    info.agent_version, info.protocol_version
                ),
            ),
            ("Vault file", info.vault.clone()),
            (
                "Vault file exists",
                if info.vault_exists {
                    "Yes"
                } else {
                    "No — create it with Create vault…, or rusthorse init"
                }
                .to_string(),
            ),
            (
                "Remembered approvals",
                info.remembered_approvals.to_string(),
            ),
            (
                "Dialogs shown with",
                info.dialogs
                    .clone()
                    .unwrap_or_else(|| "Not reported".into()),
            ),
            (
                "Credential broker",
                info.broker.clone().unwrap_or_else(|| "Not reported".into()),
            ),
            (
                "Active grants",
                info.grants
                    .map_or_else(|| "Not reported".into(), |n| n.to_string()),
            ),
            ("Agent program", info.agent_executable.clone()),
        ] {
            agent.add(&fact_row(key, &value));
        }
        // What else locks the vault (ADR 0009), one line per event, each
        // line filtered on its own: the breaks are this app's.
        let triggers = label("");
        triggers.set_text(
            &rusthorse::session_lock::summary(&info.lock_triggers)
                .iter()
                .map(|line| rusthorse::ui::dialog_text(line))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        triggers.set_selectable(true);
        triggers.set_hexpand(true);
        agent.add(&key_row("Also locks on", &triggers));
        self.status_page.append(&agent);
        if info.agent_executable_replaced == Some(true) {
            let warn = group(
                "Restart needed",
                Some(
                    "The agent's program file was replaced after it started. Restart the agent service before using dialogs.",
                ),
            );
            self.status_page.append(&warn);
        }
    }

    fn clear_entries(&self) {
        // The history names entries too.
        self.clear_history();
        self.entries.borrow_mut().clear();
        self.row_groups.borrow_mut().clear();
        self.selected.borrow_mut().take();
        self.filling.set(true);
        while let Some(row) = self.rows.first_child() {
            self.rows.remove(&row);
        }
        self.filling.set(false);
        self.paint_empty("Unlock to see your entries.");
    }

    fn paint_empty(&self, text: &str) {
        clear(&self.detail);
        let empty = adw::StatusPage::builder()
            .icon_name("dialog-password-symbolic")
            .title("No entry selected")
            .build();
        empty.set_description(Some(text));
        self.detail.append(&empty);
    }

    fn populate_groups(&self) {
        let names: BTreeSet<String> = self
            .entries
            .borrow()
            .iter()
            .map(|e| e.group.clone().unwrap_or_default())
            .collect();
        let previous = self
            .group_names
            .borrow()
            .get(self.groups.selected().wrapping_sub(1) as usize)
            .cloned();
        let mut labels = vec!["All groups".to_string()];
        labels.extend(names.iter().map(|s| {
            if s.is_empty() {
                "No group".into()
            } else {
                rusthorse::ui::dialog_text(s)
            }
        }));
        let names: Vec<String> = names.into_iter().collect();
        let selected = previous
            .and_then(|s| names.iter().position(|n| n == &s))
            .map_or(0, |i| i as u32 + 1);
        self.filling.set(true);
        let refs: Vec<_> = labels.iter().map(String::as_str).collect();
        self.groups.set_model(Some(&gtk::StringList::new(&refs)));
        self.groups.set_selected(selected);
        *self.group_names.borrow_mut() = names;
        self.filling.set(false);
    }

    fn populate_rows(self: &Rc<Self>) {
        self.hide_revealed();
        self.filling.set(true);
        while let Some(row) = self.rows.first_child() {
            self.rows.remove(&row);
        }
        let group = self
            .group_names
            .borrow()
            .get(self.groups.selected().wrapping_sub(1) as usize)
            .cloned();
        let query = self.search.text();
        let shown: Vec<EntryInfo> = self
            .entries
            .borrow()
            .iter()
            .filter(|e| model::matches(e, &query, group.as_deref()))
            .cloned()
            .collect();
        *self.row_groups.borrow_mut() = shown
            .iter()
            .map(|e| e.group.clone().unwrap_or_default())
            .collect();
        let mut selected_row = None;
        for entry in &shown {
            let row = gtk::ListBoxRow::new();
            row.set_widget_name(&entry.id);
            let content = row_box(12);
            margins(&content, 8, 6);
            let avatar = adw::Avatar::new(36, Some(&rusthorse::ui::dialog_text(&entry.name)), true);
            content.append(&avatar);
            let text = column(2);
            text.set_valign(gtk::Align::Center);
            let title = styled(&entry.name, &["heading"]);
            title.set_wrap(false);
            title.set_ellipsize(pango::EllipsizeMode::End);
            text.append(&title);
            let sub = styled(&model::summary(entry), &["caption", "dim-label"]);
            sub.set_wrap(false);
            sub.set_ellipsize(pango::EllipsizeMode::End);
            text.append(&sub);
            content.append(&text);
            row.set_child(Some(&content));
            self.rows.append(&row);
            if self.selected.borrow().as_ref() == Some(&entry.id) {
                selected_row = Some(row);
            }
        }
        if let Some(row) = selected_row {
            self.rows.select_row(Some(&row));
        } else {
            self.selected.borrow_mut().take();
        }
        self.filling.set(false);
        self.show_detail();
    }

    fn current(&self) -> Option<EntryInfo> {
        let selected = self.selected.borrow();
        self.entries
            .borrow()
            .iter()
            .find(|e| Some(&e.id) == selected.as_ref())
            .cloned()
    }

    fn show_detail(self: &Rc<Self>) {
        let Some(entry) = self.current() else {
            let unlocked = self.status.borrow().as_ref().is_some_and(|s| !s.locked);
            self.paint_empty(if unlocked {
                "Select an entry to see its details. Only names and metadata are loaded."
            } else {
                "Unlock to see your entries."
            });
            return;
        };
        clear(&self.detail);

        // Title, and the actions on the entry.
        let top = row_box(14);
        top.append(&adw::Avatar::new(
            56,
            Some(&rusthorse::ui::dialog_text(&entry.name)),
            true,
        ));
        let names = column(4);
        names.set_valign(gtk::Align::Center);
        names.append(&styled(&entry.name, &["title-2"]));
        let mut line = entry.group.clone().unwrap_or_else(|| "No group".into());
        if let Some(kind) = entry.fields.kind {
            line.push_str(" · ");
            line.push_str(kind.label());
        }
        if let Some(m) = &entry.modified {
            line.push_str(" · modified ");
            line.push_str(m);
        }
        names.append(&styled(&line, &["dim-label"]));
        top.append(&names);
        self.detail.append(&top);
        let toolbar = row_box(8);
        let edit = button("Edit…", Some("document-edit-symbolic"));
        let e = entry.clone();
        self.connect_button(&edit, move |s| s.edit(Some(e.clone())));
        toolbar.append(&edit);
        let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        spacer.set_hexpand(true);
        toolbar.append(&spacer);
        let delete = button("Delete…", Some("user-trash-symbolic"));
        delete.add_css_class("destructive-action");
        let id = entry.id.clone();
        self.connect_button(&delete, move |s| {
            s.submit(Request::Remove { name: id.clone() }, Pending::Change)
        });
        toolbar.append(&delete);
        self.detail.append(&toolbar);

        // The secret: nothing is fetched until Show or Copy is approved.
        let secret = group(
            "Secret",
            Some(
                "Show and Copy ask for your approval in the agent's dialog. A shown value hides after 30 seconds. A copied value stays on the clipboard until you copy something else, and a clipboard history may keep it even after that.",
            ),
        );
        for (title, notes, present) in [
            ("Value", false, entry.has_password),
            ("Notes", true, entry.has_notes),
        ] {
            let line = row_box(8);
            // Fixed text of this app, not from the vault: no dialog filter
            // (which would escape the bullets).
            let state = gtk::Label::builder()
                .label(if present {
                    if notes {
                        "Hidden"
                    } else {
                        "••••••••••••"
                    }
                } else if notes {
                    "None"
                } else {
                    "No value"
                })
                .use_markup(false)
                .xalign(0.0)
                .ellipsize(pango::EllipsizeMode::End)
                .css_classes(["dim-label"])
                .build();
            state.set_hexpand(true);
            state.set_valign(gtk::Align::Center);
            line.append(&state);
            // Short labels — the row says Value or Notes — keep the panel
            // narrow; the full action is in the tooltip and the accessible
            // name.
            let what = if notes { "notes" } else { "value" };
            let show = button("Show…", Some("view-reveal-symbolic"));
            show.set_widget_name(&format!("show-{what}"));
            show.set_tooltip_text(Some(&format!("Show the {what}…")));
            show.update_property(&[gtk::accessible::Property::Label(&format!(
                "Show the {what}"
            ))]);
            show.set_valign(gtk::Align::Center);
            show.set_sensitive(present);
            let e = entry.clone();
            self.connect_button(&show, move |s| {
                s.submit(
                    Request::Reveal {
                        name: e.id.clone(),
                        notes,
                        purpose: Some(RevealPurpose::Show),
                    },
                    Pending::Reveal {
                        title: e.identity(),
                        notes,
                    },
                )
            });
            line.append(&show);
            let copy = button("Copy…", Some("edit-copy-symbolic"));
            copy.set_widget_name(&format!("copy-{what}"));
            copy.set_tooltip_text(Some(&format!("Copy the {what} to the clipboard…")));
            copy.update_property(&[gtk::accessible::Property::Label(&format!(
                "Copy the {what} to the clipboard"
            ))]);
            copy.set_valign(gtk::Align::Center);
            copy.set_sensitive(present);
            let e = entry.clone();
            self.connect_button(&copy, move |s| s.copy(&e, notes));
            line.append(&copy);
            secret.add(&key_row(title, &line));
        }
        // Changing the value: each choice in view, each going straight to
        // the agent. Rows, not more buttons on the Value line, which would
        // make the window too wide for a 1024-pixel screen.
        for (name, icon, title, subtitle, change) in [
            (
                "change-value",
                "dialog-password-symbolic",
                "Change the value…",
                "Type the new value in the agent's dialog.",
                ValueMode::Prompt,
            ),
            (
                "random-value",
                "emblem-synchronizing-symbolic",
                "Replace with a random value…",
                "32 letters and digits, made by the agent after you approve. Nobody sees it; change it at the provider too.",
                ValueMode::Generate,
            ),
        ] {
            let row = adw::ActionRow::builder()
                .title(title)
                .subtitle(subtitle)
                .use_markup(false)
                .activatable(true)
                .build();
            row.set_widget_name(name);
            row.add_prefix(&gtk::Image::from_icon_name(icon));
            let id = entry.id.clone();
            let weak = Rc::downgrade(self);
            row.connect_activated(move |_| {
                if let Some(s) = weak.upgrade() {
                    s.submit(
                        Request::Edit {
                            name: id.clone(),
                            changes: EntryChanges {
                                value: change.change(),
                                ..Default::default()
                            },
                        },
                        Pending::Change,
                    )
                }
            });
            secret.add(&row);
        }
        self.detail.append(&secret);

        // Metadata. Selectable: none of it is secret.
        let details = group("Details", None);
        for (key, value) in [
            (
                "Username",
                entry.fields.username.clone().unwrap_or_default(),
            ),
            (
                EntryKind::url_label(entry.fields.kind),
                entry.fields.url.clone().unwrap_or_default(),
            ),
            ("Host", entry.fields.host.clone().unwrap_or_default()),
            (
                "Port",
                entry.fields.port.map(|p| p.to_string()).unwrap_or_default(),
            ),
            ("Tags", entry.fields.tags.join(", ")),
            ("Other fields (names only)", entry.other_fields.join(", ")),
            (
                "Protected fields (withheld)",
                entry.protected_fields.join(", "),
            ),
            ("UUID", entry.id.clone()),
        ] {
            if !value.is_empty() {
                details.add(&fact_row(key, &value));
            }
        }
        self.detail.append(&details);

        // The two ways to give the entry to a command, each labelled with
        // what the command gets. Nothing in them comes from the entry but
        // its name and UUID, and nothing is stored with it (ADR 0013). The
        // descriptions are markup: these texts are fixed and hold no markup
        // characters.
        for (name, title, description, command, copy_label, copied) in [
            (
                "value-command",
                "Give the value to a command",
                "Replace your-command. After your approval the command gets the entry's value in this environment variable; its output is redacted. The command names the entry by its UUID and holds no secret.",
                model::value_command(&entry),
                "Copy command",
                "Command copied. It contains no secret.",
            ),
            (
                "broker-command",
                "Give a token to a command, through the broker",
                "A template to fill in: replace HOST with the destination's host (with :PORT if it needs one) and BASE_PATH with your program's base path, or remove /BASE_PATH; name TOKEN_VAR and BASE_URL_VAR after the variables your program reads its key and its base URL from; and replace your-command. Until the destination is filled in, the command is refused. After your approval the command gets a temporary token in TOKEN_VAR, never the value, and the broker's local address with the base path in BASE_URL_VAR; its output is redacted. The broker puts the value where the command puts its token, in a request header, only in requests to the destination's origin — its scheme, host and port, which the agent's dialog shows you to approve — at any path there. The base path only sets up BASE_URL_VAR; it is not a limit. The token stops working when the command ends. A program that encodes the token or sends it in the URL or the body, or an API that signs its requests with the key, cannot be used through the broker: give the program the value. The command names the entry by its UUID and holds no secret.",
                model::broker_command(&entry),
                "Copy command template",
                "Command template copied. It contains no secret; fill it in before you run it.",
            ),
        ] {
            let usage = group(title, Some(description));
            usage.set_widget_name(name);
            let code = gtk::Label::builder()
                // Filtered line by line: the line breaks are the command's
                // own.
                .label(
                    command
                        .lines()
                        .map(rusthorse::ui::dialog_text)
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
                .use_markup(false)
                .selectable(true)
                .wrap(true)
                .wrap_mode(pango::WrapMode::WordChar)
                .attributes(&no_hyphens())
                .xalign(0.0)
                .css_classes(["monospace"])
                .build();
            let card = column(10);
            card.add_css_class("card");
            let inner = column(10);
            margins(&inner, 12, 14);
            inner.append(&code);
            let copy = button(copy_label, Some("edit-copy-symbolic"));
            copy.set_widget_name(&format!("copy-{name}"));
            copy.set_halign(gtk::Align::Start);
            self.connect_button(&copy, move |s| {
                s.window.clipboard().set_text(&command);
                s.feedback(copied, false);
            });
            inner.append(&copy);
            card.append(&inner);
            usage.add(&card);
            self.detail.append(&usage);
        }
        self.detail.set_sensitive(self.job.borrow().is_none());
    }

    fn copy(self: &Rc<Self>, entry: &EntryInfo, notes: bool) {
        self.submit(
            Request::Reveal {
                name: entry.id.clone(),
                notes,
                purpose: Some(RevealPurpose::Copy),
            },
            Pending::Copy {
                title: format!(
                    "The {} of {}",
                    if notes { "notes" } else { "value" },
                    entry.identity()
                ),
            },
        );
    }

    /// Put a value on the clipboard as plain text, like any copy. GTK and
    /// the desktop keep their own copies; nothing here can take them back.
    fn put_on_clipboard(&self, title: &str, value: &SecretString) {
        // GTK's text is NUL-terminated: a value with a NUL would be cut (or
        // make the conversion fail). Copy nothing rather than part of it.
        if value.contains('\0') {
            self.feedback(
                &format!(
                    "{title} contains a NUL character, which the clipboard cannot carry: nothing was copied."
                ),
                true,
            );
            return;
        }
        self.window.clipboard().set_text(value.as_str());
        self.feedback(
            &format!(
                "{title} was copied. It stays on the clipboard until you copy something else, and a clipboard history may keep it even after that."
            ),
            false,
        );
    }

    fn hide_revealed(&self) {
        if let Some(window) = self.revealed.borrow_mut().take() {
            window.close();
        }
    }

    fn show_secret(self: &Rc<Self>, title: &str, notes: bool, value: SecretString) {
        self.show_secret_for(title, notes, value, Duration::from_secs(REVEAL_SECONDS));
    }

    fn show_secret_for(
        self: &Rc<Self>,
        title: &str,
        notes: bool,
        value: SecretString,
        lifetime: Duration,
    ) {
        self.hide_revealed();
        let window = adw::Window::builder()
            .title("Revealed secret — Rusthorse")
            .transient_for(&self.window)
            .modal(true)
            .destroy_with_parent(true)
            .default_width(560)
            .default_height(320)
            .build();
        let body = column(14);
        margins(&body, 18, 24);
        body.append(&styled(title, &["title-4"]));
        // Plain text in the monospace font, which tells 0 from O and l from
        // 1; it wraps anywhere. Not selectable: no accidental export to the
        // PRIMARY selection. The Copy button below copies the value exactly,
        // escapes undone.
        let display = SecretString::new(rusthorse::ui::dialog_text(&value));
        let text = gtk::Label::builder()
            .label(display.as_str())
            .use_markup(false)
            .selectable(false)
            .wrap(true)
            .wrap_mode(pango::WrapMode::Char)
            .attributes(&no_hyphens())
            .xalign(0.0)
            .css_classes(["monospace"])
            .build();
        drop(display);
        let kept = Rc::new(RefCell::new(Some(value)));
        let shown = column(0);
        shown.add_css_class("card");
        margins(&text, 14, 16);
        shown.append(&text);
        body.append(&shown);
        let countdown = styled("", &["caption", "dim-label"]);
        body.append(&countdown);
        let buttons = row_box(8);
        let copy = button("Copy", Some("edit-copy-symbolic"));
        copy.set_tooltip_text(Some(
            "Copies what is shown, without asking again. It stays on the clipboard until you copy something else; a clipboard history may keep it longer.",
        ));
        buttons.append(&copy);
        let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        spacer.set_hexpand(true);
        buttons.append(&spacer);
        let hide = button("Hide now", None);
        hide.add_css_class("suggested-action");
        buttons.append(&hide);
        body.append(&buttons);
        let view = adw::ToolbarView::new();
        view.add_top_bar(&adw::HeaderBar::new());
        view.set_content(Some(&scrolled(&body)));
        window.set_content(Some(&view));

        let weak = window.downgrade();
        hide.connect_clicked(move |_| {
            if let Some(w) = weak.upgrade() {
                w.close();
            }
        });
        // The approval said the value could be copied from here (see the
        // agent's wording for `show`), so this asks nothing.
        let manager = Rc::downgrade(self);
        let copied = format!("The {} of {title}", if notes { "notes" } else { "value" });
        let value = Rc::clone(&kept);
        copy.connect_clicked(move |_| {
            if let Some(s) = manager.upgrade()
                && let Some(v) = value.borrow().as_ref()
            {
                s.put_on_clipboard(&copied, v);
            }
        });
        let shown_ref = shown.upcast::<gtk::Widget>();
        window.connect_close_request(move |w| {
            kept.borrow_mut().take();
            wipe_labels(&shown_ref);
            w.set_content(None::<&gtk::Widget>);
            glib::Propagation::Proceed
        });
        let active_once = Cell::new(false);
        window.connect_is_active_notify(move |w| {
            if w.is_active() {
                active_once.set(true);
            } else if active_once.get() {
                w.close();
            }
        });
        let weak = window.downgrade();
        let until = Instant::now() + lifetime;
        glib::timeout_add_local(Duration::from_millis(100), move || {
            let Some(w) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                w.close();
                return glib::ControlFlow::Break;
            }
            countdown.set_text(&format!(
                "Hides in {} s, or as soon as this window loses focus. Other programs of your desktop session can see it while it is shown.",
                left.as_secs() + 1
            ));
            glib::ControlFlow::Continue
        });
        window.present();
        *self.revealed.borrow_mut() = Some(window);
    }

    fn edit(self: &Rc<Self>, old: Option<EntryInfo>) {
        if let Some(w) = self.editor.borrow().as_ref()
            && w.is_visible()
        {
            w.present();
            return;
        }
        let window = adw::Window::builder()
            .title(if old.is_some() {
                "Edit entry"
            } else {
                "New entry"
            })
            .transient_for(&self.window)
            .modal(true)
            .destroy_with_parent(true)
            .default_width(560)
            .default_height(700)
            .build();
        let body = column(24);
        let initial = old.as_ref().map(Form::from_entry).unwrap_or_default();
        // The group is chosen from a list — No group, the groups that hold
        // entries and the groups above them, then "New group…", which opens
        // a row for a path — so that a typo does not make a new group. The
        // form starts on the entry's group, or for a new entry on the group
        // the list is filtered on.
        let known = model::group_choices(&self.entries.borrow());
        let start_group = match &old {
            Some(_) => initial.group.clone(),
            None => {
                let filtered = self.groups.selected() as usize;
                self.group_names
                    .borrow()
                    .get(filtered.wrapping_sub(1))
                    .cloned()
                    .unwrap_or_default()
            }
        };
        let start_index = known
            .iter()
            .position(|g| !start_group.is_empty() && *g == start_group)
            .map_or(0, |i| i as u32 + 1);
        let new_group_index = known.len() as u32 + 1;
        let group_list = adw::ComboRow::builder().title("Group").build();
        let group_warning = adw::ActionRow::builder()
            .title("")
            .use_markup(false)
            .visible(false)
            .build();
        group_warning.add_css_class("warning");
        let fields_group = group(
            "Entry",
            Some(
                "Names, logins, URLs, hosts and tags are not secret: never type a secret here. Saving sends the change to the agent, which asks for your approval.",
            ),
        );
        let withheld = |protected: &str| {
            old.as_ref()
                .is_some_and(|e| e.protected_fields.iter().any(|f| f == protected))
        };
        // What the entry is for: it decides which rows are offered and what
        // the URL is called. It never hides a row that has a value.
        let kind = adw::ComboRow::builder()
            .title(if withheld("Kind") {
                "Kind (protected; unchanged)"
            } else {
                "Kind"
            })
            .model(&gtk::StringList::new(
                &model::KIND_CHOICES.map(model::kind_label),
            ))
            .build();
        kind.set_selected(
            model::KIND_CHOICES
                .iter()
                .position(|k| *k == initial.kind)
                .unwrap_or(0) as u32,
        );
        kind.set_sensitive(!withheld("Kind"));
        if old
            .as_ref()
            .is_some_and(|e| e.other_fields.iter().any(|f| f == "Kind"))
        {
            kind.set_subtitle(
                "The file has a Kind field this app does not know. Choosing a kind replaces it.",
            );
        }
        fields_group.add(&kind);
        // Every row without changing the kind (for the odd entry that needs
        // one more field). Not stored: the form opens with it off.
        let all = adw::SwitchRow::builder()
            .title("Show all fields")
            .subtitle("Every field, whatever the kind")
            .build();
        fields_group.add(&all);
        let mut fields = Vec::new();
        for (name, value, protected) in [
            ("Name", &initial.name, "Title"),
            ("Group", &initial.group, ""),
            ("Username", &initial.username, "UserName"),
            ("URL", &initial.url, "URL"),
            ("Host", &initial.host, "Host"),
            ("Port", &initial.port, "Port"),
            ("Tags (comma separated)", &initial.tags, ""),
        ] {
            let withheld = withheld(protected);
            let is_group = name == "Group";
            if is_group {
                let mut labels = vec!["No group".to_string()];
                labels.extend(known.iter().map(|g| rusthorse::ui::dialog_text(g)));
                labels.push("New group…".to_string());
                let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
                group_list.set_model(Some(&gtk::StringList::new(&refs)));
                group_list.set_selected(start_index);
                fields_group.add(&group_list);
            }
            let title = if withheld {
                format!("{name} (protected; unchanged)")
            } else if is_group {
                "New group (a path such as home/firewalls)".to_string()
            } else {
                name.to_string()
            };
            let row = adw::EntryRow::builder()
                .title(title)
                .use_markup(false)
                .build();
            // The group row is for a new group only; the list holds the rest.
            row.set_text(if is_group { "" } else { value });
            row.set_visible(!is_group);
            row.set_sensitive(!withheld);
            fields_group.add(&row);
            if is_group {
                fields_group.add(&group_warning);
            }
            fields.push(row);
        }
        {
            // Weak references: these closures are stored on the form's own
            // widgets.
            let (row, warning) = (fields[1].downgrade(), group_warning.downgrade());
            let names = known.clone();
            group_list.connect_selected_notify(move |list| {
                let (Some(row), Some(warning)) = (row.upgrade(), warning.upgrade()) else {
                    return;
                };
                let new = list.selected() == new_group_index;
                row.set_visible(new);
                if new {
                    // What was typed before is still there: warn again.
                    warn_case_twin(&names, &row, &warning);
                    row.grab_focus();
                } else {
                    warning.set_visible(false);
                }
            });
            let names = known.clone();
            let warning = group_warning.downgrade();
            fields[1].connect_changed(move |row| {
                if let Some(warning) = warning.upgrade() {
                    warn_case_twin(&names, row, &warning);
                }
            });
        }
        let hidden_by_file = ["UserName", "URL", "Host", "Port"].map(withheld);
        // Weak references: the closure is stored in the handlers of `kind`
        // and `all`, so strong ones would keep both (and the rows) alive in
        // a cycle after the form closes.
        let reshape = {
            let rows: Vec<_> = fields.iter().map(|r| r.downgrade()).collect();
            let (kind, all) = (kind.downgrade(), all.downgrade());
            move || {
                let (Some(kind), Some(all)) = (kind.upgrade(), all.upgrade()) else {
                    return;
                };
                let Some(rows) = rows.iter().map(|r| r.upgrade()).collect::<Option<Vec<_>>>()
                else {
                    return;
                };
                let chosen = model::KIND_CHOICES[kind.selected() as usize];
                // "Other" shows every field already.
                all.set_visible(chosen.is_some());
                shape_rows(&rows, chosen, hidden_by_file, all.is_active());
            }
        };
        reshape();
        let again = reshape.clone();
        kind.connect_selected_notify(move |_| again());
        all.connect_active_notify(move |_| reshape());
        body.append(&fields_group);
        let value_group = group(
            "Value",
            Some(
                "You never type a value here. The agent asks for it in its own dialog, or generates one.",
            ),
        );
        // Every choice in view, one row each, the first one chosen.
        let typed = (
            ValueMode::Prompt,
            if old.is_some() {
                "Type a new value"
            } else {
                "Type the value"
            },
            "The agent asks for it in its own dialog after you send this.",
        );
        let generated = (
            ValueMode::Generate,
            "Generate a random value",
            "32 letters and digits, made by the agent. Nobody sees it.",
        );
        let choices = if old.is_some() {
            vec![
                (ValueMode::Keep, "Keep the current value", ""),
                typed,
                generated,
            ]
        } else {
            vec![typed, generated]
        };
        let mut checks: Vec<gtk::CheckButton> = Vec::new();
        for (i, (_, title, subtitle)) in choices.iter().enumerate() {
            let check = gtk::CheckButton::new();
            check.set_group(checks.first());
            check.set_active(i == 0);
            check.set_valign(gtk::Align::Center);
            let row = adw::ActionRow::builder()
                .title(*title)
                .use_markup(false)
                .activatable_widget(&check)
                .build();
            if !subtitle.is_empty() {
                row.set_subtitle(subtitle);
            }
            row.add_prefix(&check);
            value_group.add(&row);
            checks.push(check);
        }
        body.append(&value_group);
        if old.is_some() {
            body.append(&styled(
                "Editing notes comes in a later version.",
                &["caption", "dim-label"],
            ));
            // Any entry can be used through the broker, and the agent ends
            // an entry's grants when it changes (`entry_changed`).
            body.append(&styled(
                "Any change to this entry ends its grants of the credential broker, if it has any.",
                &["caption", "dim-label"],
            ));
        }
        let error = styled("", &["error"]);
        body.append(&error);

        let header = adw::HeaderBar::builder()
            .show_end_title_buttons(false)
            .show_start_title_buttons(false)
            .build();
        let cancel = gtk::Button::with_label("Cancel");
        header.pack_start(&cancel);
        let save = gtk::Button::with_label("Send to agent…");
        save.add_css_class("suggested-action");
        header.pack_end(&save);
        let view = adw::ToolbarView::new();
        view.add_top_bar(&header);
        view.set_content(Some(&page(&body)));
        window.set_content(Some(&view));
        let w = window.downgrade();
        cancel.connect_clicked(move |_| {
            if let Some(w) = w.upgrade() {
                w.close();
            }
        });
        let weak = Rc::downgrade(self);
        let w = window.downgrade();
        save.connect_clicked(move |_| {
            let picked = group_list.selected();
            let group = match picked {
                0 => String::new(),
                i if i < new_group_index => known[i as usize - 1].clone(),
                _ => {
                    let typed = fields[1].text().to_string();
                    if model::group_path(&typed).is_empty() {
                        error.set_text(
                            "Type the new group's path, such as home/firewalls, or choose a group from the list.",
                        );
                        return;
                    }
                    typed
                }
            };
            let form = Form {
                kind: model::KIND_CHOICES[kind.selected() as usize],
                name: fields[0].text().into(),
                group,
                group_edited: Some(picked != start_index),
                username: fields[2].text().into(),
                url: fields[3].text().into(),
                host: fields[4].text().into(),
                port: fields[5].text().into(),
                tags: fields[6].text().into(),
            };
            let chosen = checks.iter().position(|c| c.is_active()).unwrap_or(0);
            match form.request(old.as_ref(), choices[chosen].0) {
                Ok(request) => {
                    if let Some(s) = weak.upgrade()
                        && s.job.borrow().is_none()
                    {
                        if let Some(w) = w.upgrade() {
                            w.close();
                        }
                        s.submit(request, Pending::Change);
                    }
                }
                Err(e) => error.set_text(&rusthorse::ui::dialog_text(&e)),
            }
        });
        window.present();
        *self.editor.borrow_mut() = Some(window);
    }

    fn backup(self: &Rc<Self>) {
        let window = adw::Window::builder()
            .title("Create verified backup")
            .transient_for(&self.window)
            .modal(true)
            .destroy_with_parent(true)
            .default_width(560)
            .build();
        let body = column(18);
        let g = group(
            "Destination",
            Some(
                "A new absolute path (no ~). An existing file is never replaced. The agent copies the encrypted vault and checks that the copy opens; it may ask you to unlock first.",
            ),
        );
        let path = adw::EntryRow::builder()
            .title("File path")
            .use_markup(false)
            .build();
        g.add(&path);
        body.append(&g);
        let error = styled("", &["error"]);
        body.append(&error);
        let header = adw::HeaderBar::builder()
            .show_end_title_buttons(false)
            .show_start_title_buttons(false)
            .build();
        let cancel = gtk::Button::with_label("Cancel");
        header.pack_start(&cancel);
        let save = gtk::Button::with_label("Back up");
        save.add_css_class("suggested-action");
        header.pack_end(&save);
        let view = adw::ToolbarView::new();
        view.add_top_bar(&header);
        let content = column(0);
        margins(&content, 18, 24);
        content.append(&body);
        view.set_content(Some(&content));
        window.set_content(Some(&view));
        let w = window.downgrade();
        cancel.connect_clicked(move |_| {
            if let Some(w) = w.upgrade() {
                w.close();
            }
        });
        let weak = Rc::downgrade(self);
        let w = window.downgrade();
        save.connect_clicked(move |_| {
            let path = path.text().to_string();
            if !std::path::Path::new(&path).is_absolute() {
                error.set_text("Use an absolute path, such as /home/you/rusthorse-backup.kdbx.");
                return;
            }
            if let Some(s) = weak.upgrade()
                && s.job.borrow().is_none()
            {
                if let Some(w) = w.upgrade() {
                    w.close();
                }
                s.submit(Request::Backup { path }, Pending::Change);
            }
        });
        window.present();
        *self.editor.borrow_mut() = Some(window);
    }
}

/// Fit the entry form to `kind`: of its rows 2–5 (Username, URL, Host,
/// Port), show those the kind offers — all of them with `all` — and every
/// one with text or withheld by the file (`withheld`, in the same order);
/// name the URL row for the kind.
/// Show `warning` when the new group typed in `row` differs from an existing
/// one only in case — most likely a typo, since names are case-sensitive.
fn warn_case_twin(names: &[String], row: &adw::EntryRow, warning: &adw::ActionRow) {
    let typed = model::group_path(&row.text());
    match names
        .iter()
        .find(|g| **g != typed && g.to_lowercase() == typed.to_lowercase())
    {
        Some(existing) => {
            warning.set_title(&format!(
                "There is already a group named {}; names are case-sensitive.",
                rusthorse::ui::dialog_text(existing)
            ));
            warning.set_visible(true);
        }
        None => warning.set_visible(false),
    }
}

fn shape_rows(rows: &[adw::EntryRow], kind: Option<EntryKind>, withheld: [bool; 4], all: bool) {
    let offered = if all { None } else { kind };
    for ((row, field), withheld) in rows[2..6]
        .iter()
        .zip([Field::Username, Field::Url, Field::Host, Field::Port])
        .zip(withheld)
    {
        row.set_visible(model::shows(
            offered,
            field,
            !row.text().is_empty(),
            withheld,
        ));
    }
    let url = EntryKind::url_label(kind);
    rows[3].set_title(&if withheld[1] {
        format!("{url} (protected; unchanged)")
    } else {
        url.to_string()
    });
}

/// A job's answer, once it has one; a worker that stopped without one is a
/// lost answer.
fn answer_of(job: &Job) -> Option<Result<Response, Failure>> {
    match job.result.try_recv() {
        Ok(answer) => Some(answer),
        Err(std::sync::mpsc::TryRecvError::Empty) => None,
        Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(Err(Failure::lost())),
    }
}

/// Empty every label under `root`, so GTK drops its copy of the text now.
fn wipe_labels(root: &gtk::Widget) {
    if let Ok(l) = root.clone().downcast::<gtk::Label>() {
        l.set_text("");
    }
    let mut child = root.first_child();
    while let Some(w) = child {
        wipe_labels(&w);
        child = w.next_sibling();
    }
}

#[cfg(test)]
#[path = "widget_tests.rs"]
mod tests;
