//! The main window. The agent is the only approval authority: every action
//! that touches a value or changes the vault is a request the agent may ask
//! the human about in its own dialog.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use gtk::{gio, glib, pango};
use rusthorse::protocol::{
    EntryChanges, EntryInfo, EntryKind, Field, Request, Response, RevealPurpose, SecretString,
    StatusInfo, ValueChange,
};

use crate::connection::{Failure, Job};
use crate::model::{self, Form, ValueMode};

/// How long a shown value stays on screen.
const REVEAL_SECONDS: u64 = 30;
/// How often the status is polled while nothing else is pending.
const POLL_SECONDS: u32 = 5;

enum Pending {
    Status { list: bool },
    List,
    Change,
    Reveal { title: String, notes: bool },
    Copy { title: String },
}

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

/// A row showing requester-independent metadata as plain, selectable text.
fn fact_row(key: &str, value: &str) -> adw::PreferencesRow {
    let v = label(value);
    v.set_selectable(true);
    v.set_hexpand(true);
    v.set_valign(gtk::Align::Center);
    key_row(key, &v)
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
        let pages: Vec<(&str, &str, &str, gtk::Widget)> = vec![
            (
                "entries",
                "Entries",
                "dialog-password-symbolic",
                entries_page.upcast(),
            ),
            (
                "grants",
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
                Self::planned_page(
                    "document-open-recent-symbolic",
                    "History",
                    "A history viewer comes in a later version. Until then, run rusthorse audit in a terminal. This app does not read the audit log.",
                ),
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
        let later = group(
            "Import and restore",
            Some(
                "Importing from a .env file or GNOME Keyring, and restoring a backup, come in later versions. Today: rusthorse import in a terminal (try --dry-run first), and the restore steps in the installation guide. To look at the vault in KeePassXC, open a backup copy, never the live file.",
            ),
        );
        data.append(&later);

        // Settings.
        let settings = column(24);
        let policy = group(
            "Agent policy",
            Some(
                "Auto-lock and remembered approvals are options of the agent service today (--idle-timeout, --remember). Editing them here, and locking when the screen locks or the computer suspends, come in a later version. Closing this app does not lock the vault.",
            ),
        );
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
                "Copy the command snippet and replace your-command. The command receives the secret in its environment after your approval; its output is redacted. This is the way to give an AI agent a secret without showing it.",
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
        });
        manager.actions.replace(vec![
            refresh.clone(),
            add.clone(),
            manager.lock.clone(),
            backup.clone(),
            passwd.clone(),
        ]);
        manager.show_detail();
        manager.connect_button(&refresh, |s| s.refresh());
        manager.connect_button(&add, |s| s.edit(None));
        manager.connect_button(&manager.lock, |s| s.toggle_lock());
        manager.connect_button(&passwd, |s| {
            s.submit(Request::ChangePassword, Pending::Change)
        });
        manager.connect_button(&backup, |s| s.backup());
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
        let weak = Rc::downgrade(self);
        let waited = process.clone();
        process.communicate_utf8_async(None, gio::Cancellable::NONE, move |result| {
            let Some(s) = weak.upgrade() else { return };
            s.starting.set(false);
            s.set_busy(false);
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

    fn submit(self: &Rc<Self>, request: Request, purpose: Pending) {
        if self.closed.get() || self.job.borrow().is_some() {
            return;
        }
        self.epoch.set(self.epoch.get() + 1);
        self.lock_seen.set(false);
        if !matches!(request, Request::Status | Request::List) {
            self.hide_revealed();
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
        if busy {
            self.message.set_text("");
        }
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
        *self.status.borrow_mut() = Some(info);
        if locked {
            self.hide_revealed();
            self.clear_entries();
        } else if list || was_locked {
            // Unlocked here or elsewhere (the CLI): listing asks nothing.
            self.submit(Request::List, Pending::List);
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
        let generate = button("New random value…", Some("emblem-synchronizing-symbolic"));
        let id = entry.id.clone();
        self.connect_button(&generate, move |s| {
            s.submit(
                Request::Edit {
                    name: id.clone(),
                    changes: EntryChanges {
                        value: Some(ValueChange::Generate(Default::default())),
                        ..Default::default()
                    },
                },
                Pending::Change,
            )
        });
        toolbar.append(&generate);
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

        let endpoint = entry.fields.kind == Some(EntryKind::ApiKey) && entry.fields.url.is_some();
        let usage = group(
            "Use it from a command",
            Some(if endpoint {
                "Replace your-command. The command gets the secret in the first variable after your approval; its output is redacted. It gets the endpoint URL in the second one: that is not a secret, and your program may read it under another name. The snippet holds the entry's UUID, never the value."
            } else {
                "Replace your-command. The command gets the secret in this environment variable after your approval; its output is redacted. The snippet holds the entry's UUID, never the value."
            }),
        );
        let snippet = model::snippet(&entry);
        let code = gtk::Label::builder()
            // Filtered line by line: the line breaks are the snippet's own.
            .label(
                snippet
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
        let copy = button("Copy command snippet", Some("edit-copy-symbolic"));
        copy.set_halign(gtk::Align::Start);
        self.connect_button(&copy, move |s| {
            s.window.clipboard().set_text(&snippet);
            s.feedback("Command snippet copied. It contains no secret.", false);
        });
        inner.append(&copy);
        card.append(&inner);
        usage.add(&card);
        self.detail.append(&usage);
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
            let title = if withheld {
                format!("{name} (protected; unchanged)")
            } else if name == "Group" && old.is_some() {
                "Group (moving entries comes later)".to_string()
            } else {
                name.to_string()
            };
            let row = adw::EntryRow::builder()
                .title(title)
                .use_markup(false)
                .build();
            row.set_text(value);
            row.set_sensitive(!withheld && !(name == "Group" && old.is_some()));
            fields_group.add(&row);
            fields.push(row);
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
        let modes: &[&str] = if old.is_some() {
            &[
                "Keep the current value",
                "Type a new one in the agent's dialog",
                "Generate 32 random letters and digits",
            ]
        } else {
            &[
                "Type it in the agent's dialog",
                "Generate 32 random letters and digits",
            ]
        };
        let mode = adw::ComboRow::builder()
            .title("New value")
            .model(&gtk::StringList::new(modes))
            .build();
        value_group.add(&mode);
        body.append(&value_group);
        if old.is_some() {
            body.append(&styled(
                "Moving an entry to another group and editing notes come in a later version.",
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
            let form = Form {
                kind: model::KIND_CHOICES[kind.selected() as usize],
                name: fields[0].text().into(),
                group: fields[1].text().into(),
                username: fields[2].text().into(),
                url: fields[3].text().into(),
                host: fields[4].text().into(),
                port: fields[5].text().into(),
                tags: fields[6].text().into(),
            };
            let selected = mode.selected() + if old.is_some() { 0 } else { 1 };
            let mode = match selected {
                0 => ValueMode::Keep,
                1 => ValueMode::Prompt,
                _ => ValueMode::Generate,
            };
            match form.request(old.as_ref(), mode) {
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
