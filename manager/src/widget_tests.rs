//! Widgets with a real agent and scripted decisions, exclusively on Xvfb.
//! The grants of the credential broker need a broker program, which a test
//! agent cannot start: their page is driven by a fake agent instead.
#![allow(clippy::unwrap_used)]
use super::*;
use rusthorse::agent::{Agent, AgentConfig};
use rusthorse::broker_profile::{AutomaticLocks, Preset};
use rusthorse::protocol::{ErrorCode, PROTOCOL_VERSION};
use rusthorse::ui::{ApprovalRequest, Decision, Prompt, Typed, Ui};
use rusthorse::vault::{KdfParams, Vault};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Decisions: `allow`; `hold`, which keeps the "human" looking at the
/// dialog until it is cleared; `asking`, set while held; and a count of the
/// approval dialogs shown.
struct Scripted(
    Arc<AtomicBool>,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
    Arc<std::sync::atomic::AtomicUsize>,
);
impl Ui for Scripted {
    fn master_password(&self, _: &Prompt) -> anyhow::Result<Typed> {
        Ok(Typed::Value("fake master password".to_string().into()))
    }
    fn secret_value(&self, _: &Prompt) -> anyhow::Result<Typed> {
        Ok(Typed::Value("FAKE-desktop-value".to_string().into()))
    }
    fn approve(&self, _: &ApprovalRequest) -> anyhow::Result<Decision> {
        self.3.fetch_add(1, Ordering::SeqCst);
        let until = Instant::now() + Duration::from_secs(30);
        while self.1.load(Ordering::SeqCst) && Instant::now() < until {
            self.2.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(10));
        }
        self.2.store(false, Ordering::SeqCst);
        Ok(if self.0.load(Ordering::SeqCst) {
            Decision::AllowOnce
        } else {
            Decision::Deny
        })
    }
}

#[track_caller]
fn spin_until(check: impl Fn() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !check() {
        assert!(Instant::now() < until, "widget condition timed out");
        while glib::MainContext::default().pending() {
            glib::MainContext::default().iteration(false);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[track_caller]
fn settle(s: &Rc<Manager>) {
    spin_until(|| s.job.borrow().is_none());
}

fn descendants(root: &impl IsA<gtk::Widget>) -> Vec<gtk::Widget> {
    let mut out = vec![];
    let mut child = root.first_child();
    while let Some(w) = child {
        out.extend(descendants(&w));
        child = w.next_sibling();
        out.push(w);
    }
    out
}

fn button(root: &impl IsA<gtk::Widget>, text: &str) -> gtk::Button {
    descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Button>().ok())
        .find(|b| {
            b.label().as_deref() == Some(text)
                || b.child()
                    .and_downcast::<adw::ButtonContent>()
                    .is_some_and(|c| c.label() == text)
        })
        .unwrap_or_else(|| panic!("button missing: {text}"))
}

/// The button with this widget name.
fn named(root: &impl IsA<gtk::Widget>, name: &str) -> gtk::Button {
    descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Button>().ok())
        .find(|b| b.widget_name() == name)
        .unwrap_or_else(|| panic!("button missing: {name}"))
}

/// Whether Pango may not draw hyphens where it breaks this label's words.
fn hyphenless(l: &gtk::Label) -> bool {
    l.attributes().is_some_and(|list| {
        list.attributes().iter().any(|a| {
            a.type_() == pango::AttrType::InsertHyphens
                && a.downcast_ref::<pango::AttrInt>()
                    .is_some_and(|i| i.value() == 0)
        })
    })
}

fn entry_rows(root: &impl IsA<gtk::Widget>) -> Vec<adw::EntryRow> {
    let mut rows: Vec<_> = descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::EntryRow>().ok())
        .collect();
    // Put the rows in the order the form lists them: their index in the
    // list, which hidden rows (a kind may hide some) have too.
    rows.sort_by_key(|r| r.index());
    rows
}

/// The text a revealed value shows: one plain label, never split.
/// The form's list of groups.
fn group_list(root: &impl IsA<gtk::Widget>) -> adw::ComboRow {
    descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::ComboRow>().ok())
        .find(|c| c.title() == "Group")
        .expect("group list")
}

/// The labels a list offers, and the selected one.
fn offered_groups(list: &adw::ComboRow) -> (Vec<String>, String) {
    let model = list
        .model()
        .and_downcast::<gtk::StringList>()
        .expect("strings");
    let labels: Vec<String> = (0..model.n_items())
        .filter_map(|i| model.string(i))
        .map(|l| l.to_string())
        .collect();
    let selected = labels[list.selected() as usize].clone();
    (labels, selected)
}

/// Choose `label` in a form's list of groups.
fn pick_group(list: &adw::ComboRow, label: &str) {
    let (labels, _) = offered_groups(list);
    let i = labels.iter().position(|l| l == label).expect(label);
    list.set_selected(i as u32);
}

/// The activatable row named `name` under `root`.
fn named_row(root: &impl IsA<gtk::Widget>, name: &str) -> adw::ActionRow {
    descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::ActionRow>().ok())
        .find(|r| r.widget_name() == name)
        .unwrap_or_else(|| panic!("no row {name}"))
}

/// The value choices of an entry form: each row's title, its check button
/// and the row.
fn value_choices(root: &impl IsA<gtk::Widget>) -> Vec<(String, gtk::CheckButton, adw::ActionRow)> {
    descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::ActionRow>().ok())
        .filter(|r| r.type_() == adw::ActionRow::static_type())
        .filter_map(|r| {
            let check = descendants(&r)
                .into_iter()
                .find_map(|w| w.downcast::<gtk::CheckButton>().ok())?;
            Some((r.title().to_string(), check, r))
        })
        .collect()
}

fn shown_text(root: &impl IsA<gtk::Widget>) -> String {
    let labels = value_labels(root);
    assert_eq!(labels.len(), 1, "the value is one label");
    labels[0].text().to_string()
}

/// The labels that draw a revealed value.
fn value_labels(root: &impl IsA<gtk::Widget>) -> Vec<gtk::Label> {
    descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Label>().ok())
        .filter(|l| l.has_css_class("monospace"))
        .collect()
}

/// Run an X11 client on this test's virtual display while the GTK main loop
/// keeps answering it (the clipboard owner is this very process).
fn x11(args: &[&str]) -> (bool, String) {
    let child = std::process::Command::new(args[0])
        .args(&args[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("X11 client");
    let child = std::rc::Rc::new(std::cell::RefCell::new(Some(child)));
    let done = std::rc::Rc::new(std::cell::RefCell::new(None));
    spin_until(|| {
        let mut slot = child.borrow_mut();
        if let Some(c) = slot.as_mut()
            && c.try_wait().unwrap().is_some()
        {
            *done.borrow_mut() = Some(slot.take().unwrap().wait_with_output().unwrap());
        }
        done.borrow().is_some()
    });
    let out = done.borrow_mut().take().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Give a window the X11 input focus. A window GTK has just mapped may not
/// be viewable on the server yet, so retry for a while.
fn focus(name: &str) {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if x11(&[
            "/usr/bin/xdotool",
            "search",
            "--onlyvisible",
            "--name",
            name,
            "windowfocus",
        ])
        .0
        {
            return;
        }
        if Instant::now() >= until {
            let (_, tree) = x11(&["/usr/bin/xwininfo", "-root", "-tree"]);
            panic!("no visible window named {name}; the display has:\n{tree}");
        }
        let pause = Instant::now() + Duration::from_millis(100);
        spin_until(|| Instant::now() >= pause);
    }
}

/// Press `key` in the window that has the X11 input focus, as a person
/// would: through the server, so that GTK's own key handling runs.
fn press(key: &str) {
    assert!(
        x11(&["/usr/bin/xdotool", "key", key]).0,
        "xdotool key {key}"
    );
}

/// What another program gets when it pastes; `None` when it gets nothing
/// (an error, or empty content).
fn paste() -> Option<String> {
    let (ok, text) = x11(&["/usr/bin/xclip", "-o", "-selection", "clipboard"]);
    (ok && !text.is_empty()).then_some(text)
}

fn snapshot(s: &Manager, name: &str) {
    snapshot_window(&s.window, name);
}

fn snapshot_window(window: &impl IsA<gtk::Window>, name: &str) {
    // Optional reviewer artifact, only in this isolated test process.
    if let Some(dir) = std::env::var_os("MANAGER_TEST_SCREENSHOTS") {
        use gtk::gdk::prelude::*;
        let window = window.as_ref();
        let paintable = gtk::WidgetPaintable::new(Some(window));
        let snapshot = gtk::Snapshot::new();
        paintable.snapshot(&snapshot, window.width() as f64, window.height() as f64);
        let node = snapshot.to_node().expect("render node");
        let renderer = window.renderer().expect("renderer");
        renderer
            .render_texture(&node, None)
            .save_to_png(PathBuf::from(dir).join(name))
            .expect("screenshot");
    }
}

/// Run the test `name` again in a child process, on a private Xvfb display
/// and D-Bus session with an empty environment; returns true in that child,
/// where the test itself runs. `systemctl` on the child's `PATH` is a
/// stand-in that only records its arguments in `$HOME/systemctl.calls` (and
/// fails while `$HOME/systemctl.fails` exists, hangs while
/// `$HOME/systemctl.hangs` does): no test starts a real service.
fn on_xvfb(name: &str) -> bool {
    if std::env::var_os("RUSTHORSE_MANAGER_XVFB_CHILD").is_some() {
        return true;
    }
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().expect("isolated runtime");
    // A runtime directory must be private, whatever the umask.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(
        bin.join("systemctl"),
        "#!/bin/sh\n\
         echo \"$*\" >> \"$HOME/systemctl.calls\"\n\
         [ -e \"$HOME/systemctl.hangs\" ] && exec sleep 30\n\
         if [ -e \"$HOME/systemctl.fails\" ]; then\n\
         echo 'Failed to start rusthorse-agent.service: Unit rusthorse-agent.service not found.' >&2\n\
         exit 5\n\
         fi\n",
    )
    .unwrap();
    std::fs::set_permissions(
        bin.join("systemctl"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let log = std::fs::File::create(dir.path().join("test.log")).unwrap();
    let mut cmd = Command::new("/usr/bin/xvfb-run");
    cmd.args([
        "-a",
        "-s",
        "-screen 0 1400x1000x24",
        "/usr/bin/dbus-run-session",
        "--",
    ])
    .arg(std::env::current_exe().unwrap())
    .args(["--exact", &format!("window::tests::{name}"), "--nocapture"])
    .env_clear()
    .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
    // Window titles hold non-ASCII text ("—"): X11 clients such as
    // xdotool cannot read them in the C locale.
    .env("LANG", "C.UTF-8")
    .env("HOME", dir.path())
    .env("TMPDIR", dir.path())
    .env("XDG_RUNTIME_DIR", dir.path())
    .env("XDG_CONFIG_HOME", dir.path())
    .env("XDG_DATA_HOME", dir.path())
    .env("RUSTHORSE_SOCKET", dir.path().join("unused.sock"))
    .env("RUSTHORSE_VAULT", dir.path().join("unused.kdbx"))
    .env("RUSTHORSE_AUDIT_LOG", dir.path().join("unused.jsonl"))
    .env("GDK_BACKEND", "x11")
    .env("GSK_RENDERER", "cairo")
    .env("GSETTINGS_BACKEND", "memory")
    .env("RUSTHORSE_MANAGER_XVFB_CHILD", "1")
    .stdin(Stdio::null())
    .stdout(log.try_clone().unwrap())
    .stderr(log)
    .process_group(0);
    if let Some(path) = std::env::var_os("MANAGER_TEST_SCREENSHOTS") {
        cmd.env("MANAGER_TEST_SCREENSHOTS", path);
    }
    let mut child = cmd.spawn().expect("xvfb-run and dbus-run-session required");
    let until = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= until {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .status();
            let _ = child.wait();
            panic!("Xvfb test timed out; process group stopped");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let output = std::fs::read_to_string(dir.path().join("test.log")).unwrap();
    assert!(status.success(), "{output}");
    false
}

#[test]
fn desktop_flow() {
    if !on_xvfb("desktop_flow") {
        return;
    }
    adw::init().expect("GTK only on Xvfb");
    crate::load_style();
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("fake.kdbx");
    Vault::create(
        &vault,
        "fake master password".to_string().into(),
        KdfParams::INSECURE_FOR_TESTS,
    )
    .unwrap();
    let socket = dir.path().join("run/agent.sock");
    let allowed = Arc::new(AtomicBool::new(true));
    let hold = Arc::new(AtomicBool::new(false));
    let asking = Arc::new(AtomicBool::new(false));
    let approvals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let agent = Agent::new(
        AgentConfig {
            vault,
            socket: socket.clone(),
            audit_log: dir.path().join("fake.jsonl"),
            idle_timeout: Duration::ZERO,
            request_timeout: Duration::from_secs(5),
            send_buffer: None,
            session_lock: Default::default(),
            new_vault_kdf: rusthorse::vault::KdfParams::INSECURE_FOR_TESTS,
            keyring: Default::default(),
        },
        Box::new(Scripted(
            Arc::clone(&allowed),
            Arc::clone(&hold),
            Arc::clone(&asking),
            Arc::clone(&approvals),
        )),
    );
    let listener = Agent::bind(&socket).unwrap();
    // This thread exists only in this test's subprocess; no daemon outlives it.
    std::thread::spawn(move || {
        agent.serve(listener).unwrap();
    });
    let app = adw::Application::builder()
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.register(None::<&gio::Cancellable>).unwrap();
    let s = Manager::new(&app, socket);
    // The same shutdown wiring as the program's.
    let state = Rc::new(RefCell::new(Some(Rc::clone(&s))));
    crate::wipe_at_shutdown(&app, &state);
    s.window.present();
    s.refresh();
    settle(&s);
    assert_eq!(s.pill.text(), "Locked");
    assert!(s.entries.borrow().is_empty());
    button(&s.window, "Unlock").emit_clicked();
    settle(&s);
    assert_eq!(s.pill.text(), "Unlocked");
    // The Status page says what else locks the vault, one event per line
    // (this test's agent watches nothing).
    assert!(descendants(&s.status_page).iter().any(|w| {
        w.clone().downcast::<gtk::Label>().is_ok_and(|l| {
            l.text() == "suspend: not watched — turned off\nscreen lock: not watched — turned off"
        })
    }));

    // Fill the real form; no manager password entry exists.
    button(&s.window, "New entry").emit_clicked();
    let editor = s.editor.borrow().as_ref().unwrap().clone();
    let settle_frame = Instant::now() + Duration::from_millis(300);
    spin_until(|| Instant::now() >= settle_frame);
    let inputs = entry_rows(&editor);
    assert_eq!(inputs.len(), 7);
    assert_eq!(inputs[0].title(), "Name");
    // How the value is made: every choice in view, typing it chosen.
    let choices = value_choices(&editor);
    let titles: Vec<_> = choices.iter().map(|(t, ..)| t.as_str()).collect();
    assert_eq!(titles, ["Type the value", "Generate a random value"]);
    assert!(choices[0].1.is_active() && !choices[1].1.is_active());
    inputs[0].set_text("FAKE_DESKTOP_KEY");
    // The group: chosen from a list; a new one is typed in the row that
    // "New group…" opens.
    let groups = group_list(&editor);
    assert_eq!(
        offered_groups(&groups),
        (
            vec!["No group".into(), "New group…".into()],
            "No group".into()
        )
    );
    assert!(!inputs[1].is_visible());
    pick_group(&groups, "New group…");
    assert!(inputs[1].is_visible());
    assert_eq!(
        inputs[1].title(),
        "New group (a path such as home/firewalls)"
    );
    inputs[1].set_text("AI");
    // The kind decides which rows are offered and what the URL is called;
    // a row with a value is never hidden.
    let kind = descendants(&editor)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::ComboRow>().ok())
        .find(|c| c.title() == "Kind")
        .expect("kind row");
    let all = descendants(&editor)
        .into_iter()
        .find_map(|w| w.downcast::<adw::SwitchRow>().ok())
        .expect("show all fields");
    assert_eq!(kind.selected(), 0, "Other");
    assert!(inputs[2..6].iter().all(|r| r.is_visible()));
    assert!(!all.is_visible(), "Other shows every field already");
    kind.set_selected(1);
    assert_eq!(inputs[3].title(), "Endpoint URL");
    assert!(inputs[2].is_visible() && inputs[3].is_visible());
    assert!(!inputs[4].is_visible() && !inputs[5].is_visible());
    // Every field, without changing the kind or what the URL is called.
    assert!(all.is_visible() && !all.is_active());
    all.set_active(true);
    assert!(inputs[2..6].iter().all(|r| r.is_visible()));
    assert_eq!(inputs[3].title(), "Endpoint URL");
    assert_eq!(kind.selected(), 1);
    all.set_active(false);
    assert!(!inputs[4].is_visible() && !inputs[5].is_visible());
    inputs[3].set_text("https://example.invalid");
    kind.set_selected(3);
    assert_eq!(inputs[3].title(), "URL");
    assert!(
        inputs[3].is_visible(),
        "a server offers no URL, but this one has a value"
    );
    assert!(inputs[4].is_visible() && inputs[5].is_visible());
    kind.set_selected(4);
    assert_eq!(inputs[3].title(), "Admin page");
    assert!(!inputs[5].is_visible());
    // A row the file withholds stays, with its warning, whatever the kind.
    let loose: Vec<adw::EntryRow> = (0..7).map(|_| adw::EntryRow::new()).collect();
    shape_rows(
        &loose,
        Some(EntryKind::ApiKey),
        [false, true, true, false],
        false,
    );
    assert!(loose[4].is_visible() && !loose[5].is_visible());
    assert_eq!(loose[3].title(), "Endpoint URL (protected; unchanged)");
    kind.set_selected(1);
    let settle_frame = Instant::now() + Duration::from_millis(200);
    spin_until(|| Instant::now() >= settle_frame);
    snapshot_window(&editor, "editor.png");
    let (kind_gone, all_gone) = (kind.downgrade(), all.downgrade());
    drop((kind, all));
    button(&editor, "Send to agent…").emit_clicked();
    settle(&s);
    drop(editor);
    assert_eq!(s.entries.borrow().len(), 1);
    assert_eq!(s.entries.borrow()[0].fields.kind, Some(EntryKind::ApiKey));
    let id = s.entries.borrow()[0].id.clone();
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    assert_eq!(s.current().unwrap().id, id);
    assert!(!descendants(&s.window).iter().any(|w| {
        w.clone()
            .downcast::<gtk::Label>()
            .is_ok_and(|l| l.text().contains("FAKE-desktop-value"))
    }));
    spin_until(|| s.window.width() > 0);
    // Let a full frame settle before measuring/recording the widget tree.
    let settle_frame = Instant::now() + Duration::from_millis(200);
    spin_until(|| Instant::now() >= settle_frame);
    snapshot(&s, "manager-light.png");
    // The window fits a 1024-pixel screen: its narrowest layout, with an
    // entry selected, is measured as GTK lays it out.
    let (narrowest, _, _, _) = s
        .window
        .content()
        .expect("content")
        .measure(gtk::Orientation::Horizontal, -1);
    let (window_min, _, _, _) = s.window.measure(gtk::Orientation::Horizontal, -1);
    assert!(
        narrowest <= 960 && window_min <= 1000,
        "minimum width {narrowest}, {window_min} with the window's frame"
    );
    // Every key/value row is named by its key for screen readers, and the
    // short Show and Copy buttons carry the full action.
    let rows: Vec<_> = descendants(&s.detail)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::PreferencesRow>().ok())
        .filter(|r| r.type_() == adw::PreferencesRow::static_type())
        .collect();
    assert!(rows.len() >= 4);
    assert!(rows.iter().all(|r| gtk::test_accessible_has_relation(
        r.upcast_ref::<gtk::Widget>(),
        gtk::AccessibleRelation::LabelledBy
    )));
    for name in ["show-value", "copy-value", "show-notes", "copy-notes"] {
        assert!(gtk::test_accessible_has_property(
            &named(&s.detail, name),
            gtk::AccessibleProperty::Label
        ));
    }
    adw::StyleManager::default().set_color_scheme(adw::ColorScheme::ForceDark);
    let settle_frame = Instant::now() + Duration::from_millis(250);
    spin_until(|| Instant::now() >= settle_frame);
    snapshot(&s, "manager-dark.png");

    // The background status check never blocks the controls.
    s.poll_status();
    assert!(s.poll.borrow().is_some());
    assert!(s.actions.borrow().iter().all(|b| b.is_sensitive()));
    assert!(!s.waiting.is_visible());
    spin_until(|| s.poll.borrow().is_none());
    // It runs beside a request of the human's; a result that predates that
    // request is not used.
    s.poll_status();
    s.refresh();
    assert!(s.poll.borrow().is_some() && s.job.borrow().is_some());
    settle(&s);
    spin_until(|| s.poll.borrow().is_none());

    // Local filters really hide the selection; full metadata comes back.
    s.search.set_text("no match");
    s.populate_rows();
    assert!(s.rows.row_at_index(0).is_none());
    assert!(s.current().is_none());
    s.search.set_text("");
    s.populate_rows();
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    // An API key's details call the URL its endpoint, and the command gets
    // the endpoint too.
    assert!(descendants(&s.detail).iter().any(|w| {
        w.clone()
            .downcast::<gtk::Label>()
            .is_ok_and(|l| l.text() == "Endpoint URL")
    }));
    button(&s.detail, "Copy command snippet").emit_clicked();
    let copied = glib::MainContext::default()
        .block_on(s.window.clipboard().read_text_future())
        .unwrap()
        .unwrap();
    assert!(copied.contains(&id));
    assert!(
        copied.contains(&format!("--url FAKE_DESKTOP_BASE_URL={id}")),
        "{copied}"
    );
    // Drawn on three lines, as copied: no escaped line breaks.
    assert!(descendants(&s.detail).iter().any(|w| {
        w.clone()
            .downcast::<gtk::Label>()
            .is_ok_and(|l| l.text() == copied.as_str())
    }));
    assert!(!copied.contains("FAKE-desktop-value"));

    allowed.store(false, Ordering::SeqCst);
    named(&s.detail, "show-value").emit_clicked();
    settle(&s);
    assert!(s.revealed.borrow().is_none());
    assert!(s.message.text().contains("denied"));
    // A denial leaves the list and the selection as they were.
    assert_eq!(s.entries.borrow().len(), 1);
    assert_eq!(s.current().map(|e| e.id), Some(id.clone()));
    s.refresh();
    settle(&s);
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    allowed.store(true, Ordering::SeqCst);
    named(&s.detail, "show-value").emit_clicked();
    settle(&s);
    let reveal = s.revealed.borrow().as_ref().unwrap().clone();
    assert_eq!(shown_text(&reveal), "FAKE-desktop-value");
    let parts = value_labels(&reveal);
    // Plain text: not selectable (no PRIMARY), not bold, not split up, and
    // no hyphen drawn where a long value wraps.
    assert!(parts.iter().all(|l| !l.is_selectable()));
    assert!(parts.iter().all(hyphenless));
    assert!(
        parts
            .iter()
            .all(|l| !l.has_css_class("title-4") && !l.has_css_class("heading"))
    );
    assert!(
        !descendants(&reveal)
            .iter()
            .any(|w| w.clone().downcast::<gtk::FlowBox>().is_ok())
    );
    snapshot_window(&reveal, "reveal.png");
    button(&reveal, "Hide now").emit_clicked();
    assert!(parts.iter().all(|l| l.text().is_empty()));

    // Seed notes through the existing approved API; never via a manager field.
    let client = rusthorse::client::Client::new(s.socket.clone());
    assert!(matches!(
        client
            .call(&Request::Edit {
                name: id.clone(),
                changes: EntryChanges {
                    notes: Some("FAKE-notes".into()),
                    ..Default::default()
                }
            })
            .unwrap(),
        Response::Ok { .. }
    ));
    s.refresh();
    settle(&s);
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    named(&s.detail, "show-notes").emit_clicked();
    settle(&s);
    let notes = s.revealed.borrow().as_ref().unwrap().clone();
    assert_eq!(shown_text(&notes), "FAKE-notes");
    button(&notes, "Hide now").emit_clicked();

    // The actual expiry cleanup drops GTK text too (short lifetime for the test).
    s.show_secret_for(
        "Fake expiry",
        false,
        "FAKE-expiring".to_string().into(),
        Duration::from_millis(100),
    );
    let expiring = s.revealed.borrow().as_ref().unwrap().clone();
    assert_eq!(shown_text(&expiring), "FAKE-expiring");
    let expiring_parts = value_labels(&expiring);
    spin_until(|| !expiring.is_visible());
    assert!(expiring_parts.iter().all(|l| l.text().is_empty()));

    // Focus loss uses real X11 events, on this test's virtual display only.
    s.show_secret("Fake focus", false, "FAKE-focus".to_string().into());
    let focused = s.revealed.borrow().as_ref().unwrap().clone();
    spin_until(|| focused.is_mapped());
    focus("^Revealed secret");
    spin_until(|| focused.is_active());
    focus("^Rusthorse$");
    spin_until(|| !focused.is_visible());

    // Copy: denied, the clipboard keeps what it had; allowed, the value is
    // on it like any copied text — every paste gets it. Read by another X11
    // client.
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    s.window.clipboard().set_text("before the copy");
    allowed.store(false, Ordering::SeqCst);
    named(&s.detail, "copy-value").emit_clicked();
    settle(&s);
    assert_eq!(paste().as_deref(), Some("before the copy"));
    allowed.store(true, Ordering::SeqCst);
    named(&s.detail, "copy-value").emit_clicked();
    settle(&s);
    assert_eq!(paste().as_deref(), Some("FAKE-desktop-value"));
    assert_eq!(paste().as_deref(), Some("FAKE-desktop-value"));
    assert!(
        s.message.text().contains("clipboard history"),
        "{}",
        s.message.text()
    );

    // The Show window copies what it shows, exactly, without asking again.
    s.window.clipboard().set_text("before the copy");
    let before = approvals.load(Ordering::SeqCst);
    named(&s.detail, "show-value").emit_clicked();
    settle(&s);
    assert_eq!(approvals.load(Ordering::SeqCst), before + 1);
    let reveal = s.revealed.borrow().as_ref().unwrap().clone();
    button(&reveal, "Copy").emit_clicked();
    assert_eq!(approvals.load(Ordering::SeqCst), before + 1, "asked again");
    assert_eq!(paste().as_deref(), Some("FAKE-desktop-value"));
    button(&reveal, "Hide now").emit_clicked();
    // What is shown escaped is copied as it is.
    s.show_secret_for(
        "Fake escaped",
        false,
        "price-\u{20ac}-1".to_string().into(),
        Duration::from_secs(30),
    );
    let escaped = s.revealed.borrow().as_ref().unwrap().clone();
    // Shown escaped, as the agent's dialogs would draw it.
    assert_eq!(shown_text(&escaped), "price-\\u{20ac}-1");
    button(&escaped, "Copy").emit_clicked();
    assert_eq!(paste().as_deref(), Some("price-\u{20ac}-1"));
    button(&escaped, "Hide now").emit_clicked();
    // A value with a NUL is never copied, in part or whole, and nothing
    // crashes: neither from the entry nor from the Show window.
    s.window.clipboard().set_text("before the copy");
    s.put_on_clipboard(
        "Fake NUL",
        &SecretString::new("FAKE-before\0FAKE-after".to_string()),
    );
    assert!(s.message.text().contains("NUL"), "{}", s.message.text());
    assert!(!s.message.text().contains("FAKE-before"));
    assert_eq!(paste().as_deref(), Some("before the copy"));
    s.show_secret_for(
        "Fake NUL shown",
        false,
        "FAKE-before\0FAKE-after".to_string().into(),
        Duration::from_secs(30),
    );
    let nul = s.revealed.borrow().as_ref().unwrap().clone();
    assert_eq!(shown_text(&nul), "FAKE-before\\u{0}FAKE-after");
    button(&nul, "Copy").emit_clicked();
    assert_eq!(paste().as_deref(), Some("before the copy"));
    button(&nul, "Hide now").emit_clicked();
    s.rows.select_row(s.rows.row_at_index(0).as_ref());

    // A lock made elsewhere while a request waits for the human is seen.
    hold.store(true, Ordering::SeqCst);
    ActionRowExt::activate(&named_row(&s.detail, "random-value"));
    assert!(s.job.borrow().is_some());
    // Lock only once the request is at the approval dialog; earlier, the
    // request would find the vault locked and ask for the password again.
    spin_until(|| asking.load(Ordering::SeqCst));
    let other = rusthorse::client::Client::new(s.socket.clone());
    assert!(matches!(
        other.call(&Request::Lock).unwrap(),
        Response::Ok { .. }
    ));
    let seen = Instant::now() + Duration::from_secs(9);
    spin_until(|| s.pill.text() == "Locked" || Instant::now() >= seen);
    assert_eq!(s.pill.text(), "Locked", "lock not seen during the request");
    assert!(s.entries.borrow().is_empty());
    assert!(s.job.borrow().is_some(), "the request is still waiting");
    hold.store(false, Ordering::SeqCst);
    settle(&s);
    button(&s.window, "Unlock").emit_clicked();
    settle(&s);
    spin_until(|| s.job.borrow().is_none() && !s.entries.borrow().is_empty());
    s.rows.select_row(s.rows.row_at_index(0).as_ref());

    // A value that arrives after such a lock was seen is not used.
    s.window.clipboard().set_text("before the copy");
    hold.store(true, Ordering::SeqCst);
    named(&s.detail, "copy-value").emit_clicked();
    spin_until(|| asking.load(Ordering::SeqCst));
    s.lock_seen.set(true);
    hold.store(false, Ordering::SeqCst);
    settle(&s);
    assert!(s.revealed.borrow().is_none());
    assert!(
        s.message.text().contains("neither shown nor copied"),
        "{}",
        s.message.text()
    );
    assert_eq!(paste().as_deref(), Some("before the copy"));

    // Answers already on their way when a lock is seen do not undo it: a
    // refresh whose "unlocked" status is queued, then a lock elsewhere seen
    // by a status check of the same epoch.
    spin_until(|| s.poll.borrow().is_none());
    s.refresh();
    std::thread::sleep(Duration::from_millis(300));
    let other = rusthorse::client::Client::new(s.socket.clone());
    assert!(matches!(
        other.call(&Request::Lock).unwrap(),
        Response::Ok { .. }
    ));
    s.poll_status();
    std::thread::sleep(Duration::from_millis(300));
    settle(&s);
    spin_until(|| s.poll.borrow().is_none());
    assert_eq!(s.pill.text(), "Locked");
    assert!(s.entries.borrow().is_empty());
    let still_locked = |s: &Manager| {
        matches!(
            rusthorse::client::Client::new(s.socket.clone()).call(&Request::Status).unwrap(),
            Response::Status(i) if i.locked
        )
    };
    assert!(
        still_locked(&s),
        "a stale status made the manager list again"
    );
    // The same with a list on its way.
    button(&s.window, "Unlock").emit_clicked();
    settle(&s);
    spin_until(|| s.job.borrow().is_none() && !s.entries.borrow().is_empty());
    spin_until(|| s.poll.borrow().is_none());
    s.submit(Request::List, Pending::List);
    std::thread::sleep(Duration::from_millis(300));
    assert!(matches!(
        other.call(&Request::Lock).unwrap(),
        Response::Ok { .. }
    ));
    s.poll_status();
    std::thread::sleep(Duration::from_millis(300));
    settle(&s);
    spin_until(|| s.poll.borrow().is_none());
    assert_eq!(s.pill.text(), "Locked");
    assert!(s.entries.borrow().is_empty(), "a stale list came back");
    assert!(still_locked(&s));
    button(&s.window, "Unlock").emit_clicked();
    settle(&s);
    spin_until(|| s.job.borrow().is_none() && !s.entries.borrow().is_empty());
    s.rows.select_row(s.rows.row_at_index(0).as_ref());

    // A denied delete does not change the list on the next refresh.
    allowed.store(false, Ordering::SeqCst);
    button(&s.detail, "Delete…").emit_clicked();
    settle(&s);
    assert!(s.message.text().contains("denied"));
    s.refresh();
    settle(&s);
    assert_eq!(s.entries.borrow().len(), 1);
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    allowed.store(true, Ordering::SeqCst);

    // Backup is sent to the agent; the UI never opens the encrypted copy.
    s.backup();
    let editor = s.editor.borrow().as_ref().unwrap().clone();
    let path = entry_rows(&editor).remove(0);
    let backup = dir.path().join("backup.kdbx");
    path.set_text(backup.to_str().unwrap());
    button(&editor, "Back up").emit_clicked();
    settle(&s);
    assert!(backup.is_file());

    // Metadata edit uses UUID, keeps the password, and refreshes the list.
    s.edit(s.current());
    let editor = s.editor.borrow().as_ref().unwrap().clone();
    // The new form replaced the closed one, which leaves nothing alive: no
    // handler keeps its widgets in a cycle.
    spin_until(|| kind_gone.upgrade().is_none() && all_gone.upgrade().is_none());
    let settle_frame = Instant::now() + Duration::from_millis(300);
    spin_until(|| Instant::now() >= settle_frame);
    let inputs = entry_rows(&editor);
    assert_eq!(inputs[0].title(), "Name");
    // The form starts on the entry's group (moving: see below).
    assert_eq!(
        offered_groups(&group_list(&editor)),
        (
            vec!["No group".into(), "AI".into(), "New group…".into()],
            "AI".into()
        )
    );
    assert!(!inputs[1].is_visible());
    inputs[0].set_text("RENAMED_FAKE");
    // The value: kept unless another choice is made, one choice at a time.
    let choices = value_choices(&editor);
    let titles: Vec<_> = choices.iter().map(|(t, ..)| t.as_str()).collect();
    assert_eq!(
        titles,
        [
            "Keep the current value",
            "Type a new value",
            "Generate a random value"
        ]
    );
    assert!(choices[0].1.is_active());
    // Chosen with the keyboard, as a person would: the row takes the key.
    focus("^Edit entry$");
    for (i, key) in [(1, "space"), (2, "Return")] {
        choices[i].2.grab_focus();
        press(key);
        spin_until(|| choices[i].1.is_active());
        let others = (0..3).filter(|j| *j != i);
        assert!(others.into_iter().all(|j| !choices[j].1.is_active()), "{i}");
    }
    drop(choices);
    button(&editor, "Send to agent…").emit_clicked();
    settle(&s);
    assert_eq!(s.entries.borrow()[0].id, id);
    assert_eq!(s.entries.borrow()[0].name, "RENAMED_FAKE");
    // The form's choice was sent: the value is a generated one.
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    named(&s.detail, "show-value").emit_clicked();
    settle(&s);
    let generated = shown_text(s.revealed.borrow().as_ref().unwrap());
    assert_eq!(generated.len(), 32, "{generated:?}");
    assert!(generated.chars().all(|c| c.is_ascii_alphanumeric()));
    // Change… goes straight to the agent's dialog for the new value: no
    // form, and no approval before it.
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    let asked = approvals.load(Ordering::SeqCst);
    // With the keyboard, as a person would.
    focus("^Rusthorse$");
    named_row(&s.detail, "change-value").grab_focus();
    press("Return");
    spin_until(|| s.job.borrow().is_some());
    settle(&s);
    assert_eq!(approvals.load(Ordering::SeqCst), asked);
    assert!(s.message.text().contains("updated"), "{}", s.message.text());
    assert!(s.revealed.borrow().as_ref().is_none_or(|w| !w.is_visible()));
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    named(&s.detail, "show-value").emit_clicked();
    settle(&s);
    let typed = shown_text(s.revealed.borrow().as_ref().unwrap());
    assert_eq!(typed, "FAKE-desktop-value");
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    ActionRowExt::activate(&named_row(&s.detail, "random-value"));
    settle(&s);
    assert!(s.revealed.borrow().as_ref().is_none_or(|w| !w.is_visible()));

    // Moving: the Edit form's Group row takes a path, created if missing,
    // with spaces around a `/` left out; emptying it moves the entry to the
    // top level. Each move asks for approval and keeps the UUID.
    let move_to = |pick: &str, typed: &str| {
        s.rows.select_row(s.rows.row_at_index(0).as_ref());
        s.edit(s.current());
        let editor = s.editor.borrow().as_ref().unwrap().clone();
        pick_group(&group_list(&editor), pick);
        let group = entry_rows(&editor).remove(1);
        assert_eq!(group.is_visible(), pick == "New group…");
        group.set_text(typed);
        let asked = approvals.load(Ordering::SeqCst);
        button(&editor, "Send to agent…").emit_clicked();
        settle(&s);
        let error = descendants(&editor)
            .into_iter()
            .filter_map(|w| w.downcast::<gtk::Label>().ok())
            .find(|l| l.has_css_class("error"))
            .map(|l| l.text().to_string());
        assert!(!editor.is_visible(), "the form stayed open: {error:?}");
        assert_eq!(approvals.load(Ordering::SeqCst), asked + 1);
        assert_eq!(s.entries.borrow().len(), 1);
        assert_eq!(s.entries.borrow()[0].id, id);
        assert_eq!(s.entries.borrow()[0].name, "RENAMED_FAKE");
    };
    // The heading the list shows above the entry, and the groups the filter
    // offers after "All groups".
    let heading = |s: &Manager| {
        s.rows
            .row_at_index(0)
            .and_then(|r| r.header())
            .and_downcast::<gtk::Label>()
            .map(|l| l.text().to_string())
    };
    let offered = |s: &Manager| {
        let list = s.groups.model().and_downcast::<gtk::StringList>().unwrap();
        (0..list.n_items())
            .filter_map(|i| list.string(i))
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(heading(&s).as_deref(), Some("AI"));
    move_to("New group…", " Work / Servers ");
    assert_eq!(s.entries.borrow()[0].group.as_deref(), Some("Work/Servers"));
    assert_eq!(heading(&s).as_deref(), Some("Work/Servers"));
    assert!(descendants(&s.detail).iter().any(|w| {
        w.clone()
            .downcast::<gtk::Label>()
            .is_ok_and(|l| l.text().starts_with("Work/Servers · "))
    }));
    // The filter offers the new group (the old one has no entry left), and
    // choosing it shows the entry.
    assert_eq!(offered(&s), ["All groups", "Work/Servers"]);
    s.groups.set_selected(1);
    assert_eq!(
        s.rows.row_at_index(0).map(|r| r.widget_name().to_string()),
        Some(id.clone())
    );
    // A new entry starts in the group the list is filtered on.
    s.edit(None);
    let editor = s.editor.borrow().as_ref().unwrap().clone();
    assert_eq!(offered_groups(&group_list(&editor)).1, "Work/Servers");
    button(&editor, "Cancel").emit_clicked();
    spin_until(|| !editor.is_visible());
    drop(editor);
    s.groups.set_selected(0);
    s.edit(None);
    let editor = s.editor.borrow().as_ref().unwrap().clone();
    assert_eq!(offered_groups(&group_list(&editor)).1, "No group");
    button(&editor, "Cancel").emit_clicked();
    spin_until(|| !editor.is_visible());
    drop(editor);
    // A group name the agent would refuse is refused by the form: nothing
    // is sent and the form stays open with the reason.
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    s.edit(s.current());
    let editor = s.editor.borrow().as_ref().unwrap().clone();
    // The list offers the new group and the group above it.
    let groups = group_list(&editor);
    assert_eq!(
        offered_groups(&groups),
        (
            vec![
                "No group".into(),
                "Work".into(),
                "Work/Servers".into(),
                "New group…".into()
            ],
            "Work/Servers".into()
        )
    );
    // A new group that differs from an existing one only in case: a warning.
    pick_group(&groups, "New group…");
    let warned = |editor: &adw::Window| {
        descendants(editor)
            .into_iter()
            .filter_map(|w| w.downcast::<adw::ActionRow>().ok())
            .find(|r| r.has_css_class("warning") && r.is_visible())
            .map(|r| r.title().to_string())
    };
    entry_rows(&editor)[1].set_text("work / servers");
    let twin = Some("There is already a group named Work/Servers; names are case-sensitive.");
    assert_eq!(warned(&editor).as_deref(), twin);
    // Away from "New group…" and back: the text is still there, and so is
    // the warning.
    pick_group(&groups, "No group");
    assert_eq!(warned(&editor), None);
    pick_group(&groups, "New group…");
    assert_eq!(warned(&editor).as_deref(), twin);
    entry_rows(&editor)[1].set_text("Work/Servers/New");
    assert_eq!(warned(&editor), None);
    // "New group…" with nothing typed sends nothing.
    entry_rows(&editor)[1].set_text(" / ");
    button(&editor, "Send to agent…").emit_clicked();
    assert!(s.job.borrow().is_none() && editor.is_visible());
    assert!(descendants(&editor).iter().any(|w| {
        w.clone()
            .downcast::<gtk::Label>()
            .is_ok_and(|l| l.has_css_class("error") && l.text().starts_with("Type the new group"))
    }));
    entry_rows(&editor)[1].set_text("Work/Bad\u{200b}Name");
    let asked = approvals.load(Ordering::SeqCst);
    button(&editor, "Send to agent…").emit_clicked();
    assert!(s.job.borrow().is_none() && editor.is_visible());
    assert!(descendants(&editor).iter().any(|w| {
        w.clone()
            .downcast::<gtk::Label>()
            .is_ok_and(|l| l.has_css_class("error") && l.text().starts_with("Group: "))
    }));
    button(&editor, "Cancel").emit_clicked();
    spin_until(|| !editor.is_visible());
    drop(editor);
    assert_eq!(approvals.load(Ordering::SeqCst), asked);
    // To an existing group, chosen from the list: the group above.
    move_to("Work", "");
    assert_eq!(s.entries.borrow()[0].group.as_deref(), Some("Work"));
    // Back to the top level.
    move_to("No group", "");
    assert_eq!(s.entries.borrow()[0].group, None);
    assert_eq!(heading(&s).as_deref(), Some("No group"));
    assert_eq!(offered(&s), ["All groups", "No group"]);
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    button(&s.detail, "Delete…").emit_clicked();
    settle(&s);
    assert!(s.entries.borrow().is_empty());
    // A status result that predates a request is not used: an "unlocked"
    // read before Lock now must not make the manager list again, which
    // would make the agent ask for the master password.
    s.poll_status();
    let stale = s.poll.borrow_mut().take();
    assert!(stale.is_some());
    std::thread::sleep(Duration::from_millis(300));
    button(&s.window, "Lock now").emit_clicked();
    settle(&s);
    assert_eq!(s.pill.text(), "Locked");
    *s.poll.borrow_mut() = stale;
    spin_until(|| s.poll.borrow().is_none());
    settle(&s);
    assert_eq!(s.pill.text(), "Locked");
    let status = rusthorse::client::Client::new(s.socket.clone())
        .call(&Request::Status)
        .unwrap();
    assert!(matches!(status, Response::Status(i) if i.locked));
    // Closing, and the application's shutdown, hide a shown value.
    s.show_secret_for(
        "Fake shown at exit",
        false,
        "FAKE-shown-at-exit".to_string().into(),
        Duration::from_secs(30),
    );
    s.window.close();
    assert!(s.closed.get());
    assert!(s.job.borrow().is_none());
    assert!(s.revealed.borrow().is_none());
    s.show_secret_for(
        "Fake shown at shutdown",
        false,
        "FAKE-shown-at-shutdown".to_string().into(),
        Duration::from_secs(30),
    );
    app.emit_by_name::<()>("shutdown", &[]);
    assert!(s.revealed.borrow().is_none());
}

/// The title of the first step the detail pane shows, if any.
fn first_step(s: &Manager) -> Option<(String, String)> {
    s.detail
        .first_child()
        .and_then(|w| w.downcast::<adw::StatusPage>().ok())
        .map(|page| {
            (
                page.title().to_string(),
                page.description()
                    .map(|d| d.to_string())
                    .unwrap_or_default(),
            )
        })
}

/// From nothing to an open vault: the agent is not running, then it is but
/// there is no vault, then the vault is created — all from the window.
#[test]
fn first_start() {
    if !on_xvfb("first_start") {
        return;
    }
    adw::init().expect("GTK only on Xvfb");
    crate::load_style();
    let home = PathBuf::from(std::env::var_os("HOME").unwrap());
    let calls = || std::fs::read_to_string(home.join("systemctl.calls")).unwrap_or_default();
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("first.kdbx");
    let socket = dir.path().join("run/agent.sock");
    let app = adw::Application::builder()
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.register(None::<&gio::Cancellable>).unwrap();
    let s = Manager::new(&app, socket.clone());
    s.window.present();
    s.refresh();
    settle(&s);

    // Nothing listens on the socket: the window offers to start the agent.
    assert_eq!(s.pill.text(), "Not running");
    assert_eq!(s.lock.label().as_deref(), Some("Start agent"));
    assert_eq!(
        first_step(&s).map(|(title, _)| title).as_deref(),
        Some("The agent is not running")
    );
    // systemctl fails (the service is not installed): the window says why.
    std::fs::write(home.join("systemctl.fails"), "").unwrap();
    button(&s.detail, "Start agent").emit_clicked();
    spin_until(|| !s.starting.get());
    assert!(
        s.message.text().contains("not found"),
        "{}",
        s.message.text()
    );
    assert!(s.message.has_css_class("error"));
    std::fs::remove_file(home.join("systemctl.fails")).unwrap();
    // systemctl hangs: it is stopped after the deadline (2 s in tests).
    std::fs::write(home.join("systemctl.hangs"), "").unwrap();
    s.lock.emit_clicked();
    spin_until(|| !s.starting.get());
    assert!(
        s.message.text().contains("did not finish"),
        "{}",
        s.message.text()
    );
    std::fs::remove_file(home.join("systemctl.hangs")).unwrap();
    // It works: the agent is asked of systemd, never started by the window.
    s.lock.emit_clicked();
    spin_until(|| !s.starting.get());
    assert_eq!(calls(), "--user start rusthorse-agent.service\n".repeat(3));
    // The stand-in starts nothing; this test's agent stands in for the one
    // systemd would start.
    let agent = Agent::new(
        AgentConfig {
            vault: vault.clone(),
            socket: socket.clone(),
            audit_log: dir.path().join("first.jsonl"),
            idle_timeout: Duration::ZERO,
            request_timeout: Duration::from_secs(5),
            send_buffer: None,
            session_lock: Default::default(),
            new_vault_kdf: KdfParams::INSECURE_FOR_TESTS,
            keyring: Default::default(),
        },
        Box::new(Scripted(
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        )),
    );
    let listener = Agent::bind(&socket).unwrap();
    // This thread exists only in this test's subprocess; no daemon outlives it.
    std::thread::spawn(move || {
        agent.serve(listener).unwrap();
    });

    // No vault yet: the window offers to create it, and says where.
    spin_until(|| s.pill.text() == "No vault");
    assert_eq!(s.lock.label().as_deref(), Some("Create vault…"));
    // The agent reports a missing vault as locked; the grants page does
    // not say that a vault is locked when there is none.
    assert!(s.status.borrow().as_ref().is_some_and(|i| i.locked));
    assert!(!s.grants_locked.is_visible());
    let (title, description) = first_step(&s).expect("a first step");
    assert_eq!(title, "Create your vault");
    assert!(
        description.contains(&vault.display().to_string()),
        "{description}"
    );
    assert!(description.contains("never sees it"), "{description}");
    // A status check does not repaint the page.
    let page = s.detail.first_child().unwrap();
    s.refresh();
    settle(&s);
    assert_eq!(s.detail.first_child().unwrap(), page);

    // The agent asks for the master password (scripted here), creates the
    // vault and keeps it open.
    button(&s.detail, "Create vault…").emit_clicked();
    settle(&s);
    spin_until(|| s.pill.text() == "Unlocked");
    assert!(vault.exists());
    assert!(s.entries.borrow().is_empty());
    // What the agent reported stays after the refresh that follows.
    settle(&s);
    assert!(
        s.message.text().contains("vault created at"),
        "{}",
        s.message.text()
    );
    assert_eq!(s.lock.label().as_deref(), Some("Lock now"));
    assert_ne!(
        first_step(&s).map(|(title, _)| title).as_deref(),
        Some("Create your vault")
    );
    s.window.close();
}

/// Importing from a fake GNOME Keyring, served on this test's private
/// session bus, and from a `.env` file: the window sees names only, the
/// agent reads the values.
#[test]
fn import_windows() {
    if !on_xvfb("import_windows") {
        return;
    }
    use rusthorse::keyring::fake::{self, Item};
    adw::init().expect("GTK only on Xvfb");
    crate::load_style();
    let segredo = |name: &str, value: &str| {
        Item::new(
            &format!("segredo: {name}"),
            &[("aplicacao", "segredo"), ("nome", name)],
            value,
        )
    };
    let mut locked = segredo("FAKE_LOCKED", "fake-locked");
    locked.locked = true;
    let _keyring = fake::serve(
        None,
        vec![
            segredo("FAKE_A", "fake-a-value"),
            segredo("FAKE_B", "fake-b-value"),
            locked,
            Item::new("another program", &[("application", "other")], "not-this"),
        ],
    )
    .expect("the fake keyring on the private session bus");
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("import.kdbx");
    Vault::create(
        &vault,
        "fake master password".to_string().into(),
        KdfParams::INSECURE_FOR_TESTS,
    )
    .unwrap();
    let socket = dir.path().join("run/agent.sock");
    let approvals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let allowed = Arc::new(AtomicBool::new(true));
    let agent = Agent::new(
        AgentConfig {
            vault: vault.clone(),
            socket: socket.clone(),
            audit_log: dir.path().join("import.jsonl"),
            idle_timeout: Duration::ZERO,
            request_timeout: Duration::from_secs(5),
            send_buffer: None,
            session_lock: Default::default(),
            new_vault_kdf: KdfParams::INSECURE_FOR_TESTS,
            keyring: rusthorse::keyring::Settings {
                address: None,
                plain: true,
                ..Default::default()
            },
        },
        Box::new(Scripted(
            Arc::clone(&allowed),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::clone(&approvals),
        )),
    );
    let listener = Agent::bind(&socket).unwrap();
    // This thread exists only in this test's subprocess; no daemon outlives it.
    std::thread::spawn(move || {
        agent.serve(listener).unwrap();
    });
    let app = adw::Application::builder()
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.register(None::<&gio::Cancellable>).unwrap();
    let s = Manager::new(&app, socket.clone());
    s.window.present();
    s.refresh();
    settle(&s);

    // Locked: the window asks to unlock first, and asks the agent nothing.
    button(&s.window, "From GNOME Keyring…").emit_clicked();
    assert!(s.message.text().contains("Unlock the vault first"));
    assert!(s.job.borrow().is_none());
    button(&s.window, "Unlock").emit_clicked();
    settle(&s);
    assert_eq!(s.pill.text(), "Unlocked");

    // The agent asks before listing (approved here), then the window opens.
    button(&s.window, "From GNOME Keyring…").emit_clicked();
    settle(&s);
    assert_eq!(approvals.load(Ordering::SeqCst), 1);
    let picker = s.editor.borrow().as_ref().unwrap().clone();
    let shown = |root: &adw::Window| -> String {
        descendants(root)
            .into_iter()
            .filter_map(|w| w.downcast::<gtk::Label>().ok())
            .map(|l| l.text().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        !shown(&picker).contains("fake-a-value"),
        "a value in the window"
    );
    // Replacing says what it takes from the entry it replaces (vault.rs
    // writes a replaced entry without its broker profile).
    let replace = descendants(&picker)
        .into_iter()
        .find_map(|w| w.downcast::<adw::SwitchRow>().ok())
        .expect("the replace switch");
    assert_eq!(replace.title(), "Replace entries that already exist");
    assert_eq!(
        replace.subtitle().as_deref(),
        Some("Replacing an entry removes its broker profile, which ends its grants.")
    );
    drop(replace);
    // Names from the attribute "nome"; only the segredo items, ticked.
    let from = descendants(&picker)
        .into_iter()
        .find_map(|w| w.downcast::<gtk::DropDown>().ok())
        .expect("names from");
    let labels: Vec<String> = (0..from.model().unwrap().n_items())
        .map(|i| {
            from.model()
                .unwrap()
                .item(i)
                .and_downcast::<gtk::StringObject>()
                .unwrap()
                .string()
                .to_string()
        })
        .collect();
    let nome = labels
        .iter()
        .position(|l| l == "Attribute nome")
        .expect("nome");
    from.set_selected(nome as u32);
    // (The drop-down has a search entry of its own.)
    let search = descendants(&picker)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::SearchEntry>().ok())
        .find(|e| e.placeholder_text().as_deref() == Some("Filter"))
        .expect("filter");
    search.set_text("segredo");
    spin_until(|| {
        descendants(&picker)
            .into_iter()
            .filter_map(|w| w.downcast::<adw::ActionRow>().ok())
            .any(|r| r.title() == "another program" && !r.is_visible())
    });
    button(&picker, "Tick shown").emit_clicked();
    // Names from an attribute they share: repeated, so Import stays off.
    let aplicacao = labels
        .iter()
        .position(|l| l == "Attribute aplicacao")
        .expect("aplicacao");
    from.set_selected(aplicacao as u32);
    let text = shown(&picker);
    assert!(text.contains("segredo — repeated"), "{text}");
    assert!(text.contains("cannot be imported as they are"), "{text}");
    assert!(!button(&picker, "Import 2").is_sensitive());
    from.set_selected(nome as u32);
    let text = shown(&picker);
    assert!(text.contains("FAKE_A — new"), "{text}");
    assert!(text.contains("locked"), "{text}");
    assert!(text.contains("2 ticked: 2 new, 0 existing."), "{text}");
    let locked_check = descendants(&picker)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::ActionRow>().ok())
        .find(|r| r.title() == "segredo: FAKE_LOCKED")
        .and_then(|r| {
            descendants(&r)
                .into_iter()
                .find_map(|w| w.downcast::<gtk::CheckButton>().ok())
        })
        .expect("the locked item's box");
    assert!(!locked_check.is_sensitive() && !locked_check.is_active());
    button(&picker, "Import 2").emit_clicked();
    settle(&s);
    spin_until(|| {
        let names: Vec<String> = s.entries.borrow().iter().map(|e| e.name.clone()).collect();
        names.contains(&"FAKE_A".to_string()) && names.contains(&"FAKE_B".to_string())
    });
    assert!(
        s.message.text().starts_with("Imported."),
        "{}",
        s.message.text()
    );
    assert_eq!(approvals.load(Ordering::SeqCst), 2);
    // The closed window's widgets are freed: no handler keeps them alive.
    let weak = locked_check.downgrade();
    drop((locked_check, from, search, picker));
    s.editor.borrow_mut().take();
    spin_until(|| weak.upgrade().is_none());

    // A .env file: the agent asks before showing the names; a prefix.
    let env = dir.path().join("app.env");
    std::fs::write(&env, "FAKE_C=fake-c-value\nFAKE_EMPTY=\n").unwrap();
    let path = env.display().to_string();
    s.submit(
        Request::DotenvNames { path: path.clone() },
        Pending::DotenvNames { path },
    );
    settle(&s);
    assert_eq!(approvals.load(Ordering::SeqCst), 3);
    let picker = s.editor.borrow().as_ref().unwrap().clone();
    let prefix = entry_rows(&picker)
        .into_iter()
        .find(|r| r.title().starts_with("Prefix"))
        .expect("prefix");
    prefix.set_text("app_");
    button(&picker, "Tick shown").emit_clicked();
    assert!(shown(&picker).contains("APP_FAKE_C — new"));
    // A variable without a value is shown, and cannot be ticked.
    assert!(shown(&picker).contains("APP_FAKE_EMPTY — no value, cannot be imported"));
    let empty_check = descendants(&picker)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::ActionRow>().ok())
        .find(|r| r.title() == "FAKE_EMPTY")
        .and_then(|r| {
            descendants(&r)
                .into_iter()
                .find_map(|w| w.downcast::<gtk::CheckButton>().ok())
        })
        .expect("the empty variable's box");
    assert!(!empty_check.is_sensitive() && !empty_check.is_active());
    // Denied: the message says that nothing was imported.
    allowed.store(false, Ordering::SeqCst);
    button(&picker, "Import 1").emit_clicked();
    settle(&s);
    let message = s.message.text();
    assert!(message.contains("Stopped at batch 1 of 1"), "{message}");
    assert!(
        message.contains("no batch before it was imported"),
        "{message}"
    );
    assert!(!s.entries.borrow().iter().any(|e| e.name == "APP_FAKE_C"));
    // Again, allowed.
    allowed.store(true, Ordering::SeqCst);
    let path = env.display().to_string();
    s.submit(
        Request::DotenvNames { path: path.clone() },
        Pending::DotenvNames { path },
    );
    settle(&s);
    let picker = s.editor.borrow().as_ref().unwrap().clone();
    entry_rows(&picker)
        .into_iter()
        .find(|r| r.title().starts_with("Prefix"))
        .expect("prefix")
        .set_text("app_");
    button(&picker, "Tick shown").emit_clicked();
    button(&picker, "Import 1").emit_clicked();
    settle(&s);
    spin_until(|| s.entries.borrow().iter().any(|e| e.name == "APP_FAKE_C"));

    // The values are in the vault file, read by the agent.
    let file = Vault::open(&vault, "fake master password".to_string().into()).unwrap();
    for (name, value) in [
        ("FAKE_A", "fake-a-value"),
        ("FAKE_B", "fake-b-value"),
        ("APP_FAKE_C", "fake-c-value"),
    ] {
        let id = file.find(name).unwrap();
        assert_eq!(file.secret(id).unwrap().as_str(), value);
    }
    assert!(file.find("FAKE_LOCKED").is_err());
    s.window.close();
}

/// What the fake agent answers, and what it was asked.
struct FakeState {
    locked: bool,
    /// The protocol version its status reports.
    protocol: u32,
    /// Whether its status reports the broker's program and the number of
    /// grants, fields an agent may leave out.
    report_broker: bool,
    entries: Vec<EntryInfo>,
    grants: Vec<GrantInfo>,
    /// Answer `grants` with this refusal.
    refuse_grants: Option<String>,
    /// Answer `revoke_grant` with this refusal, revoking nothing.
    refuse_revoke: Option<String>,
    /// Requests of this type wait for their answer — made when they arrive —
    /// while it is set: a slow agent, or one that shows a dialog.
    hold: Option<&'static str>,
    /// How many answers are waiting.
    held: usize,
    /// Requests of this type wait while it is set, before anything is done
    /// for them: an agent waiting for the human's answer, which then acts.
    stall: Option<&'static str>,
    /// How many requests have waited so.
    stalled: usize,
    /// Every request, in the order it arrived (a stalled one when it is
    /// carried out).
    requests: Vec<serde_json::Value>,
}

fn fake_state(locked: bool) -> Arc<Mutex<FakeState>> {
    Arc::new(Mutex::new(FakeState {
        locked,
        protocol: PROTOCOL_VERSION,
        report_broker: true,
        entries: vec![],
        grants: vec![],
        refuse_grants: None,
        refuse_revoke: None,
        hold: None,
        held: 0,
        stall: None,
        stalled: 0,
        requests: vec![],
    }))
}

/// Serve `state` on `socket`: one thread per connection, as the agent does,
/// so that an answer held back does not hold back the others.
fn fake_agent(socket: &std::path::Path, state: &Arc<Mutex<FakeState>>) {
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
    let state = Arc::clone(state);
    // These threads exist only in this test's subprocess.
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                let Ok(request) = rusthorse::protocol::read_message::<serde_json::Value>(&stream)
                else {
                    return;
                };
                let kind = request["type"].as_str();
                let stalled = {
                    let mut s = state.lock().unwrap();
                    let stalled = s.stall.is_some() && s.stall == kind;
                    s.stalled += usize::from(stalled);
                    stalled
                };
                if stalled {
                    let until = Instant::now() + Duration::from_secs(20);
                    while state.lock().unwrap().stall == kind && Instant::now() < until {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                let (answer, held) = fake_answer(&state, &request);
                if held {
                    let until = Instant::now() + Duration::from_secs(20);
                    while state.lock().unwrap().hold == request["type"].as_str()
                        && Instant::now() < until
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                let _ = rusthorse::protocol::send_frame(&stream, &answer, &[]);
                if held {
                    state.lock().unwrap().held -= 1;
                }
            });
        }
    });
}

/// The fake agent's answer to `request`, and whether it is held back.
fn fake_answer(state: &Mutex<FakeState>, request: &serde_json::Value) -> (Response, bool) {
    let mut s = state.lock().unwrap();
    s.requests.push(request.clone());
    let kind = request["type"].as_str().unwrap_or_default();
    // Only what an agent of this protocol reads is answered.
    let understood = serde_json::from_value::<Request>(request.clone()).is_ok();
    let answer = match kind {
        _ if !understood => Response::Error {
            code: ErrorCode::InvalidRequest,
            message: format!("fake: a malformed {kind} request"),
        },
        "status" => Response::Status(StatusInfo {
            protocol_version: s.protocol,
            agent_version: "fake".into(),
            vault: "/fake/vault.kdbx".into(),
            vault_exists: true,
            audit_log: "/fake/audit.jsonl".into(),
            locked: s.locked,
            idle_timeout_secs: 0,
            locks_in_secs: None,
            remembered_approvals: 0,
            agent_executable: "/fake/rusthorse".into(),
            agent_executable_id: None,
            agent_executable_replaced: None,
            dialogs: None,
            lock_triggers: vec![],
            broker: s.report_broker.then(|| "/fake/rusthorse-broker".into()),
            grants: s
                .report_broker
                .then(|| s.grants.iter().filter(|g| g.state != "revoked").count()),
        }),
        "list" => Response::Entries {
            entries: s.entries.clone(),
        },
        "unlock" => {
            s.locked = false;
            Response::Ok {
                message: "fake: unlocked".into(),
            }
        }
        "lock" => {
            // The explicit lock ends every grant.
            s.locked = true;
            for g in &mut s.grants {
                g.state = "revoked".into();
            }
            Response::Ok {
                message: "fake: locked".into(),
            }
        }
        "grants" => match &s.refuse_grants {
            Some(why) => Response::Error {
                code: ErrorCode::InvalidRequest,
                message: why.clone(),
            },
            None => Response::Grants {
                grants: s.grants.clone(),
            },
        },
        "remove" => {
            // The entry goes, and its grants end with it (here every grant
            // the fake lists is that entry's); then its answer is lost.
            for g in &mut s.grants {
                g.state = "revoked".into();
            }
            Response::Error {
                code: ErrorCode::OutcomeUnknown,
                message: "fake: the answer was lost".into(),
            }
        }
        "revoke_grant" if s.refuse_revoke.is_some() => Response::Error {
            code: ErrorCode::NotFound,
            message: s.refuse_revoke.clone().unwrap_or_default(),
        },
        "revoke_grant" => {
            // As the agent does: a revoked grant is listed until its
            // command ends.
            let id = request["id"].as_str();
            let mut ended = 0;
            for g in s
                .grants
                .iter_mut()
                .filter(|g| g.state != "revoked" && id.is_none_or(|id| g.id == id))
            {
                g.state = "revoked".into();
                ended += 1;
            }
            Response::Ok {
                message: format!("fake: {ended} revoked"),
            }
        }
        _ => Response::Error {
            code: ErrorCode::InvalidRequest,
            message: format!("fake: {kind} is not served"),
        },
    };
    let held = s.hold == Some(kind);
    if held {
        s.held += 1;
    }
    (answer, held)
}

/// The texts of the labels under `root`.
fn texts(root: &impl IsA<gtk::Widget>) -> Vec<String> {
    descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Label>().ok())
        .map(|l| l.text().to_string())
        .collect()
}

/// Show the page `name`, as a click in the sidebar does.
fn show_page(s: &Manager, name: &str) {
    let row = descendants(&s.window)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::ListBoxRow>().ok())
        .find(|r| r.widget_name() == name)
        .unwrap_or_else(|| panic!("no page {name}"));
    row.parent()
        .and_downcast::<gtk::ListBox>()
        .unwrap()
        .select_row(Some(&row));
}

/// The value the Status page shows for `key`: the text that follows it.
fn status_value(s: &Manager, key: &str) -> Option<String> {
    let status = texts(&s.status_page);
    let at = status.iter().position(|t| t == key)?;
    status.get(at + 1).cloned()
}

/// Whether a button named `name` is under `root`.
fn has_button(root: &impl IsA<gtk::Widget>, name: &str) -> bool {
    descendants(root)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Button>().ok())
        .any(|b| b.widget_name() == name)
}

/// The grants page, driven by a fake agent: it lists what the agent lists,
/// also while the vault is locked and says so, refreshes, and sends the
/// right revocations.
#[test]
fn grants_page() {
    if !on_xvfb("grants_page") {
        return;
    }
    adw::init().expect("GTK only on Xvfb");
    crate::load_style();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/agent.sock");
    let state = fake_state(true);
    // What the requester controls is drawn as plain text, through the
    // dialogs' filter: no markup, no line break or reordering of its own.
    let mut first = crate::model::tests::grant("g0123456789abcdef", "active");
    first.command = "sh -c '<b>fake</b>'\u{202e}gpj.exe\nrm -rf fake".into();
    first.requester = "bash ← fake\u{200b}agent".into();
    let mut second = crate::model::tests::grant("gfedcba9876543210", "exhausted");
    second.preset = Preset::Openai;
    second.destination = "https://api.openai.com/v1".into();
    second.max_requests = Some(3);
    second.in_flight = 0;
    second.automatic_locks = AutomaticLocks::End;
    state.lock().unwrap().grants = vec![first, second];
    fake_agent(&socket, &state);
    let asked = |kind: &str| {
        state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r["type"] == kind)
            .count()
    };
    let revocations = || -> Vec<serde_json::Value> {
        state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r["type"] == "revoke_grant")
            .cloned()
            .collect()
    };
    let app = adw::Application::builder()
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.register(None::<&gio::Cancellable>).unwrap();
    let s = Manager::new(&app, socket.clone());
    s.window.present();
    s.refresh();
    settle(&s);
    assert_eq!(s.pill.text(), "Locked");
    // The Status page reports the broker program and the active grants.
    assert_eq!(
        status_value(&s, "Credential broker").as_deref(),
        Some("/fake/rusthorse-broker")
    );
    assert_eq!(status_value(&s, "Active grants").as_deref(), Some("2"));
    // An agent may leave them out: the rows say so.
    state.lock().unwrap().report_broker = false;
    s.refresh();
    settle(&s);
    for key in ["Credential broker", "Active grants"] {
        assert_eq!(
            status_value(&s, key).as_deref(),
            Some("Not reported"),
            "{key}"
        );
    }
    state.lock().unwrap().report_broker = true;
    s.refresh();
    settle(&s);
    assert_eq!(status_value(&s, "Active grants").as_deref(), Some("2"));

    // Listed once the page is shown, not before; nothing to revoke until
    // then.
    assert_eq!(asked("grants"), 0);
    assert!(!s.revoke_all.is_sensitive());
    assert!(s.grants_job.borrow().is_none());
    show_page(&s, "grants");
    assert!(
        s.grants_job.borrow().is_some(),
        "listed as soon as shown, not at the next tick"
    );
    spin_until(|| asked("grants") == 1 && s.grants_job.borrow().is_none());
    // The vault is locked: the page says so, and lists all the same.
    assert!(s.grants_locked.is_visible());
    assert_eq!(s.grants_locked.title(), "The vault is locked");
    assert!(
        s.grants_locked
            .description()
            .unwrap()
            .contains("you can revoke them")
    );
    let titles: Vec<String> = descendants(&s.grants_list)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::PreferencesGroup>().ok())
        .map(|g| g.title().to_string())
        .collect();
    assert_eq!(
        titles,
        ["Grant g0123456789abcdef", "Grant gfedcba9876543210"]
    );
    assert_eq!(s.grants_summary.text(), "2 grants, oldest first.");
    let shown = texts(&s.grants_list);
    for expected in [
        "AI/ANTHROPIC_API_KEY (11111111)",
        "https://api.anthropic.com (Anthropic)",
        "sh -c '<b>fake</b>'\\u{202e}gpj.exe\\u{a}rm -rf fake",
        "Requested by (unverified)",
        "bash ← fake\\u{200b}agent",
        "ANTHROPIC_AUTH_TOKEN",
        "Active",
        "2026-11-02T10:15:00-03:00",
        "in 11h43m at the latest",
        "3 (no limit); 1 in flight",
        "Do not end it: it keeps working while the screen or the vault is locked",
        "g0123456789abcdef",
        "https://api.openai.com/v1 (OpenAI)",
        "3 of 3; 0 in flight",
        "End it: the screen locking, suspend and the idle timeout",
    ] {
        assert!(
            shown.iter().any(|t| t == expected),
            "{expected:?} is not in {shown:#?}"
        );
    }
    assert!(
        shown
            .iter()
            .all(|t| !t.contains(['\u{202e}', '\u{200b}', '\n'])),
        "{shown:#?}"
    );
    // The rows hold what the agent sent: plain text. (A group's own title
    // is markup, which is why only an ID of the exact form goes there.)
    let rows: Vec<adw::PreferencesRow> = descendants(&s.grants_list)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::PreferencesRow>().ok())
        .collect();
    assert_eq!(rows.len(), 22, "eleven rows a grant");
    assert!(rows.iter().all(|row| {
        descendants(row)
            .into_iter()
            .filter_map(|w| w.downcast::<gtk::Label>().ok())
            .all(|l| !l.uses_markup())
    }));
    spin_until(|| s.window.width() > 0);
    let settle_frame = Instant::now() + Duration::from_millis(200);
    spin_until(|| Instant::now() >= settle_frame);
    snapshot(&s, "grants.png");
    if std::env::var_os("MANAGER_TEST_SCREENSHOTS").is_some() {
        let styles = adw::StyleManager::default();
        styles.set_color_scheme(adw::ColorScheme::ForceDark);
        let settle_frame = Instant::now() + Duration::from_millis(250);
        spin_until(|| Instant::now() >= settle_frame);
        snapshot(&s, "grants-dark.png");
        styles.set_color_scheme(adw::ColorScheme::Default);
    }

    // A listing that shows the same draws nothing anew: the buttons stay
    // under the pointer.
    let one = named(&s.grants_list, "revoke-g0123456789abcdef");
    let before = asked("grants");
    s.list_grants();
    spin_until(|| asked("grants") > before && s.grants_job.borrow().is_none());
    assert_eq!(named(&s.grants_list, "revoke-g0123456789abcdef"), one);

    // Revoke one: its ID, and only it. The page lists again.
    assert!(one.is_sensitive() && s.revoke_all.is_sensitive());
    assert!(gtk::test_accessible_has_property(
        &one,
        gtk::AccessibleProperty::Label
    ));
    let before = asked("grants");
    one.emit_clicked();
    spin_until(|| {
        s.revoke_job.borrow().is_none()
            && s.grants_job.borrow().is_none()
            && asked("grants") > before
    });
    assert_eq!(
        revocations(),
        [serde_json::json!({"type": "revoke_grant", "id": "g0123456789abcdef"})]
    );
    assert_eq!(s.message.text(), "fake: 1 revoked");
    // Ended, it is listed until its command ends, with nothing to revoke.
    assert!(!named(&s.grants_list, "revoke-g0123456789abcdef").is_sensitive());
    assert!(named(&s.grants_list, "revoke-gfedcba9876543210").is_sensitive());
    assert!(
        texts(&s.grants_list)
            .iter()
            .any(|t| t.starts_with("Revoked: "))
    );
    // Revoke all: no ID. Then nothing is left to revoke.
    assert!(s.revoke_all.is_sensitive());
    s.revoke_all.emit_clicked();
    spin_until(|| {
        s.revoke_job.borrow().is_none()
            && s.grants_job.borrow().is_none()
            && !s.revoke_all.is_sensitive()
    });
    assert_eq!(
        revocations().last(),
        Some(&serde_json::json!({"type": "revoke_grant"}))
    );
    assert!(
        state
            .lock()
            .unwrap()
            .grants
            .iter()
            .all(|g| g.state == "revoked")
    );
    assert!(!named(&s.grants_list, "revoke-gfedcba9876543210").is_sensitive());

    // Listed again every few seconds while shown, and not while hidden.
    let before = asked("grants");
    spin_until(|| asked("grants") > before);
    // And when a request of the human's ends, without waiting for the next
    // tick, which comes 4.75 seconds at the earliest after the one just
    // seen (GLib rounds a seconds timer to a whole second).
    spin_until(|| s.grants_job.borrow().is_none());
    let ticked = asked("grants");
    s.refresh();
    settle(&s);
    let soon = Instant::now() + Duration::from_secs(3);
    spin_until(|| asked("grants") > ticked || Instant::now() >= soon);
    assert!(
        asked("grants") > ticked,
        "not listed when a request of the human's ended"
    );
    show_page(&s, "entries");
    spin_until(|| s.grants_job.borrow().is_none());
    let before = asked("grants");
    let quiet = Instant::now() + Duration::from_secs(6);
    spin_until(|| Instant::now() >= quiet);
    assert_eq!(asked("grants"), before, "listed while not shown");
    // A revocation is followed by a listing, timer or not.
    s.revoke(Some("g0123456789abcdef".into()));
    spin_until(|| {
        s.revoke_job.borrow().is_none()
            && asked("grants") > before
            && s.grants_job.borrow().is_none()
    });
    show_page(&s, "grants");
    assert!(s.grants_job.borrow().is_some(), "listed again when shown");
    spin_until(|| asked("grants") > before + 1 && s.grants_job.borrow().is_none());

    // A revocation does not wait for a request of the human's: here the
    // agent holds Unlock, as if its password dialog were open.
    {
        let mut st = state.lock().unwrap();
        st.grants = vec![crate::model::tests::grant("g1111111111111111", "active")];
        st.hold = Some("unlock");
    }
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none() && has_button(&s.grants_list, "revoke-g1111111111111111")
    });
    s.lock.emit_clicked();
    spin_until(|| state.lock().unwrap().held == 1);
    assert!(s.job.borrow().is_some());
    named(&s.grants_list, "revoke-g1111111111111111").emit_clicked();
    spin_until(|| s.revoke_job.borrow().is_none());
    assert!(s.job.borrow().is_some(), "the unlock is still waiting");
    assert_eq!(
        revocations().last(),
        Some(&serde_json::json!({"type": "revoke_grant", "id": "g1111111111111111"}))
    );
    state.lock().unwrap().hold = None;
    settle(&s);
    assert_eq!(s.pill.text(), "Unlocked");
    // Unlocked: no note.
    assert!(!s.grants_locked.is_visible());

    // A list the agent made before a revocation ended is not shown: the
    // page lists again. Held back here, it shows the grant active, with a
    // request more.
    state.lock().unwrap().grants = vec![crate::model::tests::grant("g2222222222222222", "active")];
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none() && has_button(&s.grants_list, "revoke-g2222222222222222")
    });
    {
        let mut st = state.lock().unwrap();
        st.grants[0].requests = 4;
        st.hold = Some("grants");
    }
    s.list_grants();
    spin_until(|| state.lock().unwrap().held == 1);
    named(&s.grants_list, "revoke-g2222222222222222").emit_clicked();
    spin_until(|| s.revoke_job.borrow().is_none());
    assert_eq!(state.lock().unwrap().grants[0].state, "revoked");
    state.lock().unwrap().hold = None;
    spin_until(|| {
        let shown = texts(&s.grants_list);
        assert!(
            !(shown.iter().any(|t| t == "4 (no limit); 1 in flight")
                && shown.iter().any(|t| t == "Active")),
            "a list made before the revocation was shown: {shown:#?}"
        );
        s.grants_job.borrow().is_none()
            && state.lock().unwrap().held == 0
            && shown.iter().any(|t| t.starts_with("Revoked: "))
    });
    // The same with Lock now, which ends every grant.
    state.lock().unwrap().grants = vec![crate::model::tests::grant("g3333333333333333", "active")];
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none() && has_button(&s.grants_list, "revoke-g3333333333333333")
    });
    {
        let mut st = state.lock().unwrap();
        st.grants[0].requests = 4;
        st.hold = Some("grants");
    }
    s.list_grants();
    spin_until(|| state.lock().unwrap().held == 1);
    assert_eq!(s.lock.label().as_deref(), Some("Lock now"));
    s.lock.emit_clicked();
    settle(&s);
    assert_eq!(s.pill.text(), "Locked");
    assert!(s.grants_locked.is_visible());
    state.lock().unwrap().hold = None;
    spin_until(|| {
        let shown = texts(&s.grants_list);
        assert!(
            !(shown.iter().any(|t| t == "4 (no limit); 1 in flight")
                && shown.iter().any(|t| t == "Active")),
            "a list made before the lock was shown: {shown:#?}"
        );
        s.grants_job.borrow().is_none()
            && state.lock().unwrap().held == 0
            && shown.iter().any(|t| t.starts_with("Revoked: "))
    });
    // Nor one made while a request of the human's waited, when that request
    // has ended grants since: here a removal waits for its approval, a
    // listing is made meanwhile, then the entry goes with its grant and the
    // answer is lost, so that no refresh follows.
    state.lock().unwrap().grants = vec![crate::model::tests::grant("g5555555555555555", "active")];
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none() && has_button(&s.grants_list, "revoke-g5555555555555555")
    });
    state.lock().unwrap().stall = Some("remove");
    s.submit(
        Request::Remove {
            name: "11111111-2222-3333-4444-555555555555".into(),
        },
        Pending::Change,
    );
    spin_until(|| state.lock().unwrap().stalled == 1);
    {
        let mut st = state.lock().unwrap();
        st.grants[0].requests = 4;
        st.hold = Some("grants");
    }
    s.list_grants();
    spin_until(|| state.lock().unwrap().held == 1);
    state.lock().unwrap().stall = None;
    settle(&s);
    assert!(
        s.message.text().starts_with("Outcome unknown."),
        "{}",
        s.message.text()
    );
    state.lock().unwrap().hold = None;
    spin_until(|| {
        let shown = texts(&s.grants_list);
        assert!(
            !(shown.iter().any(|t| t == "4 (no limit); 1 in flight")
                && shown.iter().any(|t| t == "Active")),
            "a list made before the removal ended was shown: {shown:#?}"
        );
        s.grants_job.borrow().is_none()
            && state.lock().unwrap().held == 0
            && shown.iter().any(|t| t.starts_with("Revoked: "))
    });

    // An ID not of the form of one is drawn as plain text, never as a
    // group's title, which is markup. (The grants that ended while the page
    // was shown are still there, marked as ended.)
    state.lock().unwrap().grants = vec![crate::model::tests::grant("<b>g</b>&", "active")];
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none() && has_button(&s.grants_list, "revoke-<b>g</b>&")
    });
    let odd = named(&s.grants_list, "revoke-<b>g</b>&")
        .ancestor(adw::PreferencesGroup::static_type())
        .and_downcast::<adw::PreferencesGroup>()
        .expect("its group");
    assert_eq!(odd.title(), "Grant");
    assert!(texts(&odd).iter().any(|t| t == "<b>g</b>&"));
    let titles: Vec<String> = descendants(&s.grants_list)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::PreferencesGroup>().ok())
        .map(|g| g.title().to_string())
        .collect();
    assert!(
        titles.iter().all(|t| t == "Grant"
            || t.strip_prefix("Grant ")
                .is_some_and(rusthorse::broker_protocol::is_well_formed_grant_id)),
        "{titles:#?}"
    );
    assert_eq!(
        s.grants_summary.text(),
        "1 grant; 6 more ended while this page was shown."
    );

    // A refusal is shown on the page, in place of the list, through the
    // dialogs' filter like everything else the agent sends. Revoke all
    // stays: it may work all the same, and only takes away.
    state.lock().unwrap().refuse_grants = Some("fake: grants are\u{202e} refused\n".into());
    s.list_grants();
    spin_until(|| s.grants_job.borrow().is_none() && s.grants_summary.has_css_class("error"));
    assert_eq!(
        s.grants_summary.text(),
        "fake: grants are\\u{202e} refused\\u{a}"
    );
    assert!(descendants(&s.grants_list).is_empty());
    assert!(s.revoke_all.is_sensitive());

    // A refused revocation is reported as the manager reports other
    // errors, at the bottom of the window; nothing was revoked, and the
    // buttons can be used again.
    {
        let mut st = state.lock().unwrap();
        st.refuse_grants = None;
        st.refuse_revoke = Some("fake: no grant g4444444444444444".into());
        st.grants = vec![crate::model::tests::grant("g4444444444444444", "active")];
    }
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none() && has_button(&s.grants_list, "revoke-g4444444444444444")
    });
    assert!(!s.grants_summary.has_css_class("error"));
    named(&s.grants_list, "revoke-g4444444444444444").emit_clicked();
    spin_until(|| s.revoke_job.borrow().is_none());
    assert_eq!(s.message.text(), "fake: no grant g4444444444444444");
    assert!(s.message.has_css_class("error"));
    spin_until(|| s.grants_job.borrow().is_none());
    assert!(named(&s.grants_list, "revoke-g4444444444444444").is_sensitive());
    assert!(s.revoke_all.is_sensitive());

    // A revocation the agent does not answer is reported once the page
    // has waited long enough, and the page can be used again. Revoking has
    // no effect that a lost answer would leave unknown: it can be retried.
    {
        let mut st = state.lock().unwrap();
        st.refuse_revoke = None;
        st.hold = Some("revoke_grant");
    }
    s.revoke_all.emit_clicked();
    spin_until(|| state.lock().unwrap().held == 1);
    assert!(!s.revoke_all.is_sensitive(), "one revocation at a time");
    assert!(!named(&s.grants_list, "revoke-g4444444444444444").is_sensitive());
    let waited = Instant::now();
    spin_until(|| s.revoke_job.borrow().is_none());
    assert!(waited.elapsed() < GRANTS_LIMIT + Duration::from_secs(2));
    assert_eq!(
        s.message.text(),
        "No complete answer arrived from the agent."
    );
    assert!(s.message.has_css_class("error"));
    state.lock().unwrap().hold = None;
    spin_until(|| state.lock().unwrap().held == 0 && s.grants_job.borrow().is_none());
    // The agent did revoke it: the list says so.
    assert!(
        texts(&s.grants_list)
            .iter()
            .any(|t| t.starts_with("Revoked: "))
    );
    // So is a listing, in place of the list.
    state.lock().unwrap().hold = Some("grants");
    s.list_grants();
    spin_until(|| state.lock().unwrap().held >= 1);
    spin_until(|| s.grants_job.borrow().is_none() && s.grants_summary.has_css_class("error"));
    assert_eq!(
        s.grants_summary.text(),
        "No complete answer arrived from the agent."
    );
    assert!(descendants(&s.grants_list).is_empty());
    assert!(s.revoke_all.is_sensitive());
    state.lock().unwrap().hold = None;
    spin_until(|| state.lock().unwrap().held == 0);

    // No grant: the page says so, and there is nothing to revoke.
    state.lock().unwrap().grants.clear();
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none() && s.grants_summary.text().starts_with("No grants.")
    });
    assert_eq!(
        s.grants_summary.text(),
        "No grants. A command started with rusthorse run --broker gets one for each entry it uses through the broker, until it ends."
    );
    assert!(!s.grants_summary.has_css_class("error"));
    assert!(descendants(&s.grants_list).is_empty());
    assert!(!s.revoke_all.is_sensitive());

    // An agent of an older protocol is asked its status, nothing more.
    state.lock().unwrap().protocol = PROTOCOL_VERSION - 1;
    let before = asked("grants");
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none()
            && s.grants_summary
                .text()
                .starts_with("Incompatible agent protocol")
    });
    assert_eq!(asked("grants"), before);
    // Such an agent cannot say whether the vault is locked: the note goes.
    s.refresh();
    settle(&s);
    assert_eq!(s.pill.text(), "Unavailable");
    assert!(!s.grants_locked.is_visible());

    // No agent at all: the page says so, and Revoke all may be tried; it
    // says the same.
    std::fs::remove_file(&socket).unwrap();
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none()
            && s.grants_summary
                .text()
                .starts_with("The agent is not running.")
    });
    assert!(s.revoke_all.is_sensitive());
    let before = revocations().len();
    s.revoke_all.emit_clicked();
    spin_until(|| s.revoke_job.borrow().is_none());
    assert!(
        s.message.text().starts_with("The agent is not running."),
        "{}",
        s.message.text()
    );
    assert_eq!(revocations().len(), before);
    s.window.close();
}

/// A refresh does not put another grant's Revoke button under the pointer:
/// when a grant above others ends, it keeps its place, marked as ended,
/// rather than let the grants below move up. What did not change is not
/// drawn anew: the keyboard focus and a selection stay.
#[test]
fn grants_keep_their_place() {
    if !on_xvfb("grants_keep_their_place") {
        return;
    }
    adw::init().expect("GTK only on Xvfb");
    crate::load_style();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/agent.sock");
    let state = fake_state(false);
    let ids = [
        "gaaaaaaaaaaaaaaaa",
        "gbbbbbbbbbbbbbbbb",
        "gcccccccccccccccc",
    ];
    state.lock().unwrap().grants = ids
        .iter()
        .map(|id| crate::model::tests::grant(id, "active"))
        .collect();
    fake_agent(&socket, &state);
    let app = adw::Application::builder()
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.register(None::<&gio::Cancellable>).unwrap();
    let s = Manager::new(&app, socket);
    s.window.present();
    s.refresh();
    settle(&s);
    show_page(&s, "grants");
    spin_until(|| {
        s.grants_job.borrow().is_none() && has_button(&s.grants_list, "revoke-gcccccccccccccccc")
    });
    let pause = |ms| {
        let until = Instant::now() + Duration::from_millis(ms);
        spin_until(|| Instant::now() >= until);
    };
    spin_until(|| s.window.width() > 0);
    let revoke = |id: &str| named(&s.grants_list, &format!("revoke-{id}"));
    let group_of = |b: &gtk::Button| {
        b.ancestor(adw::PreferencesGroup::static_type())
            .and_downcast::<adw::PreferencesGroup>()
            .expect("its group")
    };
    let (a, b, c) = (revoke(ids[0]), revoke(ids[1]), revoke(ids[2]));
    // The keyboard focus on B's Revoke, and part of B's command selected.
    assert!(b.grab_focus());
    let command = descendants(&group_of(&b))
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Label>().ok())
        .find(|l| l.text() == "claude --print hello")
        .expect("B's command");
    command.select_region(0, 6);
    pause(300);
    let at = |w: &gtk::Button| {
        let p = w
            .compute_point(&s.window, &gtk::graphene::Point::new(4.0, 4.0))
            .expect("in the window");
        (f64::from(p.x()), f64::from(p.y()))
    };
    // The button a click at this point reaches; with INSENSITIVE, the one
    // drawn there, usable or not.
    let under_as = |(x, y): (f64, f64), flags: gtk::PickFlags| {
        s.window
            .pick(x, y, flags)
            .and_then(|w| {
                if w.is::<gtk::Button>() {
                    Some(w)
                } else {
                    w.ancestor(gtk::Button::static_type())
                }
            })
            .and_downcast::<gtk::Button>()
    };
    let under = |point| under_as(point, gtk::PickFlags::DEFAULT);
    let drawn = |point| under_as(point, gtk::PickFlags::INSENSITIVE);
    // The pointer is on A's Revoke.
    let (aimed, b_at, c_at) = (at(&a), at(&b), at(&c));
    assert_eq!(under(aimed).as_ref(), Some(&a));

    // A's command ends: the agent lists B and C only, and B has made a
    // request more.
    {
        let mut st = state.lock().unwrap();
        st.grants.remove(0);
        st.grants[0].requests = 4;
    }
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none()
            && texts(&s.grants_list)
                .iter()
                .any(|t| t == "4 (no limit); 1 in flight")
    });
    pause(300);
    // What is under the pointer is still A's Revoke, which revokes nothing
    // now: a click there reaches no button. B and C keep their buttons,
    // where they were.
    assert_eq!(drawn(aimed).as_ref(), Some(&a));
    assert_eq!(under(aimed), None);
    assert!(!a.is_sensitive());
    assert_eq!(revoke(ids[0]), a);
    assert_eq!((revoke(ids[1]), at(&b)), (b.clone(), b_at));
    assert_eq!((revoke(ids[2]), at(&c)), (c.clone(), c_at));
    assert!(b.is_sensitive() && c.is_sensitive());
    let ended = texts(&group_of(&a));
    for shown in [
        "Ended: the agent no longer lists it",
        "It has ended.",
        "3 (no limit) when last listed",
    ] {
        assert!(ended.iter().any(|t| t == shown), "{shown:?} in {ended:#?}");
    }
    assert!(group_of(&a).has_css_class("dim-label"));
    assert_eq!(
        s.grants_summary.text(),
        "2 grants, oldest first; 1 more ended while this page was shown."
    );
    snapshot(&s, "grants-ended.png");
    // Only what changed was set anew.
    assert_eq!(
        gtk::prelude::RootExt::focus(&s.window).as_ref(),
        Some(b.upcast_ref())
    );
    assert_eq!(command.selection_bounds(), Some((0, 6)));
    // A new grant comes last: nothing above it moves.
    state
        .lock()
        .unwrap()
        .grants
        .push(crate::model::tests::grant("gdddddddddddddddd", "active"));
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none() && has_button(&s.grants_list, "revoke-gdddddddddddddddd")
    });
    pause(300);
    assert_eq!(drawn(aimed).as_ref(), Some(&a));
    assert_eq!((at(&b), at(&c)), (b_at, c_at));
    let order: Vec<String> = descendants(&s.grants_list)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::PreferencesGroup>().ok())
        .map(|g| g.title().to_string())
        .collect();
    assert_eq!(
        order,
        [
            "Grant gaaaaaaaaaaaaaaaa",
            "Grant gbbbbbbbbbbbbbbbb",
            "Grant gcccccccccccccccc",
            "Grant gdddddddddddddddd"
        ]
    );

    // Once the page is left, the ended grant goes; shown again, the page
    // lists what the agent lists.
    show_page(&s, "entries");
    assert!(!has_button(&s.grants_list, "revoke-gaaaaaaaaaaaaaaaa"));
    assert_eq!(s.grants_summary.text(), "3 grants, oldest first.");
    show_page(&s, "grants");
    spin_until(|| s.grants_job.borrow().is_none());
    assert!(!has_button(&s.grants_list, "revoke-gaaaaaaaaaaaaaaaa"));
    assert_eq!((revoke(ids[1]), revoke(ids[2])), (b, c));
    // Every grant ends while the page is shown: they all stay, with nothing
    // to revoke, and the line above them stays one short line.
    state.lock().unwrap().grants.clear();
    s.list_grants();
    spin_until(|| {
        s.grants_job.borrow().is_none() && s.grants_summary.text().starts_with("No grants now")
    });
    assert_eq!(
        s.grants_summary.text(),
        "No grants now; 3 ended while this page was shown."
    );
    assert!(!s.revoke_all.is_sensitive());
    s.window.close();
}

/// An entry's broker profile in its details — read-only, or why it cannot
/// be used — and the command snippet that uses it, with a fake agent that
/// lists entries as the vault reports them.
#[test]
fn broker_profiles() {
    if !on_xvfb("broker_profiles") {
        return;
    }
    adw::init().expect("GTK only on Xvfb");
    crate::load_style();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/agent.sock");
    let state = fake_state(false);
    let entry = |id: &str, name: &str, kind: EntryKind| {
        let mut e = crate::model::tests::entry();
        e.id = id.into();
        e.name = name.into();
        e.fields.kind = Some(kind);
        e.protected_fields.clear();
        e
    };
    let mut usable = entry(
        "10000000-0000-4000-8000-000000000001",
        "ANTHROPIC_API_KEY",
        EntryKind::ApiKey,
    );
    usable.broker = Some(crate::model::tests::usable(Preset::Anthropic));
    let mut unusable = entry(
        "10000000-0000-4000-8000-000000000002",
        "OLD_KEY",
        EntryKind::ApiKey,
    );
    unusable.other_fields = vec!["Rusthorse.Broker".into()];
    let mut protected = entry(
        "10000000-0000-4000-8000-000000000003",
        "SEALED_KEY",
        EntryKind::ApiKey,
    );
    protected.protected_fields = vec!["Rusthorse.Broker".into()];
    let absent = entry(
        "10000000-0000-4000-8000-000000000004",
        "PLAIN_KEY",
        EntryKind::ApiKey,
    );
    let device = entry(
        "10000000-0000-4000-8000-000000000005",
        "core-router",
        EntryKind::Device,
    );
    state.lock().unwrap().entries = vec![
        usable.clone(),
        unusable.clone(),
        protected.clone(),
        absent.clone(),
        device.clone(),
    ];
    fake_agent(&socket, &state);
    let app = adw::Application::builder()
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.register(None::<&gio::Cancellable>).unwrap();
    let s = Manager::new(&app, socket);
    s.window.present();
    s.refresh();
    settle(&s);
    assert_eq!(s.entries.borrow().len(), 5);
    let select = |e: &EntryInfo| {
        let row = (0..)
            .map_while(|i| s.rows.row_at_index(i))
            .find(|r| r.widget_name() == e.id.as_str())
            .expect("its row");
        s.rows.select_row(Some(&row));
        assert_eq!(s.current().map(|c| c.id), Some(e.id.clone()));
    };
    let groups = |s: &Manager| {
        descendants(&s.detail)
            .into_iter()
            .filter_map(|w| w.downcast::<adw::PreferencesGroup>().ok())
            .collect::<Vec<_>>()
    };
    let broker = |s: &Manager| {
        groups(s)
            .into_iter()
            .find(|g| g.widget_name() == "credential-broker")
    };
    let usage = |s: &Manager| {
        groups(s)
            .into_iter()
            .find(|g| g.title() == "Use it from a command")
            .and_then(|g| g.description())
            .map(|d| d.to_string())
            .expect("the usage")
    };
    let snippet_shown = |s: &Manager| {
        descendants(&s.detail)
            .into_iter()
            .filter_map(|w| w.downcast::<gtk::Label>().ok())
            .find(|l| l.has_css_class("monospace"))
            .map(|l| l.text().to_string())
            .expect("the snippet")
    };

    // Usable: the profile as approval dialogs show it, read-only.
    select(&usable);
    let g = broker(&s).expect("the profile");
    assert_eq!(g.title(), "Credential broker");
    let shown = texts(&g);
    for (key, value) in crate::model::profile_facts(usable.broker.as_ref().unwrap()) {
        assert!(
            shown.contains(&key) && shown.contains(&value),
            "{key}: {value} is not in {shown:#?}"
        );
    }
    assert!(shown.contains(&"Anthropic (anthropic), revision 1".to_string()));
    assert!(
        g.description()
            .unwrap()
            .contains("rusthorse edit ENTRY --broker PRESET")
    );
    assert!(
        descendants(&g).iter().all(|w| {
            !w.is::<gtk::Button>() && !w.is::<gtk::Editable>() && !w.is::<gtk::Switch>()
        })
    );
    // A screenshot of the profile, for reviewers: the details scrolled down.
    spin_until(|| s.window.width() > 0);
    let settle_frame = Instant::now() + Duration::from_millis(200);
    spin_until(|| Instant::now() >= settle_frame);
    let scroll = s
        .detail
        .ancestor(gtk::ScrolledWindow::static_type())
        .and_downcast::<gtk::ScrolledWindow>()
        .expect("the details scroll");
    scroll.vadjustment().set_value(scroll.vadjustment().upper());
    let settle_frame = Instant::now() + Duration::from_millis(200);
    spin_until(|| Instant::now() >= settle_frame);
    snapshot(&s, "details-broker.png");
    // Its command goes through the broker, and copies as shown.
    let expected = crate::model::snippet(&usable);
    assert!(
        expected.starts_with(&format!(
            "rusthorse run \\\n  --broker ANTHROPIC_AUTH_TOKEN={} \\\n  \
             --url ANTHROPIC_BASE_URL={} ",
            usable.id, usable.id
        )),
        "{expected}"
    );
    assert_eq!(snippet_shown(&s), expected);
    assert!(usage(&s).contains("temporary token"), "{}", usage(&s));
    button(&s.detail, "Copy command snippet").emit_clicked();
    let copied = glib::MainContext::default()
        .block_on(s.window.clipboard().read_text_future())
        .unwrap()
        .unwrap();
    assert_eq!(copied.as_str(), expected);
    // The Edit form says that a change ends the entry's grants.
    s.edit(s.current());
    let editor = s.editor.borrow().as_ref().unwrap().clone();
    assert!(
        texts(&editor)
            .iter()
            .any(|t| t.starts_with("Any change to this entry ends its grants"))
    );
    button(&editor, "Cancel").emit_clicked();
    spin_until(|| !editor.is_visible());
    drop(editor);

    // Unusable or protected: said so, with how to fix it; the command
    // gives the value, and says why.
    for (e, said) in [(&unusable, "Unusable: "), (&protected, "Withheld: ")] {
        select(e);
        let g = broker(&s).expect("the profile's state");
        let shown = texts(&g);
        assert!(shown.iter().any(|t| t.starts_with(said)), "{shown:#?}");
        assert!(g.description().unwrap().contains("--clear broker"));
        assert_eq!(snippet_shown(&s), crate::model::snippet(e));
        assert!(!snippet_shown(&s).contains("--broker"));
        assert!(
            usage(&s).starts_with("The entry's broker profile cannot be used"),
            "{}",
            usage(&s)
        );
        s.edit(s.current());
        let editor = s.editor.borrow().as_ref().unwrap().clone();
        assert!(
            !texts(&editor)
                .iter()
                .any(|t| t.starts_with("Any change to this entry ends its grants"))
        );
        button(&editor, "Cancel").emit_clicked();
        spin_until(|| !editor.is_visible());
    }
    // No profile: an API key is told how to give it one; other entries
    // say nothing about it.
    select(&absent);
    let shown = texts(&broker(&s).expect("how to give it one"));
    assert!(
        shown
            .iter()
            .any(|t| t == "None: commands get the value itself.")
    );
    assert!(!snippet_shown(&s).contains("--broker"));
    assert!(!usage(&s).contains("broker"));
    select(&device);
    assert!(broker(&s).is_none());
    s.window.close();
}
