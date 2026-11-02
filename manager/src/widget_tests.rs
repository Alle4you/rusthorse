//! Widgets with a real agent and scripted decisions, exclusively on Xvfb.
#![allow(clippy::unwrap_used)]
use super::*;
use rusthorse::agent::{Agent, AgentConfig};
use rusthorse::ui::{ApprovalRequest, Decision, Prompt, Typed, Ui};
use rusthorse::vault::{KdfParams, Vault};
use std::sync::{
    Arc,
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
    assert_eq!(
        warned(&editor).as_deref(),
        Some("There is already a group named Work/Servers; names are case-sensitive.")
    );
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
