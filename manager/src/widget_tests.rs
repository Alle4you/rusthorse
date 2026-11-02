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

#[test]
fn desktop_flow() {
    if std::env::var_os("RUSTHORSE_MANAGER_XVFB_CHILD").is_none() {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let dir = tempfile::tempdir().expect("isolated runtime");
        // A runtime directory must be private, whatever the umask.
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
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
        .args(["--exact", "window::tests::desktop_flow", "--nocapture"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
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

    // Fill the real form; no manager password entry exists.
    button(&s.window, "New entry").emit_clicked();
    let editor = s.editor.borrow().as_ref().unwrap().clone();
    let settle_frame = Instant::now() + Duration::from_millis(300);
    spin_until(|| Instant::now() >= settle_frame);
    let inputs = entry_rows(&editor);
    assert_eq!(inputs.len(), 7);
    assert_eq!(inputs[0].title(), "Name");
    inputs[0].set_text("FAKE_DESKTOP_KEY");
    inputs[1].set_text("AI");
    // The kind decides which rows are offered and what the URL is called;
    // a row with a value is never hidden.
    let kind = descendants(&editor)
        .into_iter()
        .filter_map(|w| w.downcast::<adw::ComboRow>().ok())
        .find(|c| c.title() == "Kind")
        .expect("kind row");
    assert_eq!(kind.selected(), 0, "Other");
    assert!(inputs[2..6].iter().all(|r| r.is_visible()));
    kind.set_selected(1);
    assert_eq!(inputs[3].title(), "Endpoint URL");
    assert!(inputs[2].is_visible() && inputs[3].is_visible());
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
    shape_rows(&loose, Some(EntryKind::ApiKey), [false, true, true, false]);
    assert!(loose[4].is_visible() && !loose[5].is_visible());
    assert_eq!(loose[3].title(), "Endpoint URL (protected; unchanged)");
    kind.set_selected(1);
    let settle_frame = Instant::now() + Duration::from_millis(200);
    spin_until(|| Instant::now() >= settle_frame);
    snapshot_window(&editor, "editor.png");
    button(&editor, "Send to agent…").emit_clicked();
    settle(&s);
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
    button(&s.detail, "Show value…").emit_clicked();
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
    button(&s.detail, "Show value…").emit_clicked();
    settle(&s);
    let reveal = s.revealed.borrow().as_ref().unwrap().clone();
    assert_eq!(shown_text(&reveal), "FAKE-desktop-value");
    let parts = value_labels(&reveal);
    // Plain text: not selectable (no PRIMARY), not bold, not split up.
    assert!(parts.iter().all(|l| !l.is_selectable()));
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
    button(&s.detail, "Show notes…").emit_clicked();
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
    button(&s.detail, "Copy value…").emit_clicked();
    settle(&s);
    assert_eq!(paste().as_deref(), Some("before the copy"));
    allowed.store(true, Ordering::SeqCst);
    button(&s.detail, "Copy value…").emit_clicked();
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
    button(&s.detail, "Show value…").emit_clicked();
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
    button(&s.detail, "New random value…").emit_clicked();
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
    button(&s.detail, "Copy value…").emit_clicked();
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
    let settle_frame = Instant::now() + Duration::from_millis(300);
    spin_until(|| Instant::now() >= settle_frame);
    let inputs = entry_rows(&editor);
    assert_eq!(inputs[0].title(), "Name");
    assert!(!inputs[1].is_sensitive());
    inputs[0].set_text("RENAMED_FAKE");
    button(&editor, "Send to agent…").emit_clicked();
    settle(&s);
    assert_eq!(s.entries.borrow()[0].id, id);
    assert_eq!(s.entries.borrow()[0].name, "RENAMED_FAKE");
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    button(&s.detail, "New random value…").emit_clicked();
    settle(&s);
    assert!(s.revealed.borrow().as_ref().is_none_or(|w| !w.is_visible()));
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
