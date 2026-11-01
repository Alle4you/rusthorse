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
/// dialog until it is cleared; and `asking`, set while held.
struct Scripted(Arc<AtomicBool>, Arc<AtomicBool>, Arc<AtomicBool>);
impl Ui for Scripted {
    fn master_password(&self, _: &Prompt) -> anyhow::Result<Typed> {
        Ok(Typed::Value("fake master password".to_string().into()))
    }
    fn secret_value(&self, _: &Prompt) -> anyhow::Result<Typed> {
        Ok(Typed::Value("FAKE-desktop-value".to_string().into()))
    }
    fn approve(&self, _: &ApprovalRequest) -> anyhow::Result<Decision> {
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
    // `descendants` lists children before their parents, last child first
    // within each level; put the rows back in the order the form shows them.
    rows.sort_by_key(|r| {
        let root = r.root().expect("root");
        let point = r
            .compute_point(&root, &gtk::graphene::Point::zero())
            .expect("on screen");
        (point.y() * 100.0) as i64
    });
    rows
}

/// The text a revealed value shows, whether grouped by four or not.
fn shown_text(root: &impl IsA<gtk::Widget>) -> String {
    let flow = descendants(root)
        .into_iter()
        .find_map(|w| w.downcast::<gtk::FlowBox>().ok());
    match flow {
        Some(flow) => {
            let mut parts = vec![];
            let mut i = 0;
            while let Some(child) = flow.child_at_index(i) {
                if let Some(l) = child.child().and_downcast::<gtk::Label>() {
                    parts.push(l.text().to_string());
                }
                i += 1;
            }
            parts.concat()
        }
        None => descendants(root)
            .into_iter()
            .filter_map(|w| w.downcast::<gtk::Label>().ok())
            .filter(|l| l.has_css_class("monospace"))
            .map(|l| l.text().to_string())
            .collect(),
    }
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
/// (an error, or empty content from a wiped value).
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
    inputs[3].set_text("https://example.invalid");
    button(&editor, "Send to agent…").emit_clicked();
    settle(&s);
    assert_eq!(s.entries.borrow().len(), 1);
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
    button(&s.detail, "Copy command snippet").emit_clicked();
    let copied = glib::MainContext::default()
        .block_on(s.window.clipboard().read_text_future())
        .unwrap()
        .unwrap();
    assert!(copied.contains(&id));
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
    let parts: Vec<_> = descendants(&reveal)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Label>().ok())
        .filter(|l| l.has_css_class("monospace"))
        .collect();
    assert_eq!(parts.len(), 5, "grouped by four");
    assert!(parts.iter().all(|l| !l.is_selectable()));
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
    // Short or spaced values are shown as they are, never grouped.
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
    let expiring_parts: Vec<_> = descendants(&expiring)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Label>().ok())
        .filter(|l| l.has_css_class("monospace"))
        .collect();
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

    // Copy: one paste gets the value, the next gets nothing, and clipboard
    // histories are told it is a password. Read by another X11 client.
    s.rows.select_row(s.rows.row_at_index(0).as_ref());
    allowed.store(false, Ordering::SeqCst);
    button(&s.detail, "Copy value…").emit_clicked();
    settle(&s);
    assert!(s.copied.borrow().is_none());
    assert!(!s.banner.is_revealed());
    allowed.store(true, Ordering::SeqCst);
    button(&s.detail, "Copy value…").emit_clicked();
    settle(&s);
    assert!(s.banner.is_revealed());
    assert!(s.banner.title().contains("for one paste"));
    // GTK 4 on X11 serves only formats whose name has a slash, so the
    // password hint is offered but cannot be read here (docs/manager.md).
    let (ok, hint) = x11(&[
        "/usr/bin/xclip",
        "-o",
        "-selection",
        "clipboard",
        "-t",
        crate::clipboard::HINT,
    ]);
    assert!(!ok && hint.is_empty());
    let wait = Instant::now() + Duration::from_millis(600);
    spin_until(|| Instant::now() >= wait);
    assert_eq!(paste().as_deref(), Some("FAKE-desktop-value"));
    // A second reader, right away, gets nothing.
    assert_eq!(paste(), None);
    spin_until(|| s.copied.borrow().is_none());
    assert!(!s.banner.is_revealed());
    assert!(
        s.message.text().contains("pasted once"),
        "{}",
        s.message.text()
    );
    assert_eq!(paste(), None);

    // Taken right after the copy (as a clipboard history does): say so.
    s.put_on_clipboard_for(
        "Fake grabbed copy",
        "FAKE-copy-grabbed".to_string().into(),
        Duration::from_secs(20),
    );
    assert_eq!(paste().as_deref(), Some("FAKE-copy-grabbed"));
    spin_until(|| s.copied.borrow().is_none());
    assert!(
        s.message.text().contains("clipboard history"),
        "{}",
        s.message.text()
    );

    // Not pasted in time: cleared.
    s.put_on_clipboard_for(
        "Fake expiring copy",
        "FAKE-copy-expiring".to_string().into(),
        Duration::from_millis(200),
    );
    spin_until(|| s.copied.borrow().is_none());
    assert!(s.message.text().contains("Not pasted in time"));
    assert_eq!(paste(), None);

    // Something copied afterwards is left alone.
    s.put_on_clipboard_for(
        "Fake replaced copy",
        "FAKE-copy-replaced".to_string().into(),
        Duration::from_secs(20),
    );
    s.window.clipboard().set_text("not a secret");
    spin_until(|| s.copied.borrow().is_none());
    assert_eq!(paste().as_deref(), Some("not a secret"));

    // Another program that takes the clipboard before GTK has noticed keeps
    // it: clearing wipes our value and never claims the clipboard back.
    s.put_on_clipboard_for(
        "Fake raced copy",
        "FAKE-copy-raced".to_string().into(),
        Duration::from_secs(20),
    );
    let mut owner = std::process::Command::new("/usr/bin/xclip")
        .args(["-selection", "clipboard", "-i", "-quiet"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut input = owner.stdin.take().unwrap();
        input.write_all(b"copied by another program").unwrap();
    }
    // Without running the main loop, GTK cannot see that it lost the
    // clipboard: it still believes it owns it.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        s.copied
            .borrow()
            .as_ref()
            .unwrap()
            .content
            .is_on(&s.window.clipboard())
    );
    s.clear_clipboard("cleared during a race");
    let settle_frame = Instant::now() + Duration::from_millis(300);
    spin_until(|| Instant::now() >= settle_frame);
    assert_eq!(paste().as_deref(), Some("copied by another program"));
    let _ = owner.kill();
    let _ = owner.wait();

    // Locking clears a copied value at once.
    s.put_on_clipboard_for(
        "Fake locked copy",
        "FAKE-copy-locked".to_string().into(),
        Duration::from_secs(20),
    );
    button(&s.window, "Lock now").emit_clicked();
    assert!(s.copied.borrow().is_none());
    assert_eq!(paste(), None);
    settle(&s);
    assert_eq!(s.pill.text(), "Locked");
    button(&s.window, "Unlock").emit_clicked();
    settle(&s);
    spin_until(|| s.job.borrow().is_none() && !s.entries.borrow().is_empty());
    s.rows.select_row(s.rows.row_at_index(0).as_ref());

    // A lock made elsewhere while a request waits for the human is seen,
    // and the copied value goes at once.
    button(&s.detail, "Copy value…").emit_clicked();
    settle(&s);
    assert!(s.copied.borrow().is_some());
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
    spin_until(|| s.copied.borrow().is_none() || Instant::now() >= seen);
    assert!(
        s.copied.borrow().is_none(),
        "lock not seen during the request"
    );
    assert!(s.job.borrow().is_some(), "the request is still waiting");
    assert_eq!(s.pill.text(), "Locked");
    assert_eq!(paste(), None);
    hold.store(false, Ordering::SeqCst);
    settle(&s);
    button(&s.window, "Unlock").emit_clicked();
    settle(&s);
    spin_until(|| s.job.borrow().is_none() && !s.entries.borrow().is_empty());
    s.rows.select_row(s.rows.row_at_index(0).as_ref());

    // A value that arrives after such a lock was seen is not used.
    hold.store(true, Ordering::SeqCst);
    button(&s.detail, "Copy value…").emit_clicked();
    spin_until(|| asking.load(Ordering::SeqCst));
    s.lock_seen.set(true);
    hold.store(false, Ordering::SeqCst);
    settle(&s);
    assert!(s.copied.borrow().is_none());
    assert!(s.revealed.borrow().is_none());
    assert!(
        s.message.text().contains("neither shown nor copied"),
        "{}",
        s.message.text()
    );
    assert_eq!(paste(), None);

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
    // Closing wipes a value still on the clipboard.
    s.put_on_clipboard_for(
        "Fake copy at exit",
        "FAKE-copy-at-exit".to_string().into(),
        Duration::from_secs(20),
    );
    s.window.close();
    assert!(s.closed.get());
    assert!(s.job.borrow().is_none());
    assert!(s.copied.borrow().is_none());
    assert_eq!(paste(), None);
    // So does the application's shutdown, which a termination signal
    // triggers (tests/signals.rs checks that a signal quits normally).
    s.put_on_clipboard_for(
        "Fake copy at shutdown",
        "FAKE-copy-at-shutdown".to_string().into(),
        Duration::from_secs(20),
    );
    app.emit_by_name::<()>("shutdown", &[]);
    assert!(s.copied.borrow().is_none());
    assert_eq!(paste(), None);
}
