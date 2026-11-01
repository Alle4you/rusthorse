//! The visual Rusthorse client. It never opens a vault or starts the agent.

mod clipboard;
mod connection;
mod model;
mod window;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use adw::prelude::*;
use gtk::{gdk, gio};

/// Rusthorse's accent (the orange of its icon) and the state pill. Only
/// named colours of libadwaita are redefined; the theme does the rest.
const STYLE: &str = "
@define-color accent_bg_color #e66100;
@define-color accent_fg_color #ffffff;
.pill-label { padding: 2px 10px; border-radius: 999px; font-weight: bold; }
.pill-label.success { background-color: alpha(@success_color, 0.18); }
.pill-label.warning { background-color: alpha(@warning_color, 0.18); }
";
/// The accent as text: darker on a light background, lighter on a dark one,
/// so that it stays readable.
const ACCENT_LIGHT: &str = "@define-color accent_color #c64600;";
const ACCENT_DARK: &str = "@define-color accent_color #ffa348;";

fn load_style() {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    let base = gtk::CssProvider::new();
    base.load_from_string(STYLE);
    gtk::style_context_add_provider_for_display(
        &display,
        &base,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    let accent = gtk::CssProvider::new();
    gtk::style_context_add_provider_for_display(
        &display,
        &accent,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    let styles = adw::StyleManager::default();
    let apply = move |s: &adw::StyleManager| {
        accent.load_from_string(if s.is_dark() {
            ACCENT_DARK
        } else {
            ACCENT_LIGHT
        });
    };
    apply(&styles);
    styles.connect_dark_notify(apply);
}

/// Set when SIGINT, SIGTERM or SIGHUP arrives; the main loop then quits the
/// application the normal way, which wipes shown and copied values.
static QUIT: AtomicBool = AtomicBool::new(false);

/// Block the termination signals in every thread (call before any thread
/// starts) and wait for them on a thread of their own.
fn watch_signals() -> Result<(), String> {
    use nix::sys::signal::{SigSet, Signal};
    let mut set = SigSet::empty();
    for signal in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
        set.add(signal);
    }
    set.thread_block().map_err(|e| e.to_string())?;
    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            if set.wait().is_ok() {
                QUIT.store(true, Ordering::SeqCst);
            }
        })
        .map(drop)
        .map_err(|e| e.to_string())
}

/// Wipe a shown or copied value when the application shuts down — when its
/// window closes, when it quits, and when a termination signal makes it quit
/// — before GTK can offer the clipboard to a clipboard manager.
pub(crate) fn wipe_at_shutdown(
    app: &adw::Application,
    state: &Rc<RefCell<Option<Rc<window::Manager>>>>,
) {
    let at_exit = Rc::clone(state);
    app.connect_shutdown(move |_| {
        if let Some(manager) = at_exit.borrow().as_ref() {
            manager.shutdown();
        }
    });
}

fn main() -> std::process::ExitCode {
    // Apply before GTK can hold a revealed value. No child program is started.
    if let Err(e) = rusthorse::agent::harden_process() {
        eprintln!("rusthorse-manager: cannot protect process memory: {e}");
        return std::process::ExitCode::FAILURE;
    }
    if let Err(e) = watch_signals() {
        eprintln!("rusthorse-manager: cannot handle termination signals: {e}");
        return std::process::ExitCode::FAILURE;
    }
    let app = adw::Application::builder()
        .application_id("io.github.alle4you.Rusthorse")
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.connect_startup(|_| load_style());
    let state = Rc::new(RefCell::new(None::<Rc<window::Manager>>));
    wipe_at_shutdown(&app, &state);
    let quitting = app.downgrade();
    gtk::glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
        if !QUIT.load(Ordering::SeqCst) {
            return gtk::glib::ControlFlow::Continue;
        }
        if let Some(app) = quitting.upgrade() {
            app.quit();
        }
        gtk::glib::ControlFlow::Break
    });
    let keep = Rc::clone(&state);
    app.connect_activate(move |app| {
        if let Some(manager) = keep.borrow().as_ref() {
            manager.window.present();
            return;
        }
        let manager = window::Manager::new(app, rusthorse::paths::socket());
        manager.window.present();
        manager.refresh();
        *keep.borrow_mut() = Some(manager);
    });
    let code = app.run();
    state.borrow_mut().take();
    if code == gtk::glib::ExitCode::SUCCESS {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
