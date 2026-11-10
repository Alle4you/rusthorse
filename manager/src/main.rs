//! The visual Rusthorse client. It never opens a vault, and the agent is
//! never its child: Start agent asks systemd to start the service.

mod connection;
mod model;
mod window;

use std::cell::RefCell;
use std::rc::Rc;

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

/// Hide a shown value and drop what the window holds when the application
/// shuts down normally. (A signal that ends the process skips this; the
/// window and its memory go with the process.)
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
    // Apply before GTK can hold a revealed value. The one child program is
    // `systemctl`, when the human asks to start the agent.
    if let Err(e) = rusthorse::agent::harden_process() {
        eprintln!("rusthorse-manager: cannot protect process memory: {e}");
        return std::process::ExitCode::FAILURE;
    }
    let app = adw::Application::builder()
        .application_id("io.github.alle4you.Rusthorse")
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.connect_startup(|_| load_style());
    let state = Rc::new(RefCell::new(None::<Rc<window::Manager>>));
    wipe_at_shutdown(&app, &state);
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
