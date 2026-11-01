//! `rusthorse-dialog`: shows one dialog for the Rusthorse agent and answers
//! through the socket the agent gave it as standard input and output
//! ([ADR 0006](../../docs/adr/0006-own-dialog-program.md)).
//!
//! It reads one request, refuses it if its version is not this program's or
//! if any of its text is not drawable as it is (the agent passes every string
//! through `rusthorse::ui::dialog_text`), shows the dialog with plain-text
//! labels only, writes exactly one answer and exits. Nothing else is ever
//! written to standard output.

use std::cell::{Cell, RefCell};
use std::io::Read;
use std::process::ExitCode;
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gdk, gio, glib, pango};
use rusthorse::dialog_protocol::{self as wire, Answer, Dialog, Reply, Request};
use rusthorse::protocol::SecretString;

/// Why a request was refused before anything was shown.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// Another protocol version.
    Incompatible,
    /// Malformed, or text that dialogs must not draw.
    Invalid,
}

impl Refusal {
    fn exit_code(&self) -> ExitCode {
        let code = match self {
            Refusal::Incompatible => wire::EXIT_INCOMPATIBLE,
            Refusal::Invalid => wire::EXIT_INVALID,
        };
        ExitCode::from(code as u8)
    }
}

/// Read and check the request: one frame, then the end of the stream (the
/// agent closes its side after the request).
fn read_request(input: &mut impl Read) -> Result<Request, Refusal> {
    let body = wire::read_frame(input, wire::MAX_REQUEST).map_err(|_| Refusal::Invalid)?;
    let mut extra = [0u8; 1];
    if !matches!(input.read(&mut extra), Ok(0)) {
        return Err(Refusal::Invalid);
    }
    // The version first, from a loose reading, so that a request of another
    // version is told apart from a malformed one.
    let version = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("version")?.as_u64());
    match version {
        Some(v) if v == u64::from(wire::VERSION) => {}
        Some(_) => return Err(Refusal::Incompatible),
        None => return Err(Refusal::Invalid),
    }
    let request: Request = wire::parse(&body).map_err(|_| Refusal::Invalid)?;
    if !request.is_drawable() || request.id.is_empty() {
        return Err(Refusal::Invalid);
    }
    Ok(request)
}

/// Whether the end of the content is in view, from the scroll adjustment;
/// `None` before the first layout, when the page size is still zero.
fn end_in_view(value: f64, page: f64, upper: f64) -> Option<bool> {
    (page > 0.0).then_some(value + page >= upper - 1.0)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {}
        [check] if check == "--check" => {
            // Version and protocol, for `rusthorse doctor`; opens no window.
            println!(
                "{}",
                serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "protocol": wire::VERSION,
                })
            );
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("rusthorse-dialog is started by the Rusthorse agent; it takes no arguments");
            return ExitCode::from(2);
        }
    }
    let request = match read_request(&mut std::io::stdin().lock()) {
        Ok(request) => request,
        Err(refusal) => return refusal.exit_code(),
    };
    show(request)
}

/// The answer, written once, and whether writing it succeeded.
struct Outcome {
    id: String,
    sent: Cell<Option<bool>>,
}

impl Outcome {
    /// Send `reply` unless an answer was already sent, then quit.
    fn answer(&self, app: &adw::Application, reply: Reply) {
        if self.sent.get().is_none() {
            let answer = Answer {
                version: wire::VERSION,
                id: self.id.clone(),
                reply,
            };
            let written =
                wire::write_frame(&mut std::io::stdout().lock(), &answer, wire::MAX_ANSWER).is_ok();
            self.sent.set(Some(written));
        }
        app.quit();
    }
}

fn show(request: Request) -> ExitCode {
    let app = adw::Application::builder()
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    let outcome = Rc::new(Outcome {
        id: request.id.clone(),
        sent: Cell::new(None),
    });
    let request = RefCell::new(Some(request));
    let state = Rc::clone(&outcome);
    app.connect_activate(move |app| {
        let Some(request) = request.borrow_mut().take() else {
            return;
        };
        let timeout = request.timeout_secs.clamp(1, 3600) as u32;
        let window = match &request.dialog {
            Dialog::Approval { .. } => approval_window(app, &request, &state),
            Dialog::Entry { .. } => entry_window(app, &request, &state),
        };
        let (app2, state2) = (app.clone(), Rc::clone(&state));
        glib::timeout_add_seconds_local(timeout, move || {
            state2.answer(&app2, Reply::TimedOut);
            glib::ControlFlow::Break
        });
        window.present();
    });
    app.run_with_args::<&str>(&[]);
    match outcome.sent.get() {
        Some(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

/// A plain-text label: no markup, no mnemonics, wrapping anywhere it must.
/// Selectable labels also take the keyboard focus, so that Tab moves through
/// the content and scrolls it: the end can be reached without a mouse.
fn label(text: &str, classes: &[&str], xalign: f32, selectable: bool) -> gtk::Label {
    let label = gtk::Label::builder()
        .label(text)
        .use_markup(false)
        .use_underline(false)
        .xalign(xalign)
        .yalign(0.0)
        .wrap(true)
        .wrap_mode(pango::WrapMode::WordChar)
        .selectable(selectable)
        .focusable(selectable)
        .build();
    for class in classes {
        label.add_css_class(class);
    }
    label
}

fn card(child: &impl IsA<gtk::Widget>, margin: i32) -> gtk::Box {
    let card = gtk::Box::new(gtk::Orientation::Vertical, 0);
    card.add_css_class("card");
    child.set_margin_top(margin);
    child.set_margin_bottom(margin);
    child.set_margin_start(margin + 2);
    child.set_margin_end(margin + 2);
    card.append(child);
    card
}

fn warning(text: &str) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
    icon.add_css_class("warning");
    icon.set_valign(gtk::Align::Start);
    row.append(&icon);
    let text = label(text, &["warning"], 0.0, true);
    text.set_hexpand(true);
    row.append(&text);
    card(&row, 12)
}

/// Label | value rows. A "(unverified)" suffix moves under its label.
fn grid(rows: &[(String, String)], dim_values: bool) -> gtk::Grid {
    let grid = gtk::Grid::builder()
        .column_spacing(18)
        .row_spacing(10)
        .build();
    for (row, (key, value)) in rows.iter().enumerate() {
        let keys = gtk::Box::new(gtk::Orientation::Vertical, 0);
        keys.set_halign(gtk::Align::End);
        match key.strip_suffix(" (unverified)") {
            Some(key) => {
                keys.append(&label(key, &["dim-label"], 1.0, false));
                keys.append(&label("unverified", &["dim-label", "caption"], 1.0, false));
            }
            None => keys.append(&label(key, &["dim-label"], 1.0, false)),
        }
        let classes: &[&str] = if dim_values {
            &["dim-label"]
        } else {
            &["monospace"]
        };
        let value = label(value, classes, 0.0, true);
        value.set_hexpand(true);
        grid.attach(&keys, 0, row as i32, 1, 1);
        grid.attach(&value, 1, row as i32, 1, 1);
    }
    grid
}

/// The window, its body inside a scroller, and a bottom bar that never
/// scrolls.
fn window(
    app: &adw::Application,
    title: &str,
    subtitle: &str,
    body: &gtk::Box,
    buttons: &[&gtk::Widget],
) -> (adw::ApplicationWindow, gtk::ScrolledWindow) {
    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&adw::WindowTitle::new("Rusthorse", subtitle)));
    header.set_decoration_layout(Some(":close"));
    let view = adw::ToolbarView::new();
    view.add_top_bar(&header);

    body.set_margin_top(12);
    body.set_margin_bottom(18);
    body.set_margin_start(24);
    body.set_margin_end(24);
    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .propagate_natural_height(true)
        .max_content_height(max_content_height())
        .child(body)
        .build();
    view.set_content(Some(&scroller));

    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    bar.set_margin_top(12);
    bar.set_margin_bottom(12);
    bar.set_margin_start(24);
    bar.set_margin_end(24);
    for button in buttons {
        bar.append(*button);
    }
    view.add_bottom_bar(&bar);

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title(title)
        .default_width(660)
        .content(&view)
        .build();
    (window, scroller)
}

/// Two thirds of the first monitor's height, so that the window with its
/// buttons fits on the screen; 600 pixels if the monitor is unknown.
fn max_content_height() -> i32 {
    gdk::Display::default()
        .and_then(|display| display.monitors().item(0))
        .and_then(|item| item.downcast::<gdk::Monitor>().ok())
        .map(|monitor| monitor.geometry().height() * 2 / 3)
        .filter(|height| *height > 200)
        .unwrap_or(600)
}

fn spacer() -> gtk::Widget {
    gtk::Box::builder().hexpand(true).build().upcast()
}

/// Escape and closing the window both mean `reply`.
fn on_dismiss(
    window: &adw::ApplicationWindow,
    app: &adw::Application,
    outcome: &Rc<Outcome>,
    reply: Reply,
) {
    let (app2, outcome2, reply2) = (app.clone(), Rc::clone(outcome), reply.clone());
    let controller = gtk::ShortcutController::new();
    controller.add_shortcut(gtk::Shortcut::new(
        gtk::ShortcutTrigger::parse_string("Escape"),
        Some(gtk::CallbackAction::new(move |_, _| {
            outcome2.answer(&app2, reply2.clone());
            glib::Propagation::Stop
        })),
    ));
    window.add_controller(controller);
    let (app3, outcome3) = (app.clone(), Rc::clone(outcome));
    window.connect_close_request(move |_| {
        outcome3.answer(&app3, reply.clone());
        glib::Propagation::Proceed
    });
}

fn approval_window(
    app: &adw::Application,
    request: &Request,
    outcome: &Rc<Outcome>,
) -> adw::ApplicationWindow {
    let Dialog::Approval {
        headline,
        explanation,
        warnings,
        command,
        details,
        facts,
        remember,
    } = &request.dialog
    else {
        unreachable!("an approval request");
    };
    let body = gtk::Box::new(gtk::Orientation::Vertical, 16);
    body.append(&label(headline, &["title-2"], 0.0, false));
    if !explanation.is_empty() {
        body.append(&label(explanation, &["dim-label"], 0.0, false));
    }
    for text in warnings {
        body.append(&warning(text));
    }
    if let Some(command) = command {
        body.append(&label("Command", &["heading"], 0.0, false));
        body.append(&card(&label(command, &["monospace"], 0.0, true), 14));
    }
    if !details.is_empty() || !facts.is_empty() {
        body.append(&label("Details", &["heading"], 0.0, false));
        let rows = gtk::Box::new(gtk::Orientation::Vertical, 10);
        if !details.is_empty() {
            rows.append(&grid(details, false));
        }
        if !facts.is_empty() {
            rows.append(&grid(facts, true));
        }
        body.append(&card(&rows, 14));
    }
    if let Some(remember) = remember {
        body.append(&label(
            &remember.note,
            &["dim-label", "caption"],
            0.0,
            false,
        ));
    }

    let deny = gtk::Button::with_label("Deny");
    let once = gtk::Button::with_label("Allow once");
    let for_n = remember.as_ref().map(|r| gtk::Button::with_label(&r.label));
    let mut buttons: Vec<gtk::Widget> = vec![deny.clone().upcast(), spacer()];
    if let Some(button) = &for_n {
        buttons.push(button.clone().upcast());
    }
    buttons.push(once.clone().upcast());
    let refs: Vec<&gtk::Widget> = buttons.iter().collect();
    let (window, scroller) = window(app, &request.title, "Approval required", &body, &refs);

    // Approval waits until the end of the content has been in view once.
    let reached = Rc::new(Cell::new(false));
    let allow: Vec<gtk::Button> = std::iter::once(once.clone()).chain(for_n.clone()).collect();
    for button in &allow {
        button.set_sensitive(false);
    }
    let adjustment = scroller.vadjustment();
    let update = {
        let (reached, allow) = (Rc::clone(&reached), allow.clone());
        move |adjustment: &gtk::Adjustment| {
            if end_in_view(
                adjustment.value(),
                adjustment.page_size(),
                adjustment.upper(),
            ) == Some(true)
            {
                reached.set(true);
            }
            for button in &allow {
                button.set_sensitive(reached.get());
            }
        }
    };
    adjustment.connect_changed(update.clone());
    adjustment.connect_value_changed(update);

    let (app1, outcome1) = (app.clone(), Rc::clone(outcome));
    deny.connect_clicked(move |_| outcome1.answer(&app1, Reply::Deny));
    let (app2, outcome2, reached2) = (app.clone(), Rc::clone(outcome), Rc::clone(&reached));
    once.connect_clicked(move |_| {
        if reached2.get() {
            outcome2.answer(&app2, Reply::AllowOnce);
        }
    });
    if let Some(button) = &for_n {
        let (app3, outcome3, reached3) = (app.clone(), Rc::clone(outcome), Rc::clone(&reached));
        button.connect_clicked(move |_| {
            if reached3.get() {
                outcome3.answer(&app3, Reply::AllowFor);
            }
        });
    }
    on_dismiss(&window, app, outcome, Reply::Deny);
    window.set_default_widget(Some(&deny));
    let deny2 = deny.clone();
    window.connect_map(move |_| {
        deny2.grab_focus();
    });
    window
}

fn entry_window(
    app: &adw::Application,
    request: &Request,
    outcome: &Rc<Outcome>,
) -> adw::ApplicationWindow {
    let Dialog::Entry {
        headline,
        explanation,
        notice,
        details,
        field,
        confirm,
    } = &request.dialog
    else {
        unreachable!("an entry request");
    };
    let body = gtk::Box::new(gtk::Orientation::Vertical, 16);
    if let Some(notice) = notice {
        body.append(&warning(notice));
    }
    body.append(&label(headline, &["title-3"], 0.0, false));
    if !explanation.is_empty() {
        body.append(&label(explanation, &["dim-label"], 0.0, false));
    }
    let entry = adw::PasswordEntryRow::builder()
        .title(field.as_str())
        .build();
    let group = adw::PreferencesGroup::new();
    group.add(&entry);
    body.append(&group);
    if !details.is_empty() {
        body.append(&card(&grid(details, false), 14));
    }

    let cancel = gtk::Button::with_label("Cancel");
    let ok = gtk::Button::with_label(confirm);
    ok.add_css_class("suggested-action");
    let buttons: Vec<gtk::Widget> = vec![cancel.clone().upcast(), spacer(), ok.clone().upcast()];
    let refs: Vec<&gtk::Widget> = buttons.iter().collect();
    let (window, _) = window(app, &request.title, field, &body, &refs);

    let submit = {
        let (app, outcome, entry) = (app.clone(), Rc::clone(outcome), entry.clone());
        move || {
            let typed = entry.text();
            if typed.len() > wire::MAX_TYPED {
                entry.add_css_class("error");
                return;
            }
            let text = SecretString::new(typed.to_string());
            entry.set_text("");
            outcome.answer(&app, Reply::Typed { text });
        }
    };
    let submit2 = submit.clone();
    ok.connect_clicked(move |_| submit2());
    entry.connect_entry_activated(move |_| submit());
    let (app2, outcome2) = (app.clone(), Rc::clone(outcome));
    cancel.connect_clicked(move |_| outcome2.answer(&app2, Reply::Cancel));
    on_dismiss(&window, app, outcome, Reply::Cancel);
    let entry2 = entry.clone();
    window.connect_map(move |_| {
        entry2.grab_focus();
    });
    window
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusthorse::dialog_protocol::Remember;

    fn request() -> Request {
        Request {
            version: wire::VERSION,
            id: "abc".into(),
            timeout_secs: 60,
            title: "Rusthorse — use a secret".into(),
            dialog: Dialog::Approval {
                headline: "Run a command with your secrets?".into(),
                explanation: String::new(),
                warnings: Vec::new(),
                command: Some("true".into()),
                details: Vec::new(),
                facts: Vec::new(),
                remember: Some(Remember {
                    label: "Allow for 15m".into(),
                    note: "note".into(),
                }),
            },
        }
    }

    fn framed(value: &impl serde::Serialize) -> Vec<u8> {
        let mut out = Vec::new();
        wire::write_frame(&mut out, value, wire::MAX_REQUEST).expect("frame");
        out
    }

    #[test]
    fn requests_are_checked_before_anything_is_shown() {
        assert_eq!(
            read_request(&mut framed(&request()).as_slice()).expect("ok"),
            request()
        );
        let mut newer = serde_json::to_value(request()).expect("value");
        newer["version"] = serde_json::json!(wire::VERSION + 1);
        assert_eq!(
            read_request(&mut framed(&newer).as_slice()),
            Err(Refusal::Incompatible)
        );
        let mut unknown = serde_json::to_value(request()).expect("value");
        unknown["surprise"] = serde_json::json!(1);
        assert_eq!(
            read_request(&mut framed(&unknown).as_slice()),
            Err(Refusal::Invalid)
        );
        let mut undrawable = request();
        undrawable.title = "p\u{430}ypal".into();
        assert_eq!(
            read_request(&mut framed(&undrawable).as_slice()),
            Err(Refusal::Invalid)
        );
        assert_eq!(read_request(&mut &b"\0\0"[..]), Err(Refusal::Invalid));
        // Anything after the request.
        let mut extra = framed(&request());
        extra.push(b'x');
        assert_eq!(read_request(&mut extra.as_slice()), Err(Refusal::Invalid));
    }

    #[test]
    fn the_end_is_in_view_only_after_layout_and_at_the_bottom() {
        assert_eq!(end_in_view(0.0, 0.0, 0.0), None);
        assert_eq!(end_in_view(0.0, 500.0, 400.0), Some(true));
        assert_eq!(end_in_view(0.0, 500.0, 1200.0), Some(false));
        assert_eq!(end_in_view(699.5, 500.0, 1200.0), Some(true));
        assert_eq!(end_in_view(600.0, 500.0, 1200.0), Some(false));
    }
}
