//! Clipboard content that hands a revealed value to one paste, then nothing.
//!
//! The value is never given to GTK as a string. GTK asks this provider for the
//! bytes each time a program pastes, so the provider can count pastes: the
//! first request for text starts a short grace period (one paste can make more
//! than one request), after which every request fails and the manager clears
//! the clipboard. The provider also offers `x-kde-passwordManagerHint:
//! secret`, which clipboard histories that honour it (Klipper, KDE Connect,
//! some others) use to skip the value, and declares nothing storable, so GTK
//! never hands the value to a clipboard manager when the manager exits.
//!
//! On X11, GTK 4 serves only formats whose name contains a slash, so the hint
//! is announced but cannot be read there: a clipboard history on X11 is not
//! told. What protects the value there is the single paste: a history that
//! reads it takes that paste, and the human's own paste comes back empty.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use gtk::gdk::subclass::prelude::*;
use gtk::prelude::*;
use gtk::{gdk, gio, glib};
use rusthorse::protocol::SecretString;
use zeroize::Zeroizing;

/// How long requests from the paste that first took the value are still
/// answered. Some programs ask more than once for one paste.
pub(crate) const PASTE_GRACE: Duration = Duration::from_secs(1);
/// How long a copied value stays on the clipboard when nobody pastes it.
pub(crate) const CLIPBOARD_SECONDS: u64 = 20;
/// The text formats offered. GTK maps them to the X11 and Wayland targets
/// (`UTF8_STRING`, `STRING`, …).
pub(crate) const TEXT: &str = "text/plain;charset=utf-8";
const LEGACY_TEXT: &str = "text/plain";
/// The format clipboard histories check to skip passwords; its content is
/// `secret`. Asking for it is not a paste.
pub(crate) const HINT: &str = "x-kde-passwordManagerHint";

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct SecretContent {
        pub value: RefCell<Option<SecretString>>,
        pub served_at: Cell<Option<Instant>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for SecretContent {
        const NAME: &'static str = "RusthorseSecretContent";
        type Type = super::SecretContent;
        type ParentType = gdk::ContentProvider;
    }

    impl ObjectImpl for SecretContent {}

    impl ContentProviderImpl for SecretContent {
        fn formats(&self) -> gdk::ContentFormats {
            gdk::ContentFormatsBuilder::new()
                .add_mime_type(TEXT)
                .add_mime_type(LEGACY_TEXT)
                .add_mime_type(HINT)
                .build()
        }

        // Nothing may be stored by a clipboard manager when the app exits.
        fn storable_formats(&self) -> gdk::ContentFormats {
            gdk::ContentFormatsBuilder::new().build()
        }

        fn write_mime_type_future(
            &self,
            mime_type: &str,
            stream: &gio::OutputStream,
            io_priority: glib::Priority,
        ) -> Pin<Box<dyn Future<Output = Result<(), glib::Error>> + 'static>> {
            let data = self.data_for(mime_type, Instant::now());
            let stream = stream.clone();
            Box::pin(async move {
                let data = data?;
                match stream.write_all_future(data, io_priority).await {
                    Ok((_, _, None)) => {}
                    Ok((_, _, Some(e))) | Err((_, e)) => return Err(e),
                }
                stream.close_future(io_priority).await
            })
        }
    }

    impl SecretContent {
        /// The bytes for one request, or an error once the value is gone or
        /// was already taken by an earlier paste.
        pub(super) fn data_for(
            &self,
            mime_type: &str,
            now: Instant,
        ) -> Result<Zeroizing<Vec<u8>>, glib::Error> {
            if mime_type == HINT {
                return Ok(Zeroizing::new(b"secret".to_vec()));
            }
            if mime_type != TEXT && mime_type != LEGACY_TEXT {
                return Err(glib::Error::new(
                    gio::IOErrorEnum::NotSupported,
                    "unsupported clipboard format",
                ));
            }
            if self
                .served_at
                .get()
                .is_some_and(|first| now.saturating_duration_since(first) > PASTE_GRACE)
            {
                return Err(gone());
            }
            let value = self.value.borrow();
            let Some(value) = value.as_ref() else {
                return Err(gone());
            };
            if self.served_at.get().is_none() {
                self.served_at.set(Some(now));
            }
            Ok(Zeroizing::new(value.as_str().as_bytes().to_vec()))
        }
    }

    fn gone() -> glib::Error {
        glib::Error::new(
            gio::IOErrorEnum::PermissionDenied,
            "the value was already pasted or cleared",
        )
    }
}

glib::wrapper! {
    /// Clipboard content holding one revealed value for a single paste.
    pub struct SecretContent(ObjectSubclass<imp::SecretContent>)
        @extends gdk::ContentProvider;
}

impl SecretContent {
    pub fn new(value: SecretString) -> Self {
        let content: Self = glib::Object::new();
        content.imp().value.replace(Some(value));
        content
    }

    /// When the first paste took the value, if one did.
    pub fn served_at(&self) -> Option<Instant> {
        self.imp().served_at.get()
    }

    /// Whether the clipboard still holds this content.
    pub fn is_on(&self, clipboard: &gdk::Clipboard) -> bool {
        clipboard
            .content()
            .is_some_and(|c| c == *self.upcast_ref::<gdk::ContentProvider>())
    }

    /// Drop the value (it is zeroized) so that no later request gets it.
    pub fn wipe(&self) {
        self.imp().value.replace(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_paste_gets_the_value_and_later_requests_get_nothing() {
        let content = SecretContent::new(SecretString::new("FAKE-one-paste".into()));
        let imp = content.imp();
        let start = Instant::now();
        // Asking for the hint or the list of formats is not a paste.
        assert_eq!(
            imp.data_for(HINT, start).ok().as_deref().map(|v| &v[..]),
            Some(&b"secret"[..])
        );
        assert!(content.served_at().is_none());
        assert!(imp.data_for("image/png", start).is_err());
        assert!(content.served_at().is_none());
        // The paste, and a second request from that same paste.
        let first = imp.data_for(TEXT, start).expect("first paste");
        assert_eq!(&first[..], b"FAKE-one-paste");
        assert_eq!(content.served_at(), Some(start));
        assert!(imp.data_for(LEGACY_TEXT, start + PASTE_GRACE).is_ok());
        // Any later request fails, even before the manager clears.
        assert!(
            imp.data_for(TEXT, start + PASTE_GRACE + Duration::from_millis(1))
                .is_err()
        );
    }

    #[test]
    fn a_wiped_value_is_never_served() {
        let content = SecretContent::new(SecretString::new("FAKE-wiped".into()));
        content.wipe();
        assert!(content.imp().data_for(TEXT, Instant::now()).is_err());
        assert!(content.served_at().is_none());
    }

    #[test]
    fn nothing_is_storable_by_a_clipboard_manager() {
        let content = SecretContent::new(SecretString::new("FAKE".into()));
        let provider = content.upcast_ref::<gdk::ContentProvider>();
        assert!(provider.storable_formats().mime_types().is_empty());
        let offered: Vec<String> = provider
            .formats()
            .mime_types()
            .iter()
            .map(|m| m.to_string())
            .collect();
        assert!(offered.iter().any(|m| m == TEXT));
        assert!(offered.iter().any(|m| m == HINT));
    }
}
