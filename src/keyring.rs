//! The agent's view of GNOME Keyring — any freedesktop Secret Service — for
//! imports that the agent reads itself
//! ([ADR 0012](https://github.com/Alle4you/rusthorse/blob/main/docs/adr/0012-import-read-by-the-agent.md)).
//!
//! [`items`] lists what the keyring holds and [`describe`] tells what some
//! items are, without reading any secret; [`read`] reads the secrets of
//! items that are still what was described. Nothing is unlocked: a locked
//! item is refused, because the keyring's unlock prompt has no time limit.
//!
//! Every operation is bounded: each call by [`CALL_TIMEOUT`], the whole
//! operation — connecting and authenticating included — by
//! [`Settings::deadline`]. When the deadline passes, the agent shuts the
//! socket down, which makes the connection's pending reads and writes fail at
//! once, so that nothing is left waiting.

use std::time::Duration;

use crate::protocol::{KeyringItem, SecretString};
#[cfg(feature = "secret-service")]
use {
    anyhow::{Context, bail},
    secret_service::{EncryptionType, blocking::SecretService},
    std::collections::{BTreeMap, HashMap},
    std::os::unix::net::UnixStream,
    zbus::zvariant::OwnedObjectPath,
};

/// How long one call to the Secret Service may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a whole operation — connecting, authenticating and every call —
/// may take by default.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// The most items [`items`] lists; a keyring with more is refused.
pub const MAX_ITEMS: usize = 10_000;

/// Where the agent finds the Secret Service.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Address of the bus to use; `None` is the session bus. Only Unix
    /// sockets are used.
    pub address: Option<String>,
    /// Transfer secrets unencrypted over the bus: only for tests, whose fake
    /// service does not implement the Diffie-Hellman exchange that real
    /// keyrings use. (Encryption over the local bus protects only against
    /// programs that watch the bus; programs of the user can read the
    /// keyring directly anyway.)
    pub plain: bool,
    /// How long a whole operation may take ([`DEADLINE`]).
    pub deadline: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            address: None,
            plain: false,
            deadline: DEADLINE,
        }
    }
}

/// A Unix socket connected to the bus at `address` (the session bus without
/// one). Connecting is local and does not wait: a full backlog is retried
/// until `deadline`.
#[cfg(feature = "secret-service")]
fn connect_stream(
    address: Option<&str>,
    deadline: std::time::Instant,
) -> anyhow::Result<UnixStream> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
    use std::os::fd::AsRawFd;
    use std::str::FromStr;
    use zbus::address::transport::{Transport, UnixSocket};
    let address = match address {
        Some(text) => zbus::Address::from_str(text),
        None => zbus::Address::session(),
    }
    .context("cannot find the session bus to reach the keyring")?;
    let Transport::Unix(unix) = address.transport() else {
        bail!(
            "the session bus is not on a Unix socket ({address}); Rusthorse reaches the keyring only through one"
        );
    };
    let target = match unix.path() {
        UnixSocket::File(path) => UnixAddr::new(path.as_path())?,
        #[cfg(target_os = "linux")]
        UnixSocket::Abstract(name) => {
            use std::os::unix::ffi::OsStrExt;
            UnixAddr::new_abstract(name.as_bytes())?
        }
        _ => bail!("the session bus address {address} is not one a client can connect to"),
    };
    loop {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )?;
        match connect(fd.as_raw_fd(), &target) {
            Ok(()) => return Ok(UnixStream::from(fd)),
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR)
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => bail!("cannot connect to the session bus to reach the keyring: {e}"),
        }
    }
}

/// Run `operation` on the Secret Service within `settings.deadline`.
#[cfg(feature = "secret-service")]
fn with_service<T: Send + 'static>(
    settings: &Settings,
    operation: impl FnOnce(&SecretService<'_>) -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<T> {
    let deadline = std::time::Instant::now() + settings.deadline;
    let stream = connect_stream(settings.address.as_deref(), deadline)?;
    let cancel = stream
        .try_clone()
        .context("cannot prepare the connection to the keyring")?;
    let encryption = if settings.plain {
        EncryptionType::Plain
    } else {
        EncryptionType::Dh
    };
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("rusthorse-keyring".into())
        .spawn(move || {
            let result = (|| {
                let connection = zbus::blocking::connection::Builder::async_io_unix_stream(stream)
                    .method_timeout(CALL_TIMEOUT)
                    .build()
                    .context("cannot connect to the session bus to reach the keyring")?;
                let service = SecretService::connect_with_existing(encryption, connection)
                    .context(
                        "cannot reach the Secret Service (is GNOME Keyring or KWallet running?)",
                    )?;
                operation(&service)
            })();
            let _ = sender.send(result);
        })
        .context("cannot start a thread to reach the keyring")?;
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    match receiver.recv_timeout(left) {
        Ok(result) => result,
        Err(_) => {
            // Every pending read and write of the connection now fails, and
            // the thread ends.
            let _ = cancel.shutdown(std::net::Shutdown::Both);
            let _ = receiver.recv_timeout(Duration::from_secs(5));
            bail!(
                "the keyring did not answer within {} seconds",
                settings.deadline.as_secs()
            )
        }
    }
}

#[cfg(feature = "secret-service")]
fn metadata(item: &secret_service::blocking::Item<'_>) -> anyhow::Result<KeyringItem> {
    let attributes: BTreeMap<String, String> = item.get_attributes()?.into_iter().collect();
    Ok(KeyringItem {
        id: item.item_path.to_string(),
        label: item.get_label()?,
        attributes,
        locked: item.is_locked()?,
    })
}

/// The metadata of every item of every collection: object path, label,
/// attributes, whether locked. No secret is read, and nothing is unlocked.
#[cfg(feature = "secret-service")]
pub fn items(settings: &Settings) -> anyhow::Result<Vec<KeyringItem>> {
    with_service(settings, |service| {
        let mut out = Vec::new();
        for collection in service
            .get_all_collections()
            .context("cannot list the keyring's collections")?
        {
            for item in collection
                .get_all_items()
                .context("cannot list a collection's items")?
            {
                if out.len() >= MAX_ITEMS {
                    bail!(
                        "the keyring has more than {MAX_ITEMS} items; Rusthorse does not list so many"
                    );
                }
                out.push(metadata(&item)?);
            }
        }
        out.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    })
}

/// What the items `ids` (object paths) are, in the same order: `None` for
/// one that does not exist or cannot be examined. No secret is read.
#[cfg(feature = "secret-service")]
pub fn describe(settings: &Settings, ids: Vec<String>) -> anyhow::Result<Vec<Option<KeyringItem>>> {
    with_service(settings, move |service| {
        Ok(ids
            .iter()
            .map(|id| {
                let path = OwnedObjectPath::try_from(id.clone()).ok()?;
                let item = service.get_item_by_path(path).ok()?;
                metadata(&item).ok()
            })
            .collect())
    })
}

/// The secrets of the items `shown`, in the same order — each only if it is
/// still exactly what was shown (label, attributes) and unlocked. Fails,
/// returning nothing, otherwise or on a secret that is not UTF-8 text.
#[cfg(feature = "secret-service")]
pub fn read(settings: &Settings, shown: Vec<KeyringItem>) -> anyhow::Result<Vec<SecretString>> {
    with_service(settings, move |service| {
        let mut values = Vec::with_capacity(shown.len());
        // An item asked for twice is read once.
        let mut cache: HashMap<String, SecretString> = HashMap::new();
        for expected in &shown {
            if let Some(value) = cache.get(&expected.id) {
                values.push(value.clone());
                continue;
            }
            let path = OwnedObjectPath::try_from(expected.id.clone())
                .with_context(|| format!("{:?} is not a keyring item", expected.id))?;
            let item = service.get_item_by_path(path)?;
            let now = metadata(&item)
                .with_context(|| format!("the keyring item {:?} is gone", expected.label))?;
            if now.label != expected.label || now.attributes != expected.attributes {
                bail!(
                    "the keyring item {:?} changed while you decided; nothing was imported",
                    expected.label
                );
            }
            if now.locked {
                bail!(
                    "the keyring item {:?} is locked; unlock the keyring (for example in \
                     Passwords and Keys) and try again",
                    expected.label
                );
            }
            let bytes = item
                .get_secret()
                .with_context(|| format!("cannot read the keyring item {:?}", expected.label))?;
            let value = String::from_utf8(bytes).map_err(|e| {
                let mut bytes = e.into_bytes();
                zeroize::Zeroize::zeroize(&mut bytes);
                anyhow::anyhow!(
                    "the secret of the keyring item {:?} is not text",
                    expected.label
                )
            })?;
            let value = SecretString::new(value);
            cache.insert(expected.id.clone(), value.clone());
            values.push(value);
        }
        Ok(values)
    })
}

/// How a keyring item is named in a dialog: its label and attributes.
pub fn describe_item(item: &KeyringItem) -> String {
    let attributes = item
        .attributes
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    if attributes.is_empty() {
        item.label.clone()
    } else {
        format!("{} [{attributes}]", item.label)
    }
}

#[cfg(not(feature = "secret-service"))]
const NOT_BUILT: &str =
    "this Rusthorse was built without Secret Service support (the `secret-service` feature)";

/// Without the `secret-service` feature: always an error.
#[cfg(not(feature = "secret-service"))]
pub fn items(_: &Settings) -> anyhow::Result<Vec<KeyringItem>> {
    anyhow::bail!(NOT_BUILT)
}

/// Without the `secret-service` feature: always an error.
#[cfg(not(feature = "secret-service"))]
pub fn describe(_: &Settings, _: Vec<String>) -> anyhow::Result<Vec<Option<KeyringItem>>> {
    anyhow::bail!(NOT_BUILT)
}

/// Without the `secret-service` feature: always an error.
#[cfg(not(feature = "secret-service"))]
pub fn read(_: &Settings, _: Vec<KeyringItem>) -> anyhow::Result<Vec<SecretString>> {
    anyhow::bail!(NOT_BUILT)
}

/// A Secret Service that holds fake items, for tests only (the
/// `fake-keyring` feature, never in a release): one collection, plain
/// sessions, no prompts. A locked item refuses its secret.
#[cfg(feature = "fake-keyring")]
pub mod fake {
    use std::collections::HashMap;

    use zbus::blocking::{Connection, connection};
    use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

    const COLLECTION: &str = "/org/freedesktop/secrets/collection/login";

    /// One fake item.
    #[derive(Debug, Clone)]
    pub struct Item {
        /// Its label.
        pub label: String,
        /// Its attributes.
        pub attributes: HashMap<String, String>,
        /// Its secret.
        pub secret: Vec<u8>,
        /// Whether it is locked.
        pub locked: bool,
    }

    impl Item {
        /// An unlocked item with these attributes.
        pub fn new(label: &str, attributes: &[(&str, &str)], secret: &str) -> Item {
            Item {
                label: label.into(),
                attributes: attributes
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                secret: secret.as_bytes().to_vec(),
                locked: false,
            }
        }
    }

    fn path(text: String) -> OwnedObjectPath {
        OwnedObjectPath::try_from(text).unwrap_or_else(|_| unreachable!("valid object path"))
    }

    struct Service {
        items: Vec<OwnedObjectPath>,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl Service {
        fn open_session(
            &self,
            algorithm: &str,
            _input: OwnedValue,
        ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
            if algorithm != "plain" {
                return Err(zbus::fdo::Error::NotSupported(
                    "the fake keyring offers plain sessions only".into(),
                ));
            }
            let output = OwnedValue::try_from(Value::from(""))
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
            Ok((output, path("/org/freedesktop/secrets/session/1".into())))
        }

        fn search_items(
            &self,
            _attributes: HashMap<String, String>,
        ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
            (self.items.clone(), Vec::new())
        }

        #[zbus(property)]
        fn collections(&self) -> Vec<OwnedObjectPath> {
            vec![path(COLLECTION.into())]
        }
    }

    struct Collection {
        items: Vec<OwnedObjectPath>,
    }

    #[zbus::interface(name = "org.freedesktop.Secret.Collection")]
    impl Collection {
        #[zbus(property)]
        fn items(&self) -> Vec<OwnedObjectPath> {
            self.items.clone()
        }

        #[zbus(property)]
        fn label(&self) -> String {
            "Login".into()
        }

        #[zbus(property)]
        fn locked(&self) -> bool {
            false
        }
    }

    struct FakeItem(Item);

    #[zbus::interface(name = "org.freedesktop.Secret.Item")]
    impl FakeItem {
        fn get_secret(
            &self,
            session: OwnedObjectPath,
        ) -> zbus::fdo::Result<(OwnedObjectPath, Vec<u8>, Vec<u8>, String)> {
            if self.0.locked {
                return Err(zbus::fdo::Error::AccessDenied("the item is locked".into()));
            }
            Ok((
                session,
                Vec::new(),
                self.0.secret.clone(),
                "text/plain".into(),
            ))
        }

        #[zbus(property)]
        fn label(&self) -> String {
            self.0.label.clone()
        }

        #[zbus(property)]
        fn attributes(&self) -> HashMap<String, String> {
            self.0.attributes.clone()
        }

        #[zbus(property)]
        fn locked(&self) -> bool {
            self.0.locked
        }
    }

    /// Change the label of the `index`th item (from 0) of the service that
    /// `connection` serves, as a program of the session could.
    pub fn relabel(connection: &Connection, index: usize, label: &str) -> zbus::Result<()> {
        let item = connection
            .object_server()
            .interface::<_, FakeItem>(format!("{COLLECTION}/{}", index + 1))?;
        item.get_mut().0.label = label.to_string();
        Ok(())
    }

    /// Serve `items` as `org.freedesktop.secrets` on the bus at `address`
    /// (the session bus without one), at the paths GNOME Keyring uses. The
    /// service lives as long as the returned connection.
    pub fn serve(address: Option<&str>, items: Vec<Item>) -> zbus::Result<Connection> {
        let paths: Vec<OwnedObjectPath> = (1..=items.len())
            .map(|i| path(format!("{COLLECTION}/{i}")))
            .collect();
        let mut builder = match address {
            Some(address) => connection::Builder::address(address)?,
            None => connection::Builder::session()?,
        }
        .name("org.freedesktop.secrets")?
        .serve_at(
            "/org/freedesktop/secrets",
            Service {
                items: paths.clone(),
            },
        )?
        .serve_at(
            COLLECTION,
            Collection {
                items: paths.clone(),
            },
        )?;
        for (at, item) in paths.into_iter().zip(items) {
            builder = builder.serve_at(at, FakeItem(item))?;
        }
        builder.build()
    }
}

#[cfg(all(test, feature = "secret-service"))]
mod tests {
    use super::*;

    #[test]
    fn a_bus_that_never_answers_is_given_up_at_the_deadline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mute");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        // Accepts, then says nothing: the authentication never completes.
        let held = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));
        let settings = Settings {
            address: Some(format!("unix:path={}", path.display())),
            plain: true,
            deadline: Duration::from_millis(500),
        };
        let started = std::time::Instant::now();
        let error = items(&settings).expect_err("no answer");
        assert!(error.to_string().contains("did not answer"), "{error:#}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        drop(held.join());
    }
}
