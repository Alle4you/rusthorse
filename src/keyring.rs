//! The agent's view of GNOME Keyring — any freedesktop Secret Service — for
//! imports that the agent reads itself
//! ([ADR 0012](https://github.com/Alle4you/rusthorse/blob/main/docs/adr/0012-import-read-by-the-agent.md)).
//!
//! [`items`] lists what the keyring holds without reading any secret;
//! [`read`] reads the secrets of chosen items. Neither unlocks anything: a
//! locked item is refused, because the keyring's unlock prompt has no time
//! limit and would hold the request for as long as nobody answers it. Every
//! call to the service is bounded by [`CALL_TIMEOUT`].

use std::time::Duration;

use crate::protocol::{KeyringItem, SecretString};
#[cfg(feature = "secret-service")]
use {
    anyhow::{Context, bail},
    secret_service::{EncryptionType, blocking::SecretService},
    std::collections::{BTreeMap, HashMap},
    zbus::zvariant::OwnedObjectPath,
};

/// How long one call to the Secret Service may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// The most items [`items`] lists; a keyring with more is refused.
pub const MAX_ITEMS: usize = 10_000;

/// Where the agent finds the Secret Service.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Address of the bus to use; `None` is the session bus.
    pub address: Option<String>,
    /// Transfer secrets unencrypted over the bus: only for tests, whose fake
    /// service does not implement the Diffie-Hellman exchange that real
    /// keyrings use. (Encryption over the local bus protects only against
    /// programs that watch the bus; programs of the user can read the
    /// keyring directly anyway.)
    pub plain: bool,
}

#[cfg(feature = "secret-service")]
fn connect(settings: &Settings) -> anyhow::Result<SecretService<'static>> {
    let builder = match &settings.address {
        Some(address) => zbus::blocking::connection::Builder::address(address.as_str())?,
        None => zbus::blocking::connection::Builder::session()?,
    };
    let connection = builder
        .method_timeout(CALL_TIMEOUT)
        .build()
        .context("cannot connect to the session bus to reach the keyring")?;
    let encryption = if settings.plain {
        EncryptionType::Plain
    } else {
        EncryptionType::Dh
    };
    SecretService::connect_with_existing(encryption, connection)
        .context("cannot reach the Secret Service (is GNOME Keyring or KWallet running?)")
}

/// The metadata of every item of every collection: object path, label,
/// attributes, whether locked. No secret is read, and nothing is unlocked.
#[cfg(feature = "secret-service")]
pub fn items(settings: &Settings) -> anyhow::Result<Vec<KeyringItem>> {
    let service = connect(settings)?;
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
            let attributes: BTreeMap<String, String> = item.get_attributes()?.into_iter().collect();
            out.push(KeyringItem {
                id: item.item_path.to_string(),
                label: item.get_label()?,
                attributes,
                locked: item.is_locked()?,
            });
        }
    }
    out.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));
    Ok(out)
}

/// The secrets of the items `ids` (object paths), in the same order. Fails —
/// reading nothing more — on an unknown or locked item, or a secret that is
/// not UTF-8 text.
#[cfg(feature = "secret-service")]
pub fn read(settings: &Settings, ids: &[&str]) -> anyhow::Result<Vec<SecretString>> {
    let service = connect(settings)?;
    let mut values = Vec::with_capacity(ids.len());
    // An item asked for twice is read once.
    let mut cache: HashMap<&str, SecretString> = HashMap::new();
    for &id in ids {
        if let Some(value) = cache.get(id) {
            values.push(value.clone());
            continue;
        }
        let path = OwnedObjectPath::try_from(id.to_string())
            .with_context(|| format!("{id:?} is not a keyring item"))?;
        let item = service.get_item_by_path(path)?;
        let label = item
            .get_label()
            .with_context(|| format!("there is no keyring item {id}"))?;
        if item.is_locked()? {
            bail!(
                "the keyring item {label:?} is locked; unlock the keyring (for example in \
                 Passwords and Keys) and try again"
            );
        }
        let bytes = item
            .get_secret()
            .with_context(|| format!("cannot read the keyring item {label:?}"))?;
        let value = String::from_utf8(bytes).map_err(|e| {
            let mut bytes = e.into_bytes();
            zeroize::Zeroize::zeroize(&mut bytes);
            anyhow::anyhow!("the secret of the keyring item {label:?} is not text")
        })?;
        let value = SecretString::new(value);
        cache.insert(id, value.clone());
        values.push(value);
    }
    Ok(values)
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
pub fn read(_: &Settings, _: &[&str]) -> anyhow::Result<Vec<SecretString>> {
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
