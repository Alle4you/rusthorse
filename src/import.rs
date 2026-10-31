//! Reading secrets from other places, for `rusthorse import`.
//!
//! Importers only *read*. The entries they produce are sent to the agent as a
//! single [`Request::Import`](crate::protocol::Request::Import), which the
//! human approves as a batch.

use crate::protocol::SecretString;
use crate::util::is_valid_env_name;

/// Parse a `.env` file: `NAME=value` lines, optional `export ` prefix,
/// `#` comments, and matching single or double quotes around the value.
/// Lines with invalid names or empty values are skipped.
pub fn parse_dotenv(text: &str) -> Vec<(String, SecretString)> {
    let mut pairs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let mut value = value.trim();
        if value.len() >= 2 {
            let bytes = value.as_bytes();
            let (first, last) = (bytes[0], bytes[value.len() - 1]);
            if first == last && (first == b'"' || first == b'\'') {
                value = &value[1..value.len() - 1];
            }
        }
        if is_valid_env_name(name) && !value.is_empty() {
            pairs.push((name.to_string(), SecretString::new(value.to_string())));
        }
    }
    pairs
}

/// Read items from the freedesktop Secret Service (GNOME Keyring, KWallet, …)
/// whose attributes match all of `attributes`. Each item's name comes from the
/// attribute `name_from`, or from its label when `name_from` is `None`.
#[cfg(feature = "secret-service")]
pub fn read_secret_service(
    attributes: &[(String, String)],
    name_from: Option<&str>,
) -> anyhow::Result<Vec<(String, SecretString)>> {
    use anyhow::Context;
    use secret_service::EncryptionType;
    use secret_service::blocking::SecretService;
    use std::collections::HashMap;

    let service = SecretService::connect(EncryptionType::Dh)
        .context("cannot connect to the Secret Service (is GNOME Keyring or KWallet running?)")?;
    let filter: HashMap<&str, &str> = attributes
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let found = service
        .search_items(filter)
        .context("Secret Service search failed")?;
    let mut out = Vec::new();
    for item in found.unlocked.iter().chain(found.locked.iter()) {
        item.ensure_unlocked()
            .context("an item is locked and unlocking was refused")?;
        let name = match name_from {
            Some(attr) => item
                .get_attributes()?
                .get(attr)
                .cloned()
                .with_context(|| format!("an item has no {attr:?} attribute"))?,
            None => item.get_label()?,
        };
        let bytes = item.get_secret()?;
        let value = String::from_utf8(bytes).map_err(|e| {
            let mut bytes = e.into_bytes();
            zeroize::Zeroize::zeroize(&mut bytes);
            anyhow::anyhow!("the secret of {name:?} is not UTF-8 text")
        })?;
        out.push((name, SecretString::new(value)));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_parsing() {
        let text = "\
# comment
OPENAI_API_KEY=sk-abc
export TOKEN=\"quoted value\"
SINGLE='x y'
EMPTY=
bad-name=1
  SPACED = trimmed
NOEQUALS
";
        let pairs: Vec<(String, String)> = parse_dotenv(text)
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("OPENAI_API_KEY".into(), "sk-abc".into()),
                ("TOKEN".into(), "quoted value".into()),
                ("SINGLE".into(), "x y".into()),
                ("SPACED".into(), "trimmed".into()),
            ]
        );
    }
}
