//! Preparing an approved command: resolving the program and cleaning the
//! environment before the agent spawns it.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Variables that make the dynamic loader run extra code. Always removed.
pub const LOADER_PREFIX: &str = "LD_";

/// Variables that can make a program execute code other than what the
/// command line says. They are passed through, but shown as a warning in the
/// approval dialog and included in the approval cache key.
pub const RISKY_VARS: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "PS4",
    "SHELLOPTS",
    "BASHOPTS",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_EXEC_PATH",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GCONV_PATH",
    "HOSTALIASES",
];

/// Prefixes of risky variable families (e.g. `GIT_CONFIG_KEY_0`).
pub const RISKY_PREFIXES: &[&str] = &["GIT_CONFIG_", "BASH_FUNC_"];

/// Variables that send a program's connections through another machine, or
/// change which servers it trusts or how it finds them. Compared without
/// regard to case (`https_proxy` is common). See [`destination`].
pub const ROUTE_VARS: &[&str] = &[
    // TLS trust: a certificate authority of the requester's, or none at all.
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "AWS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "GIT_SSL_NO_VERIFY",
    "PYTHONHTTPSVERIFY",
    "CARGO_HTTP_CAINFO",
    "NPM_CONFIG_CAFILE",
    "PIP_CERT",
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
    // Name resolution and proxies without the usual suffix.
    "RES_OPTIONS",
    "LOCALDOMAIN",
    "GOPROXY",
];

/// Suffixes of variables that route connections (`HTTPS_PROXY`). `NO_PROXY`,
/// which only makes a program bypass a proxy, is not one of them.
pub const ROUTE_SUFFIXES: &[&str] = &["_PROXY"];

/// Of the [`ROUTE_VARS`], those that name a certificate file or directory.
pub const TRUST_PATH_VARS: &[&str] = &[
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "AWS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "CARGO_HTTP_CAINFO",
    "NPM_CONFIG_CAFILE",
    "PIP_CERT",
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
];

/// Where Linux distributions keep the system's certificate authorities. Only
/// root can change them, so a certificate variable that names one of them
/// (`SSL_CERT_DIR=/usr/lib/ssl/certs`, set by some tools) is not listed.
pub const SYSTEM_TRUST_STORES: &[&str] = &[
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/usr/lib/ssl",
    "/usr/share/ca-certificates",
    "/usr/local/share/ca-certificates",
];

/// Whether variable `name` names a certificate file or directory inside a
/// [`SYSTEM_TRUST_STORES`] entry. Judged on the text only — absolute paths
/// without `..` — and never by following links: a link elsewhere that
/// points into a store does not count, and what lies inside a store only
/// root can change.
fn system_trust_store(name: &str, value: &str) -> bool {
    // `SSL_CERT_DIR` is a list (`/etc/ssl/certs:/tmp/ca`): every element must
    // be inside a store. Other variables name one path; one with a `:` is
    // judged the same way, which only ever lists more.
    TRUST_PATH_VARS.contains(&name.to_ascii_uppercase().as_str())
        && value.split(':').all(|part| {
            let path = Path::new(part);
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                && SYSTEM_TRUST_STORES
                    .iter()
                    .any(|store| path.starts_with(store))
        })
}

/// Variables that name the server a program connects to, without one of
/// the [`ENDPOINT_SUFFIXES`].
pub const ENDPOINT_VARS: &[&str] = &[
    "PGHOST",
    "PGHOSTADDR",
    "PGPORT",
    "PGSERVICE",
    "PGSERVICEFILE",
];

/// Prefixes of endpoint variable families without a usual suffix: the AWS
/// SDKs read `AWS_ENDPOINT_URL_<SERVICE>` (`AWS_ENDPOINT_URL_S3`) before
/// `AWS_ENDPOINT_URL`.
pub const ENDPOINT_PREFIXES: &[&str] = &["AWS_ENDPOINT_URL_"];

/// Suffixes of variables that name where a program connects:
/// `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `AZURE_OPENAI_ENDPOINT`,
/// `DATABASE_URL`, `MONGODB_URI`, `DOCKER_HOST`, `VAULT_ADDR`,
/// `NPM_CONFIG_REGISTRY`, …
pub const ENDPOINT_SUFFIXES: &[&str] = &[
    "_URL",
    "_URI",
    "_API_BASE",
    "_ENDPOINT",
    "_HOST",
    "_ADDR",
    "_REGISTRY",
];

/// What a variable decides about a program's connections (threat model L4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// Where it connects: an endpoint, URL, host or address.
    Endpoint,
    /// What its connections go through (a proxy), or which servers it
    /// trusts and how it finds them.
    Route,
}

/// Whether `name` decides where a program connects ([`ENDPOINT_VARS`],
/// [`ENDPOINT_SUFFIXES`]) or how ([`ROUTE_VARS`], [`ROUTE_SUFFIXES`]). With
/// them a requester can point an approved, well-known program at a server of
/// its own; such lists are never complete.
pub fn destination(name: &str) -> Option<Destination> {
    let name = name.to_ascii_uppercase();
    if name == "NO_PROXY" {
        return None;
    }
    let listed = |names: &[&str], suffixes: &[&str]| {
        names.contains(&name.as_str()) || suffixes.iter().any(|s| name.ends_with(s))
    };
    if listed(ROUTE_VARS, ROUTE_SUFFIXES) {
        Some(Destination::Route)
    } else if listed(ENDPOINT_VARS, ENDPOINT_SUFFIXES)
        || ENDPOINT_PREFIXES.iter().any(|p| name.starts_with(p))
    {
        Some(Destination::Endpoint)
    } else {
        None
    }
}

/// Destination variables whose value is a list: `GOPROXY` (items separated by
/// `,` or `|`), and the extra package indexes of pip and uv (separated by
/// spaces).
pub const LIST_VARS: &[&str] = &[
    "GOPROXY",
    "PIP_EXTRA_INDEX_URL",
    "UV_EXTRA_INDEX_URL",
    "UV_INDEX",
];

/// Shown instead of a destination value, or a part of one, that is not a
/// plain URL, host name or path.
pub const NOT_SHOWN: &str = "(not shown)";

/// A destination variable's value as dialogs and the audit log show it, and
/// whether part of it was [`NOT_SHOWN`].
///
/// Only unambiguous forms are shown — with `list`, item by item, the items
/// separated by `,`, `|` or spaces ([`LIST_VARS`]); otherwise the value is
/// one item, so that a comma inside a URL's path cannot make part of the
/// path look like another item. A URL keeps its
/// scheme, host and port and loses its user name, password, path, query and
/// fragment, where credentials and tokens travel (`https://…@proxy:3128/…`;
/// a webhook URL is a secret); `user:password@host` loses its user part; a
/// host name, a word (`direct`, `0`) and absolute paths without `..`
/// (`/etc/ssl/certs:/tmp/ca`) are shown as they are. Anything else — a
/// backslash or a control character anywhere, several `@`, a host with
/// characters outside letters, digits, `.`, `-` and `_`, `https:/host` — is
/// not shown at all: programs disagree on what such a value means (a URL
/// parser that reads `\` as `/` connects to the host *before* the `@`), so
/// no host drawn from it can be trusted, and copying it could disclose a
/// credential.
pub fn shown_destination(value: &str, list: bool) -> (String, bool) {
    if value.chars().any(|c| c == '\\' || c.is_control()) {
        return (NOT_SHOWN.to_string(), true);
    }
    let mut shown = String::new();
    let mut unusual = false;
    let mut item = String::new();
    let mut flush = |item: &mut String, shown: &mut String| {
        match shown_item(item) {
            Some(text) => shown.push_str(&text),
            None => {
                shown.push_str(NOT_SHOWN);
                unusual = true;
            }
        }
        item.clear();
    };
    for c in value.chars() {
        if list && matches!(c, ',' | '|' | ' ') {
            flush(&mut item, &mut shown);
            shown.push(c);
        } else {
            item.push(c);
        }
    }
    flush(&mut item, &mut shown);
    (shown, unusual)
}

/// A certificate variable's value ([`TRUST_PATH_VARS`]): paths, shown as they
/// are when made of ordinary characters (a `..` included: it shows where the
/// path leads), [`NOT_SHOWN`] otherwise.
pub fn shown_paths(value: &str) -> (String, bool) {
    let ordinary = !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+@~:".contains(&b));
    if ordinary {
        (value.to_string(), false)
    } else {
        (NOT_SHOWN.to_string(), true)
    }
}

/// One item of a destination value, or `None` when it has no unambiguous
/// form (see [`shown_destination`]).
fn shown_item(item: &str) -> Option<String> {
    let more = |tail: &str| if tail.is_empty() { "" } else { "/…" };
    if item.is_empty() {
        return Some(String::new());
    }
    if let Some((scheme, rest)) = item.split_once("://") {
        let mut chars = scheme.chars();
        let scheme_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if !scheme_ok {
            return None;
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.is_empty() {
            // A local socket or file (`unix:///run/docker.sock`): the path
            // is the destination.
            return absolute_paths(tail).then(|| format!("{scheme}://{tail}"));
        }
        let (user, host) = split_user(authority)?;
        return host_port(host).then(|| format!("{scheme}://{user}{host}{}", more(tail)));
    }
    if item.starts_with('/') {
        return absolute_paths(item).then(|| item.to_string());
    }
    let end = item.find('/').unwrap_or(item.len());
    let (authority, tail) = item.split_at(end);
    let (user, host) = split_user(authority)?;
    host_port(host).then(|| format!("{user}{host}{}", more(tail)))
}

/// `user@host` → `("…@", "host")`; `host` → `("", "host")`; `None` for
/// several `@`, which parsers resolve differently.
fn split_user(authority: &str) -> Option<(&'static str, &str)> {
    match authority.split_once('@') {
        None => Some(("", authority)),
        Some((_, host)) if !host.contains('@') => Some(("…@", host)),
        Some(_) => None,
    }
}

/// A host name, IPv4 or bracketed IPv6 address, with an optional port of
/// digits: nothing that a URL parser could decode or reinterpret.
fn host_port(text: &str) -> bool {
    let port_ok =
        |port: &str| (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = text.strip_prefix('[') {
        let Some((address, after)) = rest.split_once(']') else {
            return false;
        };
        let address_ok = !address.is_empty()
            && address
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'));
        return address_ok && (after.is_empty() || after.strip_prefix(':').is_some_and(port_ok));
    }
    let (host, port) = match text.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (text, None),
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && port.is_none_or(port_ok)
}

/// Absolute paths separated by `:`, none with `..`, made of ordinary
/// characters.
fn absolute_paths(text: &str) -> bool {
    !text.is_empty()
        && text.split(':').all(|path| {
            path.starts_with('/')
                && !Path::new(path)
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                && path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-+@~".contains(&b))
        })
}

/// The environment an approved command will receive (before secrets are added).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEnv {
    /// Variables to pass to the command.
    pub vars: Vec<(String, String)>,
    /// Names of variables that were removed (dynamic loader variables).
    pub removed: Vec<String>,
    /// Risky variables that are passed through, with their values.
    pub risky: Vec<(String, String)>,
    /// Variables that name where the program connects, with their values as
    /// [`shown_destination`] shows them.
    pub endpoints: Vec<(String, String)>,
    /// Variables that route its connections or change what it trusts, shown
    /// the same way.
    pub routes: Vec<(String, String)>,
    /// Names of the endpoint and route variables whose value, or part of it,
    /// is [`NOT_SHOWN`].
    pub unusual: Vec<String>,
}

/// Whether `name` belongs to [`RISKY_VARS`] or [`RISKY_PREFIXES`].
pub fn is_risky(name: &str) -> bool {
    RISKY_VARS.contains(&name) || RISKY_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Remove loader variables and the variables that secrets will override, and
/// collect the risky ones for the approval dialog.
pub fn prepare_env(client_env: &[(String, String)], secret_vars: &[&str]) -> PreparedEnv {
    use std::collections::{BTreeMap, BTreeSet};
    let mut vars = Vec::new();
    let mut removed = BTreeSet::new();
    // By name, so that a later duplicate replaces an earlier one, as it does
    // in the command's environment: the dialog shows what the command gets.
    let mut risky = BTreeMap::new();
    let mut endpoints = BTreeMap::new();
    let mut routes = BTreeMap::new();
    let mut unusual = BTreeMap::new();
    for (name, value) in client_env {
        if name.is_empty() || name.contains('=') || secret_vars.contains(&name.as_str()) {
            continue;
        }
        if name.starts_with(LOADER_PREFIX) {
            removed.insert(name.clone());
            continue;
        }
        // (`insert` replaces what an earlier duplicate left.)
        unusual.insert(name.clone(), false);
        if is_risky(name) {
            risky.insert(name.clone(), value.clone());
        } else {
            let list = match destination(name) {
                Some(Destination::Endpoint) => Some(&mut endpoints),
                Some(Destination::Route) if !system_trust_store(name, value) => Some(&mut routes),
                _ => None,
            };
            if let Some(list) = list {
                let (shown, odd) = if TRUST_PATH_VARS.contains(&name.to_ascii_uppercase().as_str())
                {
                    shown_paths(value)
                } else {
                    shown_destination(
                        value,
                        LIST_VARS.contains(&name.to_ascii_uppercase().as_str()),
                    )
                };
                list.insert(name.clone(), shown);
                unusual.insert(name.clone(), odd);
            }
        }
        vars.push((name.clone(), value.clone()));
    }
    PreparedEnv {
        vars,
        removed: removed.into_iter().collect(),
        risky: risky.into_iter().collect(),
        endpoints: endpoints.into_iter().collect(),
        routes: routes.into_iter().collect(),
        unusual: unusual
            .into_iter()
            .filter(|(_, odd)| *odd)
            .map(|(name, _)| name)
            .collect(),
    }
}

/// A program found for `run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProgram {
    /// The path where it was found (may be a symlink, e.g. `.venv/bin/python`).
    pub found: PathBuf,
    /// The file that will actually be executed (symlinks resolved).
    pub canonical: PathBuf,
}

impl ResolvedProgram {
    /// `found → canonical`, or just the path when they are the same.
    pub fn describe(&self) -> String {
        if self.found == self.canonical {
            self.canonical.display().to_string()
        } else {
            format!("{} → {}", self.found.display(), self.canonical.display())
        }
    }
}

/// Resolve `program` like `execvp` would, but up front, so that the approval
/// dialog can show the absolute path that will actually be executed.
///
/// A name containing `/` is taken relative to `cwd`; otherwise each `PATH`
/// entry is searched in order (an empty entry means `cwd`).
pub fn resolve_program(
    program: &str,
    path_var: Option<&str>,
    cwd: &Path,
) -> Result<ResolvedProgram, String> {
    if program.is_empty() {
        return Err("empty program name".into());
    }
    if program.contains('/') {
        let candidate = cwd.join(program);
        return if is_executable(&candidate) {
            Ok(resolved(candidate))
        } else {
            Err(format!("{program}: not an executable file"))
        };
    }
    let path_var = path_var.unwrap_or("/usr/local/bin:/usr/bin:/bin");
    for dir in path_var.split(':') {
        let dir = if dir.is_empty() {
            cwd.to_path_buf()
        } else {
            cwd.join(dir)
        };
        let candidate = dir.join(program);
        if is_executable(&candidate) {
            return Ok(resolved(candidate));
        }
    }
    Err(format!("{program}: command not found in PATH"))
}

fn resolved(found: PathBuf) -> ResolvedProgram {
    let canonical = std::fs::canonicalize(&found).unwrap_or_else(|_| found.clone());
    ResolvedProgram { found, canonical }
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn loader_vars_are_removed_and_risky_flagged() {
        let prepared = prepare_env(
            &env(&[
                ("PATH", "/usr/bin"),
                ("LD_PRELOAD", "/tmp/evil.so"),
                ("LD_LIBRARY_PATH", "/tmp"),
                ("NODE_OPTIONS", "--require /tmp/x.js"),
                ("GIT_CONFIG_KEY_0", "core.sshCommand"),
                ("API_KEY", "client-supplied"),
            ]),
            &["API_KEY"],
        );
        assert_eq!(prepared.removed, vec!["LD_LIBRARY_PATH", "LD_PRELOAD"]);
        assert_eq!(
            prepared
                .risky
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>(),
            vec!["GIT_CONFIG_KEY_0", "NODE_OPTIONS"]
        );
        let names: Vec<&str> = prepared.vars.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"PATH"));
        assert!(!names.contains(&"API_KEY"));
        assert!(!names.contains(&"LD_PRELOAD"));
    }

    #[test]
    fn destination_variables_are_listed_without_credentials() {
        let prepared = prepare_env(
            &env(&[
                ("PATH", "/usr/bin"),
                // A later duplicate wins, in the command and in the dialog.
                ("OPENAI_BASE_URL", "https://z.invalid"),
                ("OPENAI_BASE_URL", "https://api.example.invalid/v1"),
                ("https_proxy", "http://user:pw@proxy.invalid:3128"),
                ("SSL_CERT_FILE", "/tmp/fake-ca.pem"),
                ("PGHOST", "db.invalid"),
                (
                    "HOOK_URL",
                    "https://hooks.example.invalid/T0/B0/FAKE-secret,FAKE-2",
                ),
                (
                    "DATABASE_URL",
                    "postgres://u:FAKE-pw@db.invalid:5432/app?ssl=1",
                ),
                ("DOCKER_HOST", "unix:///run/docker.sock"),
                ("AWS_ENDPOINT_URL", "https://expected.invalid"),
                ("AWS_ENDPOINT_URL_S3", "https://other.invalid"),
                // A list, whose first element has credentials and no scheme.
                (
                    "GOPROXY",
                    "user:FAKE-pw@private.invalid,https://proxy.golang.org",
                ),
                // Read differently by different parsers: never shown.
                (
                    "OPENAI_API_BASE",
                    "http://127.0.0.1:1\\@provider.invalid/v1",
                ),
                (
                    "HOOK2_URL",
                    "https:/hooks.example.invalid/FAKE-token?key=FAKE",
                ),
                // A secret's own variable is never shown: it is replaced.
                ("API_URL", "client-supplied"),
                ("HOSTALIASES", "/tmp/hosts"),
                // The system's own certificate authorities: nothing to warn of.
                ("SSL_CERT_DIR", "/usr/lib/ssl/certs:/etc/ssl/certs"),
                ("CURL_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt"),
                // Not inside a store, whatever the path looks like.
                ("GIT_SSL_CAINFO", "/etc/ssl/../../tmp/fake-ca.pem"),
                ("PIP_CERT", "etc/ssl/fake-ca.pem"),
                ("REQUESTS_CA_BUNDLE", "/etc/ssl/certs:/tmp/fake-ca"),
                ("NO_PROXY", "localhost"),
            ]),
            &["API_URL"],
        );
        assert_eq!(
            prepared.endpoints,
            env(&[
                ("AWS_ENDPOINT_URL", "https://expected.invalid"),
                ("AWS_ENDPOINT_URL_S3", "https://other.invalid"),
                ("DATABASE_URL", "postgres://…@db.invalid:5432/…"),
                ("DOCKER_HOST", "unix:///run/docker.sock"),
                ("HOOK2_URL", "(not shown)"),
                ("HOOK_URL", "https://hooks.example.invalid/…"),
                ("OPENAI_API_BASE", "(not shown)"),
                ("OPENAI_BASE_URL", "https://api.example.invalid/…"),
                ("PGHOST", "db.invalid"),
            ])
        );
        assert_eq!(
            prepared.routes,
            env(&[
                ("GIT_SSL_CAINFO", "/etc/ssl/../../tmp/fake-ca.pem"),
                ("GOPROXY", "…@private.invalid,https://proxy.golang.org"),
                ("PIP_CERT", "etc/ssl/fake-ca.pem"),
                ("REQUESTS_CA_BUNDLE", "/etc/ssl/certs:/tmp/fake-ca"),
                ("SSL_CERT_FILE", "/tmp/fake-ca.pem"),
                ("https_proxy", "http://…@proxy.invalid:3128"),
            ])
        );
        assert_eq!(prepared.unusual, vec!["HOOK2_URL", "OPENAI_API_BASE"]);
        let listed = format!("{:?} {:?}", prepared.endpoints, prepared.routes);
        assert!(!listed.contains("FAKE"), "{listed}");
        // Already a risky variable: warned about once, as such.
        assert_eq!(prepared.risky, env(&[("HOSTALIASES", "/tmp/hosts")]));
        // Passed through unchanged: only the dialog's copy is shortened.
        assert!(prepared.vars.contains(&(
            "HOOK_URL".into(),
            "https://hooks.example.invalid/T0/B0/FAKE-secret,FAKE-2".into()
        )));
        for (name, expected) in [
            ("NO_PROXY", None),
            ("no_proxy", None),
            ("GOPROXY", Some(Destination::Route)),
            ("node_tls_reject_unauthorized", Some(Destination::Route)),
            ("AZURE_OPENAI_ENDPOINT", Some(Destination::Endpoint)),
            ("OPENAI_API_BASE", Some(Destination::Endpoint)),
            ("DOCKER_HOST", Some(Destination::Endpoint)),
            ("VAULT_ADDR", Some(Destination::Endpoint)),
            ("npm_config_registry", Some(Destination::Endpoint)),
            ("MONGODB_URI", Some(Destination::Endpoint)),
            ("AWS_ENDPOINT_URL_DYNAMODB", Some(Destination::Endpoint)),
            ("HOSTNAME", None),
            ("DBUS_SESSION_BUS_ADDRESS", None),
            ("PATH", None),
        ] {
            assert_eq!(destination(name), expected, "{name}");
        }
        for (value, list, shown) in [
            ("https://h.invalid", false, "https://h.invalid"),
            ("https://h.invalid/", false, "https://h.invalid/…"),
            ("https://h.invalid?k=FAKE", false, "https://h.invalid/…"),
            ("http://[::1]:8080/x", false, "http://[::1]:8080/…"),
            ("db.invalid:5432", false, "db.invalid:5432"),
            ("u:FAKE@proxy.invalid:3128", false, "…@proxy.invalid:3128"),
            ("/home/me/ca@2.pem", false, "/home/me/ca@2.pem"),
            ("1", false, "1"),
            // A list variable: item by item.
            (
                "https://a.invalid https://b.invalid",
                true,
                "https://a.invalid https://b.invalid",
            ),
            ("https://h.invalid|direct", true, "https://h.invalid|direct"),
            (
                "ok.invalid,https:/x.invalid/FAKE",
                true,
                "ok.invalid,(not shown)",
            ),
            // Any other variable: one item, so a comma or a space inside a
            // URL never turns part of its path into an item of its own.
            (
                "https://h.invalid/a,FAKE-token",
                false,
                "https://h.invalid/…",
            ),
            (
                "https://h.invalid/a|FAKE-token",
                false,
                "https://h.invalid/…",
            ),
            ("https://a.invalid FAKE.invalid", false, "(not shown)"),
            ("u:FAKE@a.invalid,https://b.invalid", false, "(not shown)"),
            // Ambiguous: never shown, whole or in part.
            ("http://a@b@h.invalid:1/x", false, "(not shown)"),
            ("http://h.invalid\\@other.invalid", false, "(not shown)"),
            ("http://h.inv\talid", false, "(not shown)"),
            ("https://h%2einvalid", false, "(not shown)"),
            ("https://ex\u{e4}mple.invalid", false, "(not shown)"),
            ("https://h.invalid:", false, "(not shown)"),
            ("https:h.invalid", false, "(not shown)"),
            ("1http://h.invalid", false, "(not shown)"),
            ("file:///etc/../tmp", false, "(not shown)"),
        ] {
            let (text, unusual) = shown_destination(value, list);
            assert_eq!(text, shown, "{value}");
            assert_eq!(unusual, shown.contains(NOT_SHOWN), "{value}");
            assert!(!text.contains("FAKE"), "{value}");
        }
        assert_eq!(shown_paths("/a b"), ("(not shown)".to_string(), true));
    }

    #[test]
    fn resolves_through_path_and_relative_names() {
        let sh = resolve_program("sh", Some("/nonexistent:/usr/bin:/bin"), Path::new("/"))
            .expect("sh exists");
        assert!(sh.canonical.is_absolute());
        assert!(
            resolve_program(
                "definitely-not-a-command-xyz",
                Some("/usr/bin"),
                Path::new("/")
            )
            .is_err()
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("tool.sh");
        std::fs::write(&script, "#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let resolved = resolve_program("./tool.sh", None, dir.path()).expect("relative");
        assert_eq!(
            resolved.canonical,
            std::fs::canonicalize(&script).expect("canonical")
        );

        // A symlink shows both the link and its target.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&script, &link).expect("symlink");
        let via_link = resolve_program("./link", None, dir.path()).expect("link");
        assert!(via_link.describe().contains(" → "));
        // Not executable -> refused.
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(resolve_program("./tool.sh", None, dir.path()).is_err());
    }
}
