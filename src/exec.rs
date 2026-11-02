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
    // Hosts whose certificates are not checked.
    "PIP_TRUSTED_HOST",
    "UV_INSECURE_HOST",
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
    "UV_INDEX",
    "UV_DEFAULT_INDEX",
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

/// Destination variables whose value is a list, and how each separates its
/// items, as the program that reads it does: `GOPROXY` by `,` or `|`; the
/// indexes and trusted hosts of pip and uv by spaces. Any other value is one
/// item, so that a comma or a space inside a URL — in a password, in a
/// path — never splits it.
pub const LIST_VARS: &[(&str, &[char])] = &[
    ("GOPROXY", &[',', '|']),
    ("PIP_EXTRA_INDEX_URL", &[' ']),
    ("PIP_TRUSTED_HOST", &[' ']),
    ("UV_EXTRA_INDEX_URL", &[' ']),
    ("UV_INDEX", &[' ']),
    ("UV_INSECURE_HOST", &[' ']),
];

/// Variables whose items may be named, `name=URL` (uv's indexes).
pub const NAMED_ITEM_VARS: &[&str] = &["UV_INDEX", "UV_DEFAULT_INDEX"];

/// URL schemes whose authority may be empty because they name a local
/// socket or file (`unix:///run/docker.sock`). For any other scheme an empty
/// authority is not shown: `https:///host/…` reaches `host`.
pub const LOCAL_SCHEMES: &[&str] = &["unix", "file"];

/// Query parameters with which a connection library takes its destination
/// from the query instead of the URL's host — libpq's `host`, `hostaddr`,
/// `port`, `service`; sockets and servers in other drivers. A URL with one
/// of them (or with an encoded parameter name) is not shown: its host is
/// not where the program connects.
pub const REDIRECTING_QUERY_KEYS: &[&str] = &[
    "host",
    "hostaddr",
    "port",
    "service",
    "servicefile",
    "socket",
    "unix_socket",
    "server",
    "addr",
    "address",
    "proxy",
];

/// Shown instead of a destination value, or a part of one, that has no
/// unambiguous form.
pub const NOT_SHOWN: &str = "(not shown)";

/// The value of destination variable `name` as dialogs and the audit log
/// show it, and whether part of it was [`NOT_SHOWN`].
///
/// A list variable ([`LIST_VARS`]) is shown item by item; any other value is
/// one item. Only unambiguous forms are shown: a URL keeps its scheme, host
/// and port and loses its user name, password, path, query and fragment,
/// where credentials and tokens travel (`https://…@proxy:3128/…`; a webhook
/// URL is a secret); `user:password@host` loses its user part; a host name,
/// a canonical IPv4 address, a word (`direct`, `0`), an absolute path
/// (`unix:///run/docker.sock`) are shown as they are. Anything else — a
/// backslash or a control character anywhere, several `@`, a host with
/// characters other than letters, digits, `.`, `-` and `_`, a numeric host
/// that is not `a.b.c.d` (`127.1`, `0x7f.1`), an empty authority outside
/// [`LOCAL_SCHEMES`], a query that names another destination
/// ([`REDIRECTING_QUERY_KEYS`]) — is not shown: programs read such values
/// differently (a URL parser that takes `\` for `/` connects to the host
/// *before* the `@`), so a host drawn from them could be the wrong one, and
/// copying them could disclose a credential.
pub fn shown_destination(name: &str, value: &str) -> (String, bool) {
    if value.chars().any(|c| c == '\\' || c.is_control()) {
        return (NOT_SHOWN.to_string(), true);
    }
    let upper = name.to_ascii_uppercase();
    let separators: &[char] = LIST_VARS
        .iter()
        .find(|(list, _)| *list == upper)
        .map_or(&[], |(_, separators)| separators);
    let named = NAMED_ITEM_VARS.contains(&upper.as_str());
    let mut shown = String::new();
    let mut unusual = false;
    let mut item = String::new();
    let mut flush = |item: &mut String, shown: &mut String| {
        match shown_named_item(item, named) {
            Some(text) => shown.push_str(&text),
            None => {
                shown.push_str(NOT_SHOWN);
                unusual = true;
            }
        }
        item.clear();
    };
    for c in value.chars() {
        if separators.contains(&c) {
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
/// are when made of ordinary characters and spaces (a `..` included: it
/// shows where the path leads), [`NOT_SHOWN`] otherwise.
pub fn shown_paths(value: &str) -> (String, bool) {
    let ordinary = !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" /._-+@~:".contains(&b));
    if ordinary {
        (value.to_string(), false)
    } else {
        (NOT_SHOWN.to_string(), true)
    }
}

/// An item that may start with a name (`local=https://…`, with `named`).
fn shown_named_item(item: &str, named: bool) -> Option<String> {
    if named
        && let Some((label, url)) = item.split_once('=')
        && !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return shown_item(url).map(|url| format!("{label}={url}"));
    }
    shown_item(item)
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
            // A local socket or file: the path is the destination.
            let local = LOCAL_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str());
            return (local && absolute_paths(tail)).then(|| format!("{scheme}://{tail}"));
        }
        if redirecting_query(tail) {
            return None;
        }
        let (user, host) = split_user(authority)?;
        return host_port(host).then(|| format!("{scheme}://{user}{host}{}", more(tail)));
    }
    if item.starts_with('/') {
        return absolute_paths(item).then(|| item.to_string());
    }
    // A lone word — `direct`, `off`, `0`, `1` — is shown as it is: switches
    // such as `GIT_SSL_NO_VERIFY=1` hold words, not hosts.
    if item
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Some(item.to_string());
    }
    let end = item.find('/').unwrap_or(item.len());
    let (authority, tail) = item.split_at(end);
    let (user, host) = split_user(authority)?;
    host_port(host).then(|| format!("{user}{host}{}", more(tail)))
}

/// Whether the query of a URL's `tail` names a destination of its own
/// ([`REDIRECTING_QUERY_KEYS`]), or has a parameter name with `%` that a
/// library would decode first.
fn redirecting_query(tail: &str) -> bool {
    let Some((_, query)) = tail.split_once('?') else {
        return false;
    };
    let query = query.split('#').next().unwrap_or_default();
    query.split(['&', ';']).any(|pair| {
        let key = pair
            .split('=')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        key.contains('%') || REDIRECTING_QUERY_KEYS.contains(&key.as_str())
    })
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

/// A host name, canonical IPv4 address or bracketed IPv6 address, with an
/// optional port of digits: nothing that a URL parser could decode or
/// reinterpret.
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
        && plain_ipv4_if_numeric(host)
        && port.is_none_or(port_ok)
}

/// URL parsers read a host whose last label is a number (`127.1`,
/// `2130706433`, `0x7f.1`, `0177.0.0.1`) as an IPv4 address, each in its
/// own way: only the canonical form `a.b.c.d` (0–255, no leading zeros) is
/// shown as it is.
fn plain_ipv4_if_numeric(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let last = host.rsplit('.').next().unwrap_or_default();
    let numeric = !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_digit())
            || last.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("0x")));
    if !numeric {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            (1..=3).contains(&p.len())
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// Absolute paths separated by `:`, none with `..` or a leading `//` (a
/// network path), made of ordinary characters.
fn absolute_paths(text: &str) -> bool {
    !text.is_empty()
        && text.split(':').all(|path| {
            path.starts_with('/')
                && !path.starts_with("//")
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
    // What the command gets: a later duplicate replaces an earlier one. The
    // dialog is built from this, never from a value that was replaced.
    let mut effective: BTreeMap<&str, &str> = BTreeMap::new();
    for (name, value) in client_env {
        if name.is_empty() || name.contains('=') || secret_vars.contains(&name.as_str()) {
            continue;
        }
        if name.starts_with(LOADER_PREFIX) {
            removed.insert(name.clone());
            continue;
        }
        effective.insert(name, value);
        vars.push((name.clone(), value.clone()));
    }
    let mut prepared = PreparedEnv {
        vars,
        removed: removed.into_iter().collect(),
        risky: Vec::new(),
        endpoints: Vec::new(),
        routes: Vec::new(),
        unusual: Vec::new(),
    };
    for (name, value) in effective {
        let entry = (name.to_string(), value.to_string());
        if is_risky(name) {
            prepared.risky.push(entry);
            continue;
        }
        let list = match destination(name) {
            Some(Destination::Endpoint) => &mut prepared.endpoints,
            Some(Destination::Route) if !system_trust_store(name, value) => &mut prepared.routes,
            _ => continue,
        };
        let (shown, odd) = if TRUST_PATH_VARS.contains(&name.to_ascii_uppercase().as_str()) {
            shown_paths(value)
        } else {
            shown_destination(name, value)
        };
        list.push((name.to_string(), shown));
        if odd {
            prepared.unusual.push(name.to_string());
        }
    }
    prepared
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
                ("SSL_CERT_DIR", "/tmp/old-fake-ca"),
                ("SSL_CERT_DIR", "/usr/lib/ssl/certs:/etc/ssl/certs"),
                ("https_proxy", "http://user:pw@proxy.invalid:3128"),
                ("SSL_CERT_FILE", "/tmp/fake-ca.pem"),
                ("PGHOST", "db.invalid"),
                (
                    "HOOK_URL",
                    "https://hooks.example.invalid/T0/B0/FAKE-secret,FAKE-2",
                ),
                (
                    "DATABASE_URL",
                    "postgres://u:FAKE-pw@db.invalid:5432/app?sslmode=require",
                ),
                // libpq takes the server from the query: the host is not it.
                (
                    "OTHER_DB_URL",
                    "postgresql://FAKE@expected.invalid/db?hostaddr=127.0.0.1&port=9",
                ),
                ("DOCKER_HOST", "unix:///run/docker.sock"),
                ("AWS_ENDPOINT_URL", "https://expected.invalid"),
                ("AWS_ENDPOINT_URL_S3", "https://other.invalid"),
                // Lists, split as the program that reads them does.
                (
                    "GOPROXY",
                    "user:FAKE-pw@private.invalid,https://proxy.golang.org",
                ),
                (
                    "PIP_EXTRA_INDEX_URL",
                    "https://user:FAKE,FAKE2@packages.invalid/simple/ https://b.invalid/simple",
                ),
                (
                    "UV_INDEX",
                    "local=http://127.0.0.1:9/simple https://pypi.invalid/simple",
                ),
                ("PIP_TRUSTED_HOST", "pypi.org files.pythonhosted.org"),
                // Read differently by different parsers: never shown.
                (
                    "OPENAI_API_BASE",
                    "http://127.0.0.1:1\\@provider.invalid/v1",
                ),
                (
                    "HOOK2_URL",
                    "https:/hooks.example.invalid/FAKE-token?key=FAKE",
                ),
                ("HOOK3_URL", "https:///hooks.invalid/FAKE-TOKEN"),
                // A secret's own variable is never shown: it is replaced.
                ("API_URL", "client-supplied"),
                ("HOSTALIASES", "/tmp/hosts"),
                ("CURL_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt"),
                // Not inside a store, whatever the path looks like.
                ("GIT_SSL_CAINFO", "/etc/ssl/../../tmp/fake-ca.pem"),
                ("PIP_CERT", "My Certs/fake-ca.pem"),
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
                ("HOOK3_URL", "(not shown)"),
                ("HOOK_URL", "https://hooks.example.invalid/…"),
                ("OPENAI_API_BASE", "(not shown)"),
                ("OPENAI_BASE_URL", "https://api.example.invalid/…"),
                ("OTHER_DB_URL", "(not shown)"),
                ("PGHOST", "db.invalid"),
                (
                    "PIP_EXTRA_INDEX_URL",
                    "https://…@packages.invalid/… https://b.invalid/…",
                ),
                (
                    "UV_INDEX",
                    "local=http://127.0.0.1:9/… https://pypi.invalid/…"
                ),
            ])
        );
        assert_eq!(
            prepared.routes,
            env(&[
                ("GIT_SSL_CAINFO", "/etc/ssl/../../tmp/fake-ca.pem"),
                ("GOPROXY", "…@private.invalid,https://proxy.golang.org"),
                ("PIP_CERT", "My Certs/fake-ca.pem"),
                ("PIP_TRUSTED_HOST", "pypi.org files.pythonhosted.org"),
                ("REQUESTS_CA_BUNDLE", "/etc/ssl/certs:/tmp/fake-ca"),
                ("SSL_CERT_FILE", "/tmp/fake-ca.pem"),
                ("https_proxy", "http://…@proxy.invalid:3128"),
            ])
        );
        assert_eq!(
            prepared.unusual,
            vec!["HOOK2_URL", "HOOK3_URL", "OPENAI_API_BASE", "OTHER_DB_URL"]
        );
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
            ("PIP_TRUSTED_HOST", Some(Destination::Route)),
            ("node_tls_reject_unauthorized", Some(Destination::Route)),
            ("AZURE_OPENAI_ENDPOINT", Some(Destination::Endpoint)),
            ("OPENAI_API_BASE", Some(Destination::Endpoint)),
            ("DOCKER_HOST", Some(Destination::Endpoint)),
            ("VAULT_ADDR", Some(Destination::Endpoint)),
            ("npm_config_registry", Some(Destination::Endpoint)),
            ("MONGODB_URI", Some(Destination::Endpoint)),
            ("AWS_ENDPOINT_URL_DYNAMODB", Some(Destination::Endpoint)),
            ("UV_INDEX", Some(Destination::Endpoint)),
            ("UV_DEFAULT_INDEX", Some(Destination::Endpoint)),
            ("HOSTNAME", None),
            ("DBUS_SESSION_BUS_ADDRESS", None),
            ("PATH", None),
        ] {
            assert_eq!(destination(name), expected, "{name}");
        }
        // One value, by any other variable name (not a list).
        for (value, shown) in [
            ("https://h.invalid", "https://h.invalid"),
            ("HTTPS://H.invalid.", "HTTPS://H.invalid."),
            ("https://h.invalid/", "https://h.invalid/…"),
            ("https://h.invalid?k=FAKE", "https://h.invalid/…"),
            ("http://[::1]:8080/x", "http://[::1]:8080/…"),
            ("http://10.0.0.1:8080", "http://10.0.0.1:8080"),
            ("db.invalid:5432", "db.invalid:5432"),
            ("u:FAKE@proxy.invalid:3128", "…@proxy.invalid:3128"),
            ("/home/me/ca@2.pem", "/home/me/ca@2.pem"),
            ("file:///etc/app.sock", "file:///etc/app.sock"),
            ("1", "1"),
            ("direct", "direct"),
            (
                "pg://h.invalid/db?sslmode=require&connect_timeout=2",
                "pg://h.invalid/…",
            ),
            // A comma or space inside one URL never splits it.
            ("https://h.invalid/a,FAKE-token", "https://h.invalid/…"),
            ("https://h.invalid/a|FAKE-token", "https://h.invalid/…"),
            ("https://a.invalid FAKE.invalid", "(not shown)"),
            ("u:FAKE@a.invalid,https://b.invalid", "(not shown)"),
            // Ambiguous: never shown, whole or in part.
            ("http://a@b@h.invalid:1/x", "(not shown)"),
            ("http://h.invalid\\@other.invalid", "(not shown)"),
            ("http://h.inv\talid", "(not shown)"),
            ("https://h%2einvalid", "(not shown)"),
            ("https://ex\u{e4}mple.invalid", "(not shown)"),
            ("https://h.invalid:", "(not shown)"),
            ("https:h.invalid", "(not shown)"),
            ("https:///h.invalid/FAKE", "(not shown)"),
            ("//FAKE@h.invalid/path", "(not shown)"),
            ("1http://h.invalid", "(not shown)"),
            ("file:///etc/../tmp", "(not shown)"),
            ("pg://u@a.invalid/db?host=b.invalid", "(not shown)"),
            (
                "pg://u@a.invalid/db?sslmode=x;HOSTADDR=1.2.3.4",
                "(not shown)",
            ),
            ("pg://u@a.invalid/db?h%6Fst=b.invalid", "(not shown)"),
            ("http://0x7f.1:9", "(not shown)"),
            ("http://127.1", "(not shown)"),
            ("2130706433.", "(not shown)"),
            ("127.1:5432", "(not shown)"),
            ("http://0177.0.0.1/", "(not shown)"),
            ("http://010.0.0.1/", "(not shown)"),
            ("http://256.0.0.1/", "(not shown)"),
        ] {
            let (text, unusual) = shown_destination("SOME_URL", value);
            assert_eq!(text, shown, "{value}");
            assert_eq!(unusual, shown.contains(NOT_SHOWN), "{value}");
            assert!(!text.contains("FAKE"), "{value}");
        }
        // Lists, item by item with their own separators.
        for (name, value, shown) in [
            (
                "GOPROXY",
                "https://h.invalid|direct",
                "https://h.invalid|direct",
            ),
            (
                "GOPROXY",
                "ok.invalid,https:/x.invalid/FAKE",
                "ok.invalid,(not shown)",
            ),
            (
                "PIP_EXTRA_INDEX_URL",
                "https://a.invalid https://b.invalid",
                "https://a.invalid https://b.invalid",
            ),
            (
                "UV_INDEX",
                "b@d=https://a.invalid name=https://a.invalid",
                "(not shown) name=https://a.invalid",
            ),
        ] {
            let (text, _) = shown_destination(name, value);
            assert_eq!(text, shown, "{name}={value}");
        }
        assert_eq!(shown_paths("/a\u{1}b"), ("(not shown)".to_string(), true));
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
