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
const TRUST_PATH_VARS: &[&str] = &[
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
/// [`SYSTEM_TRUST_STORES`] entry. Judged on the text only — an absolute path
/// without `..` — so that nothing can be swapped after the check; a symlink
/// elsewhere that points into a store does not count.
fn system_trust_store(name: &str, value: &str) -> bool {
    let path = Path::new(value);
    TRUST_PATH_VARS.contains(&name.to_ascii_uppercase().as_str())
        && path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        && SYSTEM_TRUST_STORES
            .iter()
            .any(|store| path.starts_with(store))
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
    } else if listed(ENDPOINT_VARS, ENDPOINT_SUFFIXES) {
        Some(Destination::Endpoint)
    } else {
        None
    }
}

/// A destination variable's value as dialogs and the audit log show it: a
/// URL keeps its scheme, host and port, and loses its user name, password,
/// path, query and fragment (`https://…@proxy:3128/…`), where credentials and
/// tokens travel (a webhook URL is a secret); `user:password@host:port`
/// without a scheme loses its user part; anything else is shown as it is.
pub fn shown_destination(value: &str) -> String {
    let Some((scheme, rest)) = value.split_once("://") else {
        return match value.rsplit_once('@') {
            Some((user, host)) if !user.contains('/') => format!("…@{host}"),
            _ => value.to_string(),
        };
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = match authority.rsplit_once('@') {
        Some((_, host)) => format!("…@{host}"),
        None => authority.to_string(),
    };
    let more = if tail.is_empty() { "" } else { "/…" };
    format!("{scheme}://{host}{more}")
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
}

/// Whether `name` belongs to [`RISKY_VARS`] or [`RISKY_PREFIXES`].
pub fn is_risky(name: &str) -> bool {
    RISKY_VARS.contains(&name) || RISKY_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Remove loader variables and the variables that secrets will override, and
/// collect the risky ones for the approval dialog.
pub fn prepare_env(client_env: &[(String, String)], secret_vars: &[&str]) -> PreparedEnv {
    let mut prepared = PreparedEnv {
        vars: Vec::new(),
        removed: Vec::new(),
        risky: Vec::new(),
        endpoints: Vec::new(),
        routes: Vec::new(),
    };
    for (name, value) in client_env {
        if name.is_empty() || name.contains('=') || secret_vars.contains(&name.as_str()) {
            continue;
        }
        if name.starts_with(LOADER_PREFIX) {
            prepared.removed.push(name.clone());
            continue;
        }
        if is_risky(name) {
            prepared.risky.push((name.clone(), value.clone()));
        } else {
            match destination(name) {
                Some(Destination::Endpoint) => prepared
                    .endpoints
                    .push((name.clone(), shown_destination(value))),
                Some(Destination::Route) if !system_trust_store(name, value) => prepared
                    .routes
                    .push((name.clone(), shown_destination(value))),
                Some(Destination::Route) => {}
                None => {}
            }
        }
        prepared.vars.push((name.clone(), value.clone()));
    }
    prepared.removed.sort();
    prepared.removed.dedup();
    prepared.risky.sort();
    prepared.endpoints.sort();
    prepared.routes.sort();
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
                ("OPENAI_BASE_URL", "https://api.example.invalid/v1"),
                ("https_proxy", "http://user:pw@proxy.invalid:3128"),
                ("SSL_CERT_FILE", "/tmp/fake-ca.pem"),
                ("PGHOST", "db.invalid"),
                (
                    "HOOK_URL",
                    "https://hooks.example.invalid/T0/B0/FAKE-secret",
                ),
                (
                    "DATABASE_URL",
                    "postgres://u:FAKE-pw@db.invalid:5432/app?ssl=1",
                ),
                // A secret's own variable is never shown: it is replaced.
                ("API_URL", "client-supplied"),
                ("HOSTALIASES", "/tmp/hosts"),
                // The system's own certificate authorities: nothing to warn of.
                ("SSL_CERT_DIR", "/usr/lib/ssl/certs"),
                ("CURL_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt"),
                // Not inside a store, whatever the path looks like.
                ("GIT_SSL_CAINFO", "/etc/ssl/../../tmp/fake-ca.pem"),
                ("PIP_CERT", "etc/ssl/fake-ca.pem"),
                ("NO_PROXY", "localhost"),
            ]),
            &["API_URL"],
        );
        assert_eq!(
            prepared.endpoints,
            env(&[
                ("DATABASE_URL", "postgres://…@db.invalid:5432/…"),
                ("HOOK_URL", "https://hooks.example.invalid/…"),
                ("OPENAI_BASE_URL", "https://api.example.invalid/…"),
                ("PGHOST", "db.invalid"),
            ])
        );
        assert_eq!(
            prepared.routes,
            env(&[
                ("GIT_SSL_CAINFO", "/etc/ssl/../../tmp/fake-ca.pem"),
                ("PIP_CERT", "etc/ssl/fake-ca.pem"),
                ("SSL_CERT_FILE", "/tmp/fake-ca.pem"),
                ("https_proxy", "http://…@proxy.invalid:3128"),
            ])
        );
        // Already a risky variable: warned about once, as such.
        assert_eq!(prepared.risky, env(&[("HOSTALIASES", "/tmp/hosts")]));
        // Passed through unchanged: only the dialog's copy is shortened.
        assert!(prepared.vars.contains(&(
            "HOOK_URL".into(),
            "https://hooks.example.invalid/T0/B0/FAKE-secret".into()
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
            ("HOSTNAME", None),
            ("DBUS_SESSION_BUS_ADDRESS", None),
            ("PATH", None),
        ] {
            assert_eq!(destination(name), expected, "{name}");
        }
        for (value, shown) in [
            ("https://h.invalid", "https://h.invalid"),
            ("https://h.invalid/", "https://h.invalid/…"),
            ("https://h.invalid?k=FAKE", "https://h.invalid/…"),
            ("http://a@b@h.invalid:1/x", "http://…@h.invalid:1/…"),
            ("db.invalid:5432", "db.invalid:5432"),
            ("u:FAKE@proxy.invalid:3128", "…@proxy.invalid:3128"),
            ("/home/me/ca@2.pem", "/home/me/ca@2.pem"),
            ("1", "1"),
        ] {
            assert_eq!(shown_destination(value), shown, "{value}");
        }
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
