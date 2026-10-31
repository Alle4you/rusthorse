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

/// The environment an approved command will receive (before secrets are added).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEnv {
    /// Variables to pass to the command.
    pub vars: Vec<(String, String)>,
    /// Names of variables that were removed (dynamic loader variables).
    pub removed: Vec<String>,
    /// Risky variables that are passed through, with their values.
    pub risky: Vec<(String, String)>,
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
        }
        prepared.vars.push((name.clone(), value.clone()));
    }
    prepared.removed.sort();
    prepared.removed.dedup();
    prepared.risky.sort();
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
