//! Default file locations, following the XDG Base Directory specification.
//!
//! | What        | Default                                   | Override              |
//! |-------------|-------------------------------------------|-----------------------|
//! | Vault       | `$XDG_DATA_HOME/rusthorse/vault.kdbx`     | `RUSTHORSE_VAULT`     |
//! | Socket      | `$XDG_RUNTIME_DIR/rusthorse/agent.sock`   | `RUSTHORSE_SOCKET`    |
//! | Audit log   | `$XDG_STATE_HOME/rusthorse/audit.jsonl`   | `RUSTHORSE_AUDIT_LOG` |

use std::path::PathBuf;

use nix::unistd::getuid;

/// Environment variable that overrides the vault file location.
pub const ENV_VAULT: &str = "RUSTHORSE_VAULT";
/// Environment variable that overrides the agent socket location.
pub const ENV_SOCKET: &str = "RUSTHORSE_SOCKET";
/// Environment variable that overrides the audit log location.
pub const ENV_AUDIT_LOG: &str = "RUSTHORSE_AUDIT_LOG";

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// An XDG base directory: the variable if it holds an absolute path, else `~/<fallback>`.
fn xdg_dir(var: &str, fallback: &str) -> PathBuf {
    match std::env::var_os(var).map(PathBuf::from) {
        Some(path) if path.is_absolute() => path,
        _ => home().join(fallback),
    }
}

fn from_env(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        Some(path) if path.is_absolute() => path,
        _ => PathBuf::from(format!("/run/user/{}", getuid())),
    }
}

/// The vault file: `$RUSTHORSE_VAULT`, or `$XDG_DATA_HOME/rusthorse/vault.kdbx`.
pub fn vault() -> PathBuf {
    from_env(ENV_VAULT).unwrap_or_else(|| {
        xdg_dir("XDG_DATA_HOME", ".local/share")
            .join("rusthorse")
            .join("vault.kdbx")
    })
}

/// The agent socket: `$RUSTHORSE_SOCKET`, or `$XDG_RUNTIME_DIR/rusthorse/agent.sock`.
pub fn socket() -> PathBuf {
    from_env(ENV_SOCKET).unwrap_or_else(|| runtime_dir().join("rusthorse").join("agent.sock"))
}

/// The audit log: `$RUSTHORSE_AUDIT_LOG`, or `$XDG_STATE_HOME/rusthorse/audit.jsonl`.
pub fn audit_log() -> PathBuf {
    from_env(ENV_AUDIT_LOG).unwrap_or_else(|| {
        xdg_dir("XDG_STATE_HOME", ".local/state")
            .join("rusthorse")
            .join("audit.jsonl")
    })
}
