//! Rusthorse: a local secrets vault with an approval-gated agent.
//!
//! Secrets live in a KeePass KDBX4 file. A long-running **agent** holds the
//! unlocked vault and is the only component that ever handles secret values.
//! Clients (the `rusthorse` CLI, AI coding agents, scripts) talk to the agent
//! over a Unix socket and can *use* a secret — for example by asking the agent
//! to run a command with the secret in its environment — only after the human
//! approves the exact request in a graphical dialog.
//!
//! The big picture is in `docs/architecture.md`, the security reasoning in
//! `docs/threat-model.md` and the wire format in `docs/protocol.md`.
//!
//! Module map:
//!
//! - [`vault`]: reading and writing the KDBX4 file.
//! - [`agent`]: the server side; policy, approvals, spawning approved commands.
//! - [`client`]: the client side of the socket protocol.
//! - [`protocol`]: request/response types and framing (including fd passing).
//! - [`ui`]: approval and password dialogs (zenity).
//! - [`dialog_program`]: showing dialogs with `rusthorse-dialog`, or zenity.
//! - [`dialog_protocol`]: the protocol between the agent and `rusthorse-dialog`.
//! - [`helper_program`]: finding and checking the helper programs the agent
//!   starts (`rusthorse-dialog`, `rusthorse-broker`) next to its executable.
//! - [`broker_profile`]: the credential broker's profiles and presets, and the
//!   rules a grant enforces (routes, headers, tokens), shared with
//!   `rusthorse-broker`.
//! - [`broker_protocol`]: the control channel between the agent and
//!   `rusthorse-broker`, tokens and grant IDs, the broker's limits and the
//!   file of certificate authorities it trusts.
//! - `broker_host`: the agent's side of the credential broker: the registry
//!   of grants, starting and supervising one broker per grant, admission,
//!   revocation and expiry.
//! - [`exec`]: program resolution and environment preparation for `run`.
//! - [`redact`]: streaming removal of secret values from command output.
//! - [`session_lock`]: locking when the screen locks or the computer suspends.
//! - `supervise`: deadlines and process groups for the helper processes of dialogs.
//! - [`peer`]: identifying the process on the other end of the socket.
//! - [`audit`]: the append-only audit log.
//! - [`generate`]: generating random secret values.
//! - [`import`]: parsing `.env` files for imports.
//! - [`keyring`]: the items of GNOME Keyring (any Secret Service), for imports
//!   the agent reads itself.
//! - [`paths`]: default file locations.
//! - [`util`]: small shared helpers.

pub mod agent;
pub mod audit;
mod broker_host;
pub mod broker_profile;
pub mod broker_protocol;
pub mod client;
pub mod dialog_program;
pub mod dialog_protocol;
pub mod exec;
pub mod generate;
pub mod helper_program;
pub mod import;
pub mod keyring;
pub mod paths;
pub mod peer;
pub mod protocol;
pub mod redact;
pub mod session_lock;
mod supervise;
pub mod ui;
pub mod util;
pub mod vault;
