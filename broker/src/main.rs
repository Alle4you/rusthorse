//! `rusthorse-broker`: serves one grant of the Rusthorse agent's credential
//! broker ([ADR 0013](../../docs/adr/0013-credential-broker.md)).
//!
//! The agent starts one broker per grant, after the human approved it, with
//! no arguments, an empty environment, `/` as working directory, in its own
//! process group, with standard input and output one end of a socket pair
//! (the control channel) and standard error `/dev/null`. The broker makes
//! itself non-dumpable and disables core files before it reads anything,
//! reads the agent's `install` (the grant's ID, token, credential, profile
//! and limits) with the listening socket the agent bound, checks all of it,
//! opens the system's file of certificate authorities, and answers `ready`
//! — or exits with a non-zero status without answering. It then serves the
//! grant on that socket: HTTP/1.1 requests that present the token, for the
//! routes of the profile's preset, are forwarded over TLS to the profile's
//! destination with the credential added, once the agent has admitted each
//! one ([`rusthorse::broker_protocol`]). It exits as soon as the control
//! channel ends, without waiting for work in progress.
//!
//! The modules, in the order a request meets them: [`setup`] (before
//! `ready`), [`server`] (connections and steps 1 to 5), [`framing`] (step
//! 1), [`grant`] (the conversation with the agent and the body budget),
//! [`exchange`] (steps 6 to 8), [`destination`] (resolving and connecting),
//! [`headers`] (what crosses, each way), [`answer`] (local answers and
//! response bodies) and [`control`] (the control channel once ready);
//! [`config`] holds the deadlines and the hooks of the `test-upstream`
//! feature, which is for tests only and never in a release: a build
//! without debug assertions refuses it, `--check` reports it, and a build
//! with it runs as a release one unless its environment names a test
//! authority (`RUSTHORSE_BROKER_TEST_ROOTS`), which the agent's empty
//! environment never does.
//!
//! The grant ends in the broker too when its lifetime passes, on the
//! boot-time clock, even if the agent's `revoke` never comes ([`grant`]).
//!
//! `rusthorse-broker --check` prints its version and the control channel's
//! protocol version as JSON, for `rusthorse doctor`, and exits. A build with
//! the test feature adds `"test_upstream":true`, so that it cannot pass for
//! a release.
//!
//! Exit statuses: [`EXIT_CHANNEL_ENDED`] (0) when the agent closed the
//! control channel; [`EXIT_SETUP`] when the grant could not be served
//! (nothing was answered); [`EXIT_USAGE`] for arguments other than
//! `--check`; [`EXIT_VIOLATION`] when the agent broke the conversation;
//! [`EXIT_CHANNEL_FAILED`] when the control channel failed;
//! [`EXIT_PANIC`] on an internal error. Nothing but frames of the control
//! channel (or the answer to `--check`) is ever written to standard output.

use std::process::ExitCode;

// The test feature trusts what its environment says: a build of it must
// never pass for a release.
#[cfg(all(feature = "test-upstream", not(debug_assertions)))]
compile_error!(
    "the test-upstream feature is for tests only: a build without debug assertions, as a release is, refuses it"
);

mod answer;
mod config;
mod control;
mod destination;
mod exchange;
mod framing;
mod grant;
mod headers;
mod server;
mod setup;

/// The control channel ended: the agent is done with the grant.
pub const EXIT_CHANNEL_ENDED: u8 = 0;
/// The grant could not be served: a bad or missing install, listening
/// socket, file of certificate authorities or TLS configuration. Nothing
/// was answered.
pub const EXIT_SETUP: u8 = 1;
/// Arguments other than `--check`.
pub const EXIT_USAGE: u8 = 2;
/// The agent sent what it may not send: a second install, an answer for a
/// request that is not waiting, a second revoke, a frame that is too large
/// or does not decode.
pub const EXIT_VIOLATION: u8 = 3;
/// Reading or writing the control channel failed.
pub const EXIT_CHANNEL_FAILED: u8 = 4;
/// An internal error (a panic): the broker stops at once rather than serve
/// in a state nobody checked.
pub const EXIT_PANIC: u8 = 5;

/// Most threads resolving names at once: the only blocking work the broker
/// does once it serves (`destination::Resolver` keeps the same limit).
const MAX_BLOCKING_THREADS: usize = rusthorse::broker_protocol::MAX_CONCURRENT_RESOLUTIONS;

/// The stack of each of those threads: std's own default for the threads it
/// starts. Given explicitly, so that std does not read `RUST_MIN_STACK`
/// from the environment to choose it.
const BLOCKING_THREAD_STACK_BYTES: usize = 2 * 1024 * 1024;

fn main() -> ExitCode {
    // A panic anywhere ends the process at once, with nothing printed: the
    // default hook would read RUST_BACKTRACE from the environment and could
    // leave a task's state half changed while the others go on.
    std::panic::set_hook(Box::new(|_| {
        std::process::exit(i32::from(EXIT_PANIC));
    }));
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => serve(),
        [check] if check == "--check" => {
            // Version and protocol, for `rusthorse doctor`; serves nothing.
            println!("{}", check_answer());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("rusthorse-broker is started by the Rusthorse agent; it takes no arguments");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// The answer to `--check`: `{"version":"…","protocol":N}`, with
/// `"test_upstream":true` in a build with the test feature (and nothing
/// more in one without it).
fn check_answer() -> String {
    let test_upstream = if cfg!(feature = "test-upstream") {
        r#","test_upstream":true"#
    } else {
        ""
    };
    format!(
        r#"{{"version":"{}","protocol":{}{test_upstream}}}"#,
        env!("CARGO_PKG_VERSION"),
        rusthorse::broker_protocol::VERSION
    )
}

/// Serve one grant, and exit when the control channel ends. Never returns:
/// the process exits without waiting for anything, a name resolution that
/// hangs on a thread of its own included (dropping the runtime would wait
/// for it).
fn serve() -> ! {
    if rusthorse::agent::harden_process().is_err() {
        std::process::exit(i32::from(EXIT_SETUP));
    }
    let code = run();
    std::process::exit(i32::from(code))
}

fn run() -> u8 {
    // Why the grant cannot be served goes to standard error (`/dev/null`
    // under the agent): fixed text and paths, never a value.
    let config = match config::Config::load() {
        Ok(config) => config,
        Err(why) => {
            eprintln!("rusthorse-broker: {why}");
            return EXIT_SETUP;
        }
    };
    let prepared = match setup::prepare(&config) {
        Ok(prepared) => prepared,
        Err(why) => {
            eprintln!("rusthorse-broker: {why}");
            return EXIT_SETUP;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .thread_stack_size(BLOCKING_THREAD_STACK_BYTES)
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return EXIT_SETUP,
    };
    let code = runtime.block_on(server::run(prepared, config));
    // Not dropped: that would wait for the threads of name resolutions.
    std::mem::forget(runtime);
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_check_answer_is_the_contract_of_check_program() {
        let answer: serde_json::Value = serde_json::from_str(&check_answer()).expect("JSON");
        let mut expected = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": rusthorse::broker_protocol::VERSION,
        });
        // A build for tests says so; a release adds nothing.
        if cfg!(feature = "test-upstream") {
            expected["test_upstream"] = serde_json::Value::Bool(true);
        }
        assert_eq!(answer, expected);
    }
}
