# 0002. The agent, not the client, runs approved commands

- Status: Accepted
- Date: 2026-10-31

## Context

`rusthorse run SECRET -- COMMAND` must give `COMMAND` a secret in its
environment after the human approves. The caller may be an AI agent that can
run arbitrary programs as the same user, including its own client that speaks
the socket protocol directly.

The obvious design — the agent returns the secret to the CLI after approval,
and the CLI `exec`s the command — has two flaws:

1. **The dialog would show a claim, not a fact.** A custom client can describe
   one command in the request and run another with the returned secret.
2. **The secret would live in a process the caller controls.** The CLI is a
   child of the caller's shell, so the caller can attach a debugger to it
   (Yama `ptrace_scope=1` allows inspecting descendants).

## Decision

The agent executes approved commands itself:

- The client sends `argv`, `cwd`, its environment and its stdin, stdout and
  stderr as file descriptors (`SCM_RIGHTS`).
- The agent resolves `argv[0]` to a canonical absolute path, removes `LD_*`
  variables, flags variables that can inject code, shows all of it in the
  approval dialog, and only then reads the secret values.
- The agent spawns the command as its own child, in a new process group, with
  the client's stdin and with stdout/stderr going through pipes that it
  filters for secret values before writing to the client's descriptors.
- The client only receives the exit status. If it disconnects, the agent
  terminates the command.

## Alternatives considered

- **Return the secret to the client** (as above): rejected for the two flaws
  described.
- **Return the secret only to the official CLI**, identified by its
  executable path: unenforceable — the caller can run the official binary
  under a debugger, or substitute its own.
- **A setuid helper or a separate user for the agent:** would add real
  isolation from same-user processes but requires root to install, which the
  project avoids for now (see the roadmap in the threat model).

## Consequences

- What the human approves is what runs: program path, arguments, directory,
  secrets and risky variables are decided before the dialog, and the
  approval-cache key covers all of them.
- The approved command is not a descendant of the caller, and redaction
  cannot be bypassed by a modified client.
- Commands run in the agent's systemd service, not in the caller's session:
  they have no controlling terminal (job control and some interactive
  programs behave differently), their stdout/stderr are pipes when redaction
  is on, and they are in the service's cgroup (stopping the agent stops them).
- The environment of a *running* approved command is still readable by other
  processes of the same user through `/proc/<pid>/environ`; this is a
  property of environment variables and is listed in the threat model.
