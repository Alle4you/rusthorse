# 0005. Remembered approvals are opt-in and bound to the vault generation

- Status: Accepted
- Date: 2026-10-31

## Context

An AI agent often runs the same command many times in a row (a test suite
that calls an API, a deploy script during debugging). Asking every time is
tedious, so the first design offered "Allow for 10m" in every `run` dialog,
remembering the approval for identical requests.

The adversarial review of 2026-10-31 showed that "identical request" is a
weaker notion than it looks. The approval key covered the command line,
program, directory, secrets and risky variables, but a command's behaviour
also depends on things the key cannot capture:

- its standard input (`curl --config -` takes its destination from stdin);
- files it reads (scripts, `~/.curlrc`, `.gitconfig`), which the requester may
  edit between runs;
- environment variables not on the risky list (`CURL_HOME`);
- the state of the vault (an entry edited or replaced since).

A remembered approval is therefore a *reusable capability*, not a human
decision per use.

## Decision

- Remembering is **off by default** (`rusthorse agent --remember 0`). Users
  who want it enable it explicitly with a duration.
- When enabled, the key binds the vault *generation* (bumped on every unlock,
  lock and saved change), the entries by UUID, the exact command line, the
  canonical program path, the directory, the redaction setting and the
  **complete** environment (except `_` and `OLDPWD`, which change on every
  invocation without affecting the program).
- The dialog explains, next to the button, that it lets identical requests
  run without asking even if they read different input or files.
- `reveal`, `add --stdin`, `import`, `edit` and `remove` are never remembered,
  and requests whose details are too long to show in full are refused.

## Alternatives considered

- **Keep remembering on by default with a richer key.** Still a capability
  that the human did not see used; the convenience did not justify making it
  the default.
- **Remove the feature.** Makes repetitive agent workflows painful enough
  that users would work around Rusthorse (for example by exporting secrets),
  which is worse.
- **Bind the key to stdin or file contents.** Impossible in general (stdin is
  a stream; the set of files a program reads is unknown in advance).

## Consequences

- The default is one dialog per use; users opt in to fewer dialogs with a
  clear statement of what they give up (threat model L8).
- Any change to the vault — even to an unrelated entry — invalidates every
  remembered approval, which is occasionally inconvenient but simple to
  reason about.
- The typed operations planned for the HTTP broker and SSH agent (destination
  and method bound to the approval) are the long-term answer to repetitive
  use without blank cheques.
