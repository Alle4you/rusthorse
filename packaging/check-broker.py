#!/usr/bin/env python3
"""Refuse to package a credential broker that is not a release build.

Usage: packaging/check-broker.py PROGRAM VERSION

Runs `PROGRAM --check` the way `rusthorse doctor` does (an empty
environment, `/` as working directory, nothing on standard input, at most
five seconds) and accepts only what a release build of rusthorse-broker
VERSION answers: one JSON object with exactly `version`, equal to VERSION,
and `protocol`, a number. A build with the broker's `test-upstream` feature
adds `"test_upstream": true` to that answer: such a build trusts extra
certificate authorities and addresses named in its environment and may
reach loopback destinations, so it must never be installed. It is refused,
and so is any other field, another version, an answer that does not parse,
and a program that fails or does not exit in time. Exits with status 1,
saying why, when the program is refused.
"""

import json
import os
import subprocess
import sys

TIMEOUT_SECONDS = 5


def refuse(program, why):
    sys.exit(f"check-broker.py: {program} {why}: refusing to package it; build it with "
             f"packaging/build-deb.sh, which builds every program without features")


def unique_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("a field appears twice")
    return dict(pairs)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    program, version = sys.argv[1], sys.argv[2]
    try:
        # Resolved here: the program runs in `/`.
        done = subprocess.run([os.path.abspath(program), "--check"], env={}, cwd="/",
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        refuse(program, f"did not answer --check within {TIMEOUT_SECONDS} seconds")
    except OSError as e:
        refuse(program, f"cannot be run ({e.strerror})")
    if done.returncode != 0:
        refuse(program, f"failed its --check (exit status {done.returncode})")
    try:
        answer = json.loads(done.stdout.decode("utf-8"), object_pairs_hook=unique_keys)
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        refuse(program, "gave an answer to --check that does not parse as one JSON object "
               "with each field once")
    if "test_upstream" in answer:
        refuse(program, "is a build for tests (its --check reports test_upstream)")
    if sorted(answer) != ["protocol", "version"]:
        refuse(program, "answered --check with the fields " + ", ".join(sorted(answer))
               + " instead of version and protocol")
    if answer["version"] != version:
        refuse(program, f"reports version {answer['version']!r}, not {version!r}")
    if type(answer["protocol"]) is not int or answer["protocol"] < 0:
        refuse(program, "reports a protocol that is not a number")


if __name__ == "__main__":
    main()
