#!/usr/bin/env python3
"""Refuse to package a credential broker that is not a release build.

Usage: packaging/check-broker.py PROGRAM VERSION
       packaging/check-broker.py --packages VERSION DIRECTORY < PATHS

Runs `PROGRAM --check` the way `rusthorse doctor` does (an empty
environment, `/` as working directory, nothing on standard input, at most
five seconds) and accepts only what a release build of rusthorse-broker
VERSION answers: one JSON object with exactly `version`, equal to VERSION,
and `protocol`, a number. A build with the broker's `test-upstream` feature
adds `"test_upstream": true` to that answer: such a build trusts extra
certificate authorities and addresses named in its environment and may
reach loopback destinations, so it must never be installed. It is refused,
and so is any other field, another version, an answer that does not parse,
and a program that fails or does not exit in time.

With --packages it checks what ships: the packages named on standard input,
one path per line, as cargo-deb prints those it wrote. Each is unpacked with
`dpkg-deb -x` into a temporary directory inside DIRECTORY (which must allow
running programs), and every entry named rusthorse-broker in it must be a
regular file that passes the check above; the packages must hold at least
one. If one is refused, cannot be unpacked or is not there, if no package is
named, or if anything else stops the check, every package named is deleted,
whatever its name (cargo-deb's --output can give it any): each path named
that is a regular file and either begins as a Debian package does, in the
format cargo-deb writes, or is called *.deb or *.ddeb, in any case. One that
begins as a package is emptied first, so that no other hard link to it
keeps the package. Nothing else is deleted, and a symbolic link is not
followed: cargo-deb wrote the package where it leads. The message names
such a link, and any path that may hold a package but could not be read or
deleted, to be deleted by hand.

Exits with status 1, saying why, when a program or a package is refused.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile

TIMEOUT_SECONDS = 5
BROKER = "rusthorse-broker"
# How a Debian package begins in the format cargo-deb writes, dpkg-deb's
# default: an ar archive whose first member is debian-binary. dpkg installs
# packages through dpkg-deb, which reads no other format but its old one,
# 0.939000; cargo-deb never writes that one, and a file in it is deleted only
# when called by a package's name.
PACKAGE_START = b"!<arch>\ndebian-binary"
PACKAGE_NAMES = (".deb", ".ddeb")


class Refused(Exception):
    """A program or a package that must not be packaged, and why."""


def unique_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("a field appears twice")
    return dict(pairs)


def check(program, version, shown):
    """Refuse `program` unless it answers --check as a release build of
    rusthorse-broker `version` does; `shown` names it in the refusal."""
    try:
        # Resolved here: the program runs in `/`.
        done = subprocess.run([os.path.abspath(program), "--check"], env={}, cwd="/",
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise Refused(f"{shown} did not answer --check within {TIMEOUT_SECONDS} seconds")
    except OSError as e:
        raise Refused(f"{shown} cannot be run ({e.strerror})")
    if done.returncode != 0:
        raise Refused(f"{shown} failed its --check (exit status {done.returncode})")
    try:
        answer = json.loads(done.stdout.decode("utf-8"), object_pairs_hook=unique_keys)
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        raise Refused(f"{shown} gave an answer to --check that does not parse as one JSON "
                      "object with each field once")
    if "test_upstream" in answer:
        raise Refused(f"{shown} is a build for tests (its --check reports test_upstream)")
    if sorted(answer) != ["protocol", "version"]:
        raise Refused(f"{shown} answered --check with the fields " + ", ".join(sorted(answer))
                      + " instead of version and protocol")
    if answer["version"] != version:
        raise Refused(f"{shown} reports version {answer['version']!r}, not {version!r}")
    if type(answer["protocol"]) is not int or answer["protocol"] < 0:
        raise Refused(f"{shown} reports a protocol that is not a number")


def unreadable(error):
    """A directory of a package that cannot be searched for brokers."""
    raise Refused(f"{error.filename} cannot be read in the unpacked package ({error.strerror})")


def check_packages(packages, version, directory):
    """Refuse the packages unless each unpacks and every rusthorse-broker in
    them, at least one in all, is a regular file that passes `check`."""
    if not packages:
        raise Refused("cargo-deb named no package it wrote")
    brokers = 0
    for package in packages:
        if not os.path.isfile(package):
            raise Refused(f"{package}, which cargo-deb named, is not a file (does cargo-deb "
                          f"print something else than the paths of its packages now?)")
        with tempfile.TemporaryDirectory(prefix="check-broker-", dir=directory) as unpacked:
            done = subprocess.run(["dpkg-deb", "-x", package, unpacked],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            if done.returncode != 0:
                raise Refused(f"{package} cannot be unpacked (dpkg-deb -x: exit status "
                              f"{done.returncode})")
            for path, dirnames, filenames in os.walk(unpacked, onerror=unreadable):
                dirnames.sort()
                for name in sorted(dirnames + filenames):
                    if name != BROKER:
                        continue
                    found = os.path.join(path, name)
                    shown = f"{os.path.relpath(found, unpacked)} in {package}"
                    if not stat.S_ISREG(os.lstat(found).st_mode):
                        raise Refused(f"{shown} is not a regular file")
                    check(found, version, shown)
                    brokers += 1
    if brokers == 0:
        raise Refused(f"no {BROKER} in {', '.join(packages)}")


def open_no_follow(path, flags):
    """os.open, failing on a symbolic link; also an opener for `open`."""
    return os.open(path, flags | os.O_NOFOLLOW)


def delete_package(path):
    """Delete `path` if it is a package, as the module's documentation says.
    Return True if it was deleted, None if it is not a package, or why it is
    left although it may hold one."""
    try:
        mode = os.lstat(path).st_mode
    except (FileNotFoundError, NotADirectoryError):
        return None
    if stat.S_ISLNK(mode):
        return "a symbolic link, not followed: delete by hand the package it leads to"
    if not stat.S_ISREG(mode):
        return None
    named = path.lower().endswith(PACKAGE_NAMES)
    try:
        with open(path, "rb", opener=open_no_follow) as file:
            begins = file.read(len(PACKAGE_START)) == PACKAGE_START
    except OSError:
        if not named:
            raise
        begins = False
    if begins:
        # Emptied first, so that no other hard link to it keeps the package.
        os.close(open_no_follow(path, os.O_WRONLY | os.O_TRUNC))
    elif not named:
        return None
    os.remove(path)
    return True


def delete_packages(packages):
    """Delete the packages among `packages`; say which, and which are left
    that may hold one, and why."""
    deleted, left = [], []
    for package in packages:
        try:
            done = delete_package(package)
        except OSError as e:
            done = f"{e.strerror}: delete it by hand"
        if done is True:
            deleted.append(package)
        elif done:
            left.append(f"{package} ({done})")
    said = f"deleted {', '.join(deleted) or 'nothing'}"
    if left:
        said += f"; not deleted: {', '.join(left)}"
    return said


def main_packages(version, directory):
    lines = sys.stdin.buffer.read().split(b"\n")
    packages = [os.fsdecode(line) for line in lines if line]
    try:
        check_packages(packages, version, directory)
    except BaseException as e:
        # Whatever stopped the check, nothing unchecked is left to install.
        deletion = delete_packages(packages)
        if not isinstance(e, Refused):
            print(f"check-broker.py: the packages could not all be checked; {deletion}",
                  file=sys.stderr)
            raise
        sys.exit(f"check-broker.py: {e}: refusing to package it; {deletion}. A package must "
                 f"hold the release build of the broker that packaging/build-deb.sh built "
                 f"and checked: run the script without options that make cargo-deb take "
                 f"the programs from elsewhere, and install no package it did not finish")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--packages":
        main_packages(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) != 3 or sys.argv[1].startswith("--"):
        sys.exit(__doc__)
    program, version = sys.argv[1], sys.argv[2]
    try:
        check(program, version, program)
    except Refused as e:
        sys.exit(f"check-broker.py: {e}: refusing to package it; build it with "
                 f"packaging/build-deb.sh, which builds every program without features")


if __name__ == "__main__":
    main()
