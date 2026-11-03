#!/usr/bin/env python3
"""Refuse to package a credential broker that is not a release build.

Usage: packaging/check-broker.py PROGRAM VERSION
       packaging/check-broker.py --staged VERSION DIRECTORY STAGING DEST

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

With --staged it checks what ships before it ships. STAGING is the new
directory, of packaging/build-deb.sh's own, that cargo-deb wrote its
packages into; DEST is the directory they are meant for. Every entry of
STAGING must be a regular file, and there must be at least one: anything
else (a symbolic link, a FIFO, a directory) is refused without being opened
or followed. Each is unpacked with `dpkg-deb -x` into a temporary directory
inside DIRECTORY (which must allow running programs), and every entry named
rusthorse-broker in it must be a regular file that passes the check above;
the packages must hold at least one. STAGING is listed, never taken from
what cargo-deb prints, so that a name is handled whole whatever characters
it holds.

Only when every package passes are they moved into DEST (created if
missing), each under the name cargo-deb gave it: renamed when STAGING and
DEST are on the same file system, otherwise copied into a new file created
in DEST, flushed to disk and renamed. A rename replaces a file that has
that name in DEST, a symbolic link or a hard link included, as a directory
entry: it is neither followed nor written through (a directory there makes
the move fail). STAGING is then removed and the paths in DEST are printed,
one per line.

If a package is refused, or anything else stops the check or the moves,
STAGING is removed whole (shutil.rmtree, which removes symbolic links
without following them), so that no package that was not checked and
accepted reaches DEST. Nothing else is removed but what a package that
passed replaces at its name in DEST, and the new file of a copy that fails.
A move that fails leaves in DEST the packages moved before it, which were
checked and accepted; the message names them. (A run killed outright while
it copies leaves that new file there, hidden, named .check-broker-*.tmp:
part of a package that passed.)

STAGING must be what packaging/build-deb.sh makes it: a new directory that
only its user can enter, written by cargo-deb alone, which has exited.

Exits with status 1, saying why, when a program or a package is refused.
"""

import errno
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

TIMEOUT_SECONDS = 5
BROKER = "rusthorse-broker"
# What an entry of STAGING that is not a regular file is called in the
# refusal.
KINDS = ((stat.S_ISLNK, "a symbolic link"), (stat.S_ISDIR, "a directory"),
         (stat.S_ISFIFO, "a FIFO"), (stat.S_ISSOCK, "a socket"),
         (stat.S_ISCHR, "a character device"), (stat.S_ISBLK, "a block device"))


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


def staged(staging):
    """The paths of the entries of `staging`, in the order of their names,
    if each is a regular file and there is at least one. Each is examined
    without following it (lstat), and nothing is opened."""
    with os.scandir(staging) as listed:
        entries = sorted(listed, key=lambda entry: entry.name)
    if not entries:
        raise Refused("cargo-deb wrote no package")
    for entry in entries:
        mode = entry.stat(follow_symlinks=False).st_mode
        if not stat.S_ISREG(mode):
            kind = next((name for test, name in KINDS if test(mode)), "not a regular file")
            raise Refused(f"{entry.name}, in what cargo-deb wrote, is {kind}, not a package")
    return [entry.path for entry in entries]


def check_packages(packages, version, directory):
    """Refuse the packages unless each unpacks and every rusthorse-broker in
    them, at least one in all, is a regular file that passes `check`."""
    brokers = 0
    for package in packages:
        name = os.path.basename(package)
        with tempfile.TemporaryDirectory(prefix="check-broker-", dir=directory) as unpacked:
            done = subprocess.run(["dpkg-deb", "-x", package, unpacked],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            if done.returncode != 0:
                raise Refused(f"{name} cannot be unpacked (dpkg-deb -x: exit status "
                              f"{done.returncode})")
            for path, dirnames, filenames in os.walk(unpacked, onerror=unreadable):
                dirnames.sort()
                for entry in sorted(dirnames + filenames):
                    if entry != BROKER:
                        continue
                    found = os.path.join(path, entry)
                    shown = f"{os.path.relpath(found, unpacked)} in {name}"
                    if not stat.S_ISREG(os.lstat(found).st_mode):
                        raise Refused(f"{shown} is not a regular file")
                    check(found, version, shown)
                    brokers += 1
    if brokers == 0:
        raise Refused(f"no {BROKER} in {', '.join(os.path.basename(p) for p in packages)}")


def open_no_follow(path, flags):
    """os.open, failing on a symbolic link; also an opener for `open`."""
    return os.open(path, flags | os.O_NOFOLLOW)


def copy(package, dest, final):
    """Put a copy of `package` at `final`, in the directory `dest` of
    another file system: written to a new file created in `dest`, flushed to
    disk, then renamed to `final`."""
    with open(package, "rb", opener=open_no_follow) as source:
        mode = stat.S_IMODE(os.fstat(source.fileno()).st_mode)
        # A new name, created (O_EXCL): nothing there is written through.
        descriptor, temporary = tempfile.mkstemp(prefix=".check-broker-", suffix=".tmp",
                                                 dir=dest)
        try:
            with open(descriptor, "wb") as target:
                shutil.copyfileobj(source, target)
                target.flush()
                os.fchmod(target.fileno(), mode)
                os.fsync(target.fileno())
            os.replace(temporary, final)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


def move(package, dest):
    """Move `package` into the directory `dest` under its name, replacing
    what has that name there as a directory entry; return its new path."""
    final = os.path.join(dest, os.path.basename(package))
    try:
        os.replace(package, final)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise
        copy(package, dest, final)
    return final


def remove(staging):
    """Remove `staging` and everything in it, following no symbolic link;
    return why it is still there, or None."""
    try:
        shutil.rmtree(staging)
    except OSError as e:
        if os.path.lexists(staging):
            return e.strerror or str(e)
    return None


def outcome(moved, dest, staging, left):
    """What a run that stopped did with what cargo-deb wrote."""
    if moved:
        said = f"moved {', '.join(moved)}, which passed; the rest of what cargo-deb wrote "
    else:
        said = f"nothing is moved to {dest}, and what cargo-deb wrote "
    if left is None:
        return said + "is deleted"
    return said + f"is in {staging}, which could not be deleted ({left}): delete it by hand"


def main_staged(version, directory, staging, dest):
    moved = []
    try:
        packages = staged(staging)
        check_packages(packages, version, directory)
        os.makedirs(dest, exist_ok=True)
        for package in packages:
            moved.append(move(package, dest))
    except BaseException as e:
        # Whatever stopped the check, nothing unchecked reaches DEST.
        said = outcome(moved, dest, staging, remove(staging))
        if not isinstance(e, Refused):
            print(f"check-broker.py: the packages could not all be checked and moved; {said}",
                  file=sys.stderr)
            raise
        sys.exit(f"check-broker.py: {e}: refusing to package it; {said}. A package must hold "
                 f"the release build of the broker that packaging/build-deb.sh built and "
                 f"checked: run the script without options that make cargo-deb take the "
                 f"programs from elsewhere")
    left = remove(staging)
    if left is not None:
        sys.exit(f"check-broker.py: moved {', '.join(moved)}, which passed, but {staging} "
                 f"could not be deleted ({left}): delete it by hand")
    for path in moved:
        sys.stdout.buffer.write(os.fsencode(path) + b"\n")


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "--staged":
        main_staged(*sys.argv[2:])
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
