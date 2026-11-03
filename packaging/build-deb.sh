#!/bin/sh
# Build the Debian package: target/debian/rusthorse_<version>-1_<arch>.deb
#
# Needs what building from source needs (Rust, the GTK 4 and libadwaita
# development packages), cargo-deb (`cargo install --locked cargo-deb`) and
# dpkg-deb, which every Debian system has. The package is described in
# Cargo.toml, [package.metadata.deb]; the files it installs besides the
# programs are in packaging/deb/ and data/. Extra arguments go to cargo-deb,
# except those that would install the package, build it for another target
# or package another manifest (below), and `--output DIR`, which this script
# takes itself: DIR is the directory the packages go to (target/debian by
# default; created if missing; a relative DIR is taken from the repository's
# root, where cargo-deb runs), never the name of a package. The script prints
# the path of each package it puts there.
#
# Build on the oldest release the package should install on: the package
# depends on the versions of GTK, libadwaita and glibc it was built against
# (Ubuntu 24.04 gives a package for Ubuntu 24.04 and Linux Mint 22 or later,
# and for Debian 13).
set -eu

cd "$(dirname "$0")/.."

# cargo-deb's --install would install the package before the check of what
# cargo-deb wrote (at the end) could refuse it. Another target is not
# supported: the package is built for the system that builds it, which runs
# the broker to check it. Nor is another manifest: this script packages the
# workspace it builds and checks, and cargo-deb names each package after the
# package name of its manifest, which it does not check: a / in that name
# would put the package outside the directory cargo-deb is given, where
# nothing checks it.
for arg in "$@"; do
    case $arg in
    --install | --install=* | --no-install-dbgsym | --no-install-dbgsym=*)
        echo "build-deb.sh: $arg would install the package before its credential broker is checked; install it with apt once this script has written it" >&2
        exit 1
        ;;
    --target | --target=*)
        echo "build-deb.sh: $arg is not supported: the package is built for the system that builds it" >&2
        exit 1
        ;;
    --manifest-path | --manifest-path=*)
        echo "build-deb.sh: $arg is not supported: the script packages the workspace it is in, which it builds and checks" >&2
        exit 1
        ;;
    esac
done
if [ -n "${CARGO_BUILD_TARGET+set}" ]; then
    echo "build-deb.sh: CARGO_BUILD_TARGET is set; unset it: the package is built for the system that builds it" >&2
    exit 1
fi

# cargo-deb never writes where --output says: it writes into a new directory
# of this script's own, and only the packages that pass the check are moved
# to DIR (at the end). So --output is taken out of the arguments, in each
# form that cargo-deb 3.8.0 (clap) reads as one: --output DIR, --output=DIR,
# -o DIR, -oDIR, -o=DIR, and -o after one-letter flags (-qo DIR); after --,
# nothing is an option. As cargo-deb does, it refuses a second --output, a
# missing value and a separate value that begins with -, which clap reads as
# an option; it also refuses an empty value and a separate -, which clap
# would take (--output=- names a directory called -). A form missed here
# would reach cargo-deb with the --output this script gives it, and
# cargo-deb refuses a second one.
output=
given=
escaped=
count=$#
while [ "$count" -gt 0 ]; do
    arg=$1
    shift
    count=$((count - 1))
    # Whether arg is an --output, whether its value is in it (or in the next
    # argument), and what of it goes on to cargo-deb.
    found=
    attached=
    value=
    kept=$arg
    if [ -z "$escaped" ]; then
        case $arg in
        --)
            escaped=1
            ;;
        --output=*)
            found=1
            attached=1
            value=${arg#--output=}
            kept=
            ;;
        --output)
            found=1
            kept=
            ;;
        -[!-]*)
            # One-letter flags that take no value, then one option that
            # takes one: the rest of the argument, less a leading =, or the
            # next argument. Only -o is --output.
            rest=${arg#-}
            flags=
            while [ -n "$rest" ]; do
                letter=${rest%"${rest#?}"}
                rest=${rest#?}
                case $letter in
                q | v | h | V)
                    flags=$flags$letter
                    ;;
                o)
                    found=1
                    if [ -n "$rest" ]; then
                        attached=1
                        value=${rest#=}
                    fi
                    kept=${flags:+-$flags}
                    break
                    ;;
                *)
                    break
                    ;;
                esac
            done
            ;;
        esac
    fi
    if [ -z "$found" ]; then
        set -- "$@" "$arg"
        continue
    fi
    if [ -n "$given" ]; then
        echo "build-deb.sh: $arg: --output can be given only once" >&2
        exit 1
    fi
    given=1
    if [ -z "$attached" ] && [ "$count" -gt 0 ]; then
        value=$1
        shift
        count=$((count - 1))
        case $value in
        -*)
            echo "build-deb.sh: $arg needs a directory, not $value (write $arg=DIR for one whose name begins with -)" >&2
            exit 1
            ;;
        esac
    fi
    if [ -z "$value" ]; then
        echo "build-deb.sh: $arg needs a directory" >&2
        exit 1
    fi
    output=$value
    [ -z "$kept" ] || set -- "$@" "$kept"
done
# DIR must be a directory, or nothing yet: refused before anything is built.
if [ -n "$given" ] && { [ -e "$output" ] || [ -L "$output" ]; } && [ ! -d "$output" ]; then
    echo "build-deb.sh: $output is not a directory: --output names the directory the packages go to" >&2
    exit 1
fi

# One build for the four programs, so that `rusthorse` keeps its default
# features (the dialog, the manager and the broker use the library without
# them). No feature is named: the credential broker's only feature,
# `test-upstream`, is for tests and never in a release.
cargo build --release --locked --workspace

# Files generated for the package go next to the programs; cargo-deb reads
# `target/release/` in Cargo.toml as this directory, wherever it is
# (CARGO_TARGET_DIR).
target=$(cargo metadata --format-version 1 --no-deps --locked |
    python3 -I -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
version=$(cargo metadata --format-version 1 --no-deps --locked |
    python3 -I -c 'import json, sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "rusthorse"))')
[ -n "$given" ] || output=$target/debian

# A broker built for tests (feature test-upstream) says so when asked
# `--check`, as `rusthorse doctor` asks it: never package one. The checks
# stop the script themselves, whatever `set -e` does.
python3 -I packaging/check-broker.py "$target/release/rusthorse-broker" "$version" || exit 1

# Removed and made again on each run, with what a run that was killed left
# in it.
generated="$target/release/packaging"
rm -rf "$generated"
mkdir -p "$generated/completions"

# Shell completions, generated by the program that will be installed.
"$target/release/rusthorse" completions bash >"$generated/completions/rusthorse"
"$target/release/rusthorse" completions zsh >"$generated/completions/_rusthorse"
"$target/release/rusthorse" completions fish >"$generated/completions/rusthorse.fish"

# The copyright file: Rusthorse's license and the notices and licenses of
# every crate compiled into the programs.
python3 -I packaging/copyright.py "$generated/copyright"

# The documentation, with links to files the package does not install (the
# source code) pointing to them on GitHub at this revision.
revision=$(git rev-parse HEAD 2>/dev/null || echo "v$version")
python3 -I packaging/docs.py "$generated/doc" "$revision"

# cargo-deb writes the package (and its -dbgsym package, when asked for one)
# into a new directory that only this user can enter, under the names it
# gives them. What it prints, the paths of what it wrote there, goes to
# standard error. If it fails, or the script ends before the check has moved
# what it wrote (interrupted, say), that directory is deleted; only a run
# killed outright (SIGKILL) leaves it, for the next run to delete with
# $generated. (Whatever --output says, cargo-deb itself also deletes, before
# it writes, the packages of rusthorse it finds in target/debian, its
# default directory, and keeps its temporary files, which are not packages,
# in target/rusthorse.)
staging=$(mktemp -d "$generated/staging.XXXXXXXXXX")
trap 'rm -rf -- "$staging"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cargo deb --no-build --locked -p rusthorse --output "$staging/" "$@" >&2 || {
    status=$?
    echo "build-deb.sh: cargo-deb failed (exit status $status); what it wrote is deleted" >&2
    exit "$status"
}

# What ships is checked too: options, variants and the environment of
# cargo-deb can make it take the programs from elsewhere than the file
# checked above. Only if every package passes are they moved to DIR, and
# their paths there printed; otherwise nothing reaches DIR, and the staging
# directory is deleted with whatever cargo-deb wrote.
python3 -I packaging/check-broker.py --staged "$version" "$generated" "$staging" "$output" || exit 1
