#!/usr/bin/env python3
"""Write the Debian package's copyright file.

The four programs contain, compiled in, the Rust crates that Cargo.lock
resolves for them. Their licenses (MIT, BSD, Apache-2.0, ISC, ...) require
that their copyright notices and license texts go with the binaries, so this
file lists every such crate and carries, verbatim, the license files each
crate ships. Debian policy wants all of that in
/usr/share/doc/<package>/copyright.

Usage: packaging/copyright.py OUTPUT

Reads `cargo metadata` (normal dependencies of the workspace members, for
the host platform) and the crates' sources in the Cargo registry. Cargo
resolves features there for every target, tests included, so the list may
name a crate that only a test build compiles, never one less; `cargo tree`
gives the features of the programs' own build, where a nested license file
depends on one. Fails if a crate has neither a license file nor a license it
can write the text of, if it has a license file below its top directory
that nobody checked (see NESTED_LICENSE_FILES), or if a crate checked by
hand changed.
"""

import json
import os
import re
import subprocess
import sys
import textwrap

UPSTREAM = "https://github.com/Alle4you/rusthorse"
MAINTAINER = "Alle4you <56454046+Alle4you@users.noreply.github.com>"

GPL_NOTICE = """\
Rusthorse is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version.

Rusthorse is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

On Debian systems, the full text of the GNU General Public License version 3
can be found in /usr/share/common-licenses/GPL-3."""

# Crates whose package ships no license file, checked by hand. A notice is
# never made up from the `authors` field: either the crate's own license
# file, fetched from the upstream revision it was published from, is kept in
# packaging/licenses/, or the crate is shown to contain no code. Any other
# crate without a license file stops the build.
EXCEPTIONS = {
    # Published from oconnor663/blake2_simd at 47714dc3 (.cargo_vcs_info.json);
    # its LICENSE there.
    ("blake2b_simd", "1.0.5"): "blake2b_simd-1.0.5.LICENSE",
    # A deprecation stub: its src/lib.rs is a single doc comment, so nothing
    # of it is compiled into the programs.
    ("block-modes", "0.9.1"): None,
}

# License files below a crate's top directory (or in a directory named like
# one), checked by hand. Each maps the file, relative to the crate's
# directory, to True when the code it covers is compiled into the programs:
# its text is then included (when in doubt, say True). Or to the name of a
# feature that keeps that code out, when it is compiled only without that
# feature: the file is then left out, once the programs' build is seen to
# enable the feature. Or to False when that code is never compiled into the
# programs, whatever the features (tests, examples, tools run at build
# time): the file is left out. Any other such file stops the build, and so
# does a file listed here that is not there.
NESTED_LICENSE_FILES = {
    ("ring", "0.17.14"): {
        # Its LICENSE: "See src/polyfill/once_cell/LICENSE-APACHE and
        # src/polyfill/once_cell/LICENSE-MIT for the license to code that was
        # sourced from the once_cell project": src/polyfill/once_cell/race.rs,
        # which src/cpu/intel.rs and src/cpu/arm.rs use. The MIT text is also
        # the header of src/polyfill/slice.rs.
        "src/polyfill/once_cell/LICENSE-APACHE": True,
        "src/polyfill/once_cell/LICENSE-MIT": True,
        # fiat-crypto's field arithmetic: crypto/fipsmodule/ec/p256.c and
        # crypto/curve25519/curve25519.c include its headers, and build.rs
        # assembles its x86_64 code.
        "third_party/fiat/LICENSE": True,
    },
    ("tracing-core", "0.1.36"): {
        # A trimmed copy of spin 0.5.2, for builds without std: src/lib.rs
        # compiles `mod spin` only with #[cfg(not(feature = "std"))].
        "src/spin/LICENSE": "std",
    },
}

# Crates whose license files say that the license of each source file is at
# its top, checked by hand: the copyright notices of every file in these
# directories (more than is compiled in, for any architecture) are listed
# with the crate. ring's LICENSE: "Some code that was sourced from BoringSSL
# under the ISC license. In each case, the license info is at the top of the
# file", and the ISC license asks for the notice in all copies. Its tests/
# and build.rs are not compiled into the programs.
NOTICES_IN_SOURCES = {
    ("ring", "0.17.14"): ["crypto", "include", "pregenerated", "src", "third_party"],
}

LICENSE_FILE = re.compile(r"(?i)^(licen[sc]e|copying|copyright|notice|unlicense)")

# What may stand before a notice: the markers of a comment, in source files
# and in license files written as one ("// Copyright 2015 ...").
COMMENT_MARKER = re.compile(r"^(//+|/\*+|\*+|#+|;+|--)\s*")


def host_triple():
    out = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout
    return next(line.split(": ", 1)[1] for line in out.splitlines() if line.startswith("host: "))


def distributed_crates(root):
    """Packages reached from the workspace members through normal
    dependencies: what is compiled into the programs. Also the names of the
    programs: the workspace members' binaries."""
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked",
             "--filter-platform", host_triple()],
            cwd=root, capture_output=True, text=True, check=True,
        ).stdout
    )
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    members = set(meta["workspace_members"])
    seen, stack = set(), list(members)
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            if any(kind["kind"] is None for kind in dep["dep_kinds"]):
                stack.append(dep["pkg"])
    crates = [packages[i] for i in seen - members]
    programs = sorted(target["name"] for i in members for target in packages[i]["targets"]
                      if "bin" in target["kind"])
    return sorted(crates, key=lambda p: (p["name"], p["version"])), programs


def release_features(root):
    """The features of each crate, by (name, version), in a plain `cargo
    build --workspace`: unlike `cargo metadata`, `cargo tree` without
    dev-dependency edges leaves out what only tests enable."""
    out = subprocess.run(
        ["cargo", "tree", "--workspace", "--locked", "--edges", "normal",
         "--target", host_triple(), "--prefix", "none", "--format", "{p}|{f}"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout
    features = {}
    for line in out.splitlines():
        package, _, enabled = line.removesuffix(" (*)").partition("|")
        found = re.match(r"(\S+) v(\S+)", package)
        if found:
            features.setdefault(found.groups(), set()).update(f for f in enabled.split(",") if f)
    return features


def normalized(text):
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return normalized(f.read())


def nested_license_texts(crate, features):
    """(file name, text) of the license files below the crate's top
    directory whose code is compiled in, as NESTED_LICENSE_FILES says.
    Stops the build at any it does not list."""
    directory = os.path.dirname(crate["manifest_path"])
    key = (crate["name"], crate["version"])
    listed = NESTED_LICENSE_FILES.get(key, {})
    # The manifest's own license file, wherever it is, is read already.
    named = crate.get("license_file") and os.path.normpath(crate["license_file"])
    found = []
    for path, dirnames, filenames in os.walk(directory):
        dirnames.sort()
        for name in sorted(filenames):
            relative = os.path.relpath(os.path.join(path, name), directory)
            parts = relative.split(os.sep)
            if (len(parts) > 1 and relative != named
                    and any(LICENSE_FILE.match(part) for part in parts)):
                found.append(relative)
    texts = []
    for relative in found:
        decision = listed.get(relative)
        if decision is None:
            sys.exit(f"copyright.py: {crate['name']} {crate['version']} ships {relative}, a "
                     f"license file below its top directory; find out whether the code it "
                     f"covers is compiled into the programs and list it in "
                     f"NESTED_LICENSE_FILES")
        if decision is True:
            texts.append((relative, read_text(os.path.join(directory, relative))))
        elif decision is False:
            continue
        elif decision not in features.get(key, set()):
            sys.exit(f"copyright.py: {crate['name']} {crate['version']} leaves out {relative} "
                     f"because its code is compiled only without the feature {decision}, "
                     f"which the programs' build no longer enables; check it again "
                     f"(NESTED_LICENSE_FILES)")
    for relative in listed:
        if relative not in found:
            sys.exit(f"copyright.py: {crate['name']} {crate['version']} has no {relative}, "
                     f"which NESTED_LICENSE_FILES lists; check the crate again")
    return texts


def license_texts(crate, features):
    """(file name, text) of the license files the crate ships."""
    directory = os.path.dirname(crate["manifest_path"])
    names = sorted(n for n in os.listdir(directory) if LICENSE_FILE.match(n)
                   and os.path.isfile(os.path.join(directory, n)))
    if crate.get("license_file") and os.path.basename(crate["license_file"]) not in names:
        names.append(crate["license_file"])
    texts = [(os.path.basename(name), read_text(os.path.join(directory, name)))
             for name in names]
    texts += nested_license_texts(crate, features)
    if texts:
        return texts
    key = (crate["name"], crate["version"])
    if key in EXCEPTIONS:
        kept = EXCEPTIONS[key]
        if kept is None:
            return [("(no license file; the crate contains no code)", "")]
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses", kept)
        return [(f"{kept}, its upstream license file", read_text(path))]
    sys.exit(f"copyright.py: {crate['name']} {crate['version']} ships no license file; "
             f"find its license at the revision it was published from, keep it in "
             f"packaging/licenses/ and list it in EXCEPTIONS")


def notices(texts):
    """The copyright lines in a crate's license texts, or in source files."""
    found = []
    for _, text in texts:
        for line in text.split("\n"):
            stripped = COMMENT_MARKER.sub("", line.strip())
            stripped = re.sub(r"\s*\*+/$", "", stripped).strip()
            # Notices, not the sentences of license texts about them ("the
            # copyright notice", "copyright owner", "[yyyy]").
            if re.match(r"(?i)^(copyright\b|(\(c\)|©)\s*\d{4})", stripped) and not re.search(
                r"(?i)\[|notice|license|owner|holder|permission", stripped
            ):
                if stripped not in found:
                    found.append(stripped)
    return found


def source_notices(crate):
    """The copyright notices in the source files of a crate that
    NOTICES_IN_SOURCES lists, sorted, each once."""
    directory = os.path.dirname(crate["manifest_path"])
    found = set()
    for top in NOTICES_IN_SOURCES[(crate["name"], crate["version"])]:
        base = os.path.join(directory, top)
        if not os.path.isdir(base):
            sys.exit(f"copyright.py: {crate['name']} {crate['version']} has no {top}/, which "
                     f"NOTICES_IN_SOURCES lists; check the crate again")
        for path, dirnames, filenames in os.walk(base):
            dirnames.sort()
            for name in sorted(filenames):
                with open(os.path.join(path, name), "rb") as f:
                    data = f.read()
                # Not text (object files, certificates): no notice to read.
                if b"\0" in data:
                    continue
                found.update(notices([(name, data.decode("utf-8", errors="replace"))]))
    return sorted(found)


def check_hand_checked(crates):
    """Stop the build when a crate that NOTICES_IN_SOURCES lists is no
    longer among `crates`: its successor, another version included, has not
    been checked by hand. (One that NESTED_LICENSE_FILES lists cannot slip
    by: the license files of its successor stop the build where they are.)"""
    present = {(c["name"], c["version"]) for c in crates}
    for name, version in NOTICES_IN_SOURCES:
        if (name, version) not in present:
            sys.exit(f"copyright.py: {name} {version}, which NOTICES_IN_SOURCES lists, is no "
                     f"longer compiled in; check what replaced it by hand")


def indented(text):
    return "\n".join(" " + line if line else " ." for line in text.split("\n"))


def spoken_list(names):
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    crates, programs = distributed_crates(root)
    features = release_features(root)
    order, shippers = [], {}
    listing = []
    for crate in crates:
        texts = license_texts(crate, features)
        key = (crate["name"], crate["version"])
        found = notices(texts)
        # What stands for a license text the crate does not need.
        found += [name for name, text in texts if not text]
        in_sources = source_notices(crate) if key in NOTICES_IN_SOURCES else []
        listing.append((crate, found, [n for n in in_sources if n not in found]))
        for name, text in texts:
            if not text:
                continue
            if text not in shippers:
                shippers[text] = []
                order.append(text)
            shippers[text].append(f"{crate['name']} {crate['version']} ({name})")
    check_hand_checked(crates)

    with_sources = sorted({name for name, _ in NOTICES_IN_SOURCES})
    in_their_sources = (f" (for {spoken_list(with_sources)}, also those at the top of its "
                        "source files, as its license files say)" if with_sources else "")
    out = []
    out.append("Rusthorse")
    out.append(f"Upstream: {UPSTREAM}")
    out.append(f"Packaged by: {MAINTAINER}")
    out.append("")
    out.append("Copyright: 2026 The Rusthorse contributors")
    out.append("License: GPL-3.0-or-later")
    out.append(indented(GPL_NOTICE))
    out.append("")
    out.append("Rust crates compiled into the programs")
    out.append("======================================")
    out.append("")
    out.append(indented(textwrap.fill(
        f"{spoken_list(programs)} are built from these {len(crates)} crates, as "
        "Cargo.lock resolves them (generated by packaging/copyright.py); the "
        "procedural macros among them run only while the programs are built. For "
        "each: version, license, source and the copyright notices in its license "
        f"files{in_their_sources}. The license texts follow the list, each text "
        "once, with the crates that ship it.", width=76)))
    out.append("")
    for crate, found, in_sources in listing:
        source = crate.get("repository") or "https://crates.io/crates/" + crate["name"]
        out.append(f" {crate['name']} {crate['version']} — {crate.get('license') or 'see its license file'} — {source}")
        for line in found:
            out.append(f"   {line}")
        if in_sources:
            out.append("   At the top of its source files:")
            for line in in_sources:
                out.append(f"     {line}")
    out.append("")
    out.append("License texts of the crates")
    out.append("===========================")
    for number, text in enumerate(order, 1):
        out.append("")
        out.append(f"Text {number}, shipped by: " + ", ".join(shippers[text]))
        out.append("")
        out.append(indented(text))
    with open(sys.argv[1], "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
