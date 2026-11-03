#!/usr/bin/env python3
"""Write the Debian package's copyright file.

The four programs contain, compiled in, the Rust crates that Cargo.lock
resolves for them. Their licenses (MIT, BSD, Apache-2.0, ...) require that
their copyright notices and license texts go with the binaries, so this file
lists every such crate and carries, verbatim, the license files each crate
ships. Debian policy wants all of that in /usr/share/doc/<package>/copyright.

Usage: packaging/copyright.py OUTPUT

Reads `cargo metadata` (normal dependencies of the workspace members, for
the host platform, with the features a plain `cargo build --workspace`
uses) and the crates' sources in the Cargo registry. Fails if a crate has
neither a license file nor a license it can write the text of.
"""

import json
import os
import re
import subprocess
import sys

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

LICENSE_FILE = re.compile(r"(?i)^(licen[sc]e|copying|copyright|notice|unlicense)")


def host_triple():
    out = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout
    return next(line.split(": ", 1)[1] for line in out.splitlines() if line.startswith("host: "))


def distributed_crates(root):
    """Packages reached from the workspace members through normal
    dependencies: what is compiled into the programs."""
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
    return sorted(crates, key=lambda p: (p["name"], p["version"]))


def normalized(text):
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def license_texts(crate):
    """(file name, text) of the license files the crate ships."""
    directory = os.path.dirname(crate["manifest_path"])
    names = sorted(n for n in os.listdir(directory) if LICENSE_FILE.match(n)
                   and os.path.isfile(os.path.join(directory, n)))
    if crate.get("license_file") and os.path.basename(crate["license_file"]) not in names:
        names.append(crate["license_file"])
    texts = []
    for name in names:
        with open(os.path.join(directory, name), encoding="utf-8", errors="replace") as f:
            texts.append((os.path.basename(name), normalized(f.read())))
    if texts:
        return texts
    key = (crate["name"], crate["version"])
    if key in EXCEPTIONS:
        kept = EXCEPTIONS[key]
        if kept is None:
            return [("(no license file; the crate contains no code)", "")]
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses", kept),
                  encoding="utf-8") as f:
            return [(f"{kept}, its upstream license file", normalized(f.read()))]
    sys.exit(f"copyright.py: {crate['name']} {crate['version']} ships no license file; "
             f"find its license at the revision it was published from, keep it in "
             f"packaging/licenses/ and list it in EXCEPTIONS")


def notices(texts):
    """The copyright lines in a crate's license texts."""
    found = []
    for _, text in texts:
        for line in text.split("\n"):
            stripped = line.strip()
            # Notices, not the sentences of license texts about them ("the
            # copyright notice", "copyright owner", "[yyyy]").
            if re.match(r"(?i)^(copyright\b|(\(c\)|©)\s*\d{4})", stripped) and not re.search(
                r"(?i)\[|notice|license|owner|holder|permission", stripped
            ):
                if stripped not in found:
                    found.append(stripped)
    return found


def indented(text):
    return "\n".join(" " + line if line else " ." for line in text.split("\n"))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    crates = distributed_crates(root)
    order, shippers = [], {}
    listing = []
    for crate in crates:
        texts = license_texts(crate)
        listing.append((crate, notices(texts)))
        for name, text in texts:
            if not text:
                continue
            if text not in shippers:
                shippers[text] = []
                order.append(text)
            shippers[text].append(f"{crate['name']} {crate['version']} ({name})")

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
    out.append(indented(
        "rusthorse, rusthorse-broker, rusthorse-dialog and rusthorse-manager contain\n"
        f"these {len(crates)} crates, compiled in, as Cargo.lock resolves them (generated by\n"
        "packaging/copyright.py). For each: version, license, source and the\n"
        "copyright notices in its license files. The license texts follow the list,\n"
        "each text once, with the crates that ship it."))
    out.append("")
    for crate, found in listing:
        source = crate.get("repository") or "https://crates.io/crates/" + crate["name"]
        out.append(f" {crate['name']} {crate['version']} — {crate.get('license') or 'see its license file'} — {source}")
        for line in found:
            out.append(f"   {line}")
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
