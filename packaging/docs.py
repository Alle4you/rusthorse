#!/usr/bin/env python3
"""Copy the documentation that the Debian package installs.

Usage: packaging/docs.py OUTPUT_DIR REVISION

Copies README.md, CHANGELOG.md, SECURITY.md, CONTRIBUTING.md, LICENSE,
docs/*.md, docs/adr/*.md and docs/design/ into OUTPUT_DIR, keeping their
layout (it becomes /usr/share/doc/rusthorse/). A Markdown link to a file of
the repository that the package does not install — source code, tests — is
rewritten to that file on GitHub at REVISION, so that no link of the
installed documentation leads nowhere. Fails on a relative link whose target
exists in neither place.
"""

import os
import re
import shutil
import sys

UPSTREAM = "https://github.com/Alle4you/rusthorse"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOP = ["README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE"]
LINK = re.compile(r"\]\(([^)\s]+)\)")


def installed_files():
    files = list(TOP)
    for directory in ["docs", "docs/adr"]:
        files += sorted(
            f"{directory}/{name}"
            for name in os.listdir(os.path.join(ROOT, directory))
            if name.endswith(".md")
        )
    for directory, _, names in os.walk(os.path.join(ROOT, "docs", "design")):
        files += sorted(os.path.relpath(os.path.join(directory, n), ROOT) for n in names)
    return files


def rewrite(path, text, installed, revision):
    """`text` of the Markdown file `path` (relative to the repository), with
    links to files that are not installed pointing to GitHub."""
    out, fenced, problems = [], False, []
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if fenced:
            out.append(line)
            continue

        def replace(match):
            target = match.group(1)
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                return match.group(0)
            file, _, anchor = target.partition("#")
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), file))
            if resolved in installed or any(f.startswith(resolved + "/") for f in installed):
                return match.group(0)
            absolute = os.path.join(ROOT, resolved)
            if not os.path.exists(absolute) or resolved.startswith(".."):
                problems.append(f"{path}: {target}")
                return match.group(0)
            kind = "tree" if os.path.isdir(absolute) else "blob"
            url = f"{UPSTREAM}/{kind}/{revision}/{resolved}"
            return f"]({url}{'#' + anchor if anchor else ''})"

        out.append(LINK.sub(replace, line))
    return "\n".join(out), problems


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    output, revision = sys.argv[1], sys.argv[2]
    if os.path.exists(output):
        shutil.rmtree(output)
    files = installed_files()
    installed = set(files)
    problems = []
    for path in files:
        destination = os.path.join(output, path)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        if path.endswith(".md"):
            with open(os.path.join(ROOT, path), encoding="utf-8") as f:
                text, found = rewrite(path, f.read(), installed, revision)
            problems += found
            with open(destination, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            shutil.copyfile(os.path.join(ROOT, path), destination)
    if problems:
        sys.exit("docs.py: links to files that do not exist:\n  " + "\n  ".join(problems))


if __name__ == "__main__":
    main()
