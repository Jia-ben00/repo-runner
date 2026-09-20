#!/usr/bin/env python3
"""Fail the build when the version a reader is told to install is not a version that exists.

Three sources must agree:

  1. CHANGELOG.md   -- the newest  ## [vX.Y.Z]  heading
  2. the docs       -- every       <repo>@vX.Y.Z  reference
  3. git tags       -- whether that version is actually tagged

This check exists because of a real incident in a sibling repository. It shipped
a `v0.6.0` CHANGELOG section carrying a critical security-gate fix (the `rm-root`
rule missed `rm -rf $HOME`, `rm -rf /*`, `rm -rf ~/` and friends, so a repo that
wipes a home directory was reported as `risk_level: low`) while every README
still pointed at `@v0.5.0` and no `v0.6.0` tag existed. The copy a reader pasted
was the version with the defect.

Nothing failed. CI was green, the tool ran, the docs rendered -- because nothing
compared the three numbers. So this compares the three numbers.

Failure is deliberately fail-closed: an unparseable CHANGELOG, a missing install
reference, or an undeterminable tag list is an error and not a pass.
"Could not check" must never look like "checked and clean".

To exempt a deliberate old-version reference (e.g. "pin @v0.4.0 for the old
behaviour"), put `version-check: allow` anywhere on that line.

Usage:
    python scripts/check_release_refs.py
    python scripts/check_release_refs.py --name repo-runner
    python scripts/check_release_refs.py --tags v0.6.0,v0.5.0   # explicit tags (tests)
"""

import argparse
import os
import re
import subprocess
import sys

EXEMPT = "version-check: allow"
VERSION_RE = re.compile(r"^##\s*\[v?(\d+\.\d+\.\d+)\]", re.MULTILINE)
TAG_RE = re.compile(r"^v?(\d+\.\d+\.\d+)$")
SKIP_FILES = {"CHANGELOG.md"}


def semver_key(v):
    return tuple(int(x) for x in v.split("."))


def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def changelog_version(root, errors):
    path = os.path.join(root, "CHANGELOG.md")
    if not os.path.exists(path):
        errors.append("CHANGELOG.md not found at %s" % path)
        return None
    found = VERSION_RE.findall(read(path))
    if not found:
        errors.append("CHANGELOG.md has no '## [vX.Y.Z]' heading -- cannot determine the released version")
        return None
    return max(found, key=semver_key)


def markdown_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", ".venv", "dist")]
        for fn in sorted(filenames):
            if fn.endswith(".md") and fn not in SKIP_FILES:
                p = os.path.join(dirpath, fn)
                out.append((os.path.relpath(p, root).replace(os.sep, "/"), p))
    return out


def doc_refs(root, name):
    ref_re = re.compile(re.escape(name) + r"@v(\d+\.\d+\.\d+)")
    refs = []
    for rel, path in markdown_files(root):
        for i, line in enumerate(read(path).split("\n"), 1):
            if EXEMPT in line:
                continue
            for m in ref_re.finditer(line):
                refs.append((rel, i, m.group(1)))
    return refs


def git_tags(root, errors):
    try:
        out = subprocess.run(["git", "tag", "--list"], cwd=root,
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        errors.append("could not run git to list tags: %s" % exc)
        return None
    if out.returncode != 0:
        errors.append("git tag --list failed: %s" % (out.stderr or "").strip()[:160])
        return None
    tags = sorted({m.group(1) for m in (TAG_RE.match(l.strip()) for l in out.stdout.split("\n")) if m},
                  key=semver_key)
    if not tags:
        errors.append("no vX.Y.Z tags in this checkout -- pass fetch-depth: 0 in CI")
        return None
    return tags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--name", default=None,
                    help="repository name used in install references (default: directory name)")
    ap.add_argument("--tags", default=None, help="comma-separated tag list, bypassing git (for tests)")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    name = args.name or os.path.basename(root.rstrip(os.sep))
    errors = []

    declared = changelog_version(root, errors)

    refs = doc_refs(root, name)
    if not refs:
        errors.append("no '%s@vX.Y.Z' reference found in any .md file -- the docs no longer show an "
                      "install version, or this check stopped matching them" % name)

    if args.tags is not None:
        explicit = [t.strip() for t in args.tags.split(",") if t.strip()]
        tags = sorted({m.group(1) for m in (TAG_RE.match(t) for t in explicit) if m}, key=semver_key)
        if not tags:
            errors.append("--tags was given but contained no vX.Y.Z value")
            tags = None
    else:
        tags = git_tags(root, errors)

    newest_tag = tags[-1] if tags else None

    print("version sources for '%s'" % name)
    print("  CHANGELOG.md newest heading :", declared or "(unreadable)")
    print("  newest git tag             :", newest_tag or "(unreadable)")
    print("  doc install references     :")
    for rel, line, ver in refs:
        print("      %-26s L%-4d @v%s" % (rel, line, ver))

    if declared and newest_tag and declared != newest_tag:
        errors.append("CHANGELOG declares v%s but the newest git tag is v%s -- "
                      "release the declared version or fix the CHANGELOG" % (declared, newest_tag))

    for rel, line, ver in refs:
        if declared and ver != declared:
            errors.append("%s:%d points readers at @v%s while the CHANGELOG declares v%s"
                          % (rel, line, ver, declared))
        if tags and ver not in tags:
            errors.append("%s:%d points readers at @v%s, which is not a tag in this repository (tags: %s)"
                          % (rel, line, ver, ", ".join("v" + t for t in tags)))

    print()
    if errors:
        for e in errors:
            print("::error::%s" % e)
        print("FAIL: %d problem(s) -- the version readers are told to install is not a version that exists"
              % len(errors))
        return 1

    print("OK: CHANGELOG v%s == docs @v%s == tag v%s (%d reference(s) checked)"
          % (declared, declared, newest_tag, len(refs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
