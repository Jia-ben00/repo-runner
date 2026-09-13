#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM from a repository's dependency manifests.

Stdlib only. Parses lockfiles / manifests and emits a CycloneDX JSON BOM:

  npm      package-lock.json   (lockfileVersion 1 / 2 / 3)
  pnpm     pnpm-lock.yaml      (v9+; needs Python 3.11+ for tomllib)
  yarn     yarn.lock           (v1 text blocks; v2+ YAML needs Python 3.11+)
  pip      requirements.txt / requirements-dev.txt
  pyproject.toml [project].dependencies   (needs Python 3.11+ for tomllib)
  uv       uv.lock             (needs Python 3.11+)
  poetry   poetry.lock         (needs Python 3.11+)
  go       go.mod              (require lines)
  rust     Cargo.lock          (needs Python 3.11+)
  ruby     Gemfile.lock        (SPECS section)
  php      composer.lock       (JSON packages list)

Usage:
  sbom.py <directory> [--output FILE] [--quiet]

Exit codes: 0 = BOM written (components may be empty, with a note),
            1 = bad args, 2 = directory not found / no manifests found.
"""
import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

TOOL_VERSION = "0.2.0"


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def read_text(path, limit=200000):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return fh.read(limit)
    except Exception:
        return ""


def _load_toml(root, name):
    path = os.path.join(root, name)
    if not os.path.exists(path):
        return None, []
    try:
        import tomllib
    except ImportError:
        return None, [name + " requires Python 3.11+ (tomllib) to parse"]
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh), []
    except Exception as exc:
        return None, [name + " could not be parsed: " + str(exc)]


def parse_npm_lock(root):
    data = read_json(os.path.join(root, "package-lock.json"))
    if not data:
        return [], []
    comps = {}
    ver = data.get("lockfileVersion")
    if ver in (2, 3):
        for key, info in (data.get("packages") or {}).items():
            if not key:  # root project entry
                continue
            if "node_modules/" in key:
                name = key.rsplit("node_modules/", 1)[-1]
                # scoped: node_modules/@scope/name -> @scope/name
                while name.startswith("@") and "/" in name:
                    head, tail = name.split("/", 1)
                    if tail.startswith("node_modules/"):
                        name = tail[len("node_modules/"):]
                    else:
                        name = head + "/" + tail
                        break
            else:
                name = info.get("name") or key
            if name and info.get("version"):
                comps.setdefault(name, info["version"])
    else:  # v1
        def walk(deps):
            for name, info in (deps or {}).items():
                if info and info.get("version"):
                    comps.setdefault(name, info["version"])
                walk(info.get("dependencies") if info else None)
        walk(data.get("dependencies"))
    return sorted(comps.items()), []


def parse_pnpm_lock(root):
    # pnpm-lock.yaml is YAML (not TOML), so tomllib cannot parse it.
    # Scan only the top-level "packages:" entries: each key encodes
    # name@version, which is all the SBOM needs from the lockfile.
    p = os.path.join(root, "pnpm-lock.yaml")
    if not os.path.exists(p):
        return [], []
    comps = {}
    in_packages = False
    for line in read_text(p, 300000).splitlines():
        s = line.rstrip()
        if s == "packages:":
            in_packages = True
            continue
        if not in_packages:
            continue
        if s and not s.startswith(" "):
            in_packages = False  # next top-level key (e.g. "snapshots:")
            continue
        if s.startswith("  ") and not s.startswith("    ") and ":" in s:
            key = s.strip().rstrip(":").strip("'\"")
            if "@" not in key:
                continue
            if key.startswith("@"):
                name, ver = key[: key.rfind("@")], key[key.rfind("@") + 1:]
            else:
                name, ver = key.rsplit("@", 1)
            ver = ver.split("(")[0].strip()  # strip peer-dependency suffixes
            if name and ver:
                comps.setdefault(name, ver)
    return sorted(comps.items()), []


def parse_yarn_lock(root):
    p = os.path.join(root, "yarn.lock")
    if not os.path.exists(p):
        return [], []
    comps = {}
    name = None
    for line in read_text(p).splitlines():
        s = line.strip()
        if s.startswith('"') and s.endswith(":"):
            ent = s.rstrip(":").strip('"').split(",")[0].strip()
            if "@" in ent:
                name = ent[: ent.rfind("@")] if not ent.startswith("@") else ent[: ent.rfind("@")]
                if ent.startswith("@") and name.count("/") == 1:
                    name = name  # @scope/name
        elif name and s.startswith("version"):
            # yarn v1 uses `version "4.18.2"` (space separator); tolerate colon too
            ver = s.split(None, 1)[1].strip().strip('"')
            comps.setdefault(name, ver)
            name = None
    return sorted(comps.items()), []


def parse_requirements(root):
    comps = {}
    notes = []
    for fname in ("requirements.txt", "requirements-dev.txt"):
        p = os.path.join(root, fname)
        if not os.path.exists(p):
            continue
        for line in read_text(p, 100000).splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("-r ") or line.startswith("--requirement "):
                notes.append(fname + " includes " + line.split()[-1])
                continue
            if line.startswith("-") or line.startswith("--"):
                continue
            line = line.split(";", 1)[0].strip()  # strip env markers
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$", line)
            if not m:
                continue
            name, spec = m.group(1), m.group(2).strip()
            ver = None
            vm = re.match(r"===?([^\s,]+)", spec)
            if vm:
                ver = vm.group(1).strip()
            comps.setdefault(name, ver)
    return sorted(comps.items()), notes


def parse_pyproject(root):
    data, notes = _load_toml(root, "pyproject.toml")
    if data is None:
        return [], notes
    deps = (data.get("project") or {}).get("dependencies") or []
    comps = {}
    for d in deps:
        if not isinstance(d, str):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$", d)
        if not m:
            continue
        name, rest = m.group(1), m.group(2).strip()
        if not name:
            continue
        if "@" in rest or not rest:
            ver = None
        else:
            vm = re.match(r"[<>=!~]*([^\s,]+)", rest)
            ver = vm.group(1).rstrip(",") if vm else None
        comps.setdefault(name, ver)
    return sorted(comps.items()), notes


def parse_uv_lock(root):
    data, notes = _load_toml(root, "uv.lock")
    if data is None:
        return [], notes
    comps = {}
    for pkg in data.get("package", []):
        name = pkg.get("name")
        if name:
            comps.setdefault(name, pkg.get("version"))
    return sorted(comps.items()), notes


def parse_poetry_lock(root):
    data, notes = _load_toml(root, "poetry.lock")
    if data is None:
        return [], notes
    comps = {}
    for pkg in data.get("package", []):
        name = pkg.get("name")
        if name:
            comps.setdefault(name, pkg.get("version"))
    return sorted(comps.items()), notes


def parse_go_mod(root):
    p = os.path.join(root, "go.mod")
    if not os.path.exists(p):
        return [], []
    comps = {}
    in_require = False
    for line in read_text(p, 100000).splitlines():
        s = line.split("//", 1)[0].strip()
        if s.startswith("require (") or s.startswith("require("):
            in_require = True
            continue
        if s == ")":
            in_require = False
            continue
        if s.startswith("require "):
            s = s[len("require "):]
        elif not in_require:
            continue
        parts = s.split()
        if len(parts) >= 2 and "=>" not in s:
            name, ver = parts[0], parts[1]
            if ver:
                comps.setdefault(name, ver)
    return sorted(comps.items()), []


def parse_cargo_lock(root):
    data, notes = _load_toml(root, "Cargo.lock")
    if data is None:
        return [], notes
    comps = {}
    for pkg in data.get("package", []):
        name = pkg.get("name")
        if name:
            comps.setdefault(name, pkg.get("version"))
    return sorted(comps.items()), notes


def parse_gemfile_lock(root):
    p = os.path.join(root, "Gemfile.lock")
    if not os.path.exists(p):
        return [], []
    comps = {}
    in_specs = False
    for line in read_text(p, 200000).splitlines():
        s = line.rstrip()
        if s.strip() == "specs:":
            in_specs = True
            continue
        if not in_specs:
            continue
        if s.strip() in ("PLATFORMS", "DEPENDENCIES", "RUBY VERSION", "GIT", "PATH", "CHECKSUMS", "RUBY"):
            in_specs = False
            continue
        m = re.match(r"^    ([\w.\-]+) \(([^)]+)\)", s)
        if m:
            comps.setdefault(m.group(1), m.group(2))
    return sorted(comps.items()), []


def parse_composer_lock(root):
    data = read_json(os.path.join(root, "composer.lock"))
    if not data:
        return [], []
    comps = {}
    for pkg in data.get("packages") or []:
        name = pkg.get("name")
        if name and pkg.get("version"):
            comps.setdefault(name, pkg["version"].lstrip("v"))
    return sorted(comps.items()), []


PARSERS = [
    ("npm", "package-lock.json", parse_npm_lock, "npm"),
    ("pnpm", "pnpm-lock.yaml", parse_pnpm_lock, "npm"),
    ("yarn", "yarn.lock", parse_yarn_lock, "npm"),
    ("pip", "requirements.txt", parse_requirements, "pypi"),
    ("pyproject", "pyproject.toml", parse_pyproject, "pypi"),
    ("uv", "uv.lock", parse_uv_lock, "pypi"),
    ("poetry", "poetry.lock", parse_poetry_lock, "pypi"),
    ("go", "go.mod", parse_go_mod, "golang"),
    ("rust", "Cargo.lock", parse_cargo_lock, "cargo"),
    ("ruby", "Gemfile.lock", parse_gemfile_lock, "gem"),
    ("php", "composer.lock", parse_composer_lock, "composer"),
]


def purl(pkg_type, name, version):
    enc = name.replace("@", "%40")
    if version:
        return "pkg:%s/%s@%s" % (pkg_type, enc, version)
    return "pkg:%s/%s" % (pkg_type, enc)


def main():
    ap = argparse.ArgumentParser(description="Generate a CycloneDX 1.5 SBOM from dependency manifests.")
    ap.add_argument("directory", help="repository / project directory to scan")
    ap.add_argument("--output", "-o", help="write BOM JSON to FILE instead of stdout")
    ap.add_argument("--quiet", "-q", action="store_true", help="suppress notes on stderr")
    args = ap.parse_args()

    root = os.path.abspath(args.directory)
    if not os.path.isdir(root):
        print(json.dumps({"error": "directory not found: " + root}), file=sys.stderr)
        sys.exit(2)

    comps = {}
    notes = []
    type_by_name = {}
    found_any = False
    for label, marker, parser, pkg_type in PARSERS:
        if os.path.exists(os.path.join(root, marker)):
            found_any = True
            parsed, n = parser(root)
            notes.extend(n)
            for name, ver in parsed:
                if name not in comps:
                    comps[name] = ver
                    type_by_name[name] = (label, pkg_type)

    if not found_any:
        print(json.dumps({"error": "no supported dependency manifests found in " + root}), file=sys.stderr)
        sys.exit(2)

    components = []
    for name, version in sorted(comps.items()):
        label, pkg_type = type_by_name[name]
        u = purl(pkg_type, name, version)
        entry = {"type": "library", "bom-ref": u, "name": name, "purl": u}
        if version:
            entry["version"] = version
        components.append(entry)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "repo-runner", "name": "repo-runner-sbom", "version": TOOL_VERSION}],
            "component": {"type": "application", "name": os.path.basename(os.path.normpath(root))},
        },
        "components": components,
    }
    if not components:
        notes.append("no components extracted — review manifests manually")

    if not args.quiet:
        for n in notes:
            print("note: " + n, file=sys.stderr)
    out = json.dumps(bom, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        if not args.quiet:
            print("SBOM written to " + args.output + " (%d components)" % len(components), file=sys.stderr)
    else:
        print(out)
    sys.exit(0)


if __name__ == "__main__":
    main()
