#!/usr/bin/env python3
"""Security gate for repo-runner: scan a repository for dangerous setup patterns.

Runs BEFORE any install/run step. Stdlib only, cross-platform.

Output (JSON to stdout):
{
  "risk_level": "low|medium|high|critical",
  "findings": [
    {"severity": "high", "file": "package.json", "line": 6,
     "pattern": "curl-pipe-sh", "detail": "curl ... | bash"}
  ],
  "scan_summary": {"files_scanned": 12, "matched_lines": 3}
}

Exit codes: 0 = proceed (low), 1 = review before proceeding (medium),
            2 = stop, ask the user (high/critical).
"""
import json
import os
import re
import sys

# All-lowercase: iter_target_files lowercases the relative path before matching.
TARGET_FILES = (
    "package.json", "makefile", "dockerfile", "install.sh", "setup.sh",
    "bootstrap.sh", "devcontainer.json", "docker-compose.yml",
    "docker-compose.yaml", "compose.yaml", "compose.yml", "gemfile",
    "composer.json", "build.gradle", "build.gradle.kts", "build", "build.bazel",
    "justfile", "taskfile.yml", "taskfile.yaml", "go.mod", "requirements.txt",
    "pyproject.toml", ".travis.yml", "app.json", "procfile", "deno.json",
    "deno.jsonc", "bunfig.toml", ".npmrc", ".yarnrc.yml", "cargo.toml",
    "build.rs",
)
TARGET_EXTS = (".sh", ".ps1", ".bat", ".cmd", ".py", ".rb", ".pl", ".php")
WORKFLOW_GLOB = os.path.join("**", ".github", "workflows", "*.yml")
# Only repo-committed hook dirs. `.git/hooks` is local git state (sample files
# are created by git clone itself) - scanning it produces false positives.
GIT_HOOK_DIRS = (".husky", "husky", ".githooks", "githooks")

# (key, severity, regex, detail template)
# Each regex must match the *whole dangerous fragment* so line evidence is useful.

# --- destructive `rm` detection -------------------------------------------
# A pure regex is the wrong tool for this rule. The question is "does this rm
# delete a whole filesystem root or a whole home directory?", and answering it
# by pattern alone forces a choice between missing targets (`rm -rf $HOME`) and
# swallowing safe ones (`rm -rf /tmp`, `rm -rf ~/project`). Both failure modes
# were reproduced on the previous implementation.
#
# So the rule is expressed as a predicate instead of a regex, and emitted into
# PATTERNS as a small object exposing `search()`. That keeps severity
# aggregation, SARIF output, table-driven output and the one-finding-per-line
# behaviour of scan_file completely unchanged.

# One `rm <flags> <targets...>` invocation.
_RM_CMD_RE = re.compile(r"\brm\s+(?:-{1,2}[\w-]+\s+)+[^\n;|&]*")

# A single token that, on its own, means "a whole root / a whole home".
_DANGEROUS_TARGET_RE = re.compile(
    r"^(?:"
    r"/\*?|"                                        # /        /*
    r"~|\*/?|~/\*+|\*|"                             # ~   /*   *   ~/*
    r"\$\{?HOME\}?|\$\{?USER\}?|"                   # $HOME  ${HOME}  $USER
    r"\$\{?HOME\}?/\*+|\$\{?USER\}?/\*+|"          # $HOME/*  ${HOME}/*  $USER/*
    r"\$\([^)]*\)"                                  # $(echo /)
    r")$"
)

# A target that deletes *everything inside* a root/home dir, e.g.
# `$HOME/*.bak` or `~/*.log`. These are not whole-directory wipes, but they
# still destroy the entire directory's contents, so they stay critical.
_ROOT_GLOB_RE = re.compile(
    r"^(?:"
    r"\$\{?HOME\}?|\$\{?USER\}?|~|/"
    r")/\*+\.[^\s/]+$"                              # .../*.bak  .../*.log
)


def _norm_target(raw):
    """Normalise one argument token: drop quotes, collapse a trailing slash.

    `~/` and `~` are the same target, so normalising lets one regex branch
    cover both. Doing this in code rather than regex is the point of making
    this rule a predicate.
    """
    tok = raw.strip().strip("'\"")
    if tok.endswith("/") and not tok.endswith("//"):
        tok = tok.rstrip("/") or "/"
    return tok


def _split_rm_args(cmd):
    """Split an rm command into args, keeping `$(...)` as one argument.

    A plain `str.split()` breaks `$(echo /)` into `$(echo` and `/)`.
    """
    rest = cmd.strip()[2:].strip()          # drop leading "rm"
    args, depth, buf = [], 0, ""
    for ch in rest:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch.isspace() and depth == 0:
            if buf:
                args.append(buf)
                buf = ""
            continue
        buf += ch
    if buf:
        args.append(buf)
    return args


def _rm_is_recursive(args):
    return any(re.fullmatch(r"-{1,2}(?:[a-zA-Z]*[rR][a-zA-Z]*|recursive)", a)
               for a in args)


def rm_hits_dangerous_target(text):
    """True if `text` has an `rm -r` whose target is / or a whole home dir.

    Implemented as a predicate rather than a regex: answering "is this target a
    whole root?" by pattern alone forces a choice between missing targets
    (`rm -rf $HOME`) and swallowing safe ones (`rm -rf /tmp`, `rm -rf ~/project`).
    Both failure modes were reproduced on the previous regex.
    """
    for m in _RM_CMD_RE.finditer(text):
        args = _split_rm_args(m.group(0))
        if not _rm_is_recursive(args):
            continue
        for raw in args:
            if raw.startswith("-"):
                continue
            tok = _norm_target(raw)
            if _DANGEROUS_TARGET_RE.match(tok) or _ROOT_GLOB_RE.match(tok):
                return True
    return False


PATTERNS = [
    # --- remote code execution ---
    ("curl-pipe-sh", "critical",
     r"(?:curl|wget)[^\n|;]*?[|>][^\n]*?(?:ba\s*sh|sh\s*|\s*sh\b|zsh|fish)",
     "remote content piped into a shell"),
    ("iwr-iex", "critical",
     r"(?:iwr|Invoke-WebRequest|Invoke-RestMethod)[^\n]*?iex",
     "PowerShell downloads and executes remote content"),
    ("sh-curly", "critical",
     r"(?:ba\s*sh|sh|zsh)\s+-c\s*[\"']?\$?\s*\(?(?:curl|wget)",
     "shell runs remote content via $()"),
    ("curl-exec-file", "critical",
     r"(?:curl|wget)[^\n]*?-o\s+[\w./-]+\s+[\s\S]{0,80}?(?:&&|;)\s*(?:ba\s*sh|sh|\./|python|node|perl|ruby|php)\b",
     "downloads a file then executes it"),
    ("base64-exec", "critical",
     r"base64\s*-\s*d[^\n]*?(?:\|\s*)(?:sh|ba\s*sh|eval|python|node|perl|ruby)",
     "base64-decoded payload executed"),
    ("curl-pipe-python", "high",
     r"(?:curl|wget)[^\n]*?[|>][^\n]*?python(?:3)?\b",
     "remote content piped into Python"),
    # --- reverse shells / remote control ---
    ("reverse-shell-tcp", "critical",
     r"bash\s+-i\s*[^\n]*?(?:/dev/tcp|/dev/udp)|(?:/dev/tcp/|/dev/udp/)",
     "reverse shell over /dev/tcp"),
    ("netcat-shell", "critical",
     r"\bnc\b[^\n]*(?:-e\s|/bin/|/ba\s*sh|sh\b)|(?:-e\s*/bin/)",
     "netcat with shell execution flag"),
    ("socat-reverse", "critical",
     r"\bsocat\b[^\n]*\b(?:exec|system|tcp)",
     "socat reverse shell / command execution"),
    ("mkfifo-nc", "critical",
     r"mkfifo[^\n]*\bnc\b",
     "mkfifo + nc classic reverse shell"),
    # --- secret exfiltration ---
    ("exfil-dot-env", "critical",
     r"(?:cat|type|cp|tar)[^\n]*(?:\.env|\.aws|\.ssh|\.gitconfig)[^\n]*(?:curl|wget|nc|base64)",
     "credentials read and sent to a remote"),
    ("exfil-env-var", "high",
     r"\b(?:env|printenv|export)[^\n]*(?:curl|wget|nc|base64)",
     "environment variables sent remotely"),
    ("curl-data-file", "high",
     r"(?:curl|wget)[^\n]*-d\s*@[^\n]*",
     "sends a local file body to a remote endpoint"),
    # --- privilege / system changes ---
    ("sudo-install", "high",
     r"\bsudo\b[^\n]*(?:npm|pip|gem|apt|yum|brew|dnf|pacman)\s+install",
     "package install under sudo in project script"),
    # NOTE: the alternation is wrapped in a non-capturing group. Without it the
    # top-level `|` split the pattern into three independent branches and the
    # `\b` only constrained the first, so `> /etc/...` (with a space) slipped
    # through while bare `tee /etc/hosts` matched. Grouping restores intent.
    # Kept narrow on purpose: a bare `/etc/...` path must NOT match, otherwise
    # every script that merely *reads* /etc/passwd is reported as high severity.
    ("write-system-dir", "high",
     r"\b(?:tee|cp|mv|install|rsync)\b[^\n]*?(?:/etc/|/usr/(?:local/)?bin|/root/)|"
     r">>?\s*(?:/etc/|/usr/(?:local/)?bin|/root/)",
     "writes into system directories"),
    ("docker-socket", "high",
     r"/var/run/docker\.sock|docker\s+run[^\n]*-v\s+[^\n]*/:/",
     "host docker socket or root mount access"),
    # --- destructive ---
    # `rm-root` is NOT in this table. It needs "is the last argument a whole
    # root?", which a regex cannot answer without either missing targets
    # (`rm -rf $HOME`, `rm -rf *`, `rm -rf /*`) or swallowing safe ones
    # (`rm -rf /tmp`, `rm -rf ~/project`). It is emitted by
    # `rm_findings()` below and injected by `scan_file`. The original regex
    # `rm\s+-[^\n]*\s(?:/\s|\s/\*|~\s|~/[^\s]+\s)` and its replacement are both
    # covered by tests/test_security_gate.py.
    ("dd-disk", "critical",
     r"\bdd\b[^\n]*of=/dev/(?:sda|sdb|sdc|nvme)",
     "dd writes directly to a physical disk"),
    ("fork-bomb", "critical",
     r":\(\)\s*\{\s*:\|:&\s*\};:",
     "fork bomb"),
    # --- supply chain ---
    ("npx-yes", "medium",
     r"\bnpx\b[^\n]*\s-(?:y|yes)\b",
     "npx executes a package without a pinned version"),
    ("global-install", "medium",
     r"(?:npm|pnpm|yarn|pip|gem)\s+install\s+-g\b",
     "global install inside a project script"),
    ("git-config-global", "medium",
     r"git\s+config\s+--global",
     "modifies global git configuration"),
    ("git-clone-lifecycle", "medium",
     r"\bgit\s+clone\b",
     "clones a remote repo during setup"),
    # --- raw IP endpoints in scripts ---
    ("raw-ip-exfil", "high",
     r"(?:curl|wget|nc|ping)\s+[\"']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
     "contacts a raw IP endpoint"),
    # --- known exfil / tunnel domains ---
    ("exfil-domain", "high",
     r"(?:webhook\.site|requestbin\.|pstmn\.io|oast\w*\.|interact\.sh|"
     r"burpcollaborator\.net|localhost\.run|serveo\.net|ngrok\.io|"
     r"pastebin\.com|transfer\.sh|0x0\.st)",
     "contacts a known exfiltration / tunneling / paste service"),
    ("curl-post-external", "medium",
     r"(?:curl|wget)\s+-X\s+POST|curl\s+-d\b",
     "posts data to a remote endpoint during setup"),
    # --- docker build-time fetch ---
    ("docker-add-remote", "high",
     r"^\s*ADD\s+https?://",
     "Dockerfile ADD fetches remote content at build time"),
]

# npm script names that run automatically during `npm install`.
NPM_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare",
                         "prepublish", "prepublishOnly", "prepack")

# .env files that are safe to commit (examples / templates).
SAFE_ENV_NAMES = (".env.example", ".env.sample", ".env.template",
                  ".env.dist", ".env.defaults", ".env.schema")

# Informational observations that lower risk but still worth reporting.
INFO_PATTERNS = [
    ("husky-git-hooks", r"husky|lint-staged|prepare\s*:\s*husky",
     "git hooks installed via husky/lint-staged - review .husky/* and package.json scripts"),
    ("no-lockfile-json", r'"dependencies"\s*:', "package.json without a lockfile - prefer lockfile installs"),
]

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Metadata for the predicate rule, kept beside PATTERNS so SARIF/severity code
# can look it up by key without special-casing the rule name.
RM_ROOT_META = ("rm-root", "critical",
                "recursive delete of root or home paths")


def rm_findings(rel, lineno, line):
    """Emit rm-root findings for one line (see rm_hits_dangerous_target)."""
    if rm_hits_dangerous_target(line):
        key, sev, detail = RM_ROOT_META
        return [{
            "severity": sev, "file": rel, "line": lineno,
            "pattern": key, "detail": detail,
            "evidence": line.strip()[:160],
        }]
    return []


def iter_target_files(root):
    seen = set()
    for dirpath, dirnames, filenames in os.walk(root):
        # skip heavy / hidden dirs that are not part of the repo source
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "node_modules", ".venv", "venv", "env",
                                    "__pycache__", "dist", "build", ".next", ".cache")]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            key = rel.lower()
            if key in seen:
                continue
            if key in TARGET_FILES or key.endswith(TARGET_EXTS):
                seen.add(key)
                yield rel
    # workflows
    wf_root = os.path.join(root, ".github", "workflows")
    if os.path.isdir(wf_root):
        for name in os.listdir(wf_root):
            if name.endswith((".yml", ".yaml")):
                rel = os.path.join(".github", "workflows", name)
                if rel not in seen:
                    seen.add(rel)
                    yield rel


def scan_file(root, rel):
    path = os.path.join(root, rel)
    try:
        # utf-8-sig: strip a UTF-8 BOM, otherwise json.load on package.json
        # would fail and the whole script scan would be silently skipped.
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    findings = []
    for lineno, line in enumerate(lines, 1):
        # Predicate rule first: it is critical, so it must win the
        # one-finding-per-line tie-break against lower-severity rules.
        rm_hit = rm_findings(rel, lineno, line)
        if rm_hit:
            findings.extend(rm_hit)
            continue
        for key, sev, regex, detail in PATTERNS:
            if re.search(regex, line, re.IGNORECASE):
                findings.append({
                    "severity": sev, "file": rel, "line": lineno,
                    "pattern": key, "detail": detail,
                    "evidence": line.strip()[:160],
                })
                break  # one finding per line keeps the report readable
    return findings


def scan_package_scripts(root, findings):
    pkg = os.path.join(root, "package.json")
    if not os.path.exists(pkg):
        return
    try:
        with open(pkg, "r", encoding="utf-8-sig", errors="replace") as fh:
            data = json.load(fh)
    except Exception:
        return
    scripts = data.get("scripts") or {}
    for name, cmd in scripts.items():
        if not isinstance(cmd, str):
            continue
        if name in NPM_LIFECYCLE_SCRIPTS:
            findings.append({
                "severity": "medium", "file": "package.json", "line": 0,
                "pattern": "npm-lifecycle-script",
                "detail": "npm auto-executes '%s' during install — review its contents" % name,
                "evidence": (name + ": " + cmd)[:160],
            })
        for key, sev, regex, detail in PATTERNS:
            if re.search(regex, cmd, re.IGNORECASE):
                findings.append({
                    "severity": sev, "file": "package.json",
                    "line": 0, "pattern": key, "detail": detail,
                    "evidence": (name + ": " + cmd)[:160],
                })
                break
    if not any(os.path.exists(os.path.join(root, lf))
               for lf in ("package-lock.json", "pnpm-lock.yaml", "pnpm-lock.yml",
                          "yarn.lock", "bun.lockb", "bun.lock")):
        findings.append({
            "severity": "medium", "file": "package.json", "line": 0,
            "pattern": "no-lockfile",
            "detail": "no lockfile found - dependency versions are unpinned",
            "evidence": "package.json",
        })


def scan_hooks(root, findings):
    for d in GIT_HOOK_DIRS:
        dpath = os.path.join(root, d)
        if not os.path.isdir(dpath):
            continue
        for name in os.listdir(dpath):
            p = os.path.join(dpath, name)
            try:
                with open(p, "r", encoding="utf-8-sig", errors="replace") as fh:
                    text = fh.read(4000)
            except OSError:
                continue
            for key, sev, regex, detail in PATTERNS:
                if re.search(regex, text, re.IGNORECASE):
                    findings.append({
                        "severity": sev, "file": os.path.join(d, name),
                        "line": 0, "pattern": key, "detail": detail,
                        "evidence": text.strip()[:160],
                    })
                    break


def scan_committed_env(root, findings):
    """Flag .env / .env.local etc. committed to the repo (secrets leak risk).

    .env.example / .sample / .template / .dist are explicitly safe and skipped.
    """
    skip_dirs = (".git", "node_modules", ".venv", "venv", "env",
                 "__pycache__", "dist", "build", ".next", ".cache")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            if name == ".env" or (name.startswith(".env.") and name not in SAFE_ENV_NAMES):
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                findings.append({
                    "severity": "high", "file": rel, "line": 0,
                    "pattern": "committed-env",
                    "detail": "secrets file committed to the repo — should be gitignored",
                    "evidence": name,
                })


def scan_dependency_sources(root, findings):
    """Flag dependencies installed from git / local paths instead of a registry."""
    pkg = os.path.join(root, "package.json")
    if os.path.exists(pkg):
        try:
            with open(pkg, "r", encoding="utf-8-sig", errors="replace") as fh:
                data = json.load(fh)
        except Exception:
            data = None
        if data:
            for section in ("dependencies", "devDependencies"):
                for name, ver in (data.get(section) or {}).items():
                    if isinstance(ver, str) and re.match(r"^(git\+|github:|file:|git:|ssh:)", ver):
                        findings.append({
                            "severity": "medium", "file": "package.json", "line": 0,
                            "pattern": "git-or-local-dependency",
                            "detail": "%s dependency '%s' points to a git/local source (unpinned)" % (section, name),
                            "evidence": "%s: %s" % (name, ver),
                        })
    req = os.path.join(root, "requirements.txt")
    if os.path.exists(req):
        try:
            with open(req, "r", encoding="utf-8-sig", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    s = line.strip()
                    if s.startswith("git+") or s.startswith("-e git+"):
                        findings.append({
                            "severity": "medium", "file": "requirements.txt", "line": lineno,
                            "pattern": "git-or-local-dependency",
                            "detail": "pip dependency installed from git (unpinned)",
                            "evidence": s[:160],
                        })
        except OSError:
            pass


def severity_of(findings):
    if not findings:
        return "low"
    worst = max(SEVERITY_ORDER[f["severity"]] for f in findings)
    if worst >= 3:
        return "critical"
    if worst == 2:
        return "high"
    if worst == 1:
        return "medium"
    return "low"


# --- SARIF 2.1.0 output (for GitHub code scanning) ---

VERSION = "0.6.0"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}

# Metadata for rules that are not simple PATTERNS entries.
# key: pattern id -> (rule name, short description, full description)
RULE_INFO = {
    "rm-root": (
        "RmRootTarget",
        "Recursive delete of a filesystem root or home directory",
        "An `rm -r` whose target is `/`, `/*`, `~`, `$HOME`, `${HOME}`, "
        "`$USER`, or a bare `*`. This destroys the whole filesystem or the "
        "user's entire home directory. Never run it without reading the script.",
    ),
    "committed-env": (
        "CommittedEnvFile",
        "Secrets file (.env) committed to repository",
        "A .env or .env.local file that may contain secrets is committed to the "
        "repo. It should be gitignored; only .env.example should be tracked.",
    ),
    "npm-lifecycle-script": (
        "NpmLifecycleScript",
        "npm auto-executing lifecycle script",
        "An npm lifecycle script (preinstall/install/postinstall/prepare) runs "
        "automatically during npm install. Review its contents before installing.",
    ),
    "docker-add-remote": (
        "DockerAddRemote",
        "Dockerfile ADD fetches remote content at build time",
        "Dockerfile ADD with a remote URL fetches and may execute content at "
        "build time. Prefer COPY with locally-vetted files.",
    ),
    "git-or-local-dependency": (
        "GitOrLocalDependency",
        "Dependency installed from git or local path",
        "A dependency is installed from a git URL or local path instead of a "
        "registry, so its version is unpinned and its contents can change.",
    ),
    "no-lockfile": (
        "NoLockfile",
        "No lockfile found",
        "No lockfile was found — dependency versions are unpinned and could "
        "change between installs.",
    ),
}


def _rule_name(pattern):
    return "".join(w.capitalize() for w in pattern.split("-"))


def to_sarif(findings, root):
    """Convert findings to SARIF 2.1.0 for GitHub code scanning upload."""
    rules = []
    seen = set()
    results = []
    for f in findings:
        pat = f["pattern"]
        if pat not in seen:
            seen.add(pat)
            if pat in RULE_INFO:
                name, short, full = RULE_INFO[pat]
            else:
                match = next((p for p in PATTERNS if p[0] == pat), None)
                name = _rule_name(pat)
                short = match[3] if match else pat
                full = short
            rules.append({
                "id": pat,
                "name": name,
                "shortDescription": {"text": short},
                "fullDescription": {"text": full},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(f["severity"], "warning")},
                "helpUri": "https://github.com/Jia-ben00/repo-runner#security-gate",
            })
        phys = {
            "artifactLocation": {"uri": f["file"], "uriBaseId": "%SRCROOT%"},
        }
        if f.get("line"):
            phys["region"] = {"startLine": f["line"]}
        msg = f["detail"]
        if f.get("evidence"):
            msg += " — evidence: " + f["evidence"]
        results.append({
            "ruleId": pat,
            "level": SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": phys}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "repo-runner security_gate",
                    "version": VERSION,
                    "informationUri": "https://github.com/Jia-ben00/repo-runner",
                    "rules": rules,
                },
            },
            "originalUriBaseIds": {"SRCROOT": {"uri": "file://" + root + "/"}},
            "results": results,
        }],
    }


def main():
    args = sys.argv[1:]
    sarif = False
    if "--sarif" in args:
        sarif = True
        args.remove("--sarif")
    if len(args) < 1:
        print("usage: security_gate.py [--sarif] <directory>", file=sys.stderr)
        sys.exit(1)
    root = os.path.abspath(args[0])
    if not os.path.isdir(root):
        print(json.dumps({"error": "directory not found: " + root}))
        sys.exit(2)
    findings = []
    scanned = 0
    for rel in iter_target_files(root):
        scanned += 1
        findings.extend(scan_file(root, rel))
    scan_package_scripts(root, findings)
    scan_hooks(root, findings)
    scan_committed_env(root, findings)
    scan_dependency_sources(root, findings)
    dedup = {}
    line_keys = {(f["file"], f["pattern"]) for f in findings if f["line"]}
    for f in findings:
        if not f["line"] and (f["file"], f["pattern"]) in line_keys:
            continue  # scripts-scan duplicate of a line-level finding
        key = (f["file"], f["line"] or "scripts", f["pattern"])
        if key not in dedup:
            dedup[key] = f
    findings = sorted(dedup.values(), key=lambda f: -SEVERITY_ORDER[f["severity"]])
    level = severity_of(findings)
    if sarif:
        print(json.dumps(to_sarif(findings, root), ensure_ascii=False, indent=2))
    else:
        print(json.dumps({
            "risk_level": level,
            "findings": findings,
            "scan_summary": {"files_scanned": scanned, "matched": len(findings)},
        }, ensure_ascii=False, indent=2))
    sys.exit(0 if level == "low" else 1 if level == "medium" else 2)


if __name__ == "__main__":
    main()
