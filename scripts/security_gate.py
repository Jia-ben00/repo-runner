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

TARGET_FILES = (
    "package.json", "Makefile", "Dockerfile", "install.sh", "setup.sh",
    "bootstrap.sh", "devcontainer.json", "docker-compose.yml",
    "docker-compose.yaml", "compose.yaml", "compose.yml", "Gemfile",
    "composer.json", "build.gradle", "build.gradle.kts", "BUILD", "BUILD.bazel",
    "justfile", "Taskfile.yml", "Taskfile.yaml", "go.mod", "requirements.txt",
    "pyproject.toml", ".travis.yml", "app.json", "Procfile", "deno.json",
    "deno.jsonc", "bunfig.toml", ".npmrc", ".yarnrc.yml", "Cargo.toml",
)
TARGET_EXTS = (".sh", ".ps1", ".bat", ".cmd", ".py", ".rb", ".pl", ".php")
WORKFLOW_GLOB = os.path.join("**", ".github", "workflows", "*.yml")
# Only repo-committed hook dirs. `.git/hooks` is local git state (sample files
# are created by git clone itself) - scanning it produces false positives.
GIT_HOOK_DIRS = (".husky", "husky", ".githooks", "githooks")

# (key, severity, regex, detail template)
# Each regex must match the *whole dangerous fragment* so line evidence is useful.
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
    ("write-system-dir", "high",
     r"\b(?:tee|>|>>)\s*/etc/|/usr/(?:local/)?bin|/root/",
     "writes into system directories"),
    ("docker-socket", "high",
     r"/var/run/docker\.sock|docker\s+run[^\n]*-v\s+[^\n]*/:/",
     "host docker socket or root mount access"),
    # --- destructive ---
    ("rm-root", "critical",
     r"rm\s+-[^\n]*\s(?:/\s|\s/\*|~\s|~/[^\s]+\s)",
     "recursive delete of root or home paths"),
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
]

# Informational observations that lower risk but still worth reporting.
INFO_PATTERNS = [
    ("husky-git-hooks", r"husky|lint-staged|prepare\s*:\s*husky",
     "git hooks installed via husky/lint-staged - review .husky/* and package.json scripts"),
    ("no-lockfile-json", r'"dependencies"\s*:', "package.json without a lockfile - prefer lockfile installs"),
]

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


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


def main():
    if len(sys.argv) < 2:
        print("usage: security_gate.py <directory>", file=sys.stderr)
        sys.exit(1)
    root = os.path.abspath(sys.argv[1])
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
    print(json.dumps({
        "risk_level": level,
        "findings": findings,
        "scan_summary": {"files_scanned": scanned, "matched": len(findings)},
    }, ensure_ascii=False, indent=2))
    sys.exit(0 if level == "low" else 1 if level == "medium" else 2)


if __name__ == "__main__":
    main()
