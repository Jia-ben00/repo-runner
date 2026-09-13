**English** | [中文版 (Chinese)](README.zh-CN.md)

# repo-runner

### Run any GitHub repo. Safely. — an Agent Skill (SKILL.md)

[![smoke](https://github.com/Jia-ben00/repo-runner/actions/workflows/smoke.yml/badge.svg)](https://github.com/Jia-ben00/repo-runner/actions/workflows/smoke.yml)

Take any repository — a GitHub URL or a local folder — from *just cloned* to *actually running*: stack detection, supply-chain security gate, environment prep, lockfile-first install, service startup, health check, and a reproducible run report.

**Zero external dependencies. No API keys. No daemons. Pure Python stdlib scripts + one SKILL.md.**

![repo-runner 5-stage workflow overview](docs/repo-runner-overview.svg)

## Why this skill exists

Cloning is easy. **Running is where the pain starts**: unknown stacks, broken lockfiles, missing `.env`, native build tools, port conflicts, flaky registries — and since 2026, actively malicious repos that weaponize `postinstall` and setup scripts to hijack AI agents ([CVE-2026-47729: a clean GitHub repo can talk Claude Code into opening a reverse shell](https://datawater.com/claude-code-reverse-shell-mozilla/)). AI coding agents clone repos constantly, yet none of the major skill libraries (anthropics/skills, superpowers, ECC, awesome-claude-skills) ship a **safe** "get it running" workflow. This skill fills that gap:

> Most skills help agents *write* code. **repo-runner helps agents *run* other people's code — without getting owned.**

## Features

- **5-stage deterministic workflow**: Detect → Security Gate → Prepare → Install → Run & Verify
- **Security gate with evidence**: scans for remote code execution, reverse shells, secret exfiltration, privilege escalation, destructive commands, supply-chain and obfuscation patterns — reports file/line/evidence, verdicts `low / medium / high / critical` (exit codes `0 / 1 / 2`)
- **Lockfile-first installs**: `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`, `uv sync`, poetry, pip+venv (PEP 668 aware)
- **China-friendly out of the box**: npm/pip/Go/Ruby/Maven mirrors + `ghproxy` clone fallback
- **Reproducible output**: every run ends with a one-line command to re-run everything, plus known issues and workarounds
- **Portable**: one folder, standard `SKILL.md` format, works with Claude Code, Codex, Cursor, OpenClaw and any agent that loads skills folders

## Install

```bash
# One command (Claude Code / Codex / Cursor / any agent with npx skills)
npx skills add Jia-ben00/repo-runner

# Manual: copy the folder to your agent's skills directory
cp -r repo-runner ~/.claude/skills/
```

Requires: `git`, a runtime for the target stack, and Python 3.8+ for the helper scripts (the workflow still runs via manual checks if Python is unavailable).

## Usage

Just say:

```
Run https://github.com/owner/repo
Clone and run this project
Get this repo running so I can debug it
```

The skill then:

1. **Shallow-clones** the repo (`--depth 1`, ghproxy fallback for CN networks)
2. **Detects** the stack, package manager, start scripts, version pins, docker config (`scripts/detect_stack.py`)
3. **Gates** the repo for dangerous setup patterns — **nothing executes before this passes** (`scripts/security_gate.py`)
4. **Prepares** the environment: version pins (`.nvmrc` / `.python-version`), `.env` from `.env.example`, `docker compose` for database dependencies
5. **Installs** with lockfiles; falls back to mirrors on network failure; never global-installs
6. **Starts** the service, **health-checks** it (TCP + common health paths, `scripts/health_check.py`), and reports ports/URLs + a reproduce command

## The 5 stages

| Stage | What happens | Key artifact |
|---|---|---|
| 1. Detect | Clone + identify stack, package manager, scripts, version pins, docker | `detect_stack.py` → JSON |
| 2. Security Gate | Scan install/start surfaces for malicious patterns; verdict before any execution | `security_gate.py` → risk level + evidence |
| 3. Prepare | Toolchain versions, `.env`, compose dependencies, native build tools | env checklist |
| 4. Install | Lockfile-first, mirror fallback, venv/isolated envs | installed deps |
| 5. Run & Verify | Start in background, health-check, log analysis, reproduce report | `health_check.py` + report |

## Scripts

| Script | Purpose | Output |
|---|---|---|
| `scripts/detect_stack.py` | Stack / package manager / scripts / version pins / docker detection | JSON |
| `scripts/security_gate.py` | Supply-chain & malicious-pattern scan of install/start surfaces | JSON + exit `0/1/2` |
| `scripts/health_check.py` | TCP + HTTP health probing of a started service | JSON + exit code |

## Security model

- **Nothing executes before the gate passes.** `curl | bash`, `postinstall` scripts, Makefile targets, Dockerfile `RUN`, GitHub Actions, husky hooks and devcontainer `postCreateCommand` are all scanned.
- **Exit codes are a contract**: `0` proceed · `1` review with the user first · `2` stop and ask — high/critical findings are never auto-run.
- **Obfuscation is treated as guilt**: base64/hex payloads, string-spliced commands, download-then-execute — anything hidden is handled as worst-case.
- Full manual pattern catalog: [`references/security-patterns.md`](references/security-patterns.md).

## Compatibility

| Agent | Install |
|---|---|
| Claude Code | `npx skills add Jia-ben00/repo-runner` or copy to `~/.claude/skills/` |
| Codex / Cursor / OpenClaw | copy folder to the agent's skills directory |
| Any SKILL.md loader | copy folder, reload |

## License

[MIT](LICENSE)
