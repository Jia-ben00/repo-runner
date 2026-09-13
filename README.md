# repo-runner

### Run any GitHub repo. Safely. — an Agent Skill (SKILL.md) · 安全跑通任意 GitHub 仓库

> **中英双语介绍 · Bilingual intro**

**EN — What it does:** Take any repository — a GitHub URL or a local folder — from *just cloned* to *actually running*: stack detection, supply-chain security gate, environment prep, lockfile-first install, service startup, health check, and a reproducible run report. Zero external dependencies. No API keys. No daemons.

**中文 — 它能做什么：** 把任意仓库（GitHub 链接或本地目录）从"刚克隆完"带到"真正跑起来"：技术栈探测 → 供应链安全门 → 环境准备 → 锁文件优先安装 → 启动服务 → 健康检查，并输出可复现的运行报告。零外部依赖、无需 API Key、无常驻服务。

![repo-runner 5 阶段介绍图 / 5-stage overview](docs/repo-runner-overview.svg)

## Why this skill exists · 为什么做这个 skill

**EN —** Cloning is easy. **Running is where the pain starts**: unknown stacks, broken lockfiles, missing `.env`, native build tools, port conflicts, flaky registries — and since 2026, actively malicious repos that weaponize `postinstall` and setup scripts to hijack AI agents ([CVE-2026-47729: a clean GitHub repo can talk Claude Code into opening a reverse shell](https://datawater.com/claude-code-reverse-shell-mozilla/)). AI coding agents clone repos constantly, yet none of the major skill libraries (anthropics/skills, superpowers, ECC, awesome-claude-skills) ship a **safe** "get it running" workflow. This skill fills that gap:

> Most skills help agents *write* code. **repo-runner helps agents *run* other people's code — without getting owned.**

**中文 —** 克隆很容易，跑起来才是痛点：未知技术栈、坏掉的锁文件、缺失的 `.env`、原生编译工具、端口冲突、不稳定的镜像源——还有 2026 年以来利用 `postinstall` 和安装脚本劫持 AI 代理的恶意仓库（[CVE-2026-47729：一个干净的 GitHub 仓库就能诱导 Claude Code 打开反向 shell](https://datawater.com/claude-code-reverse-shell-mozilla/)）。AI 编程代理每天都在克隆仓库，但主流 skill 库（anthropics/skills、superpowers、ECC、awesome-claude-skills）里没有一个提供**安全**的"跑通"工作流。repo-runner 补上这个缺口：

> 大多数 skill 教代理*写*代码；**repo-runner 让代理安全地*跑*别人的代码——不翻车。**

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
