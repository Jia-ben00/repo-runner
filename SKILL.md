---
name: repo-runner
description: >-
  Safely bootstrap and run any GitHub repository or local project directory:
  detect the tech stack, run a supply-chain security gate before executing
  anything, prepare the environment, install dependencies (lockfile-first
  with China-mirror fallback), start the service, health-check it, and
  deliver a reproducible run command with troubleshooting notes. Optionally
  sandbox the run in a hardened Docker container (docker_sandbox.py) and
  emit a CycloneDX SBOM (sbom.py). Use when
  the user asks to "run this repo", "clone and run a project", "get this
  project running", "launch/start this project", "install and run an
  open-source project", "set up this codebase and start it", "verify this
  project runs", "make this demo work", or when an unfamiliar codebase must
  be brought to a running state before modifying, debugging, or evaluating
  it. 也适用于中文指令："跑一下这个仓库 / 把这个项目跑起来 / clone 并运行 /
  本地启动这个开源项目 / 帮我安装运行这个项目 / 验证这个项目能否运行"。
---

# Repo Runner

## Overview

Take any repository (a GitHub URL or a local directory) from "a folder" to "a running service". The core is not brute-force installing — it is **detect first, audit first, execute second, verify last** — every step reproducible, rollback-able, and explainable.

## Core Principles

1. **Safety above all**: before any install, build, or start command runs, the security gate (Stage 2) must pass. Never trust `curl | bash`, postinstall scripts, or third-party installers from a README blindly; never auto-run high/critical risk operations — always stop and ask the user.
2. **Read first, don't guess**: trust the README, lockfiles, and config files over filenames when deciding how to start; when docs and code conflict, trust the code and note the discrepancy.
3. **Pin versions**: prefer lockfiles (package-lock / pnpm-lock / uv.lock etc.) and version-pin files (.nvmrc / .python-version) to avoid drift.
4. **Minimal side effects**: prefer project-scoped environments (venv, direnv, docker compose); never install globally, modify system config, or touch files outside the repo.
5. **Fail honestly**: when it won't run, report "where it's stuck + what was tried + what's still missing". Never downgrade the deliverable or fake success.

## Workflow (5 stages, in order)

### Stage 1: Discover & Detect

1. Identify the target: GitHub URL → shallow-clone into the working dir (`git clone --depth 1 <url>`; retry with a `ghproxy` mirror prefix if the network fails); local directory → use it directly.
2. Run the detection script (if Python is available):
   ```bash
   python <skill_dir>/scripts/detect_stack.py <repo_dir>
   ```
   Without Python, identify manually: package.json / pyproject.toml / go.mod / Cargo.toml / Gemfile / pom.xml / Dockerfile / docker-compose.yml etc.
3. Read the first 200 lines of the README, `.env.example`, and root config files. Record: tech stack, package manager, start scripts, required env vars, ports.
4. Report a one-line conclusion: "This is a Node (Next.js) + pnpm project; the dev script is `pnpm dev`; it needs `.env` (example file provided); expected port 3000."

### Stage 2: Security Gate — mandatory, not skippable

1. Run the security scan script:
   ```bash
   python <skill_dir>/scripts/security_gate.py <repo_dir>
   ```
2. Also **manually spot-check** the high-risk patterns in `references/security-patterns.md`, focusing on: all package.json scripts (especially postinstall/prepare/prestart), `install.sh`, Makefile, Dockerfile RUN, .github/workflows, husky hooks, devcontainer postCreateCommand.
3. Act on the script result:
   - `risk_level: low` (exit 0) → continue.
   - `medium` (exit 1) → list the findings to the user with risk and mitigation, continue only with user consent (e.g. unpinned npx → use `npx --yes <pkg>@<pinned>`; no lockfile → generate one before installing).
   - `high / critical` (exit 2) → **stop immediately**, present the evidence (file/line/pattern), and ask the user whether to continue, skip that step, or use a safe alternative (e.g. **docker isolation** via `docker_sandbox.py`, skipping postinstall). Never silently proceed.
4. Record the security conclusion in the final report (passed / passed with caveats / rejected + reason).
5. Boundary: if the repo demands obviously suspicious actions (download-and-execute remote scripts, exfiltrating secrets, writing to system dirs), treat it as high risk even if no pattern matches.

### Stage 3: Prepare

1. Verify the toolchain: are node / python / go / rust / java installed, and do versions satisfy `version_pins` (.nvmrc, .python-version, mise.toml, engines fields)? If not: prefer project-scoped solutions (nvm / fnm / pyenv / uv / mise) — never uninstall the user's existing versions.
2. If docker-compose.yml exists and the project depends on databases/middleware: prefer `docker compose up -d` for dependencies (state first that this runs containers in Docker).
3. Create missing local config: if `.env.example` exists, copy it to `.env` (copy verbatim, don't invent fake secrets; ask the user for required values that are missing).
4. Check for native build tooling if needed (Windows lacking the node-gyp toolchain → see `references/troubleshooting.md`).
5. **Isolation mode** (when the user decides to run a suspicious repo anyway): build a hardened container command with
   ```bash
   python <skill_dir>/scripts/docker_sandbox.py --repo <repo_dir> --cmd "<install && start>" [--port <port>]
   ```
   The script checks docker, auto-picks a base image by stack, and prints two `docker run` commands: a root-only **prep** container that copies the repo into an isolated named volume, then the app container running as **nobody** (`--user 65534:65534`, dropped capabilities, no-new-privileges, read-only rootfs, tmpfs, memory/CPU limits, read-only repo mount) — nothing executes at image build time, and no install/start script ever runs as root. Run the printed commands (or pass `--exec`). If it exits 1 (docker unavailable), report it and let the user decide (skip the step / proceed non-isolated).

### Stage 4: Install

1. **Lockfile first**: npm → `npm ci`; pnpm → `pnpm install --frozen-lockfile`; yarn → `yarn install --immutable`; bun → `bun install --frozen-lockfile`; uv → `uv sync`; poetry → `poetry install`; pip → create a venv first, then `pip install -r requirements.txt` (Python 3.12+ direct pip triggers PEP 668 — a venv is required).
2. On install failure, switch channels in order: verify network → switch to China mirrors (npmmirror for npm, Tsinghua/PyPI mirrors for pip, see `references/troubleshooting.md`) → retry (exponential backoff, at most 2 times) → lower concurrency (`--no-audit --no-fund`) → inspect the exact error and fix the root cause.
3. Do not run: `npm install -g`, `sudo pip install`, or global installs from repo scripts (the security gate already blocks these).
4. For compiled projects (Rust/Go/Java), run the official wrapper first (`cargo build`, `go build ./...`, `./mvnw` / `./gradlew`).

### Stage 5: Run & Verify

1. Choose how to start: use the dev script for development; for availability verification prefer `build + start` (closer to production). Check package.json scripts (dev/build/start), Makefile targets, and README instructions.
2. Start in the background (`run_in_background` or `&`), redirect logs to a file; avoid blocking interactive commands.
3. Run the health check:
   ```bash
   python <skill_dir>/scripts/health_check.py --ports 3000,8000 --timeout 90
   ```
   or manually `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:<port>/`.
4. Decide "it really runs": port reachable + common paths return 2xx + no fatal errors in the logs. On 4xx/5xx or logged errors, go back to `references/troubleshooting.md` (port in use, missing .env, database not ready, missing build artifacts, etc.).
5. Emit a software bill of materials from the dependency manifests:
   ```bash
   python <skill_dir>/scripts/sbom.py <repo_dir> [--output <repo_dir>/sbom.json]
   ```
   Note the component count in the report (CycloneDX 1.5 JSON; unsupported manifests are reported as notes, not silent).
6. Announce before killing extra processes; then deliver the final report.

## Deliverable report (fixed format)

```markdown
## Run result
- Repo/path:
- Stack & package manager:
- Security gate conclusion: passed / passed with caveats (list findings) / rejected (reason)
- Start command:
- Access URL: http://127.0.0.1:<port> (health-checked: 2xx / port not open)
- SBOM: <N components> → <path> (CycloneDX 1.5)
- Repro command (one-liner to re-run):
- Known issues & workarounds:
- Unfinished items & reasons:
```

## Resources

### scripts/ (deterministic operations — run them directly)
- `detect_stack.py` — Stage 1: detect tech stack, package managers, start scripts, version pins, docker config. Outputs JSON.
- `security_gate.py` — Stage 2: the security gate. Scans for remote code execution, reverse shells, secret exfiltration, supply-chain poisoning, destructive commands, and obfuscation; outputs risk level + evidence; exit codes 0/1/2 map to proceed / review / stop.
- `health_check.py` — Stage 5: TCP connect + common health-path probing, outputs JSON.
- `sbom.py` — Stage 5: emit a CycloneDX 1.5 SBOM from lockfiles/manifests (npm, pnpm, yarn, pip, pyproject, uv, poetry, Go, Rust, Ruby, PHP). Outputs JSON.
- `docker_sandbox.py` — Stage 3 isolation mode: check docker, pick a base image by stack, and build (or `--exec`) hardened two-stage `docker run` commands — app runs as nobody, dropped caps, read-only rootfs, resource limits.

### references/ (read on demand, not all at once)
- `security-patterns.md` — high-risk patterns the gate may miss but that need manual spot-checks (with examples). Read in Stage 2.
- `stack-recipes.md` — standard install/start recipes per stack (Node, Python, Go, Rust, Java, Ruby, PHP, .NET, Flutter, Docker Compose, static sites) + China mirror configs. Read in Stages 3/4 when a specific stack is hit.
- `troubleshooting.md` — common failures as symptom → cause → fix (port in use, version mismatch, missing native build tooling, PEP 668, Go proxy, mirrors, etc.). Look up by symptom on errors in Stages 4/5.
