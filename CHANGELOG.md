# Changelog

All notable changes to repo-runner are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/), and versioning is [Semantic Versioning](https://semver.org/).

## [v0.5.0] - 2026-09-13

### Added

- **GitHub Action** (`action.yml`) — repo-runner is now usable as a standalone composite Action, no AI agent required. Scans any repo URL or local path in CI.
  - Inputs: `target` (URL or path), `sarif-output`, `fail-on` (low/medium/high), `upload-sarif` (auto-upload to code scanning).
  - Outputs: `risk-level`, `findings`.
  - Clones remote repos with `--depth 1`; runs the same security gate as the skill; can block the pipeline on high/critical findings.
- CI — `action-self-test` job: scans the repo itself (expects `low`) and an evil fixture (expects the action to fail), verifying both the pass and block paths.
- README (EN + zh-CN) — "GitHub Action" section with usage example, inputs/outputs table.

## [v0.4.0] - 2026-09-13

### Added

- `security_gate.py --sarif` — emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for GitHub code scanning. Each finding becomes a `result` with `ruleId`, level (`critical`/`high` → error, `medium` → warning, `low`/`info` → note), message with evidence, and physical location (file + line). Rule definitions include name, short/full description, default configuration, and help URI.
- CI — generates SARIF from the evil supply-chain fixture and uploads it via `github/codeql-action/upload-sarif@v3` on every push to `main` (category: `repo-runner-security-gate`). Workflow now declares `security-events: write` permission.
- README (EN + zh-CN) — "Code scanning integration" section with a copy-paste workflow snippet; scripts table notes `--sarif`.

## [v0.3.0] - 2026-09-13

### Added

- `security_gate.py` — four new supply-chain rules:
  - `committed-env` (high): `.env` / `.env.local` etc. committed to the repo (`.env.example` / `.sample` / `.template` / `.dist` are explicitly safe).
  - `npm-lifecycle-script` (medium): `preinstall` / `install` / `postinstall` / `prepare` / `prepublish` scripts that npm auto-executes during install.
  - `docker-add-remote` (high): Dockerfile `ADD https://...` fetching remote content at build time.
  - `git-or-local-dependency` (medium): `package.json` dependencies pointing to `git+` / `github:` / `file:` / `ssh:` sources, or `requirements.txt` lines starting with `git+`.
- `security_gate.py` — `build.rs` added to target files (Rust build scripts execute at compile time).
- CI — `security_gate` supply-chain expansion step with `evil_supply` / `clean_supply` fixtures asserting all four new rules fire and none false-positive.
- CI — `docker-smoke` expanded from node-only to a **three-stack matrix**: `node:22-slim`, `python:3.12-slim`, `golang:1.24-bookworm`, each asserting the app runs as uid 65534 inside the hardened container.
- README (EN + zh-CN) — "Example" section with real `security_gate` JSON output and the final reproducible report format.

### Fixed

- **Critical**: `security_gate.py` `TARGET_FILES` contained capitalized names (`Dockerfile`, `Makefile`, `Gemfile`, `Cargo.toml`, `BUILD`) while `iter_target_files` lowercased the path before matching — these files were **never scanned** since v0.1.0. `TARGET_FILES` is now all-lowercase. Discovered while adding the `docker-add-remote` rule.
- CI golang fixture: `go run` placed the compiled binary on tmpfs (`/tmp`), which can be `noexec`; changed to `go build -o main main.go && ./main` (compiles into the named volume).

## [v0.2.0] - 2026-09-13

### Added

- `scripts/sbom.py` — CycloneDX 1.5 SBOM generation from lockfiles/manifests: npm (`package-lock.json` v1/2/3), pnpm-lock.yaml, yarn.lock (v1), requirements.txt, pyproject.toml, uv.lock, poetry.lock, go.mod, Cargo.lock, Gemfile.lock, composer.lock. Each component carries a purl; unsupported manifests are reported as notes, never silently skipped.
- `scripts/docker_sandbox.py` — hardened Docker isolation for suspicious repos: a root-only **prep** container copies the repo into an isolated named volume, then the app container runs as **nobody** (`--user 65534:65534` at start), `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only` rootfs + tmpfs, `--memory`/`--cpus` limits, repo bind-mounted read-only, single `127.0.0.1` port mapping. `--check-only` prints both commands; `--exec` runs them. Auto-picks a base image from stack markers.
- SKILL.md: isolation-mode step in Stage 3 (gate-flagged repos can be run sandboxed), SBOM step in Stage 5, an SBOM line in the deliverable report, and both new scripts in Resources. Frontmatter description mentions the two capabilities.
- README (EN + zh-CN): SBOM and sandboxed-run feature bullets + two new rows in the scripts table.
- `references/troubleshooting.md`: Docker isolation section (docker not found, daemon down, setpriv fallback, slow image pulls, read-only write errors, leftover volume cleanup).

### Fixed

- (v0.2 development) sbom parsers: version specifiers without a space (`fastapi>=0.100`), yarn v1 `version "x.y.z"` syntax, pnpm-lock.yaml being YAML (not TOML).
- (v0.2 development) `docker_sandbox.py`: privilege dropping cannot use `chown`, `cp -a` or a runtime setuid/setpriv step under `--cap-drop ALL` (container root has no CAP_CHOWN/CAP_SETUID → EPERM) — the container now starts directly as uid 65534 via `--user` (runc sets the uid at exec), and repo copy + volume permissions happen in a separate root-only prep container. Windows repo paths are normalized to forward slashes for Docker volume syntax.

### CI

- `sbom` fixture tests (npm lock + pyproject → CycloneDX structure/purl assertions).
- `docker_sandbox` command-build assertions (cap-drop/read-only/setpriv present, image detection).
- New `docker-smoke` job: actually runs a node fixture inside the hardened container on every push/PR and asserts the app ran as uid 65534.

## [v0.1.0] - 2026-09-13

First public release — a safe, reproducible "get it running" Agent Skill for any GitHub repo or local project.

### Added

- `SKILL.md` with a 5-stage workflow (Discover & Detect → Security Gate → Prepare → Install → Run & Verify) and a fixed deliverable-report format.
- `scripts/detect_stack.py` — tech-stack / package-manager / scripts / version-pins / docker detection (JSON output).
- `scripts/security_gate.py` — supply-chain gate with evidence (file/line/pattern), risk levels `low / medium / high / critical`, exit codes `0 / 1 / 2`.
- `scripts/health_check.py` — TCP connect + common health-path probing (JSON output).
- `references/security-patterns.md` — 9 categories of high-risk patterns for manual spot-checks.
- `references/stack-recipes.md` — per-stack install/start recipes (Node, Python, Go, Rust, Java, Ruby, PHP, .NET, Flutter, Docker Compose, static sites) + China mirror configs.
- `references/troubleshooting.md` — symptom → cause → fix handbook.
- English README with a `README.zh-CN.md` Chinese entry and language switch, plus an English 5-stage overview diagram.
- MIT license.

### Fixed

- Security gate no longer flags `.git/hooks/*.sample` (created by `git clone` itself) as high risk — scanning only covers repo-committed hook dirs (`.husky`, `husky`, `.githooks`, `githooks`).
- `detect_stack.py` and `security_gate.py` read files as UTF-8-sig, so a BOM'd `package.json` (common from Windows editors) still parses — previously the gate could silently skip script scanning on such files.

### CI

- `.github/workflows/smoke.yml` runs on every push/PR: script fixture tests (incl. a UTF-8 BOM edge case and malicious/clean security-gate cases), real-repo regression (`socketio/chat-example`), skill-structure validation, and an end-to-end `npx skills add Jia-ben00/repo-runner` install check.
