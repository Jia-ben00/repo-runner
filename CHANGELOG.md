# Changelog

All notable changes to repo-runner are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/), and versioning is [Semantic Versioning](https://semver.org/).

## [v0.2.0] - 2026-09-13

### Added

- `scripts/sbom.py` — CycloneDX 1.5 SBOM generation from lockfiles/manifests: npm (`package-lock.json` v1/2/3), pnpm-lock.yaml, yarn.lock (v1), requirements.txt, pyproject.toml, uv.lock, poetry.lock, go.mod, Cargo.lock, Gemfile.lock, composer.lock. Each component carries a purl; unsupported manifests are reported as notes, never silently skipped.
- `scripts/docker_sandbox.py` — hardened Docker isolation for suspicious repos: non-root user (setpriv drop to nobody/65534), `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only` rootfs + tmpfs, `--memory`/`--cpus` limits, repo bind-mounted read-only, single `127.0.0.1` port mapping. `--check-only` prints the command; `--exec` runs it. Auto-picks a base image from stack markers.
- SKILL.md: isolation-mode step in Stage 3 (gate-flagged repos can be run sandboxed), SBOM step in Stage 5, an SBOM line in the deliverable report, and both new scripts in Resources. Frontmatter description mentions the two capabilities.
- README (EN + zh-CN): SBOM and sandboxed-run feature bullets + two new rows in the scripts table.
- `references/troubleshooting.md`: Docker isolation section (docker not found, daemon down, setpriv fallback, slow image pulls, read-only write errors, leftover volume cleanup).

### Fixed

- (v0.2 development) sbom parsers: version specifiers without a space (`fastapi>=0.100`), yarn v1 `version "x.y.z"` syntax, pnpm-lock.yaml being YAML (not TOML).
- (v0.2 development) `docker_sandbox.py`: the copy step used `chown`/`cp -a`, both of which fail with EPERM under `--cap-drop ALL` (container root has no CAP_CHOWN) — replaced with `cp -R` + `chmod -R a+rwX`, keeping the dropped (nobody) user writable for installs. Windows repo paths are normalized to forward slashes for Docker volume syntax.

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
