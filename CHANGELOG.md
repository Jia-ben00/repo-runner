# Changelog

All notable changes to repo-runner are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/), and versioning is [Semantic Versioning](https://semver.org/).

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
