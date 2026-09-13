# Your AI Agent Should Never Run a Random GitHub Repo Blindly. Here's a Skill That Fixes That.

*Cross-posted from the [repo-runner](https://github.com/Jia-ben00/repo-runner) project. Now available as both an **AI Agent Skill** and a **GitHub Action**. Install with `npx skills add Jia-ben00/repo-runner` or `uses: Jia-ben00/repo-runner@v0.5.0`.*

---

## The problem: every "clone and run" is a supply-chain decision

You ask your coding agent: *"Get this repo running on my machine."*

What happens next is usually a blind trust exercise:

1. It clones the repo.
2. It reads `package.json` / `pyproject.toml` / `Makefile`.
3. It runs `npm install` — which fires every `postinstall` script in the dependency tree.
4. It runs the start command — which might shell out to anything.

At no point does it ask: *does this repo curl a remote script and pipe it to bash? Does it open a reverse shell? Does it exfiltrate my `.env`?*

This isn't hypothetical. **CVE-2026-47729** demonstrated that a malicious repository can hijack an AI agent during the setup phase — the agent's own helpfulness becomes the attack vector. And the ecosystem response has been mostly CLI tools and one-off scripts, not a reusable agent skill.

## What's missing: a deterministic, security-first workflow

There are hundreds of skills for *writing* code. There are effectively zero for *safely running arbitrary code you didn't write*.

`repo-runner` fills that gap. It's an Agent Skill (`SKILL.md`) that turns "get this repo running" into a 5-stage pipeline with a hard security gate:

```
Clone → Detect → Security Gate → Prepare → Install → Run & Verify
```

Every stage has a defined contract. The agent never improvises past a `high` or `critical` finding.

## Stage 2 is the differentiator: a security gate with evidence

The bundled `security_gate.py` scans every install/start surface — `package.json` scripts, `Makefile` targets, `Dockerfile` `RUN` instructions, GitHub Actions, husky hooks, devcontainer `postCreateCommand`, `build.rs`, and more — and looks for:

- Remote code execution (`curl | bash`, `wget | sh`, `Invoke-Expression`)
- Reverse shells (`nc -e`, `bash -i >& /dev/tcp/...`)
- Secret exfiltration (`.env` uploads, `curl` to paste sites)
- Privilege escalation and destructive commands
- Obfuscation (base64/hex payloads, string-spliced commands)
- **Committed `.env` files** (high — secrets should never be tracked)
- **npm lifecycle scripts** (`preinstall`/`postinstall`/`prepare` — auto-executed on install)
- **Dockerfile `ADD https://...`** (build-time remote fetch)
- **Git/local dependencies** (unpinned, mutable sources)

Each finding comes back with **file, line, and the matched evidence**. Verdicts are `low / medium / high / critical` with exit codes `0 / 1 / 2` — and `high` or `critical` means **stop and ask the user**. Nothing auto-runs past the gate.

We caught two real bugs during development:

1. The gate initially flagged `.git/hooks/*.sample` — files that `git clone` itself creates — as high risk. That would have meant *every* real repo triggered a false positive. Fixed by scanning only repo-committed hook directories (`.husky`, `.githooks`, etc.).
2. **More seriously:** `TARGET_FILES` contained capitalized names (`Dockerfile`, `Makefile`, `Gemfile`, `Cargo.toml`) while the matcher lowercased paths before comparing — these files were **never scanned** since v0.1.0. Discovered while adding the Dockerfile `ADD` rule. Now all-lowercase, with a CI regression test.

Both bugs are fixed and covered by CI.

## v0.2: SBOM output + hardened Docker sandbox

The latest release adds two capabilities that turn "it runs" into "it runs safely and audibly":

### CycloneDX SBOM

`sbom.py` parses **11 lockfile/manifest formats** — npm (lockfileVersion 1/2/3), pnpm-lock.yaml, yarn.lock, requirements.txt, pyproject.toml, uv.lock, poetry.lock, go.mod, Cargo.lock, Gemfile.lock, composer.lock — and emits a CycloneDX 1.5 JSON BOM. Every component carries a purl. Unsupported manifests are reported as notes, never silently skipped.

The component count goes into the final report, so you always know what you just installed.

### Hardened Docker isolation

When the security gate flags something but you still want to run it, `docker_sandbox.py` builds a two-stage container setup:

1. A **root-only prep container** copies the repo into an isolated named volume and makes it writable.
2. The **app container** starts directly as `nobody` (uid 65534) via `--user` — no setuid call needed — with `--cap-drop ALL`, `--security-opt no-new-privileges`, a read-only rootfs, tmpfs `/tmp`, 1 GB memory / 1 CPU limits, and the repo bind-mounted **read-only**.

Nothing in the install or start lifecycle ever runs as root. The port (if any) binds to `127.0.0.1` only.

> **Engineering note:** getting this right took three CI iterations. `chown` fails under `--cap-drop ALL` (no CAP_CHOWN). `cp -a` fails too (it preserves ownership → also chowns). And a runtime `setpriv`/`su` drop is impossible because CAP_SETUID is also dropped. The solution: start the app container as the target uid directly. The full writeup is in the [CHANGELOG](https://github.com/Jia-ben00/repo-runner/blob/main/CHANGELOG.md).

## v0.3–v0.5: from agent skill to CI-native security tool

Three releases turned repo-runner from a clever agent skill into a CI-native security control:

### v0.3: Security gate expansion + multi-stack CI

Four new supply-chain rules (committed `.env`, npm lifecycle scripts, Dockerfile `ADD` remote, git/local dependencies), plus the critical `TARGET_FILES` case-sensitivity fix. Docker smoke tests expanded from node-only to a **three-stack matrix** — node, python, and golang — each proving the app runs as uid 65534 inside the hardened container.

### v0.4: SARIF output + GitHub Code Scanning

`security_gate.py --sarif` emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), the OASIS standard for static analysis. CI uploads the SARIF file on every push, and findings appear natively under **Security → Code scanning** and as inline PR annotations. No extra tools, no dashboards — it's the same interface your team already uses for CodeQL.

The repo currently has **6 live code-scanning alerts** from the test fixture, proving the end-to-end integration works.

### v0.5: Standalone GitHub Action

The biggest shift: repo-runner is now a **composite GitHub Action**. You don't need an AI agent to use it — drop it into any workflow:

```yaml
- uses: Jia-ben00/repo-runner@v0.5.0
  with:
    target: https://github.com/owner/repo
    fail-on: high
    upload-sarif: true
```

It clones the repo with `--depth 1`, runs the same security gate, and can **fail the pipeline** on high/critical findings. This opens repo-runner to every team using GitHub Actions, not just agent early adopters.

## It's verified, not just claimed

CI runs **six jobs** on every push:

- **Script fixtures** — stack detection (including a UTF-8 BOM edge case), malicious vs. clean security-gate assertions, supply-chain expansion rules, a real-repo regression (`socketio/chat-example`), health-check live/dead ports, SBOM parser tests, and sandbox command-build assertions.
- **Install** — the exact README command `npx skills add Jia-ben00/repo-runner` runs end-to-end.
- **Docker smoke (×3)** — real node, python, and golang fixtures each execute inside the hardened container and assert the app ran as uid 65534.
- **Action self-test** — the GitHub Action scans both a clean fixture (expects `low`) and an evil fixture (expects the action to fail with `critical`).

All green. [See the Actions page.](https://github.com/Jia-ben00/repo-runner/actions)

## Try it

**As an agent skill:**

```bash
npx skills add Jia-ben00/repo-runner
```

Then tell your agent: *"Clone and run https://github.com/some/repo safely."* The skill triggers on phrases like *run this repo, get this project running, clone and install, reproduce this project, set up this codebase*.

**As a GitHub Action (no agent required):**

```yaml
- uses: Jia-ben00/repo-runner@v0.5.0
  with:
    target: .
    fail-on: high
```

It works with Claude Code, Codex, Cursor, and any agent that loads skills folders — or any GitHub Actions workflow. MIT licensed.

## Links

- Repository: https://github.com/Jia-ben00/repo-runner
- Latest release: [v0.5.0](https://github.com/Jia-ben00/repo-runner/releases/tag/v0.5.0)
- Overview diagram: [5-stage pipeline](https://github.com/Jia-ben00/repo-runner/blob/main/docs/repo-runner-overview.svg)
- Chinese README: [README.zh-CN.md](https://github.com/Jia-ben00/repo-runner/blob/main/README.zh-CN.md)

---

*If this saves you from one `curl | bash` surprise, star the repo — it helps other agents find it.*
