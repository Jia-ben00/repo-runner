# Your AI Agent Should Never Run a Random GitHub Repo Blindly. Here's a Skill That Fixes That.

*Cross-posted from the [repo-runner](https://github.com/Jia-ben00/repo-runner) project. Install with `npx skills add Jia-ben00/repo-runner`.*

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

The bundled `security_gate.py` scans every install/start surface — `package.json` scripts, `Makefile` targets, `Dockerfile` `RUN` instructions, GitHub Actions, husky hooks, devcontainer `postCreateCommand` — and looks for:

- Remote code execution (`curl | bash`, `wget | sh`, `Invoke-Expression`)
- Reverse shells (`nc -e`, `bash -i >& /dev/tcp/...`)
- Secret exfiltration (`.env` uploads, `curl` to paste sites)
- Privilege escalation and destructive commands
- Obfuscation (base64/hex payloads, string-spliced commands)

Each finding comes back with **file, line, and the matched evidence**. Verdicts are `low / medium / high / critical` with exit codes `0 / 1 / 2` — and `high` or `critical` means **stop and ask the user**. Nothing auto-runs past the gate.

We caught a real bug during development: the gate initially flagged `.git/hooks/*.sample` — files that `git clone` itself creates — as high risk. That would have meant *every* real repo triggered a false positive. Fixed by scanning only repo-committed hook directories (`.husky`, `.githooks`, etc.). The regression test is in CI.

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

## It's verified, not just claimed

CI runs three jobs on every push:

- **Script fixtures** — stack detection (including a UTF-8 BOM edge case), malicious vs. clean security-gate assertions, a real-repo regression (`socketio/chat-example`), health-check live/dead ports, SBOM parser tests, and sandbox command-build assertions.
- **Install** — the exact README command `npx skills add Jia-ben00/repo-runner` runs end-to-end.
- **Docker smoke** — a real node fixture executes inside the hardened container and asserts the app ran as uid 65534.

All green. [See the Actions page.](https://github.com/Jia-ben00/repo-runner/actions)

## Try it

```bash
npx skills add Jia-ben00/repo-runner
```

Then tell your agent: *"Clone and run https://github.com/some/repo safely."* The skill triggers on phrases like *run this repo, get this project running, clone and install, reproduce this project, set up this codebase*.

It works with Claude Code, Codex, Cursor, and any agent that loads skills folders. MIT licensed.

## Links

- Repository: https://github.com/Jia-ben00/repo-runner
- Latest release: [v0.2.0](https://github.com/Jia-ben00/repo-runner/releases/tag/v0.2.0)
- Overview diagram: [5-stage pipeline](https://github.com/Jia-ben00/repo-runner/blob/main/docs/repo-runner-overview.svg)
- Chinese README: [README.zh-CN.md](https://github.com/Jia-ben00/repo-runner/blob/main/README.zh-CN.md)

---

*If this saves you from one `curl | bash` surprise, star the repo — it helps other agents find it.*
