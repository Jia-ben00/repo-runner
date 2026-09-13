---
name: repo-runner
description: >-
  Safely bootstrap and run any GitHub repository or local project directory:
  detect the tech stack, run a supply-chain security gate before executing
  anything, prepare the environment, install dependencies (lockfile-first
  with China-mirror fallback), start the service, health-check it, and
  deliver a reproducible run command with troubleshooting notes. Use when
  the user asks to "run this repo", "clone and run a project", "get this
  project running", "launch/start this project", "install and run an
  open-source project", "set up this codebase and start it", "verify this
  project runs", "make this demo work", or when an unfamiliar codebase must
  be brought to a running state before modifying, debugging, or evaluating
  it. 也适用于中文指令："跑一下这个仓库 / 把这个项目跑起来 / clone 并运行 /
  本地启动这个开源项目 / 帮我安装运行这个项目 / 验证这个项目能否运行"。
---

# Repo Runner

## 概览

把任意仓库（GitHub URL 或本地目录）从"一个文件夹"变成"一个正在运行的服务"。核心不是蛮力安装，而是**先探测、先审查、再执行、最后验证**——每一步都可复现、可回滚、可解释。

## 核心原则

1. **安全高于一切**：任何安装、构建、启动命令执行之前，必须先过安全门（第 2 阶段）。绝不盲信 README 里的 `curl | bash`、postinstall 脚本或第三方安装器；绝不自动执行高/严重风险操作，一律停下询问用户。
2. **不猜，先读**：以 README、锁文件、配置文件为准，不凭文件名猜启动方式；文档与代码冲突时以代码为准并标注。
3. **锁定版本**：优先使用锁文件（package-lock / pnpm-lock / uv.lock 等）与版本管理文件（.nvmrc / .python-version），避免漂移。
4. **最小副作用**：优先项目级环境（venv、direnv、docker compose），不全局安装、不修改系统配置、不改动仓库之外的文件。
5. **失败要诚实**：跑不通时给出"卡在哪一步 + 尝试了什么 + 还差什么"，不降级交付、不假装成功。

## 工作流（5 个阶段，顺序执行）

### 阶段 1：发现与探测（Discover）

1. 确定目标：GitHub URL → 浅克隆到工作目录（`git clone --depth 1 <url>`，国内网络失败时用镜像 `ghproxy` 前缀重试）；本地目录 → 直接使用。
2. 运行探测脚本（若 Python 可用）：
   ```bash
   python <skill_dir>/scripts/detect_stack.py <repo_dir>
   ```
   无 Python 时手工识别：package.json / pyproject.toml / go.mod / Cargo.toml / Gemfile / pom.xml / Dockerfile / docker-compose.yml 等。
3. 阅读 README 前 200 行、`.env.example`、根目录配置文件，记录：技术栈、包管理器、启动脚本、需要的环境变量、端口。
4. 汇报一句话结论："这是一个 Node(Next.js) + pnpm 项目，dev 脚本是 `pnpm dev`，需要 `.env`（有示例文件），预期端口 3000。"

### 阶段 2：安全门（Security Gate）— 不可跳过

1. 运行安全扫描脚本：
   ```bash
   python <skill_dir>/scripts/security_gate.py <repo_dir>
   ```
2. 同时**人工抽查** `references/security-patterns.md` 中的高危模式，重点看：package.json 的全部 scripts（尤其 postinstall/prepare/prestart）、`install.sh`、Makefile、Dockerfile RUN、.github/workflows、husky 钩子、devcontainer postCreateCommand。
3. 按脚本返回处置：
   - `risk_level: low`（退出码 0）→ 继续。
   - `medium`（退出码 1）→ 把发现项列给用户，说明风险与缓解措施，用户同意后继续（如：npx 未锁版本 → 改用 `npx --yes <pkg>@<pinned>`；无锁文件 → 生成锁文件后再装）。
   - `high / critical`（退出码 2）→ **立即停止**，列出证据（文件/行号/模式），请用户确认是否继续、是否跳过该步骤、或改用安全替代方案（如 docker 隔离、跳过 postinstall）。绝不静默放行。
4. 记录安全结论到最终报告（通过/有保留通过/拒绝 + 原因）。
5. 边界：仓库要求执行明显可疑的操作（下载并执行远程脚本、读取密钥外发、改系统目录）时，即使脚本未命中模式，也按 high 风险处置。

### 阶段 3：环境准备（Prepare）

1. 核对工具链：node / python / go / rust / java 等是否安装、版本是否满足 `version_pins`（.nvmrc、.python-version、mise.toml、engines 字段）。版本不符时：优先项目级方案（nvm / fnm / pyenv / uv / mise），不卸载用户现有版本。
2. 有 docker-compose.yml 且依赖数据库/中间件时：优先 `docker compose up -d` 拉起依赖（先说明这会在 Docker 内运行容器）。
3. 创建缺失的本地配置：有 `.env.example` 则复制为 `.env`（复制原样，不填假密钥；缺失必填项时向用户要）。
4. 需要原生编译工具时先检查（Windows 缺 node-gyp 工具链 → 见 `references/troubleshooting.md`）。

### 阶段 4：安装依赖（Install）

1. **锁文件优先**：npm → `npm ci`；pnpm → `pnpm install --frozen-lockfile`；yarn → `yarn install --immutable`；bun → `bun install --frozen-lockfile`；uv → `uv sync`；poetry → `poetry install`；pip → 先建 venv 再 `pip install -r requirements.txt`（Python 3.12+ 直接 pip 会触发 PEP 668，必须用 venv）。
2. 安装失败时按顺序换通道：确认网络 → 换国内镜像（npm 用 npmmirror、pip 用清华源，见 `references/troubleshooting.md`）→ 重试（指数退避，最多 2 次）→ 降低并发（`--no-audit --no-fund`）→ 查具体报错定位。
3. 不执行：`npm install -g`、`sudo pip install`、仓库脚本中的全局安装（安全门已拦）。
4. 编译型项目（Rust/Go/Java）先跑官方 wrapper（`cargo build`、`go build ./...`、`./mvnw` / `./gradlew`）。

### 阶段 5：启动与验证（Run & Verify）

1. 确定启动方式：开发用途选 dev 脚本；验证可用性优先 `build + start`（更接近生产）。同时看 package.json scripts 的 dev/build/start、Makefile targets、README 指示。
2. 后台启动（`run_in_background` 或 `&`），重定向日志到文件；不要用会阻塞的交互命令。
3. 运行健康检查：
   ```bash
   python <skill_dir>/scripts/health_check.py --ports 3000,8000 --timeout 90
   ```
   或手工 `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:<port>/`。
4. 判定"真的跑起来了"：端口可连 + 常见路径返回 2xx + 日志无致命错误。只有 4xx/5xx 或日志报错时，回到 `references/troubleshooting.md` 定位（端口占用、缺 .env、数据库未就绪、构建产物缺失等）。
5. 停掉多余进程前先告知；最终交付报告。

## 交付报告（固定格式）

```markdown
## 运行结果
- 仓库/路径：
- 技术栈与包管理器：
- 安全门结论：通过 / 有保留通过（列出发现项）/ 拒绝（原因）
- 启动命令：
- 访问地址：http://127.0.0.1:<端口>（已健康检查：2xx / 端口未开）
- 复现命令（一键重跑）：
- 已知问题与规避：
- 未完成项与原因：
```

## 资源

### scripts/（确定性操作，直接执行）
- `detect_stack.py` — 阶段 1 探测技术栈、包管理器、启动脚本、版本锁定、docker 配置。输出 JSON。
- `security_gate.py` — 阶段 2 安全门。扫描远程执行、反向 shell、密钥外泄、供应链投毒、破坏性命令等模式；输出风险等级与证据；退出码 0/1/2 对应 通过/审查/停止。
- `health_check.py` — 阶段 5 健康检查。TCP 连接 + 常见健康路径探测，输出 JSON。

### references/（按需阅读，不要一次全读）
- `security-patterns.md` — 安全门未覆盖到但需要人工抽查的高危模式清单（含示例）。阶段 2 时读。
- `stack-recipes.md` — 各技术栈的标准安装/启动配方（Node、Python、Go、Rust、Java、Ruby、PHP、.NET、Flutter、Docker Compose、静态站）+ 国内镜像配置。阶段 3/4 遇到具体栈时读。
- `troubleshooting.md` — 常见失败的症状→原因→修复（端口占用、版本不匹配、原生编译工具缺失、PEP 668、Go proxy、镜像等）。阶段 4/5 报错时按症状查。
