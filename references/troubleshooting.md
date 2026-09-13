# 常见失败排查手册

> 阶段 4/5 报错时按症状查找。原则：先读完整报错原文 → 定位是哪一步（安装/构建/启动/运行时）→ 按下表对照。同一动作失败两次就换通道（镜像、版本、工具），不要原地重试。

## 目录
1. 安装类
2. 构建/编译类
3. 启动/运行时类
4. 网络类
5. 权限类
6. 环境/系统类

---

## 1. 安装类

| 症状 | 原因 | 修复 |
|---|---|---|
| `npm ERR! code EINTEGRITY` / checksum 不匹配 | 锁文件与 registry 不一致或缓存损坏 | 清缓存 `npm cache clean --force` 后重装；或删除 node_modules + 锁文件重新生成（需说明版本漂移风险） |
| `npm ERR! EACCES` / `EPERM`（Windows） | node_modules 被占用/权限 | 关掉占用进程（杀 node 进程、编辑器文件监听）；`npm ci` 前先删 node_modules |
| `python -m pip install` 报 `externally-managed-environment`（PEP 668） | 系统 Python 拒绝裸装 | 用 venv：`python -m venv .venv && .venv/Scripts/pip install -r requirements.txt` |
| `ModuleNotFoundError: distutils` | Python 3.12+ 移除了 distutils | `pip install setuptools`；或用 uv/poetry 管理 |
| `yarn install` 报 Yarn Berry 语法错误 | 锁文件是经典版（yarn v1）而本机是 Berry | 看 `.yarnrc.yml` 是否存在；经典版用 `yarn install --frozen-lockfile` 或装 v1 |
| `bun` / `uv` / `pnpm` 命令不存在 | 工具未安装 | 优先仓库自带方案；或 `npm i -g pnpm`、`pip install uv`（这些是开发工具，安装前告知用户） |
| pnpm 报 `Cannot read properties of undefined` | pnpm 版本过旧/锁文件版本不匹配 | 升级 pnpm；或检查 `packageManager` 字段指定版本 |

## 2. 构建/编译类

| 症状 | 原因 | 修复 |
|---|---|---|
| `node-gyp` / `node-pre-gyp` 编译失败（Windows） | 缺 VS Build Tools / 本机 Python | 装 "Visual Studio Build Tools"（含 C++ 工作负载）；或用 `npm install --ignore-scripts` 跳过（仅当该包有预编译产物） |
| `make: command not found`（Windows） | 项目要 GNU make | 用 WSL；或 `winget install GnuWin32.make`；或改用项目 wrapper（mvnw/gradlew 等） |
| Rust `error: linker 'cc' not found` | 缺 C 链接器 | 装 MSVC Build Tools / MinGW；WSL 装 `build-essential` |
| `cannot find -lssl` 等缺库 | 系统库缺失 | 按发行版安装（`libssl-dev` 等）；Windows 用 vcpkg 或换纯 Rust 实现 |
| Java `invalid source release` | JDK 版本不符 | 用项目要求的 JDK（spring boot 3 → 17+）；`java -version` 核对 |
| 前端构建内存不足 `JavaScript heap out of memory` | Node 默认堆太小 | `NODE_OPTIONS=--max-old-space-size=4096` 重跑 build |
| 构建成功但启动 404 | 服务了旧产物 | 确认 `start` 指向最新 `dist/`；SPA 加 history 回退（见 stack-recipes 静态站） |

## 3. 启动/运行时类

| 症状 | 原因 | 修复 |
|---|---|---|
| 端口被占用 `EADDRINUSE` / `port already in use` | 已有进程占用 | `netstat -ano | findstr :<port>`（Win）/ `lsof -i :<port>`（macOS/Linux）找到 PID 后确认再杀；或换端口 `PORT=3001 npm run dev` |
| 启动即退出、日志 `Missing .env` / `DATABASE_URL` 未定义 | 环境变量缺失 | 有 `.env.example` 就复制为 `.env`；必填密钥向用户索取，不编造 |
| 连接数据库失败 `ECONNREFUSED` | 依赖服务没起 | 有 compose 文件就 `docker compose up -d db`；无则安装/启动本地数据库（告知用户） |
| `Sequelize/Prisma/TypeORM` 迁移未执行 | 表结构未建 | 按文档跑迁移：`prisma migrate deploy`、`python manage.py migrate`、`php artisan migrate` 等 |
| 首次启动交互式提示卡住（如 Next.js telemetry、npm 登录） | CLI 等待输入 | 后台运行 + `CI=1` / `--yes` / `--no-telemetry` 环境变量跳过 |
| 浏览器访问 CORS 报错 | 前后端不同源 | 开发模式一般已配代理（vite/next proxy）；没有则确认是否需要在后端加 `Access-Control-Allow-Origin`（仅本地调试） |
| 进程起来了但端口探测失败 | 服务绑定在别的主机/端口 | 看日志实际监听地址；`--host 0.0.0.0` 或 `127.0.0.1` 差异；端口在 `.env` 或代码常量 |
| `uvicorn` 等报 `[Errno 10048]` | Windows 端口占用 | 同上 netstat 处理 |

## 4. 网络类

| 症状 | 原因 | 修复 |
|---|---|---|
| npm/pip 下载超时或极慢 | 直连海外源 | 用国内镜像（见 stack-recipes 第 12 节），仍失败则重试 2 次（指数退避） |
| `git clone` 超时 | GitHub 连通性 | 用 ghproxy 镜像前缀重试；或 `git config --global http.postBuffer` 调大 |
| Go `dial tcp: lookup proxy.golang.org` | Go proxy 不通 | `go env -w GOPROXY=https://goproxy.cn,direct` |
| `curl: (60) SSL certificate problem` | 证书/镜像问题 | 不要关校验；换 `https://registry.npmmirror.com` 等正规源，或更新 CA 证书 |
| 安装到一半 `ECONNRESET` | 网络抖动 | 清部分缓存后重试；npm 可 `--fetch-retries=5 --fetch-retry-mintimeout=20000` |

## 5. 权限类

| 症状 | 原因 | 修复 |
|---|---|---|
| `EACCES: permission denied`（macOS/Linux） | node_modules 或缓存属主问题 | 项目级处理：`sudo chown -R $(whoami) <项目目录>`（改动前说明）；不用 `sudo npm install` |
| `docker: permission denied`（Linux） | 用户不在 docker 组 | `sudo usermod -aG docker $USER` 后重登；或临时 `sudo docker compose ...` |
| Docker Desktop 报引擎未启动 | Docker 服务未运行 | 启动 Docker Desktop / 服务；`docker info` 验证 |
| `Operation not permitted`（Windows 解压/构建） | 路径过长或杀软占用 | 移到短路径（如 `C:\dev\x`）；关掉对该目录的杀软实时扫描（仅本地，需用户同意） |

## 6. 环境/系统类

| 症状 | 原因 | 修复 |
|---|---|---|
| 版本不匹配（engines / .nvmrc / .python-version） | 本机工具链版本不符 | 优先项目级：`nvm use` / `fnm use` / `pyenv local` / `mise use`；不卸载系统版本 |
| Windows 上 shell 脚本（`./install.sh`）无法执行 | 项目为 Unix 脚本 | 用 WSL 或 Git Bash 执行；或按其等价命令手动执行（先过安全门） |
| 路径含中文/空格导致构建失败 | 工具链兼容性 | 复制到无中文无空格的短路径再试 |
| WSL 与 Windows 文件权限互相干扰 | 跨文件系统 | 仓库放 WSL 侧（`~/projects`）而非 `/mnt/c/...` |
| 项目要 GPU/CUDA 但本机没有 | 硬件限制 | 如实报告：能装依赖但无法满足算力需求；建议换 CPU 模式或远端 |
| `fatal: not a git repository` | 目录不是 git 仓库 | 确认克隆路径/浅克隆目录正确 |

## 兜底流程

排查超过 2 次仍失败时，停止原地重试并输出：
1. 完整报错原文（前 20 行）
2. 已尝试的通道（版本/镜像/工具）与结果
3. 需要用户决策的点（装系统工具？换 WSL？提供密钥？）
