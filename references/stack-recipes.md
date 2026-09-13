# 技术栈运行配方

> 阶段 3/4 遇到具体技术栈时读取。每项给出：检测依据 → 安装 → 启动 → 端口与环境注意点。优先使用仓库自带锁文件与 wrapper。

## 目录
1. Node.js 系（React / Vue / Next / Nuxt / Vite / Express / Nest）
2. Python 系（Django / Flask / FastAPI / Streamlit）
3. Go
4. Rust
5. Java（Spring Boot / Gradle / Maven）
6. Ruby（Rails）
7. PHP（Laravel）
8. .NET
9. Flutter
10. Docker Compose
11. 纯静态站
12. 国内镜像速查

---

## 1. Node.js 系

- **检测**：package.json + 锁文件（pnpm-lock / yarn.lock / package-lock / bun.lock）
- **安装**（锁文件优先，失败再看下方镜像）：
  ```bash
  npm ci            # 有 package-lock.json
  pnpm install --frozen-lockfile   # 有 pnpm-lock.yaml
  yarn install --immutable         # 有 yarn.lock（Yarn Berry）
  bun install --frozen-lockfile    # 有 bun.lock
  ```
- **启动**：看 scripts 顺序——优先 `dev`（热更，前台开发）；验证可用性用 `build && start`。常见框架：
  - Next.js：`npm run dev` → http://localhost:3000
  - Vite：`npm run dev` → http://localhost:5173
  - Nuxt：`npm run dev` → http://localhost:3000
  - Express/Fastify/Nest：`npm run dev` / `npm start` → 端口见 `.env`/代码（常为 3000/4000/8080）
- **注意**：`.env` 缺失常导致启动即挂——有 `.env.example` 就复制；首次交互提示可用 `CI=1` 或 `--yes` 跳过；Electron/Tauri 项目需要图形环境，容器/无头环境跑不起来要如实说明。

## 2. Python 系

- **检测**：requirements.txt / pyproject.toml / Pipfile / uv.lock / manage.py / app.py
- **安装**（Python 3.12+ 直接 pip 会报 PEP 668，**必须**用虚拟环境）：
  ```bash
  # uv（最快，推荐）
  uv sync                        # 有 uv.lock / pyproject.toml
  uv venv && uv pip install -r requirements.txt

  # 标准 venv
  python -m venv .venv
  .venv/Scripts/activate         # Windows
  source .venv/bin/activate      # macOS / Linux
  pip install -r requirements.txt
  ```
- **启动**：
  - Django：`python manage.py migrate && python manage.py runserver` → :8000
  - Flask：`flask --app app run` / `python app.py` → :5000
  - FastAPI：`uvicorn main:app --reload` → :8000（看文档）
  - Streamlit：`streamlit run app.py` → :8501
- **注意**：Django 先 migrate 再 runserver；依赖里含 numpy/pandas 等二进制包时先确认 Python 版本匹配；`distutils` 缺失（3.12+）时 `pip install setuptools`。

## 3. Go

- **检测**：go.mod（+ go.sum）
- **安装**：`go mod download`（有 go.sum 时自动校验）
- **启动**：`go run .` / `go run ./cmd/<name>`；构建：`go build ./...`
- **注意**：国内拉取失败 → 设 `GOPROXY=https://goproxy.cn,direct`；CGO 项目（依赖 cgo 的库）在 Windows 需 gcc（MinGW）或 WSL。

## 4. Rust

- **检测**：Cargo.toml + Cargo.lock
- **安装**：`cargo build`（首轮编译可能很慢，属正常；可加 `--release` 供生产验证）
- **启动**：`cargo run`；多 bin 时 `cargo run --bin <name>`
- **注意**：编译失败看缺失系统库（如 `libssl` → Windows 装 OpenSSL 或用 vcpkg）；不要中断首次编译（会丢增量）。

## 5. Java（Spring Boot / Gradle / Maven）

- **检测**：pom.xml（Maven）/ build.gradle、gradlew、mvnw
- **安装与启动**：
  ```bash
  ./mvnw spring-boot:run        # 或 ./mvnw package && java -jar target/*.jar
  ./gradlew bootRun             # Gradle
  ```
  Windows 用 `.\mvnw.cmd` / `.\gradlew.bat`。
- **注意**：先确认 JDK 版本（spring boot 3 需 JDK 17+）；Maven 国内拉包慢 → 阿里云镜像（settings.xml mirrors）；端口默认 8080。

## 6. Ruby（Rails）

- **检测**：Gemfile + Gemfile.lock
- **安装**：`bundle install`（锁文件存在时自动用锁定版本）
- **启动**：`bin/rails server` / `bin/rails db:prepare && bin/rails server` → :3000
- **注意**：原生 gem（pg、nokogiri）需编译工具；Windows 上 Rails 建议 WSL2；国内 gem 源：`bundle config mirror.https://rubygems.org https://gems.ruby-china.com`。

## 7. PHP（Laravel）

- **检测**：composer.json + composer.lock
- **安装**：`composer install`（`--no-dev` 供生产验证）
- **启动**：`php artisan serve` → :8000；先 `cp .env.example .env && php artisan key:generate`，数据库就绪后 `php artisan migrate`
- **注意**：PHP 版本需满足 composer 要求；缺扩展（如 `pdo_mysql`）按报错补。

## 8. .NET

- **检测**：.sln / .csproj
- **安装**：`dotnet restore`
- **启动**：`dotnet run` → 端口见 launchSettings.json（常见 5000/5001/7000 等）
- **注意**：SDK 与目标框架版本需匹配（`dotnet --list-sdks` 核对）；HTTPS 端口需要开发证书（`dotnet dev-certs https`）。

## 9. Flutter

- **检测**：pubspec.yaml + pubspec.lock
- **安装**：`flutter pub get`
- **运行**：桌面/web：`flutter run -d windows` / `flutter run -d chrome`；先 `flutter doctor` 检查工具链
- **注意**：无头/服务器环境无法跑 GUI，如实说明；只验证依赖与静态分析可用 `flutter analyze`。

## 10. Docker Compose

- **检测**：docker-compose.yml / compose.yaml；常同时有服务端（web）+ 数据库（db/redis/...）
- **流程**：
  ```bash
  docker compose up -d          # 后台起全部服务
  docker compose logs -f web    # 看服务日志
  docker compose ps             # 端口映射状态
  ```
- **注意**：先确认 Docker 运行中（`docker info`）；端口映射冲突时改 `ports`；数据库初始化脚本挂载在 `docker-entrypoint-initdb.d` 时首次启动会执行，等 `healthy` 再连；停止：`docker compose down`（数据卷除非加 `-v` 不会删）。

## 11. 纯静态站

- **检测**：index.html + dist/ / public/ / docs/，无后端依赖
- **启动**：
  ```bash
  python -m http.server 8080 -d .          # 或指定 dist 目录
  npx serve .                               # Node 环境
  ```
- **注意**：SPA（history 路由）需要 `serve -s` 回退到 index.html；跨域调试可用 `npx http-server --cors`。

## 12. 国内镜像速查

| 工具 | 镜像配置 |
|---|---|
| npm | `npm config set registry https://registry.npmmirror.com`（或临时 `--registry`） |
| pnpm | `pnpm config set registry https://registry.npmmirror.com` |
| pip | `pip install -i https://pypi.tuna.tsinghua.edu.cn/simple <pkg>` |
| uv | `export UV_DEFAULT_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple`（或 `--default-index`） |
| Go | `go env -w GOPROXY=https://goproxy.cn,direct` |
| Ruby | `bundle config mirror.https://rubygems.org https://gems.ruby-china.com` |
| Maven | settings.xml 配阿里云 `https://maven.aliyun.com/repository/public` |
| GitHub 克隆 | `git clone https://ghproxy.com/https://github.com/<owner>/<repo>.git`（或 gh-proxy.com 等可用镜像） |
