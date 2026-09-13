#!/usr/bin/env python3
"""Detect the tech stack of a repository or project directory.

Stdlib only, cross-platform. Prints one JSON object to stdout:
{
  "path": <abs path>,
  "stacks": ["node", ...],
  "package_managers": ["pnpm", ...],
  "scripts": {"dev": "...", "build": "...", "start": "..."},   # node only
  "version_pins": {"node": "20", "python": "3.12"},
  "docker": {"has_dockerfile": true, "compose": ["db", "web"]},
  "notes": ["found lockfile: pnpm-lock.yaml"]
}

Exit codes: 0 = ok, 1 = bad args, 2 = directory not found.
"""
import json
import os
import sys


def has_any(path, names):
    return [n for n in names if os.path.exists(os.path.join(path, n))]


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def read_text(path, limit=4000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except Exception:
        return ""


def node_detection(root, out):
    pkg_path = os.path.join(root, "package.json")
    pkg = read_json(pkg_path)
    if not pkg:
        return
    out["stacks"].append("node")
    scripts = pkg.get("scripts") or {}
    out["scripts"] = scripts
    deps = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, ver in (pkg.get(key) or {}).items():
            deps[name] = ver
    lowered = " ".join(deps.keys()).lower()
    framework_map = {
        "next": "next", "nuxt": "nuxt", "vite": "vite", "react": "react",
        "vue": "vue", "svelte": "svelte", "angular": "angular", "astro": "astro",
        "express": "express", "fastify": "fastify", "@nestjs/core": "nestjs",
        "electron": "electron", "remix": "remix", "gatsby": "gatsby",
        "docusaurus": "docusaurus", "umi": "umi", "taro": "taro",
    }
    for needle, label in framework_map.items():
        if needle in lowered:
            out["notes"].append("framework: " + label)
    managers = []
    for lock in ("pnpm-lock.yaml", "pnpm-lock.yml"):
        if os.path.exists(os.path.join(root, lock)):
            managers.append("pnpm")
    if "yarn.lock" in has_any(root, ["yarn.lock"]):
        managers.append("yarn")
    if os.path.exists(os.path.join(root, "bun.lockb")) or os.path.exists(os.path.join(root, "bun.lock")):
        managers.append("bun")
    if os.path.exists(os.path.join(root, "package-lock.json")):
        managers.append("npm")
    if not managers:
        managers.append("npm(no-lockfile)")
        out["notes"].append("no lockfile found - supply-chain risk, prefer lockfile install")
    out["package_managers"].extend(managers)
    if pkg.get("packageManager"):
        out["notes"].append("packageManager field: " + str(pkg["packageManager"]))


def python_detection(root, out):
    markers = ["requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile",
               "setup.py", "setup.cfg", "uv.lock", "poetry.lock", "Pipfile.lock",
               "manage.py", "app.py", "wsgi.py", "asgi.py"]
    found = has_any(root, markers)
    if not found:
        return
    out["stacks"].append("python")
    if "uv.lock" in found:
        out["package_managers"].append("uv")
    elif "poetry.lock" in found:
        out["package_managers"].append("poetry")
    elif "Pipfile.lock" in found:
        out["package_managers"].append("pipenv")
    elif "pyproject.toml" in found:
        out["package_managers"].append("pip+pyproject")
    elif "requirements.txt" in found or "requirements-dev.txt" in found:
        out["package_managers"].append("pip")
    for marker in ("manage.py",):
        if marker in found:
            out["notes"].append("framework: django")
    text = ""
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        p = os.path.join(root, name)
        if os.path.exists(p):
            text += read_text(p) + "\n"
    lowered = text.lower()
    for needle, label in (("django", "django"), ("flask", "flask"),
                          ("fastapi", "fastapi"), ("streamlit", "streamlit"),
                          ("gradio", "gradio"), ("tornado", "tornado"),
                          ("sanic", "sanic")):
        if needle in lowered and ("framework: " + label) not in out["notes"]:
            out["notes"].append("framework: " + label)


def version_pins(root, out):
    pins = {}
    for name, key in ((".nvmrc", "node"), (".node-version", "node"),
                      (".python-version", "python"), (".tool-versions", "mise")):
        p = os.path.join(root, name)
        if os.path.exists(p):
            pins[key] = read_text(p, 200).strip().splitlines()[:1]
    mise = os.path.join(root, "mise.toml")
    if os.path.exists(mise):
        pins.setdefault("mise", True)
    if pins:
        out["version_pins"] = pins


def docker_detection(root, out):
    docker = {"has_dockerfile": False, "compose": []}
    if os.path.exists(os.path.join(root, "Dockerfile")):
        docker["has_dockerfile"] = True
    compose_name = None
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yaml", "compose.yml"):
        if os.path.exists(os.path.join(root, name)):
            compose_name = name
            break
    if compose_name:
        services = []
        try:
            import yaml  # optional
        except ImportError:
            yaml = None
        if yaml is not None:
            try:
                data = yaml.safe_load(read_text(os.path.join(root, compose_name), 20000))
                services = list((data or {}).get("services", {}).keys())
            except Exception:
                services = []
        docker["compose"] = services
        docker["compose_file"] = compose_name
    if docker["has_dockerfile"] or docker["compose"]:
        out["docker"] = docker


def main():
    if len(sys.argv) < 2:
        print("usage: detect_stack.py <directory>", file=sys.stderr)
        sys.exit(1)
    root = os.path.abspath(sys.argv[1])
    if not os.path.isdir(root):
        print(json.dumps({"error": "directory not found: " + root}), file=sys.stderr)
        sys.exit(2)
    out = {"path": root, "stacks": [], "package_managers": [], "scripts": {},
           "version_pins": {}, "docker": {}, "notes": []}
    node_detection(root, out)
    python_detection(root, out)
    for name, key in (("go.mod", "go"), ("Cargo.toml", "rust"),
                      ("Gemfile", "ruby"), ("composer.json", "php"),
                      ("pubspec.yaml", "dart"), ("mix.exs", "elixir")):
        if os.path.exists(os.path.join(root, name)):
            out["stacks"].append(key)
    if has_any(root, ["pom.xml", "build.gradle", "build.gradle.kts", "gradlew", "mvnw"]):
        out["stacks"].append("java")
        if os.path.exists(os.path.join(root, "mvnw")) or os.path.exists(os.path.join(root, "gradlew")):
            out["notes"].append("wrapper available (mvnw/gradlew)")
    if has_any(root, ["*.sln"]):
        out["stacks"].append("dotnet")
    if has_any(root, ["Makefile"]):
        out["notes"].append("Makefile present - use make targets")
    version_pins(root, out)
    docker_detection(root, out)
    if not out["stacks"]:
        out["notes"].append("no known stack markers found - inspect README")
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
