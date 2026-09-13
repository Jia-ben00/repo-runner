#!/usr/bin/env python3
"""Sandbox a repo run inside a hardened Docker container (repo-runner isolation mode).

Builds (or executes) a docker run command with supply-chain hardening:
non-root user, dropped capabilities, no-new-privileges, read-only rootfs,
tmpfs, memory/CPU limits, a read-only repo bind-mount, and (optionally) a
single port bound to 127.0.0.1. The repo is copied into a named volume so
package managers can write their install dirs; install/start lifecycle
scripts run only as the unprivileged user inside the container — nothing is
executed at image build time.

Usage:
  docker_sandbox.py --repo <dir> [--image <image>] [--cmd "<install; start>"]
                    [--port <p>] [--name <name>] [--check-only] [--exec]

  --check-only   check docker and print the command; do not run it (default)
  --exec         build the container and run it now (foreground; captures output)

Output (JSON): {docker_available, docker_version, image, command,
                hardening[], notes[], container_output?}
Exit codes: 0 = command built (or container ran ok), 1 = docker not available,
            2 = bad args / repo dir missing.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import time

MEMORY = "1g"
CPUS = "1"
SANDBOX_UID = "65534"  # nobody


def default_image_for(root):
    markers = {
        ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
         "bun.lockb", "bun.lock"): "node:22-slim",
        ("pyproject.toml", "requirements.txt", "requirements-dev.txt",
         "uv.lock", "poetry.lock", "Pipfile"): "python:3.12-slim",
        ("go.mod",): "golang:1.24-bookworm",
        ("Cargo.toml",): "rust:1-bookworm",
        ("Gemfile",): "ruby:3.3-slim",
        ("composer.json",): "php:8.3-cli",
        ("pom.xml", "build.gradle", "build.gradle.kts"): "openjdk:21-slim",
    }
    for names, image in markers.items():
        if any(os.path.exists(os.path.join(root, n)) for n in names):
            return image
    return "debian:bookworm-slim"


def docker_info():
    try:
        ver = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None, None, False
    if ver.returncode != 0:
        return None, ver.stdout.strip() + ver.stderr.strip(), False
    try:
        info = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=30)
        daemon = info.returncode == 0
    except subprocess.TimeoutExpired:
        daemon = False
    return (ver.stdout.strip() or ver.stderr.strip()), daemon, True


def build_commands(repo_abs, image, name, port, cmd):
    hardening = [
        "app runs as nobody (uid 65534) via --user at container start — no setuid call",
        "--cap-drop ALL and --security-opt no-new-privileges on both containers",
        "--read-only rootfs with tmpfs /tmp",
        "--memory %s and --cpus %s limits" % (MEMORY, CPUS),
        "repo bind-mounted read-only; installs write into an isolated named volume",
    ]
    notes = []
    # Stage 1 (prep, root-only): copy the repo into the named volume and make it
    # world-writable. uid 0 only needs DAC-on-own-files here (cp -R and chmod by
    # owner need no capability), so --cap-drop ALL stays intact. The app never
    # sees root: --cap-drop ALL also removes CAP_SETUID, so a runtime "drop to
    # nobody" (setpriv/su) is impossible — instead the app container starts
    # directly as uid 65534 (runc sets the uid at exec, no setuid syscall).
    prep_argv = ["docker", "run", "--rm", "--name", name + "-prep",
                 "--user", "0:0",
                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--read-only", "--tmpfs", "/tmp:rw,size=256m",
                 "--env", "HOME=/tmp",
                 "--volume", repo_abs.replace("\\", "/") + ":/repo:ro",
                 "--volume", name + "-vol:/app",
                 image, "sh", "-c",
                 "cp -R /repo/. /app/ && chmod -R a+rwX /app"]
    app_argv = ["docker", "run", "--rm", "--name", name,
                "--network", "bridge",
                "--memory", MEMORY, "--cpus", CPUS,
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", "%s:%s" % (SANDBOX_UID, SANDBOX_UID),
                "--read-only", "--tmpfs", "/tmp:rw,size=256m",
                "--env", "HOME=/tmp",
                "--volume", name + "-vol:/app",
                "--workdir", "/app"]
    if port:
        app_argv += ["--publish", "127.0.0.1:%s:%s" % (port, port)]
        hardening.append("port %s bound to 127.0.0.1 only" % port)
    app_argv.append(image)
    if cmd:
        app_argv += ["sh", "-c", cmd]
    else:
        notes.append("no --cmd given — the app container opens an interactive sh instead")
        app_argv.append("sh")
    notes.append("cleanup: docker rm -f %s %s-prep && docker volume rm %s-vol" % (name, name, name))
    return prep_argv, app_argv, hardening, notes


def main():
    ap = argparse.ArgumentParser(description="Sandbox a repo run in a hardened Docker container.")
    ap.add_argument("--repo", required=True, help="repository / project directory")
    ap.add_argument("--image", help="base image (default: auto-detected by stack markers)")
    ap.add_argument("--cmd", help="install/start command to run inside the container")
    ap.add_argument("--port", help="host port to map (127.0.0.1 only)")
    ap.add_argument("--name", help="container name (default: rr-sandbox-<ts>)")
    ap.add_argument("--check-only", action="store_true", help="only check docker and print the command (default)")
    ap.add_argument("--exec", action="store_true", help="run the container now (foreground)")
    args = ap.parse_args()

    root = os.path.abspath(args.repo)
    if not os.path.isdir(root):
        print(json.dumps({"error": "directory not found: " + root}))
        sys.exit(2)

    version, daemon, present = docker_info()
    if not present:
        print(json.dumps({"docker_available": False,
                          "error": "docker not found on PATH — install Docker or fall back to a non-isolated run"}))
        sys.exit(1)

    name = args.name or ("rr-sandbox-" + str(int(time.time())))
    image = args.image or default_image_for(root)
    prep_argv, app_argv, hardening, notes = build_commands(root, image, name, args.port, args.cmd)
    prep_command = " ".join(shlex.quote(a) for a in prep_argv)
    command = " ".join(shlex.quote(a) for a in app_argv)

    notes.append("daemon reachable: %s" % ("yes" if daemon else "no (command will fail until Docker is running)"))

    result = {
        "docker_available": True,
        "docker_version": version,
        "daemon_reachable": daemon,
        "image": image,
        "prepare_command": prep_command,
        "command": command,
        "hardening": hardening,
        "notes": notes,
    }

    if args.exec:
        if not daemon:
            result["error"] = "docker daemon not reachable — cannot --exec"
            print(json.dumps(result, ensure_ascii=False, indent=2))
            sys.exit(1)
        try:
            prep = subprocess.run(prep_argv, capture_output=True, text=True, timeout=300)
            if prep.returncode != 0:
                result["error"] = "prep container failed (copy repo into volume)"
                result["prep_output"] = (prep.stdout or prep.stderr).strip()[-2000:]
                print(json.dumps(result, ensure_ascii=False, indent=2))
                sys.exit(1)
            proc = subprocess.run(app_argv, capture_output=True, text=True, timeout=1800)
            result["exit_code"] = proc.returncode
            out = (proc.stdout or "").strip()
            result["container_output"] = out[-2000:] if out else (proc.stderr or "").strip()[-2000:]
            print(json.dumps(result, ensure_ascii=False, indent=2))
            sys.exit(0 if proc.returncode == 0 else 1)
        except subprocess.TimeoutExpired:
            result["error"] = "container run timed out (1800s)"
            print(json.dumps(result, ensure_ascii=False, indent=2))
            sys.exit(1)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
