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


def build_command(repo_abs, image, name, port, cmd):
    hardening = [
        "non-root user (nobody, uid 65534) via setpriv after file copy",
        "--cap-drop ALL and --security-opt no-new-privileges",
        "--read-only rootfs with tmpfs /tmp",
        "--memory %s and --cpus %s limits" % (MEMORY, CPUS),
        "repo bind-mounted read-only; installs write into an isolated named volume",
    ]
    notes = []
    argv = ["docker", "run", "--rm", "--name", name, "--network", "bridge",
            "--memory", MEMORY, "--cpus", CPUS,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "0:0", "--read-only", "--tmpfs", "/tmp:rw,size=256m",
            "--env", "HOME=/tmp",
            "--volume", repo_abs + ":/repo:ro",
            "--volume", name + "-vol:/app",
            "--workdir", "/app"]
    if port:
        argv += ["--publish", "127.0.0.1:%s:%s" % (port, port)]
        hardening.append("port %s bound to 127.0.0.1 only" % port)
    argv.append(image)

    if cmd:
        quoted = shlex.quote(cmd)
        inner = ("cp -a /repo/. /app/ 2>/dev/null && chown -R %s:%s /app && "
                 "{ if command -v setpriv >/dev/null 2>&1; then "
                 "exec setpriv --reuid %s --regid %s --clear-groups sh -c %s; "
                 "else exec su nobody -s /bin/sh -c %s; fi; }"
                 % (SANDBOX_UID, SANDBOX_UID, SANDBOX_UID, SANDBOX_UID, quoted, quoted))
    else:
        notes.append("no --cmd given — pass the install/start command to actually run inside the container")
        inner = ("cp -a /repo/. /app/ 2>/dev/null && chown -R %s:%s /app && "
                 "{ if command -v setpriv >/dev/null 2>&1; then "
                 "exec setpriv --reuid %s --regid %s --clear-groups sh; "
                 "else exec su nobody -s /bin/sh; fi; }"
                 % (SANDBOX_UID, SANDBOX_UID, SANDBOX_UID, SANDBOX_UID))
    argv += ["sh", "-c", inner]
    notes.append("cleanup: docker rm -f %s && docker volume rm %s-vol" % (name, name))
    return argv, hardening, notes


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
    argv, hardening, notes = build_command(root, image, name, args.port, args.cmd)
    command = " ".join(shlex.quote(a) for a in argv)

    notes.append("daemon reachable: %s" % ("yes" if daemon else "no (command will fail until Docker is running)"))

    result = {
        "docker_available": True,
        "docker_version": version,
        "daemon_reachable": daemon,
        "image": image,
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
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
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
