#!/usr/bin/env python3
"""Health-check a locally started service (repo-runner stage 5).

Stdlib only, cross-platform. Quick TCP connect first, then HTTP probe on
common health paths for ports that are open.

Usage:
  health_check.py --ports 3000,8000 [--host 127.0.0.1]
                  [--timeout 60] [--interval 2] [--paths /,/health,/api/health]

Output (JSON to stdout):
{
  "targets": [ {"port": 3000, "tcp_open": true, "http": {...}} ],
  "summary": {"reachable": 1, "unreachable": 1, "all_up": false}
}

Exit codes: 0 = all probed targets reachable, 1 = some/all unreachable.
"""
import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.request

DEFAULT_PORTS = (3000, 8000, 8080, 5000, 5173, 4173, 9090, 8888)
DEFAULT_PATHS = ("/", "/health", "/healthz", "/api/health", "/api/v1/health", "/status")


def tcp_open(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_probe(host, port, path, timeout=3.0):
    url = "http://%s:%d%s" % (host, port, path)
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "repo-runner-health-check"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(300)
            return {
                "url": url, "status": resp.status, "ok": resp.status < 500,
                "ms": int((time.time() - start) * 1000),
                "snippet": body[:120].decode("utf-8", "replace").replace("\n", " "),
            }
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code, "ok": exc.code < 500,
                "ms": int((time.time() - start) * 1000), "snippet": ""}
    except Exception as exc:
        return {"url": url, "status": None, "ok": False,
                "ms": int((time.time() - start) * 1000), "snippet": str(exc)[:120]}


def wait_for_port(host, port, timeout, interval):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if tcp_open(host, port):
            return True
        time.sleep(interval)
    return tcp_open(host, port)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS),
                    help="comma-separated ports to probe")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--timeout", type=int, default=60, help="wait up to N seconds for first open port")
    ap.add_argument("--interval", type=int, default=2)
    ap.add_argument("--paths", default=",".join(DEFAULT_PATHS),
                    help="comma-separated HTTP paths to probe once a port is open")
    args = ap.parse_args()
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    paths = [p for p in args.paths.split(",") if p.strip()]

    targets = []
    for port in ports:
        opened = wait_for_port(args.host, port, args.timeout, args.interval)
        entry = {"port": port, "tcp_open": opened, "http": None}
        if opened:
            for path in paths:
                probe = http_probe(args.host, port, path)
                if probe["ok"]:
                    entry["http"] = probe
                    break
            else:
                entry["http"] = {
                    "url": None, "status": None, "ok": False,
                    "ms": 0, "snippet": "port open but no HTTP 2xx on common paths",
                }
        targets.append(entry)

    reachable = sum(1 for t in targets if t["tcp_open"])
    all_up = reachable == len(ports) and any(t["http"] and t["http"]["ok"] for t in targets if t["tcp_open"])
    print(json.dumps({
        "host": args.host,
        "targets": targets,
        "summary": {"reachable": reachable, "unreachable": len(ports) - reachable, "all_up": all_up},
    }, ensure_ascii=False, indent=2))
    sys.exit(0 if all_up else 1)


if __name__ == "__main__":
    main()
