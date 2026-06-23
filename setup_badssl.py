#!/usr/bin/env python3
"""
Setup a local badssl.com Docker instance for aws-c-io TLS tests.

Clones the repo, generates certs, builds and runs the Docker container,
and updates /etc/hosts with *.badssl.test entries.

Tests use BADSSL_CA_ROOT env var to find the CA cert (no system trust store needed).

Usage:
    sudo python3 setup_badssl.py
    sudo python3 setup_badssl.py --stop
"""
import argparse
import subprocess
from pathlib import Path

REPO_URL = "https://github.com/chromium/badssl.com.git"
SCRIPT_DIR = Path(__file__).resolve().parent
BADSSL_DIR = SCRIPT_DIR / "badssl.com"


def run(cmd, **kwargs):
    print(f"  $ {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
    subprocess.run(cmd, shell=isinstance(cmd, str), check=True, **kwargs)


def clone_repo():
    if BADSSL_DIR.exists():
        print(f"[*] badssl.com already at {BADSSL_DIR}")
        return
    print(f"[*] Cloning badssl.com -> {BADSSL_DIR}")
    run(["git", "clone", "--depth=1", REPO_URL, str(BADSSL_DIR)])


def update_hosts():
    """Add *.badssl.test entries to /etc/hosts."""
    hosts_path = Path("/etc/hosts")
    marker_start = "#### start of badssl.test hosts ####"
    marker_end = "#### end of badssl.test hosts ####"

    result = subprocess.run(
        ["make", "list-hosts"], cwd=BADSSL_DIR, capture_output=True, text=True)
    entries = [l for l in result.stdout.splitlines() if l.startswith("127.0.0.1")]

    current = hosts_path.read_text()

    if marker_start in current:
        before = current[:current.index(marker_start)]
        after = current[current.index(marker_end) + len(marker_end):]
        current = before.rstrip("\n") + after

    block = "\n".join([marker_start] + entries + [marker_end])
    hosts_path.write_text(current.rstrip("\n") + "\n" + block + "\n")
    print(f"[+] Added {len(entries)} host entries to /etc/hosts")


def main():
    parser = argparse.ArgumentParser(description="Setup local badssl.com for TLS testing")
    parser.add_argument("--stop", action="store_true", help="Stop and remove container")
    args = parser.parse_args()

    if args.stop:
        subprocess.run(["docker", "rm", "-f", "badssl"], capture_output=True)
        print("[*] Stopped")
        return

    clone_repo()
    print("[*] Generating certs and building Docker image...")
    run("make certs-test docker-build", cwd=BADSSL_DIR)
    print("[*] Starting container (detached)...")
    subprocess.run(["docker", "rm", "-f", "badssl"], capture_output=True)
    run(["docker", "run", "-d", "--name", "badssl",
         "-p", "80:80", "-p", "443:443", "-p", "1000-1024:1000-1024",
         "badssl"])
    update_hosts()

    ca_root = BADSSL_DIR / "certs" / "sets" / "current" / "gen" / "crt" / "ca-root.crt"
    print(f"[+] Done. badssl.test running on ports 80, 443, 1000-1024")
    print(f"    CA root: {ca_root}")
    print(f"    Set: export BADSSL_CA_ROOT={ca_root}")


if __name__ == "__main__":
    main()
