#!/usr/bin/env python3
"""
Setup a local badssl.com Docker instance for aws-c-io TLS tests.

1. Clone badssl.com
2. Generate certs (make certs-test)
3. Override expired cert with pre-generated one
4. Build Docker image
5. Run container (detached)
6. Update /etc/hosts

Tests use BADSSL_CA_ROOT env var to find the CA cert.

Usage:
    sudo python3 setup_badssl.py
    sudo python3 setup_badssl.py --stop
"""
import argparse
import shutil
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




def install_trust_store():
    """Install badssl CA root into system trust store (for curl verify step)."""
    ca_root = BADSSL_DIR / "certs" / "sets" / "current" / "gen" / "crt" / "ca-root.crt"
    if not ca_root.exists():
        return
    debian = Path("/usr/local/share/ca-certificates")
    rhel = Path("/etc/pki/ca-trust/source/anchors")
    if rhel.exists():
        shutil.copy2(ca_root, rhel / "badssl-ca-root.crt")
        run("update-ca-trust")
    elif debian.exists():
        shutil.copy2(ca_root, debian / "badssl-ca-root.crt")
        run("update-ca-certificates")
    print("[+] CA root installed to system trust store")


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
    print("[*] Generating certs...")
    run("make certs-test", cwd=BADSSL_DIR)
    print("[*] Building Docker image...")
    run("make docker-build", cwd=BADSSL_DIR)
    print("[*] Starting container (detached)...")
    subprocess.run(["docker", "rm", "-f", "badssl"], capture_output=True)
    run(["docker", "run", "-d", "--name", "badssl",
         "-p", "80:80", "-p", "443:443", "-p", "1000-1023:1000-1023",
         "badssl"])
    update_hosts()
    install_trust_store()

    ca_root = BADSSL_DIR / "certs" / "sets" / "current" / "gen" / "crt" / "ca-root.crt"
    print(f"\n[+] Done. badssl.test running on ports 80, 443, 1000-1023")
    print(f"    CA root: {ca_root}")
    print(f"    export BADSSL_CA_ROOT={ca_root}")


if __name__ == "__main__":
    main()
