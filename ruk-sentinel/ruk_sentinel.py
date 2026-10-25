#!/usr/bin/env python3
"""RUK Sentinel: safe, local-only security hygiene checks.

Uses only Python's standard library. It does not make network requests,
read the contents of files during filename checks, or require root access.
"""
from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit


SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production",
    "id_rsa", "id_ed25519", "id_ecdsa",
    "credentials.json", "secrets.json", "token.txt",
    "passwords.txt", "config.php",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
COMMON_TOOLS = (
    "git", "python3", "curl", "wget", "ssh", "openssl",
    "ufw", "nmap",
)


def pause() -> None:
    input("\nPress Enter to return to the menu...")


def system_overview() -> None:
    print("\n=== Local system overview ===")
    print(f"OS:             {platform.system()} {platform.release()}")
    print(f"Architecture:   {platform.machine()}")
    print(f"Python:         {platform.python_version()}")
    print(f"Python path:    {sys.executable}")
    print(f"Current folder: {Path.cwd()}")
    print("\nCommand availability (presence only):")
    for name in COMMON_TOOLS:
        found = shutil.which(name)
        print(f"  [{'FOUND' if found else 'MISSING'}] {name}")
    print("\nNote: this does not test whether services are secure or running.")


def check_directory() -> None:
    print("\n=== Sensitive-filename hygiene check ===")
    raw = input("Directory to inspect (blank = current directory): ").strip()
    target = Path(raw).expanduser() if raw else Path.cwd()

    try:
        target = target.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        print(f"Cannot access that path: {exc}")
        return

    if not target.is_dir():
        print("That path is not a directory.")
        return

    print(f"Inspecting names in: {target}")
    print("File contents will NOT be opened or displayed.")
    matches: list[str] = []
    skipped = 0

    try:
        for root, dirs, files in os.walk(target, followlinks=False):
            # Avoid traversing symlinked directories.
            dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
            for filename in files:
                path = Path(root) / filename
                low = filename.lower()
                if low in SENSITIVE_NAMES or low.endswith(SENSITIVE_SUFFIXES):
                    matches.append(str(path))
                if len(matches) >= 500:
                    skipped = 1
                    break
            if skipped:
                break
    except OSError as exc:
        print(f"Some entries could not be inspected: {exc}")

    if matches:
        print(f"\nFound {len(matches)} filename(s) worth reviewing:")
        for item in matches:
            print(f"  [REVIEW] {item}")
        print("\nThese are filename-based hints, not proof that a file contains a secret.")
        print("Check permissions and ensure secrets are not committed to public repos.")
    else:
        print("No matching filenames found in the accessible files.")

    if skipped:
        print("Stopped after 500 matches to keep output manageable.")


def review_url() -> None:
    print("\n=== URL format hygiene check (offline) ===")
    raw = input("Enter a URL: ").strip()
    if not raw:
        print("No URL supplied.")
        return

    candidate = raw if "://" in raw else "https://" + raw
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        # Accessing .port validates malformed port values.
        _ = parts.port
    except ValueError as exc:
        print(f"Invalid URL format: {exc}")
        return

    if parts.scheme.lower() not in {"http", "https"}:
        print(f"[REVIEW] Unexpected scheme: {parts.scheme or '(missing)'}")
    if not hostname:
        print("[REVIEW] No valid hostname was found.")
        return

    print(f"Host:   {hostname}")
    print(f"Scheme: {parts.scheme.lower()}")
    if parts.scheme.lower() == "https":
        print("[INFO] HTTPS is requested by the URL; this does not prove the site is trustworthy.")
    else:
        print("[WARNING] HTTP does not protect traffic with TLS.")

    if parts.username is not None or parts.password is not None:
        print("[WARNING] URL contains user-info before the hostname. Avoid sharing such URLs.")

    if hostname.startswith("-") or hostname.endswith("-") or ".." in hostname:
        print("[REVIEW] Hostname formatting looks unusual.")
    if hostname.isascii() and any(ch.isdigit() for ch in hostname) and hostname.replace(".", "").isdigit():
        print("[REVIEW] Host looks like an IPv4-style numeric address; verify it carefully.")

    print("No DNS lookup or network request was performed.")
    print("This check cannot determine whether a website is malicious or safe.")


def main() -> int:
    while True:
        print("\n" + "=" * 42)
        print("          RUK SENTINEL")
        print("   Local Security Hygiene Helper")
        print("=" * 42)
        print("1. System overview")
        print("2. Check local directory filenames")
        print("3. Review URL format (offline)")
        print("4. Exit")

        try:
            choice = input("\nSelect [1-4]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return 0

        if choice == "1":
            system_overview()
            pause()
        elif choice == "2":
            check_directory()
            pause()
        elif choice == "3":
            review_url()
            pause()
        elif choice == "4":
            print("Goodbye.")
            return 0
        else:
            print("Please choose 1, 2, 3, or 4.")


if __name__ == "__main__":
    raise SystemExit(main())
