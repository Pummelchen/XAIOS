#!/usr/bin/env python3
"""Create an XAIOS SSH password credential file without exposing a CLI secret."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import secrets


MIN_ITERATIONS = 100_000
MAX_ITERATIONS = 1_000_000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default="admin", choices=("admin",))
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--iterations", type=int, default=200_000)
    args = parser.parse_args()
    if not MIN_ITERATIONS <= args.iterations <= MAX_ITERATIONS:
        parser.error(
            f"--iterations must be between {MIN_ITERATIONS} and {MAX_ITERATIONS}"
        )
    password = args.password_file.read_bytes()
    if password.endswith(b"\n"):
        password = password[:-1]
    if not password or len(password) > 128 or b"\x00" in password:
        parser.error("password must contain 1-128 non-NUL bytes")
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password, salt, args.iterations, dklen=32
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        f"{args.username}:pbkdf2-sha256:{args.iterations}:"
        f"{salt.hex()}:{password_hash.hex()}\n",
        encoding="ascii",
    )
    args.output.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
