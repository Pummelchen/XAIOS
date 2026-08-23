#!/usr/bin/env python3
"""Build and run bounded coverage-guided parser fuzz campaigns."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build" / "fuzz"
RUNS = int(os.environ.get("XAIOS_FUZZ_RUNS", "20000"))


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    common = [
        "clang", "-std=c99", "-O1", "-g", "-fno-omit-frame-pointer",
        "-fsanitize=fuzzer,address,undefined", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-function",
    ]
    targets = {
        "ssh-packet": [
            "-Iuserspace/include", "-Iuserspace/sshd",
            "tests/fuzz/fuzz_ssh_packet.c", "userspace/sshd/ssh_protocol.c",
            "tests/fuzz/ssh_protocol_stubs.c",
        ],
        "dns": [
            "-DXAIOS_LIBFUZZER=1", "-Ikernel/include", "-Iuserspace/include",
            "-Iuserspace/sshd", "-Ithird_party/bearssl/inc",
            "-Ithird_party/bearssl/src",
            "kernel/net/dns.c", "kernel/net/dnssec.c", "kernel/net/ipv4.c",
            "userspace/sshd/ssh_crypto.c", "userspace/sshd/tweetnacl_subset.c",
            *sorted(str(path) for path in (ROOT / "third_party" / "bearssl" / "src").rglob("*.c")),
            "tests/crashtest/test_dns.c",
        ],
        "sftp": [
            "-DXAIOS_LIBFUZZER=1", "-Iuserspace/include",
            "-Iuserspace/sshd", "-Iuserspace/apps/terminal", "-Ikernel/include",
            "userspace/sshd/sftp_server.c", "tests/storage/test_sftp_large.c",
        ],
    }
    for name, sources in targets.items():
        binary = BUILD / f"fuzz-{name}"
        run([*common, *sources, "-o", str(binary)])
        seed_corpus = ROOT / "tests" / "fuzz" / f"{name}-corpus"
        corpus = BUILD / f"{name}-corpus"
        # Merge the checked-in seeds into whatever the corpus already holds
        # rather than resetting it. A campaign that starts from one seed every
        # time relearns the same shallow coverage; carrying the corpus forward
        # is what lets successive runs reach deeper states.
        corpus.mkdir(parents=True, exist_ok=True)
        for seed in seed_corpus.iterdir():
            if seed.is_file():
                target_path = corpus / seed.name
                if not target_path.exists():
                    shutil.copy2(seed, target_path)
        run([
            str(binary), str(corpus), f"-runs={RUNS}", "-timeout=5",
            "-rss_limit_mb=1024", "-print_final_stats=1",
            f"-artifact_prefix={BUILD}/",
        ])
    print(f"parser-fuzz: PASS targets={len(targets)} runs_per_target={RUNS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
