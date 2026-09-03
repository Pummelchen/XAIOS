#!/usr/bin/env python3
"""Force-link every mandatory ISO C99 function for one XAIOS target."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("arch", choices=("aarch64", "x86_64", "riscv64"))
    args = parser.parse_args()
    runtime = ROOT / f"build/libc/{args.arch}/runtime-test"
    sysroot = ROOT / f"build/libc/{args.arch}/sysroot"
    inventory = json.loads(
        (ROOT / "tests/libc/c99-library-functions.json").read_text()
    )
    functions = sorted({name for names in inventory.values() for name in names})
    output = runtime / "c99-all-symbols.elf"
    command = [
        "ld.lld", "-nostdlib", "--gc-sections", "-T",
        str(ROOT / "userspace/libc/linker.ld"), "-o", str(output),
        str(runtime / "crt0.o"), str(runtime / "runtime.o"),
        str(runtime / "os_adapter.o"), str(runtime / "thread_context.o"),
        str(runtime / "locking.o"), str(runtime / "thread_api.o"),
        str(runtime / "c99_runtime_smoke.o"),
        str(runtime / "c99_conformance_suite.o"),
        str(runtime / "c99_language_conformance.o"),
    ]
    command.extend(f"--undefined={name}" for name in functions)
    command.extend([
        "--start-group", str(sysroot / "lib/libc.a"),
        str(sysroot / "lib/libm.a"),
        str(sysroot / "lib/libcompiler_rt_xaios.a"), "--end-group",
    ])
    subprocess.run(command, cwd=ROOT, check=True)
    undefined_output = subprocess.check_output(
        ["llvm-nm", "-u", str(output)], cwd=ROOT, text=True
    ).strip()
    undefined = "\n".join(
        line for line in undefined_output.splitlines()
        if line.split() and line.split()[0].upper() == "U"
    )
    if undefined:
        raise SystemExit(f"{args.arch} all-symbol image is unresolved:\n{undefined}")
    print(f"libc-symbol-probe: {args.arch}: PASS: {len(functions)} functions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
