#!/usr/bin/env python3
"""Check the reproducible C99 profile, public surface and syscall budget."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIREMENTS = json.loads((ROOT / "tests/libc/c99-requirements.json").read_text())
PIN = "2ae376c6cdf4fef90ca2388ecf7a07457fa63cff"


def fail(message: str) -> None:
    raise SystemExit(f"libc-contract: FAIL: {message}")


def run(*command: str) -> str:
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def check_source_identity() -> None:
    source = ROOT / "third_party/picolibc"
    if not (source / "meson.build").is_file():
        fail("Picolibc submodule is not initialized")
    if run("git", "-C", str(source), "rev-parse", "HEAD") != PIN:
        fail("Picolibc checkout does not match the pinned commit")
    compiler_rt = ROOT / "third_party/compiler-rt-builtins"
    if not (compiler_rt / "LICENSE.TXT").is_file():
        fail("compiler-rt license is missing")


def check_syscall_budget() -> None:
    header = (ROOT / "kernel/include/xaios/syscall.h").read_text()
    values = [int(value) for value in re.findall(
        r"^#define XAIOS_SYSCALL_[A-Z0-9_]+\s+UINT64_C\((\d+)\)$",
        header, re.MULTILINE,
    )]
    budget = REQUIREMENTS["syscall_budget"]
    if len(values) != budget["baseline_count"]:
        fail(f"syscall count changed: expected {budget['baseline_count']}, found {len(values)}")
    if max(values, default=0) != budget["maximum_identifier"]:
        fail("maximum syscall identifier changed")
    if len(set(values)) != len(values):
        fail("duplicate syscall identifier")


def check_profile() -> None:
    build_script = (ROOT / "scripts/build-libc.sh").read_text()
    required_options = (
        "-Dio-c99-formats=true", "-Dio-long-long=true",
        "-Dio-long-double=true", "-Dio-float-exact=true",
        "-Dprintf-percent-n=true", "-Dio-wchar=true", "-Dmb-capable=true",
        "-Dstdio-exit-flush=true", "-Dwant-math-errno=true",
        "-Dtmpdir=/tmp/",
        "-Dposix-console=false", "-Dtests-enable-posix-io=false",
        "-Dsemihost=false", "-Dpicocrt=false",
    )
    missing = [option for option in required_options if option not in build_script]
    if missing:
        fail("mandatory profile options missing: " + ", ".join(missing))


def check_elf_image(arch: str, image: Path) -> None:
    if not image.is_file() or image.stat().st_size == 0:
        fail(f"{arch} hosted runtime image is missing: {image.name}")
    undefined_output = run("llvm-nm", "-u", str(image))
    undefined = [
        line for line in undefined_output.splitlines()
        if line.split() and line.split()[0].upper() == "U"
    ]
    if undefined:
        fail(
            f"{arch} hosted runtime has strong unresolved symbols:\n"
            + "\n".join(undefined)
        )
    segments = run("llvm-readelf", "-l", str(image))
    ranges = []
    for line in segments.splitlines():
        match = re.match(
            r"\s*LOAD\s+0x[0-9a-f]+\s+0x([0-9a-f]+)\s+0x[0-9a-f]+"
            r"\s+0x[0-9a-f]+\s+0x([0-9a-f]+)",
            line,
        )
        if match:
            start = int(match.group(1), 16) & ~0xFFF
            size = int(match.group(2), 16)
            end = (int(match.group(1), 16) + size + 0xFFF) & ~0xFFF
            for other_start, other_end in ranges:
                if start < other_end and other_start < end:
                    fail(
                        f"{arch} {image.name} has overlapping PT_LOAD pages"
                    )
            ranges.append((start, end))


def compile_source(arch: str, source: str) -> subprocess.CompletedProcess[str]:
    target = "aarch64-none-elf" if arch == "aarch64" else "x86_64-none-elf"
    include = ROOT / f"build/libc/{arch}/sysroot/include"
    temporary = tempfile.TemporaryDirectory(prefix=f"xaios-c99-{arch}-")
    test_c = Path(temporary.name) / "probe.c"
    test_o = Path(temporary.name) / "probe.o"
    test_c.write_text(source)
    result = subprocess.run(
        ["clang", f"--target={target}", "-std=c99", "-fhosted",
         "-pedantic-errors", "-Werror", "-nostdinc", "-isystem", str(include),
         "-isystem", run("clang", "-print-resource-dir") + "/include",
         "-c", str(test_c), "-o", str(test_o)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    temporary.cleanup()
    return result


def all_headers_source() -> str:
    return "\n".join(
        f"#include <{header}>" for header in REQUIREMENTS["public_headers"]
    ) + "\n"


def check_public_namespace(arch: str) -> None:
    inventory = json.loads(
        (ROOT / "tests/libc/c99-library-functions.json").read_text()
    )
    required = {name for names in inventory.values() for name in names}
    if len(required) != REQUIREMENTS["mandatory_function_count"]:
        fail("mandatory function inventory count changed")

    target = "aarch64-none-elf" if arch == "aarch64" else "x86_64-none-elf"
    include = ROOT / f"build/libc/{arch}/sysroot/include"
    with tempfile.TemporaryDirectory(prefix=f"xaios-c99-ast-{arch}-") as temp:
        source = Path(temp) / "surface.c"
        source.write_text(all_headers_source())
        result = subprocess.run(
            ["clang", f"--target={target}", "-std=c99", "-fhosted",
             "-nostdinc", "-isystem", str(include), "-isystem",
             run("clang", "-print-resource-dir") + "/include", "-Xclang",
             "-ast-dump", "-fsyntax-only", str(source)],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    if result.returncode:
        fail(f"{arch} public namespace AST failed:\n{result.stderr}")
    declared = set(re.findall(
        r"FunctionDecl .*?\b([A-Za-z_][A-Za-z0-9_]*) '", result.stdout
    ))
    missing = sorted(required - declared)
    extras = sorted(
        name for name in declared - required if not name.startswith("_")
    )
    if missing:
        fail(f"{arch} mandatory declarations missing: {', '.join(missing)}")
    if extras:
        fail(f"{arch} non-C99 declarations exposed: {', '.join(extras)}")

    headers = all_headers_source()
    for identifier in REQUIREMENTS["forbidden_public_identifiers"]:
        probe = headers + f"\nint main(void){{ (void){identifier}; return 0; }}\n"
        if compile_source(arch, probe).returncode == 0:
            fail(f"{arch} exposes forbidden identifier {identifier}")
    for macro in REQUIREMENTS["forbidden_public_macros"]:
        probe = headers + f"\n#ifdef {macro}\n#error forbidden macro\n#endif\n"
        probe += "int main(void){return 0;}\n"
        result = compile_source(arch, probe)
        if result.returncode != 0:
            fail(f"{arch} exposes forbidden macro {macro}")


def check_sysroot(arch: str) -> None:
    sysroot = ROOT / f"build/libc/{arch}/sysroot"
    include = sysroot / "include"
    manifest_path = sysroot / "manifest.json"
    if not manifest_path.is_file():
        fail(f"{arch} sysroot has not been built")
    manifest = json.loads(manifest_path.read_text())
    if manifest["picolibc_commit"] != PIN:
        fail(f"{arch} sysroot has wrong source identity")
    for forbidden in REQUIREMENTS["forbidden_public_headers"]:
        if (include / forbidden).exists():
            fail(f"{arch} exposes forbidden public header {forbidden}")

    source = "\n".join(f"#include <{header}>" for header in REQUIREMENTS["public_headers"])
    source += "\n#if __STDC_HOSTED__ != 1\n#error not hosted\n#endif\n"
    source += "#if __STDC_VERSION__ != 199901L\n#error not C99\n#endif\nint main(void){return 0;}\n"
    result = compile_source(arch, source)
    if result.returncode:
        fail(f"{arch} strict header compile failed:\n{result.stdout}")
    check_public_namespace(arch)

    runtime = ROOT / f"build/libc/{arch}/runtime-test"
    images = sorted(runtime.glob("*.elf"))
    if not images:
        fail(f"{arch} runtime images are missing")
    for image in images:
        check_elf_image(arch, image)


def main() -> int:
    check_source_identity()
    check_syscall_budget()
    check_profile()
    for arch in REQUIREMENTS["architecture_gates"]:
        check_sysroot(arch)
    print(
        "libc-contract: PASS: 24 headers, 464 functions, exact strict-C99 "
        f"namespace, pinned source, non-POSIX surface, "
        f"{REQUIREMENTS['syscall_budget']['baseline_count']}-syscall budget"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, KeyError, ValueError) as error:
        fail(str(error))
