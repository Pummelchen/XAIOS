#!/usr/bin/env python3
"""Create the public ISO C99 XAIOS sysroot from a Picolibc installation."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

ISO_HEADERS = (
    "assert.h", "complex.h", "ctype.h", "errno.h", "fenv.h", "float.h",
    "inttypes.h", "iso646.h", "limits.h", "locale.h", "math.h", "setjmp.h",
    "signal.h", "stdarg.h", "stdbool.h", "stddef.h", "stdint.h", "stdio.h",
    "stdlib.h", "string.h", "tgmath.h", "time.h", "wchar.h", "wctype.h",
)

# These are OS/extension entry points, not implementation-private dependencies.
FORBIDDEN_PUBLIC = (
    "arpa", "dirent.h", "fcntl.h", "fnmatch.h", "getopt.h", "glob.h",
    "grp.h", "libgen.h", "netdb.h", "netinet", "poll.h", "pthread.h",
    "pwd.h", "regex.h", "sched.h", "spawn.h", "syslog.h", "termios.h",
    "unistd.h", "utime.h", "wordexp.h",
)

INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)

# Picolibc intentionally exposes a small extension set even when the compiler
# selects strict C99. Keep those implementation details usable internally but
# rename them into the implementation-reserved namespace in application
# translations. This avoids presenting a POSIX/GNU/BSD compatibility surface.
NON_C99_DECLARATIONS = {
    "fenv.h": (
        "fedisableexcept", "feenableexcept", "fegetexcept", "fesetexcept",
    ),
    "math.h": (
        "gamma", "gammaf", "gammal", "getpayload", "getpayloadf",
        "getpayloadl", "infinity", "infinityf", "infinityl", "j0l",
        "j1l", "jnl", "scalb", "scalbf", "scalbl", "significand",
        "significandf", "significandl", "y0l", "y1l", "ynl",
    ),
    "stdio.h": (
        "asnprintf", "asprintf", "clearerr_unlocked", "fdevopen", "fdopen",
        "feof_unlocked", "ferror_unlocked", "fileno", "fmemopen",
        "setbuffer", "setlinebuf", "vasnprintf", "vasprintf",
    ),
    "stdlib.h": ("strfromd", "strfromf", "strfroml", "valloc"),
    "time.h": ("nanosleep", "timespec_get", "tzset"),
}

NON_C99_MACROS = {
    "signal.h": (
        "SIGHUP", "SIGQUIT", "SIGTRAP", "SIGIOT", "SIGEMT", "SIGKILL",
        "SIGBUS", "SIGSYS", "SIGPIPE", "SIGALRM", "SIGURG", "SIGSTOP",
        "SIGTSTP", "SIGCONT", "SIGCHLD", "SIGCLD", "SIGTTIN", "SIGTTOU",
        "SIGIO", "SIGPOLL", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF",
        "SIGWINCH", "SIGLOST", "SIGUSR1", "SIGUSR2",
    ),
    "time.h": ("TIME_UTC",),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True,
                        choices=("aarch64", "x86_64", "riscv64"))
    parser.add_argument("--install", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def restrict_public_header(output_include: Path, header: str) -> None:
    declarations = NON_C99_DECLARATIONS.get(header, ())
    macros = NON_C99_MACROS.get(header, ())
    if not declarations and not macros:
        return
    public = output_include / header
    private_relative = Path("sys/_xaios_c99") / header
    private = output_include / private_relative
    private.parent.mkdir(parents=True, exist_ok=True)
    public.replace(private)

    guard = "XAIOS_C99_" + re.sub(r"[^A-Za-z0-9]", "_", header).upper()
    lines = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
    ]
    for name in declarations:
        lines.append(f"#define {name} __xaios_noniso_{name}")
    lines.extend(("", f"#include <{private_relative.as_posix()}>", ""))
    for name in declarations:
        lines.append(f"#undef {name}")
    for name in macros:
        lines.append(f"#undef {name}")
    lines.extend(("", f"#endif /* {guard} */", ""))
    public.write_text("\n".join(lines))


def main() -> int:
    args = parse_args()
    source_include = args.install / "include"
    source_lib = args.install / "lib"
    if args.output.exists():
        shutil.rmtree(args.output)
    output_include = args.output / "include"
    output_lib = args.output / "lib"
    args.output.mkdir(parents=True, exist_ok=True)

    pending = [name for name in ISO_HEADERS if (source_include / name).is_file()]
    copied: set[str] = set()
    while pending:
        relative = pending.pop()
        if relative in copied:
            continue
        source = source_include / relative
        if not source.is_file():
            # Compiler-provided C headers such as stdarg.h are intentionally absent.
            continue
        target = output_include / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.add(relative)
        for include in INCLUDE_RE.findall(source.read_text(errors="ignore")):
            if (source_include / include).is_file() and include not in copied:
                pending.append(include)

    # Picolibc conditionally includes these only for non-strict extension modes.
    # They are not needed by a strict C99 translation and are not public XAIOS APIs.
    for conditional_extension in ("alloca.h", "strings.h"):
        path = output_include / conditional_extension
        if path.exists():
            path.unlink()
            copied.discard(conditional_extension)

    # Clang 22 diagnoses the imaginary suffix used by upstream's required I
    # macro as a later-language extension under -std=c99 -pedantic-errors.
    # __extension__ is an implementation-reserved spelling which preserves the
    # C99 complex value and type without leaking a non-C99 diagnostic to apps.
    complex_header = output_include / "complex.h"
    complex_text = complex_header.read_text()
    imaginary_literal = "#define _Complex_I 1.0fi"
    if imaginary_literal not in complex_text:
        raise SystemExit("error: unexpected Picolibc complex.h layout")
    complex_header.write_text(
        complex_text.replace(
            imaginary_literal,
            "#define _Complex_I (__extension__ 1.0fi)",
        )
    )

    for header in sorted(set(NON_C99_DECLARATIONS) | set(NON_C99_MACROS)):
        restrict_public_header(output_include, header)

    for name in FORBIDDEN_PUBLIC:
        if (output_include / name).exists():
            raise SystemExit(f"error: POSIX public header escaped into sysroot: {name}")

    output_lib.mkdir(parents=True, exist_ok=True)
    archives = []
    for name in ("libc.a", "libm.a"):
        source = source_lib / name
        if not source.is_file():
            raise SystemExit(f"error: missing required archive: {source}")
        target = output_lib / name
        shutil.copy2(source, target)
        archives.append({"path": f"lib/{name}", "sha256": sha256(target)})

    notice = Path(__file__).resolve().parents[1] / "third_party/picolibc/COPYING.picolibc"
    shutil.copy2(notice, args.output / notice.name)
    extension_include = Path(__file__).resolve().parents[1] / "userspace/libc/include/xaios"
    if extension_include.is_dir():
        shutil.copytree(extension_include, output_include / "xaios", dirs_exist_ok=True)
    manifest = {
        "schema": "xaios.libc.sysroot.v1",
        "architecture": args.arch,
        "public_headers": list(ISO_HEADERS),
        "compiler_headers": [name for name in ISO_HEADERS if name not in copied],
        "private_dependency_headers": sorted(copied - set(ISO_HEADERS)),
        "archives": archives,
        "picolibc_commit": "2ae376c6cdf4fef90ca2388ecf7a07457fa63cff",
        "tls_status": "not-required-for-xaios-stack-bound-libc-contexts",
        "xaios_extension_headers": ["xaios/thread.h"],
    }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
