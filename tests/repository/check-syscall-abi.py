#!/usr/bin/env python3
"""Keep the syscall request structures the same on both sides of the trap.

Every userspace call builds a request structure, hands its address to the
kernel, and the kernel copies it out and reads named fields from it. The two
definitions live in separate headers that share no include: the kernel's
`kernel/include/xaios/syscall.h` and userspace's
`userspace/include/xaios_user.h`. Nothing makes them agree.

They have to agree field for field, because the kernel reads the caller's
buffer as its own type. A field added to one side and not the other does not
fail to compile and does not fault: every field after it silently shifts, and
the kernel reads a descriptor as a port or an address pointer as a size. That
is not hypothetical -- it is what a first attempt at `net_open_udp` did, adding
an out-pointer to one structure and watching the kernel write a chosen UDP port
to an address the caller never passed.

This reads both headers as text and compares the field names, in order, for
each request structure they share. Text rather than a compiled check because
the two cannot be compiled into one program: the kernel header pulls in the
kernel's own types, and userspace cannot include it.

Field widths are not compared beyond the name: both sides spell every field
`uint64_t` or `u64`, and if that ever stops being true the widths are the least
of the problem.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KERNEL_HEADER = ROOT / "kernel/include/xaios/syscall.h"
USERSPACE_HEADER = ROOT / "userspace/include/xaios_user.h"

# Kernel structure name -> userspace structure name.
STRUCTURES = {
    "xaios_syscall_socket_request_t": "xaios_socket_request_t",
    "xaios_syscall_net_resolve_request_t": "xaios_net_resolve_request_t",
}

def fields_in(path: Path, structure: str) -> list[str]:
    """The field names of one structure, in declaration order.

    Scanned line by line rather than matched with one regular expression. A
    non-greedy `\\{.*?\\}` does not stop at this structure's closing brace when
    the typedef name it is looking for comes after several other structures --
    it stops at the first brace that happens to be followed by the wanted name,
    which is the brace of whatever structure precedes it, and the result is
    every field in between. That mistake was made here once and the check
    reported a hundred fields of disagreement, so the reading is explicit now.
    """
    text = path.read_text(encoding="utf-8")
    body: list[str] = []
    inside = False
    for line in text.splitlines():
        if not inside:
            if re.match(r"^\s*typedef\s+struct\s+[A-Za-z_]", line):
                inside = True
                body = []
                # A one-line `typedef struct x { ... } x_t;` is not used in
                # these headers, so the opening brace is always on this line.
                if "{" in line:
                    line = line.split("{", 1)[1]
                else:
                    continue
            else:
                continue
        if "}" in line:
            tail = line.split("}", 1)[1]
            if re.search(rf"\b{re.escape(structure)}\s*;", tail):
                return body
            inside = False
            continue
        body.append(line)
    raise ValueError(f"no typedef struct {structure} in {path.name}")


def field_names(body: list[str]) -> list[str]:
    """The declared names of a structure body, in order.

    Comments are tracked as state rather than matched line by line, because a
    wrapped block comment's middle lines do not begin with an asterisk: prose
    like "is a refusal rather than a wrap" reads exactly like a declaration to
    a naive splitter, and it was counted as a field named `a`.
    """
    names: list[str] = []
    in_block = False
    for line in body:
        text = ""
        remainder = line
        while remainder:
            if in_block:
                end = remainder.find("*/")
                if end < 0:
                    remainder = ""
                    continue
                remainder = remainder[end + 2:]
                in_block = False
                continue
            start = remainder.find("/*")
            if start < 0:
                text += remainder
                remainder = ""
                continue
            text += remainder[:start]
            remainder = remainder[start + 2:]
            in_block = True
        text = text.split("//", 1)[0].strip()
        if not text:
            continue
        parts = text.replace(";", " ").split()
        if len(parts) < 2:
            continue
        name = parts[-1].lstrip("*")
        if name:
            names.append(name)
    return names


def main() -> int:
    failures: list[str] = []
    for kernel_name, user_name in STRUCTURES.items():
        try:
            kernel_fields = field_names(
                fields_in(KERNEL_HEADER, kernel_name))
            user_fields = field_names(
                fields_in(USERSPACE_HEADER, user_name))
        except ValueError as error:
            failures.append(str(error))
            continue
        if kernel_fields == user_fields:
            continue
        only_kernel = [f for f in kernel_fields if f not in user_fields]
        only_user = [f for f in user_fields if f not in kernel_fields]
        detail = []
        if only_kernel:
            detail.append(f"kernel only: {', '.join(only_kernel)}")
        if only_user:
            detail.append(f"userspace only: {', '.join(only_user)}")
        if not detail:
            detail.append(
                f"same names, different order: kernel {kernel_fields} "
                f"against userspace {user_fields}")
        failures.append(
            f"{kernel_name} / {user_name} disagree ({'; '.join(detail)}); "
            f"every field after the first difference is read as the wrong one")

    if failures:
        for failure in failures:
            print(f"syscall-abi: {failure}", file=sys.stderr)
        return 1
    count = len(STRUCTURES)
    print(f"syscall-abi: {count} request structures agree field for field "
          f"across the kernel and userspace headers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
