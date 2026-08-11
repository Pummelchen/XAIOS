#!/usr/bin/env python3
"""Reject unfinished implementation markers in freestanding production source."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = ("boot", "engine", "kernel", "userspace")
SOURCE_SUFFIXES = {".c", ".h", ".s", ".S"}
UNFINISHED = re.compile(r"\b(?:TODO|FIXME|XXX|PLACEHOLDER|STUB)\b", re.IGNORECASE)


def main() -> int:
    findings: list[str] = []
    checked = 0
    for root_name in SOURCE_ROOTS:
        for path in sorted((ROOT / root_name).rglob("*")):
            if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
                continue
            checked += 1
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
            ):
                if UNFINISHED.search(line):
                    findings.append(
                        f"{path.relative_to(ROOT)}:{line_number}: {line.strip()}"
                    )

    if findings:
        print("production-source-audit: unfinished markers found")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print(
        "production-source-audit: passed "
        f"files={checked} markers=TODO,FIXME,XXX,PLACEHOLDER,STUB"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
