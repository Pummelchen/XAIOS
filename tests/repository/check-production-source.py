#!/usr/bin/env python3
"""Reject unfinished implementation markers in freestanding production source."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = ("boot", "engine", "kernel", "userspace")
SOURCE_SUFFIXES = {".c", ".h", ".s", ".S"}
# TODO, FIXME, XXX and PLACEHOLDER are annotations: nobody writes them in
# ordinary prose, so matching them case-insensitively costs nothing.
#
# "stub" is not like them. It is an ordinary technical noun -- a trap stub, a
# PLT stub -- and matching it as a word flagged seven lines of correct RISC-V
# prose, one of which reads "is real work rather than a stub". A check that
# fires on a comment saying the opposite of what it is looking for teaches
# people to stop writing comments.
#
# So it is matched as an annotation (capitalised, the way the others are
# written) or as an admission about the code beneath it -- "stubbed out", "is
# a stub", a comment whose whole content is the word. A name is none of those.
UNFINISHED = re.compile(
    r"\b(?:TODO|FIXME|XXX|PLACEHOLDER)\b", re.IGNORECASE)
STUBBED = re.compile(
    r"\bSTUB\b"                              # the annotation, capitalised
    r"|\bstubbed\b"                          # "stubbed out"
    r"|\bis\s+(?:a|just\s+a|still\s+a|only\s+a)\s+stub\b"
    r"|^\s*(?://|/\*|\*)\s*stub\b")

# ... and not when the sentence is saying it is not one. "PCI is no longer
# stubbed here" is a note that the work was done; flagging it asks an author
# to delete the sentence that records it.
NOT_AN_ADMISSION = re.compile(
    r"\b(?:no longer|not|never|rather than|instead of|used to be|"
    r"stopped being)\b[^.]{0,60}?stub", re.IGNORECASE)


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
                if UNFINISHED.search(line) or (
                        STUBBED.search(line)
                        and not NOT_AN_ADMISSION.search(line)):
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
        f"files={checked} markers=TODO,FIXME,XXX,PLACEHOLDER and stub "
        f"used as an admission rather than as a name"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
