#!/usr/bin/env python3
"""The xaiFS chunk-size bounds are written in four places, so all four must agree.

B-102. `XAI_FS_MAX_CHUNK_SIZE` in `engine/src/xai_fs_writer.c` was 16 MiB while
the C reader, the host tool and `docs/MODELFS-FORMAT.md` all said 64 MiB. The
cap was raised by `78bafd1` -- "raise the chunk cap to where it stops binding"
-- which changed `engine/src/xai_fs.c`, `tests/xai_fs/test_xai_fs.py` and
`wiki/Filesystem-and-Storage.md` and did not touch the writer. The result was
one documented format with two caps: a volume the specification permits, the
reader opens and `tools/xaios_xai_fs.py` writes could be neither formatted nor
accepted by the C writer, and nothing reported the disagreement because no two
of the four are read together.

That is the shape `B-77` records for three private port constants and
`check-ssh-wire-bound.py` exists to prevent for `SSH_MAX_PACKET_SIZE`: a value
that cannot share a header, copied across a boundary, drifting. The bounds are
now compared by name rather than trusted, so raising one is raising all of
them, and a change that means to raise only one has to say why here.

`wiki/Filesystem-and-Storage.md` is deliberately not read: the format's bounds
are normative in `docs/`, and a wiki sentence describing them is prose about
the specification rather than a fourth definition of it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

WRITER = ROOT / "engine" / "src" / "xai_fs_writer.c"
READER = ROOT / "engine" / "src" / "xai_fs.c"
TOOL = ROOT / "tools" / "xaios_xai_fs.py"
FORMAT = ROOT / "docs" / "MODELFS-FORMAT.md"


def writer_bounds() -> tuple[int, int]:
    text = WRITER.read_text(encoding="utf-8")
    found = re.search(
        r"#define XAI_FS_MIN_CHUNK_SIZE UINT64_C\((\d+)\)\s*\n"
        r"(?:.*?\n)*?"
        r"#define XAI_FS_MAX_CHUNK_SIZE UINT64_C\((\d+)\)", text)
    if not found:
        raise SystemExit(
            "check-xai-fs-chunk-bounds: cannot find XAI_FS_MIN_CHUNK_SIZE and "
            f"XAI_FS_MAX_CHUNK_SIZE in {WRITER.relative_to(ROOT)}. This check "
            "compares four definitions of one range and cannot do that if one "
            "has moved or been renamed; passing quietly would be worse than "
            "stopping.")
    return int(found.group(1)), int(found.group(2))


def reader_bounds() -> tuple[int, int]:
    text = READER.read_text(encoding="utf-8")
    found = re.search(
        r"static int valid_chunk_size\(uint64_t value\) \{\s*"
        r"return value >= UINT64_C\((\d+)\) && value <= UINT64_C\((\d+)\)",
        text)
    if not found:
        raise SystemExit(
            "check-xai-fs-chunk-bounds: cannot find the bounds in "
            f"{READER.relative_to(ROOT)}'s valid_chunk_size().")
    return int(found.group(1)), int(found.group(2))


def tool_bounds() -> tuple[int, int]:
    text = TOOL.read_text(encoding="utf-8")

    def value(name: str) -> int:
        found = re.search(rf"^{name} = (\d+) \* 1024 \* 1024$", text, re.M)
        if not found:
            raise SystemExit(
                f"check-xai-fs-chunk-bounds: cannot find {name} in "
                f"{TOOL.relative_to(ROOT)} as a whole number of mebibytes.")
        return int(found.group(1)) * 1024 * 1024

    return value("MIN_CHUNK_SIZE"), value("MAX_CHUNK_SIZE")


def documented_bounds() -> tuple[int, int]:
    """The range `docs/MODELFS-FORMAT.md` states, in MiB, as bytes.

    Written the way the document writes it rather than as a constant, because a
    reader has to be able to check it against the sentence.
    """
    text = FORMAT.read_text(encoding="utf-8")
    found = re.search(
        r"Chunk size is one power of two from (\d+) MiB through (\d+) MiB", text)
    if not found:
        raise SystemExit(
            "check-xai-fs-chunk-bounds: cannot find the chunk-size sentence in "
            f"{FORMAT.relative_to(ROOT)}; the format's own statement of its "
            "bounds is the fourth thing this compares.")
    mib = 1024 * 1024
    return int(found.group(1)) * mib, int(found.group(2)) * mib


def main() -> int:
    sources = (
        (WRITER.relative_to(ROOT).as_posix(), writer_bounds()),
        (READER.relative_to(ROOT).as_posix(), reader_bounds()),
        (TOOL.relative_to(ROOT).as_posix(), tool_bounds()),
        (FORMAT.relative_to(ROOT).as_posix(), documented_bounds()),
    )

    failures: list[str] = []
    minimums = {bounds[0] for _, bounds in sources}
    maximums = {bounds[1] for _, bounds in sources}
    if len(minimums) != 1:
        failures.append(
            "the minimum chunk size differs: " + ", ".join(
                f"{name} says {bounds[0]}" for name, bounds in sources))
    if len(maximums) != 1:
        failures.append(
            "the maximum chunk size differs: " + ", ".join(
                f"{name} says {bounds[1]}" for name, bounds in sources))

    for name, (low, high) in sources:
        if low >= high:
            failures.append(f"{name} has an empty range: {low}..{high}")

    if failures:
        print("xai-fs-chunk-bounds: failed")
        for failure in failures:
            print(f"  - {failure}")
        print(
            "  one format with two caps is one cap nobody can rely on: the "
            "reader will open a volume the writer refuses, and which one a "
            "person meets depends on which tool they used")
        return 1

    low, high = sources[0][1]
    mib = 1024 * 1024
    print(f"xai-fs-chunk-bounds: writer, reader, host tool and "
          f"{FORMAT.name} all say {low // mib}-{high // mib} MiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
