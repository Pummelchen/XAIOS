#!/usr/bin/env python3
"""Refuse to release a build whose package does not match its image.

The image is around 220 MB and GitHub will not take a file that size, so the
release travels as a zip. That makes the zip the thing people actually receive,
and a zip is a copy: copies go stale, and a stale one is indistinguishable from
a current one by looking at it.

That is not a hypothetical failure either. Build 1's first archive held a
kernel still calling itself 0.1.0 while every file describing it said Build 1,
made an hour before the image was rebuilt. Nothing about the archive showed it.
It took checksumming what was inside, which is precisely what nobody does by
hand before shipping.

So this checks what a person cannot see: that the archive exists, contains the
image and nothing else, and that the bytes inside it are the bytes the release
note says were tested.
"""

from __future__ import annotations

import hashlib
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "release"
# 220 MB does not want to be read into memory in one piece.
CHUNK = 1024 * 1024


def digest(handle) -> str:
    sha = hashlib.sha256()
    while True:
        block = handle.read(CHUNK)
        if not block:
            break
        sha.update(block)
    return sha.hexdigest()


def recorded_checksums(note: Path, build: str) -> dict[str, str]:
    """The checksums the release note publishes, by filename."""
    text = note.read_text(encoding="utf-8")
    found = {}
    for name in (f"xaios_b{build}.iso", f"xaios_b{build}.iso.zip"):
        match = re.search(
            r"`" + re.escape(name) + r"` — [\d,]+ bytes\nSHA-256 `([0-9a-f]{64})`",
            text)
        if match:
            found[name] = match.group(1)
    return found


def main() -> int:
    build_file = ROOT / "BUILD_NUMBER"
    if not build_file.is_file():
        print("release-package: BUILD_NUMBER is missing")
        return 1
    build = build_file.read_text(encoding="utf-8").strip()

    image_name = f"xaios_b{build}.iso"
    archive = RELEASE / f"{image_name}.zip"
    note = RELEASE / f"xaios_b{build}.md"
    failures = []

    if not note.is_file():
        print(f"release-package: no release note at {note.relative_to(ROOT)}")
        print("  A build nobody has described is not a release.")
        return 1
    if not archive.is_file():
        print(f"release-package: no archive at {archive.relative_to(ROOT)}")
        print("  The image is too large for git; the archive is what ships.")
        print("  Run: make release-package")
        return 1

    published = recorded_checksums(note, build)
    for name in (image_name, f"{image_name}.zip"):
        if name not in published:
            failures.append(f"the release note publishes no SHA-256 for {name}")

    with archive.open("rb") as handle:
        archive_digest = digest(handle)
    if f"{image_name}.zip" in published and \
            published[f"{image_name}.zip"] != archive_digest:
        failures.append(
            f"the archive on disk is {archive_digest[:12]} but the note "
            f"publishes {published[f'{image_name}.zip'][:12]}")

    with zipfile.ZipFile(archive) as bundle:
        names = [n for n in bundle.namelist() if not n.endswith("/")]
        if names != [image_name]:
            failures.append(
                f"the archive should contain {image_name} and nothing else, "
                f"and contains: {', '.join(names) or 'nothing'}")
        elif image_name in published:
            with bundle.open(image_name) as inner:
                inner_digest = digest(inner)
            if inner_digest != published[image_name]:
                failures.append(
                    f"the image inside the archive is {inner_digest[:12]} but "
                    f"the note publishes {published[image_name][:12]} -- the "
                    f"archive is a copy of a different build")

    # The uncompressed image is not committed, but if this machine has one it
    # must be the same image, or somebody is about to publish the wrong pair.
    loose = RELEASE / image_name
    if loose.is_file() and image_name in published:
        with loose.open("rb") as handle:
            loose_digest = digest(handle)
        if loose_digest != published[image_name]:
            failures.append(
                f"{loose.relative_to(ROOT)} is {loose_digest[:12]} but the note "
                f"publishes {published[image_name][:12]}")

    if failures:
        print(f"release-package: build {build}'s package does not match its note")
        for failure in failures:
            print(f"  - {failure}")
        print("  Run: make release-package")
        return 1

    print(f"release-package: build {build} ships {archive.name} "
          f"({archive.stat().st_size:,} bytes) carrying the image the note "
          f"publishes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
