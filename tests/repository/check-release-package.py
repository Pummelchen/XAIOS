#!/usr/bin/env python3
"""Refuse to release a build whose packages do not match its images.

A release is three images now, one per architecture, and a zip beside each. The
AArch64 image is around 220 MB and GitHub will not take a file that size, so
the zips are what people actually receive -- and a zip is a copy: copies go
stale, and a stale one is indistinguishable from a current one by looking at
it.

That is not a hypothetical failure either. Build 1's first archive held a
kernel still calling itself 0.1.0 while every file describing it said Build 1,
made an hour before the image was rebuilt. Nothing about the archive showed it.
It took checksumming what was inside, which is precisely what nobody does by
hand before shipping.

So this checks what a person cannot see: that each archive exists, contains its
image and nothing else, and that the bytes inside it are the bytes the release
note says were tested. Three times over, because an architecture that is right
says nothing about the two beside it -- and a note that describes three
downloads while release/ holds two is a release that is short an image.
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
    """Every checksum the release note publishes, by filename.

    Two layouts, because the notes have used both: a prose pair, and the
    table build 4 introduced when the note grew to six downloads. Reading
    only the first meant this check found nothing in a note full of
    checksums and said so on every build since -- which is the right answer
    to "are they verified" and the wrong reason for it.

    Every file the note names is collected, not just the image and its
    archive: a note that publishes a checksum for a kit is making a claim
    about that kit, and an unverified claim is what this exists to catch.
    """
    text = note.read_text(encoding="utf-8")
    found = {}
    prose = re.compile(
        r"`(xaios_b" + re.escape(build) + r"[^`]*)` — [\d,]+ bytes\n"
        r"SHA-256 `([0-9a-f]{64})`")
    table = re.compile(
        r"\|\s*`(xaios_b" + re.escape(build) + r"[^`]*)`\s*\|\s*[\d,]+\s*\|"
        r"\s*`([0-9a-f]{64})`\s*\|")
    for pattern in (prose, table):
        for match in pattern.finditer(text):
            found[match.group(1)] = match.group(2)
    return found


def main() -> int:
    build_file = ROOT / "BUILD_NUMBER"
    if not build_file.is_file():
        print("release-package: BUILD_NUMBER is missing")
        return 1
    build = build_file.read_text(encoding="utf-8").strip()

    note = RELEASE / f"xaios_b{build}.md"
    if not note.is_file():
        print(f"release-package: no release note at {note.relative_to(ROOT)}")
        print("  A build nobody has described is not a release.")
        return 1

    published = recorded_checksums(note, build)

    # The images this build ships are the ones its note says it ships, rather
    # than a list written here.
    #
    # A list written here would have to be right about every build, and builds
    # do not all ship the same shape: up to build 5 a release was one image
    # carrying all three architectures, and from the split it is one image per
    # architecture. Hard-coding the new shape would declare build 5's note
    # wrong about build 5, which it is not -- it describes what was actually
    # published.
    #
    # What keeps this from being circular is the rule below it: every archive
    # in release/ for this build must appear in the note. A builder that
    # produced fewer images than intended is caught by build-release.sh, which
    # refuses to package an architecture it was asked for and cannot find; a
    # release/ holding an image nobody described is caught here.
    images = sorted(name for name in published if name.endswith(".iso"))
    failures = []
    if not images:
        print(f"release-package: build {build}'s note publishes no image "
              f"checksum, so there is nothing to check it against")
        print(f"  {note.relative_to(ROOT)} should publish a SHA-256 for each "
              f"image and each archive.")
        return 1

    packaged = set()
    for image_name in images:
        archive_name = f"{image_name}.zip"
        archive = RELEASE / archive_name
        packaged.update((image_name, archive_name))

        if archive_name not in published:
            failures.append(
                f"the note publishes {image_name} but no SHA-256 for "
                f"{archive_name}, which is the file people receive")
        if not archive.is_file():
            failures.append(
                f"the note publishes {archive_name} and release/ has no such "
                f"file; the image is too large for git, so the archive is what "
                f"ships")
            continue

        with archive.open("rb") as handle:
            archive_digest = digest(handle)
        if archive_name in published and \
                published[archive_name] != archive_digest:
            failures.append(
                f"{archive_name} on disk is {archive_digest[:12]} but the note "
                f"publishes {published[archive_name][:12]}")

        with zipfile.ZipFile(archive) as bundle:
            names = [n for n in bundle.namelist() if not n.endswith("/")]
            if names != [image_name]:
                failures.append(
                    f"{archive_name} should contain {image_name} and nothing "
                    f"else, and contains: {', '.join(names) or 'nothing'}")
            else:
                with bundle.open(image_name) as inner:
                    inner_digest = digest(inner)
                if inner_digest != published[image_name]:
                    failures.append(
                        f"the image inside {archive_name} is "
                        f"{inner_digest[:12]} but the note publishes "
                        f"{published[image_name][:12]} -- the archive is a "
                        f"copy of a different build")

        # The uncompressed image is not committed, but if this machine has one
        # it must be the same image, or somebody is about to publish the wrong
        # pair.
        loose = RELEASE / image_name
        if loose.is_file():
            with loose.open("rb") as handle:
                loose_digest = digest(handle)
            if loose_digest != published[image_name]:
                failures.append(
                    f"{loose.relative_to(ROOT)} is {loose_digest[:12]} but the "
                    f"note publishes {published[image_name][:12]}")

    # Anything in release/ for this build that the note does not mention.
    #
    # This is the half that stops the rule above from being circular. A note
    # that describes three images and a release/ holding four is a release with
    # a file in it nobody has said anything about -- which is how a build ends
    # up shipping an artifact from a layout it abandoned, sitting beside the
    # ones it meant to ship and looking exactly as official.
    for candidate in sorted(RELEASE.glob(f"xaios_b{build}*")):
        name = candidate.name
        if name == note.name or name in published or name in packaged:
            continue
        failures.append(
            f"{candidate.relative_to(ROOT)} is in release/ for this build and "
            f"the note does not mention it")

    # The kits the note publishes checksums for. They are not committed --
    # copies of an image are chances for it to disagree with itself -- so they
    # are checked where they exist, which on the machine cutting the build is
    # all of them. A kit whose bytes have moved on since the note was written
    # is the same fault as a stale archive, one download further out.
    for name, expected in sorted(published.items()):
        if name in packaged:
            continue
        candidate = RELEASE / name
        if not candidate.is_file():
            continue
        with candidate.open("rb") as handle:
            found_digest = digest(handle)
        if found_digest != expected:
            failures.append(
                f"{candidate.relative_to(ROOT)} is {found_digest[:12]} but "
                f"the note publishes {expected[:12]}")

    if failures:
        print(f"release-package: build {build}'s packages do not match its note")
        for failure in failures:
            print(f"  - {failure}")
        print("  Run: make release-package")
        return 1

    total = sum((RELEASE / f"{name}.zip").stat().st_size for name in images)
    print(f"release-package: build {build} ships {len(images)} "
          f"image{'s' if len(images) != 1 else ''} "
          f"({total:,} bytes of archive) carrying what the note publishes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
