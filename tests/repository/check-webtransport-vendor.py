#!/usr/bin/env python3
"""Keep the vendored WebTransport C99 tree exactly what upstream shipped.

`third_party/webtransport-c99/` is a copy of an upstream library at a pinned
commit, and the whole value of a copy is that it is one: the moment a local
edit lands here without the vendoring record moving, the tree stops being an
audited implementation and starts being another in-tree fork nobody can
compare against upstream. `B-131`'s first requirement is that the modules are
vendored *with the upstream commit recorded*, so this checks both halves --
every file's SHA-256 against `MANIFEST.sha256`, and the commit in the README
against the one this file knows about.

A port that needs different behaviour adds a file beside the tree, the way
`userspace/wt/` does, rather than editing upstream in place.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VENDOR = ROOT / "third_party" / "webtransport-c99"
MANIFEST = VENDOR / "MANIFEST.sha256"
README = VENDOR / "README.md"

# The commit the tree was copied from. Changing the vendored tree means
# changing this, the README and the manifest in one change, which is the
# point.
UPSTREAM_COMMIT = "46937e29eb734887ca7b739abfedaf68ae565de2"


def read_manifest() -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, line in enumerate(
        MANIFEST.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = line.strip()
        if not line:
            continue
        digest, _, relative = line.partition("  ")
        if len(digest) != 64 or not relative:
            raise SystemExit(
                f"MANIFEST.sha256:{number}: not '<sha256>  <path>': {line!r}")
        entries[relative] = digest
    return entries


def main() -> int:
    failures: list[str] = []

    if not VENDOR.is_dir():
        print("webtransport-vendor: failed")
        print("  - third_party/webtransport-c99 is missing")
        return 1

    readme = README.read_text(encoding="utf-8")
    if UPSTREAM_COMMIT not in readme:
        failures.append(
            f"README.md does not record the vendored commit {UPSTREAM_COMMIT}")

    entries = read_manifest()
    on_disk = {
        path.relative_to(VENDOR).as_posix()
        for path in VENDOR.rglob("*")
        if path.is_file() and path != MANIFEST
    }

    for relative in sorted(on_disk - set(entries)):
        failures.append(f"unrecorded file in the vendored tree: {relative}")
    for relative in sorted(set(entries) - on_disk):
        failures.append(f"recorded file is missing: {relative}")
    for relative, digest in sorted(entries.items()):
        path = VENDOR / relative
        if not path.is_file():
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            failures.append(f"vendored file was modified: {relative}")

    if failures:
        print("webtransport-vendor: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        f"webtransport-vendor: {len(entries)} files match upstream "
        f"{UPSTREAM_COMMIT[:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
