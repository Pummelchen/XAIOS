#!/usr/bin/env python3
"""Compare the curated Wiki in wiki/ against the Wiki that is actually published.

risk R-012 records "repository Wiki diverges from live Wiki" as a live risk and
names three mitigations, the middle one being a *post-push byte comparison
against the live Wiki*. That comparison did not exist. `check-wiki-layout.py`
validates the curated pages in this repository -- their names, their links and
their tables -- and cannot see the published copy at all, and `publish-wiki`
copied the tree and pushed it without reading anything back. The risk was
therefore recorded as mitigated while nothing mitigated it.

It was not theoretical. The published Project-Tracker was 98 lines behind the
repository for a day: the run for `023afed0` spent about six hours queued and
pushed its copy at 12:54:21Z, thirty-five seconds *after* the run for `8345bb2`
had pushed a newer one. Nothing failed. `publish-wiki` now stands down unless
its commit is still the tip, and this is the check that reads the result back.

**This is deliberately not part of `make docs-check`.** `docs-check` is run by
`qemu-core-os-rc` under a 120-second budget and must work on a machine with no
network, because a documentation gate that needs the internet is one that
eventually gets skipped. It is run by `publish-wiki` after it pushes, which is
where a post-push comparison belongs, and by `make wiki-parity-check` for a
person. A divergence in a run that never published is reported by that run
failing, not by this script.

Usage:

    python3 tests/repository/check-wiki-parity.py

`XAIOS_WIKI_DIR` points at an already-checked-out copy of the published Wiki
instead of cloning one, which is how this is exercised without a network.
`XAIOS_WIKI_REMOTE` overrides the clone URL, and `GITHUB_TOKEN` is used when it
is set so the same code works against a private Wiki.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WIKI = ROOT / "wiki"

DEFAULT_REMOTE = "https://github.com/Pummelchen/XAIOS.wiki.git"


def clone_published(destination: Path) -> None:
    """Fetch the published Wiki into `destination`, or explain why not.

    The repository is public, so this needs no credential, but the token is
    used when one is present: a check that only works because a repository
    happens to be public stops working the day it is not.
    """
    remote = os.environ.get("XAIOS_WIKI_REMOTE", DEFAULT_REMOTE)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("XAIOS_WIKI_TOKEN")
    if token and remote.startswith("https://github.com/"):
        remote = remote.replace(
            "https://github.com/", f"https://x-access-token:{token}@github.com/", 1
        )

    result = subprocess.run(
        # A credential helper here would turn a missing token into a prompt,
        # and a check that waits for input is indistinguishable from a hang.
        ["git", "-c", "credential.helper=", "clone", "--depth", "1",
         "--single-branch", remote, str(destination)],
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if result.returncode != 0:
        raise SystemExit(
            "check-wiki-parity: cannot read the published Wiki from "
            f"{os.environ.get('XAIOS_WIKI_REMOTE', DEFAULT_REMOTE)}.\n"
            "This check compares the repository against what is published and "
            "cannot report on something it could not read; passing quietly "
            "would be worse than stopping.\n"
            f"  git said: {result.stderr.strip()}"
        )


def compare(published: Path) -> list[str]:
    """Every curated page, against the same page as published."""
    failures: list[str] = []
    curated = {path.name: path for path in sorted(WIKI.glob("*.md"))}
    live = {path.name: path for path in sorted(published.glob("*.md"))}

    for name in sorted(set(curated) - set(live)):
        failures.append(
            f"{name} is curated in wiki/ but was never published; the Wiki is "
            "missing a page this repository says it has")
    for name in sorted(set(live) - set(curated)):
        failures.append(
            f"{name} is published but absent from wiki/; `publish-wiki` leaves "
            "an orphan in place on purpose, so a person has to decide")

    for name in sorted(set(curated) & set(live)):
        ours = curated[name].read_bytes()
        theirs = live[name].read_bytes()
        if ours == theirs:
            continue
        ours_lines = ours.split(b"\n")
        theirs_lines = theirs.split(b"\n")
        first = next(
            (index for index, (a, b) in enumerate(zip(ours_lines, theirs_lines))
             if a != b),
            min(len(ours_lines), len(theirs_lines)),
        )
        failures.append(
            f"{name} differs: repository {len(ours)} bytes, published "
            f"{len(theirs)} bytes, first difference at line {first + 1}")
    return failures


def main() -> int:
    override = os.environ.get("XAIOS_WIKI_DIR")
    if override:
        published = Path(override).resolve()
        if not published.is_dir():
            raise SystemExit(
                f"check-wiki-parity: XAIOS_WIKI_DIR={override} is not a directory")
        failures = compare(published)
        where = override
        temporary = None
    else:
        temporary = tempfile.TemporaryDirectory(prefix="xaios-wiki-parity-")
        published = Path(temporary.name) / "wiki"
        clone_published(published)
        failures = compare(published)
        where = os.environ.get("XAIOS_WIKI_REMOTE", DEFAULT_REMOTE)

    if failures:
        print("wiki-parity: failed")
        for failure in failures:
            print(f"  - {failure}")
        print(
            "  the published Wiki is the page people read; wiki/ is the page "
            "this repository gates, so the two disagreeing means one of them is "
            "wrong and a reader has no way to tell which")
        return 1

    pages = len(list(WIKI.glob("*.md")))
    print(f"wiki-parity: all {pages} curated pages are byte-identical to {where}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
