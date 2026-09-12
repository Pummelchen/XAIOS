#!/usr/bin/env python3
"""Did CI actually pass on the commit being released?

`release-check` printed "this commit is verified on all four environments" on
the strength of a local gate record and a package audit. Neither of those knows
anything about CI, and CI was red on `main` for nine days while that sentence
kept being true -- build 6 was cut in the middle of it. The four environments
are the four this Mac can drive; the runner is a fifth, it runs Linux, and
every defect in that nine-day stretch was invisible here and immediate there.

So this asks. The repository is public, so the question needs no credential;
if one is in the environment it is used, and the answer is the same either way.

Three verdicts, as everywhere else:

  * the run for this commit succeeded -- pass
  * it failed -- fail, naming the jobs
  * anything else -- INCONCLUSIVE and non-zero, naming what could not be
    established: no run yet, a run still going, an unpushed commit, no network

The last of those is the point. A release check that cannot see CI and passes
anyway is worse than no check, because it prints the same sentence either way.

A dirty tree is a failure rather than an inconclusive. CI tested a commit; if
the working tree has moved since, the artefacts about to be released are not
the artefacts that were tested, and that is knowable here without asking
anyone.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = os.environ.get("XAIOS_CI_WORKFLOW", "XAIOS CI")
TIMEOUT = float(os.environ.get("XAIOS_CI_STATUS_TIMEOUT", "20"))


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True,
                          stdout=subprocess.PIPE, text=True).stdout.strip()


def repository() -> str:
    """owner/repo, from the remote, with any credential discarded.

    The push URL in this checkout carries a token. It is parsed away here and
    never printed: a check that leaks a credential into CI output has created a
    worse problem than the one it reports on.
    """
    override = os.environ.get("XAIOS_CI_REPOSITORY")
    if override:
        return override
    url = git("remote", "get-url", "origin")
    match = re.search(r"github\.com[/:]([^/]+/[^/]+?)(?:\.git)?$", url)
    if not match:
        raise SystemExit(
            "check-ci-status: INCONCLUSIVE -- the origin remote is not a "
            "GitHub URL, so there is no CI to ask about. Set "
            "XAIOS_CI_REPOSITORY=owner/repo if it lives elsewhere.")
    return match.group(1)


def runs_for(repo: str, sha: str) -> list[dict]:
    url = (f"https://api.github.com/repos/{repo}/actions/runs"
           f"?head_sha={sha}&per_page=100")
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "xaios-release-check",
    })
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.load(response).get("workflow_runs", [])


def failing_jobs(repo: str, run_id: int) -> list[str]:
    try:
        url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
        request = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "xaios-release-check",
        })
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            jobs = json.load(response).get("jobs", [])
    except Exception:  # noqa: BLE001 - the verdict is already decided
        return []
    return [j["name"] for j in jobs if j.get("conclusion") not in
            (None, "success", "skipped")]


def main() -> int:
    sha = git("rev-parse", "HEAD")
    dirty = git("status", "--porcelain")
    if dirty:
        count = len(dirty.split("\n"))
        print("check-ci-status: failed")
        print(f"  - the working tree has {count} uncommitted change(s), so "
              f"whatever CI verified is not what is about to be released. "
              f"Commit them, or stash them, and ask again.")
        return 1

    repo = repository()
    try:
        runs = runs_for(repo, sha)
    except urllib.error.HTTPError as error:
        # A 404 is a different statement from a network that is down, and
        # saying "could not be reached" about a repository that does not exist
        # sends whoever reads it to check their wifi.
        detail = {403: "the API refused the request; an unauthenticated rate "
                       "limit will do this, and GH_TOKEN raises it",
                  404: f"no repository {repo} is visible from here"}.get(
            error.code, f"the API answered {error.code}")
        print(f"check-ci-status: INCONCLUSIVE -- {detail}, so whether "
              f"{sha[:8]} passed CI is unknown. That is not a claim that it "
              f"failed, and it is not a licence to release.")
        return 1
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print(f"check-ci-status: INCONCLUSIVE, and the fault is this host's: "
              f"GitHub could not be reached ({type(error).__name__}), so "
              f"whether {sha[:8]} passed CI is unknown. That is not a claim "
              f"that it failed, and it is not a licence to release.")
        return 1

    ours = [r for r in runs if r.get("name") == WORKFLOW]
    if not ours:
        others = sorted({str(r.get("name")) for r in runs})
        print(f"check-ci-status: INCONCLUSIVE -- no {WORKFLOW!r} run exists "
              f"for {sha[:8]} in {repo}."
              + (f" Runs that do exist: {', '.join(others)}." if others else
                 " No workflow has run on this commit at all, which usually "
                 "means it has not been pushed."))
        return 1

    # Newest first is what the API returns; the latest attempt is the answer.
    run = ours[0]
    status, conclusion = run.get("status"), run.get("conclusion")
    if status != "completed":
        print(f"check-ci-status: INCONCLUSIVE -- the {WORKFLOW} run for "
              f"{sha[:8]} is {status}, so it has not said anything yet. "
              f"{run.get('html_url')}")
        return 1
    if conclusion != "success":
        named = failing_jobs(repo, int(run["id"]))
        print("check-ci-status: failed")
        print(f"  - the {WORKFLOW} run for {sha[:8]} concluded {conclusion}"
              + (f": {', '.join(named)}" if named else "")
              + f". {run.get('html_url')}")
        return 1

    print(f"ci-status: {WORKFLOW} passed on {sha[:8]} in {repo}, and the "
          f"working tree matches it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
