#!/usr/bin/env python3
"""Keep resolved CodeQL security boundaries from regressing."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECK = "tests/repository/check-code-scanning-contract.py"

# tests/repository/check-test-layout.py requires every top-level *.py in this
# directory to be named `check-*`, and an import statement cannot name a module
# with a hyphen in it. So the sibling holding the narrow YAML reader is loaded
# by name, with this file's own directory on sys.path -- which is where
# python3 already puts it when the check runs as
# `python3 tests/repository/check-code-scanning-contract.py`.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

_YAML = importlib.import_module("check-code-scanning-yaml")

BLOCK_SCALAR = _YAML.BLOCK_SCALAR
WorkflowParseError = _YAML.WorkflowParseError
WORKFLOW = _YAML.WORKFLOW
parse_workflow = _YAML.parse_workflow


# --------------------------------------------------------------------------
# The permission rule
#
# GitHub resolves a job's GITHUB_TOKEN permissions in two steps. The top-level
# `permissions:` block is the default for every job; a job's own `permissions:`
# block does not merge with that default, it replaces it -- "If you specify the
# access for any of these permissions, all of those that are not specified are
# set to none" (Workflow syntax reference, `permissions`). So a job block is the
# whole truth for that job, and every scope it leaves out is `none` however
# generous the workflow default was. That is why the effective set below is
# computed as a replacement and never as an update.
# --------------------------------------------------------------------------

# Scope names and the access levels each one accepts, from the workflow-syntax
# reference. An unknown name fails rather than being waved through: if GitHub
# adds a scope, that failure is the prompt to add it here on purpose.
PERMISSION_SCOPES: dict[str, tuple[str, ...]] = {
    "actions": ("read", "write"),
    "artifact-metadata": ("read", "write"),
    "attestations": ("read", "write"),
    "checks": ("read", "write"),
    "code-quality": ("read", "write"),
    "contents": ("read", "write"),
    "deployments": ("read", "write"),
    "discussions": ("read", "write"),
    "id-token": ("write",),
    "issues": ("read", "write"),
    "packages": ("read", "write"),
    "pages": ("read", "write"),
    "pull-requests": ("read", "write"),
    "security-events": ("read", "write"),
    "statuses": ("read", "write"),
    "vulnerability-alerts": ("read",),
}

ACCESS_LEVELS = {"none": 0, "read": 1, "write": 2}

# The workflow default every job inherits unless it says otherwise.
REQUIRED_DEFAULT = {"contents": "read"}

# Every grant above that default, keyed by job name and the exact scope, with
# the reason it exists. A job holding a permission that is not written here
# fails the check, so granting one is an edit to this file that a reviewer sees
# rather than a line in the workflow that nothing reads.
ALLOWED_ELEVATIONS: dict[tuple[str, str], tuple[str, str]] = {
    ("publish-wiki", "contents"): (
        "write",
        "pushes the curated wiki/ tree to the separate repository Wiki",
    ),
}


def _resolve_permissions(node, where: str) -> dict[str, str]:
    """Turn a `permissions:` value into {scope: level}, refusing what it cannot read."""
    if node is None:
        raise WorkflowParseError(f"{where}: empty permissions block")
    if node is BLOCK_SCALAR:
        raise WorkflowParseError(f"{where}: permissions given as a block scalar")
    if isinstance(node, str):
        if node == "read-all":
            return {
                scope: ("read" if "read" in levels else "none")
                for scope, levels in PERMISSION_SCOPES.items()
            }
        if node == "write-all":
            return {scope: levels[-1] for scope, levels in PERMISSION_SCOPES.items()}
        raise WorkflowParseError(
            f"{where}: unrecognised permissions shorthand {node!r} "
            "(expected a mapping, 'read-all' or 'write-all')"
        )
    if not isinstance(node, dict):
        raise WorkflowParseError(f"{where}: permissions is not a mapping")
    resolved: dict[str, str] = {}
    for scope, level in node.items():
        if scope not in PERMISSION_SCOPES:
            raise WorkflowParseError(
                f"{where}: unknown permission scope {scope!r}; if GitHub added it, "
                f"add it to PERMISSION_SCOPES in {CHECK}"
            )
        if not isinstance(level, str) or level not in ACCESS_LEVELS:
            raise WorkflowParseError(
                f"{where}: permission {scope!r} has value {level!r}, "
                "expected read, write or none"
            )
        if level != "none" and level not in PERMISSION_SCOPES[scope]:
            raise WorkflowParseError(
                f"{where}: permission {scope!r} does not accept {level!r}"
            )
        resolved[scope] = level
    return resolved


def _level(value: str) -> int:
    return ACCESS_LEVELS[value]


def _describe(mapping: dict[str, str]) -> str:
    granted = sorted(
        f"{scope}: {level}" for scope, level in mapping.items() if level != "none"
    )
    return ", ".join(granted) if granted else "nothing"


def audit_workflow_permissions(text: str) -> list[str]:
    failures: list[str] = []
    try:
        document = parse_workflow(text)
    except WorkflowParseError as error:
        return [
            f"{error}; this check cannot confirm the CI permission boundary "
            "until the workflow parses"
        ]

    try:
        default = _resolve_permissions(
            document.get("permissions"), f"{WORKFLOW} top-level permissions"
        )
    except WorkflowParseError as error:
        return [str(error)]

    explicit_default = {
        scope: level for scope, level in default.items() if level != "none"
    }
    if explicit_default != REQUIRED_DEFAULT:
        failures.append(
            f"{WORKFLOW} top-level permissions must grant exactly "
            f"{_describe(REQUIRED_DEFAULT)}, but grant {_describe(default)}; "
            "restore the read-only default"
        )

    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return failures + [
            f"{WORKFLOW} declares no jobs this check can read; the permission "
            "boundary is unverified"
        ]

    seen_elevations: set[tuple[str, str]] = set()
    for name, body in jobs.items():
        if not isinstance(body, dict):
            failures.append(f"{WORKFLOW} job {name!r} is not a mapping")
            continue
        if "runs-on" not in body and "uses" not in body:
            failures.append(
                f"{WORKFLOW} job {name!r} has neither runs-on nor uses; this check "
                "did not read the job body it was meant to audit"
            )
            continue

        if "permissions" in body:
            try:
                # A job block replaces the workflow default outright.
                effective = _resolve_permissions(
                    body["permissions"], f"{WORKFLOW} job {name!r} permissions"
                )
            except WorkflowParseError as error:
                failures.append(str(error))
                continue
        else:
            effective = dict(default)

        for scope in PERMISSION_SCOPES:
            granted = effective.get(scope, "none")
            baseline = default.get(scope, "none")
            if _level(granted) <= _level(baseline):
                continue
            seen_elevations.add((name, scope))
            allowed = ALLOWED_ELEVATIONS.get((name, scope))
            if allowed is not None and allowed[0] == granted:
                continue
            if allowed is not None:
                failures.append(
                    f"{WORKFLOW} job {name!r} grants '{scope}: {granted}', but "
                    f"{CHECK} only allows it '{scope}: {allowed[0]}'; change the job "
                    f"back, or update the ALLOWED_ELEVATIONS entry for "
                    f"({name!r}, {scope!r}) and say why"
                )
                continue
            failures.append(
                f"{WORKFLOW} job {name!r} grants '{scope}: {granted}', above the "
                f"workflow default of '{scope}: {baseline}', and no entry in "
                f"{CHECK} allows it; drop the grant from the job, or add "
                f"({name!r}, {scope!r}): ({granted!r}, \"<reason>\") to "
                "ALLOWED_ELEVATIONS"
            )

    for (name, scope), (granted, reason) in sorted(ALLOWED_ELEVATIONS.items()):
        if (name, scope) not in seen_elevations:
            failures.append(
                f"{CHECK} still allows job {name!r} to hold '{scope}: {granted}' "
                f"({reason}), but {WORKFLOW} no longer grants it; remove the stale "
                "ALLOWED_ELEVATIONS entry"
            )

    return failures


def main() -> int:
    failures: list[str] = []

    workflow = (ROOT / WORKFLOW).read_text(encoding="utf-8")
    failures.extend(audit_workflow_permissions(workflow))

    loopback_scripts = (
        "tests/scripts/qemu-local-console-gate.py",
        "tests/scripts/qemu-docker-network-suite.py",
        "tests/scripts/qemu-freebsd-bidirectional-suite.py",
    )
    for relative in loopback_scripts:
        source = (ROOT / relative).read_text(encoding="utf-8")
        if 'sock.bind(("0.0.0.0", 0))' in source:
            failures.append(f"{relative} reserves ephemeral ports on every interface")
        if 'sock.bind(("127.0.0.1", 0))' not in source:
            failures.append(f"{relative} does not reserve ephemeral ports on loopback")

    console_gate = (ROOT / loopback_scripts[0]).read_text(encoding="utf-8")
    if '" ".join(command)' in console_gate:
        failures.append("local-console gate logs unsanitized command arguments")

    readiness = (ROOT / "tests/scripts/qemu-readiness-gate.py").read_text(
        encoding="utf-8"
    )
    if 'print(f"  - {failure}")' in readiness:
        failures.append("readiness gate logs unsanitized validation values")

    xaiboot_fs = (ROOT / "kernel/fs/xaiboot_fs.c").read_text(encoding="utf-8")
    narrow_loop = (
        "for (uint16_t i = 0; i < g_active_data_sectors && found < count; ++i)"
    )
    if narrow_loop in xaiboot_fs:
        failures.append("xaibootFS block scan uses a narrowing loop index")
    # The invariant these guard is that a block number never silently loses
    # bits on its way onto a volume that records sixteen of them. It used to
    # live in the allocator, which numbered blocks directly; v6 records extents
    # and 32-bit starts, so the only place a block is narrowed is the
    # conversion written when an older volume's metadata is stored. Two checks
    # moved rather than removed: dropping them because the code moved would
    # leave the truncation they exist to prevent unguarded.
    if "if (block > UINT16_MAX) return UINT32_MAX;" not in xaiboot_fs:
        failures.append(
            "xaibootFS does not refuse a block that will not fit a 16-bit "
            "volume's metadata"
        )
    if "blocks[written++] = (uint16_t)block;" not in xaiboot_fs:
        failures.append("xaibootFS block-index conversion is not explicit")

    if failures:
        print("code-scanning-contract: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        "code-scanning-contract: passed workflow=read-only "
        f"job-elevations={len(ALLOWED_ELEVATIONS)}-allowlisted "
        "port-reservation=loopback diagnostics=bounded integer-width=safe"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
