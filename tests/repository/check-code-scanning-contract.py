#!/usr/bin/env python3
"""Keep resolved CodeQL security boundaries from regressing."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/ci.yml"
CHECK = "tests/repository/check-code-scanning-contract.py"


# --------------------------------------------------------------------------
# A very small YAML reader, deliberately narrow
#
# The workflow is the only file read here, and it uses a small subset of YAML:
# block mappings, block sequences, plain and quoted scalars, single-line flow
# collections, block scalars and comments. Nothing else appears in it -- no
# anchors, aliases, merge keys, document markers, tabs or multi-line plain
# scalars.
#
# PyYAML is not a declared dependency of this repository (requirements-dev.txt
# carries paramiko and nothing else), no other check in tests/repository/
# imports it, and the Documentation Contract job runs `make docs-check` against
# whatever python3 the runner ships. So the subset is parsed here instead of
# taking a dependency the checks do not otherwise have.
#
# Every construct outside that subset raises. That is the point: this file
# exists to see a permission grant, and a reader that shrugged at a line it
# could not interpret would hide exactly the grant it was written to find.
# --------------------------------------------------------------------------


class WorkflowParseError(Exception):
    """The workflow used a construct this reader will not guess at."""


BLOCK_SCALAR = object()  # opaque stand-in for a `|` / `>` value

_BLOCK_SCALAR_HEADER = re.compile(r"^[|>][+-]?[0-9]*$")


class _Token:
    __slots__ = ("line", "indent", "dash", "content")

    def __init__(self, line: int, indent: int, dash: bool, content: str) -> None:
        self.line = line
        self.indent = indent
        self.dash = dash
        self.content = content


def _strip_comment(text: str, line: int) -> str:
    """Drop a trailing comment, respecting quoting."""
    out: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote == "'":
            if char == "'":
                if text[index + 1 : index + 2] == "'":
                    out.append("''")
                    index += 2
                    continue
                quote = None
            out.append(char)
            index += 1
            continue
        if quote == '"':
            if char == "\\":
                out.append(text[index : index + 2])
                index += 2
                continue
            if char == '"':
                quote = None
            out.append(char)
            index += 1
            continue
        if char in "'\"":
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "#" and (not out or out[-1] in " \t"):
            break
        out.append(char)
        index += 1
    if quote is not None:
        raise WorkflowParseError(f"{WORKFLOW}:{line}: unterminated {quote} quote")
    return "".join(out).rstrip()


def _split_key(content: str) -> tuple[str, str] | None:
    """Split `key: value` at the first structural colon, or return None."""
    quote: str | None = None
    depth = 0
    index = 0
    while index < len(content):
        char = content[index]
        if quote == "'":
            if char == "'":
                if content[index + 1 : index + 2] == "'":
                    index += 2
                    continue
                quote = None
        elif quote == '"':
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quote = None
        elif char in "'\"":
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == ":" and depth == 0 and content[index + 1 : index + 2] in ("", " "):
            return content[:index].strip(), content[index + 1 :].strip()
        index += 1
    return None


def _tokenize(text: str) -> list[_Token]:
    raw = text.split("\n")
    tokens: list[_Token] = []
    index = 0
    while index < len(raw):
        line = raw[index]
        number = index + 1
        if not line.strip():
            index += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:indent] or line[indent : indent + 1] == "\t":
            raise WorkflowParseError(f"{WORKFLOW}:{number}: tab used for indentation")
        body = line[indent:]
        if body.lstrip().startswith("#"):
            index += 1
            continue
        if body.strip() in ("---", "..."):
            raise WorkflowParseError(
                f"{WORKFLOW}:{number}: document markers are not supported"
            )
        content = _strip_comment(body, number)
        if not content:
            index += 1
            continue

        # Peel off any leading dashes, so `- key: value` becomes a sequence
        # marker plus a mapping token indented to where the key really starts.
        while content == "-" or content.startswith("- "):
            tokens.append(_Token(number, indent, True, ""))
            offset = 2 if content.startswith("- ") else 1
            rest = content[offset:]
            indent += offset + (len(rest) - len(rest.lstrip(" ")))
            content = rest.lstrip(" ")
            if not content:
                break
        if not content:
            index += 1
            continue

        if content[:1] in ("&", "*"):
            raise WorkflowParseError(
                f"{WORKFLOW}:{number}: anchors and aliases are not supported"
            )
        if content.startswith("? "):
            raise WorkflowParseError(
                f"{WORKFLOW}:{number}: explicit keys are not supported"
            )
        if content.startswith("<<:"):
            raise WorkflowParseError(
                f"{WORKFLOW}:{number}: merge keys are not supported"
            )

        tokens.append(_Token(number, indent, False, content))

        split = _split_key(content)
        value = split[1] if split else content
        if _BLOCK_SCALAR_HEADER.match(value):
            # Swallow the block scalar's body. It is free text -- `#`, `:` and
            # anything else in it must never be read as structure.
            index += 1
            while index < len(raw):
                following = raw[index]
                if following.strip() and (
                    len(following) - len(following.lstrip(" "))
                ) <= indent:
                    break
                index += 1
            continue
        index += 1
    return tokens


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        body = value[1:-1]
        return body.replace("''", "'") if value[0] == "'" else body
    return value


def _parse_flow(value: str, line: int):
    """Parse a single-line flow collection of scalars."""
    if value.count("[") + value.count("{") != value.count("]") + value.count("}"):
        raise WorkflowParseError(
            f"{WORKFLOW}:{line}: flow collection spanning lines is not supported"
        )
    inner = value[1:-1].strip()
    if "[" in inner or "{" in inner:
        raise WorkflowParseError(
            f"{WORKFLOW}:{line}: nested flow collections are not supported"
        )
    if value.startswith("["):
        if not value.endswith("]"):
            raise WorkflowParseError(f"{WORKFLOW}:{line}: malformed flow sequence")
        if not inner:
            return []
        return [_unquote(item.strip()) for item in inner.split(",")]
    if not value.endswith("}"):
        raise WorkflowParseError(f"{WORKFLOW}:{line}: malformed flow mapping")
    if not inner:
        return {}
    mapping: dict[str, str] = {}
    for entry in inner.split(","):
        split = _split_key(entry.strip())
        if split is None:
            raise WorkflowParseError(
                f"{WORKFLOW}:{line}: flow mapping entry {entry.strip()!r} "
                "is not 'key: value'"
            )
        key, item = split
        key = _unquote(key)
        if key in mapping:
            raise WorkflowParseError(f"{WORKFLOW}:{line}: duplicate key {key!r}")
        mapping[key] = _unquote(item)
    return mapping


def _parse_block(tokens: list[_Token], pos: int, indent: int):
    if tokens[pos].dash:
        return _parse_sequence(tokens, pos, indent)
    return _parse_mapping(tokens, pos, indent)


def _parse_sequence(tokens: list[_Token], pos: int, indent: int):
    items: list = []
    while pos < len(tokens) and tokens[pos].dash and tokens[pos].indent == indent:
        pos += 1
        if pos < len(tokens) and tokens[pos].indent > indent:
            node, pos = _parse_block(tokens, pos, tokens[pos].indent)
        else:
            node = None
        items.append(node)
    return items, pos


def _parse_mapping(tokens: list[_Token], pos: int, indent: int):
    mapping: dict[str, object] = {}
    while pos < len(tokens) and not tokens[pos].dash and tokens[pos].indent >= indent:
        token = tokens[pos]
        if token.indent > indent:
            raise WorkflowParseError(f"{WORKFLOW}:{token.line}: unexpected indentation")
        split = _split_key(token.content)
        if split is None:
            raise WorkflowParseError(
                f"{WORKFLOW}:{token.line}: expected 'key: value', found "
                f"{token.content!r}"
            )
        key, value = split
        key = _unquote(key)
        if key in mapping:
            raise WorkflowParseError(f"{WORKFLOW}:{token.line}: duplicate key {key!r}")
        pos += 1
        if value == "":
            if pos < len(tokens) and tokens[pos].indent > indent:
                node, pos = _parse_block(tokens, pos, tokens[pos].indent)
            elif pos < len(tokens) and tokens[pos].dash and tokens[pos].indent == indent:
                node, pos = _parse_sequence(tokens, pos, indent)
            else:
                node = None
        elif value[:1] in ("&", "*"):
            raise WorkflowParseError(
                f"{WORKFLOW}:{token.line}: anchors and aliases are not supported"
            )
        elif _BLOCK_SCALAR_HEADER.match(value):
            node = BLOCK_SCALAR
        elif value[:1] in ("[", "{"):
            node = _parse_flow(value, token.line)
        else:
            node = _unquote(value)
        mapping[key] = node
    return mapping, pos


def parse_workflow(text: str) -> dict:
    tokens = _tokenize(text)
    if not tokens:
        raise WorkflowParseError(f"{WORKFLOW}: no content")
    document, pos = _parse_block(tokens, 0, tokens[0].indent)
    if pos != len(tokens):
        raise WorkflowParseError(
            f"{WORKFLOW}:{tokens[pos].line}: trailing content this reader cannot place"
        )
    if not isinstance(document, dict):
        raise WorkflowParseError(f"{WORKFLOW}: top level is not a mapping")
    return document


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
