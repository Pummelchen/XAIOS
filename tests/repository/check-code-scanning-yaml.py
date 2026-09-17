#!/usr/bin/env python3
"""The deliberately narrow YAML reader used by the code-scanning contract.

This is not itself a repository check and is not wired into `make docs-check`;
`tests/repository/check-code-scanning-contract.py` loads it by name. It was
split out so that no source file in the tree exceeds 500 lines.
"""

from __future__ import annotations

import re


WORKFLOW = ".github/workflows/ci.yml"


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
