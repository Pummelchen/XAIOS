#!/usr/bin/env python3
"""Validate the model registry against the single human project tracker."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "docs/MODEL-SUPPORT.json"
ALLOWED = ("DONE", "TESTING", "IN PROGRESS", "NOT STARTED", "BLOCKED", "FAILED")


def tracked(text: str, name: str) -> bool:
    plain = text.replace("`", "")
    return any(f"| {name} | {status} |" in plain for status in ALLOWED)


def main() -> int:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    failures: list[str] = []
    if registry.get("schema") != "xaios.model_catalog.v2":
        failures.append("model catalog schema mismatch")
    relative = registry.get("canonical_tracker")
    tracker = ROOT / relative if isinstance(relative, str) else ROOT / "missing"
    if not tracker.is_file():
        failures.append("canonical model tracker is missing")
        text = ""
    else:
        text = tracker.read_text(encoding="utf-8")
    for entry in registry.get("delivery_workstreams", []):
        if not tracked(text, entry["name"]):
            failures.append(f"tracker missing delivery workstream: {entry['name']}")
    for entry in registry.get("models", []):
        if not tracked(text, entry["name"]):
            failures.append(f"tracker missing model status: {entry['name']}")
    if failures:
        for failure in failures:
            print(f"model-support: {failure}")
        return 1
    print("model-support: registry and canonical project tracker agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
