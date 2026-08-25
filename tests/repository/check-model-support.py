#!/usr/bin/env python3
"""Validate the model registry against the single human project tracker."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "docs/MODEL-SUPPORT.json"
ALLOWED = ("DONE", "TESTING", "IN PROGRESS", "NOT STARTED", "BLOCKED", "FAILED")
RETIRED_TARGETS = ("GLM 5.2", "Qwen 3.6 27B", "Qwen3.6")
STATUS_SURFACES = (
    "README.md",
    "docs/MODEL-SUPPORT.json",
    "docs/ARCHITECTURE-ADAPTERS.md",
    "docs/MODEL-V2-SPECIFICATION.md",
    "wiki/Architecture.md",
    "wiki/Current-Limitations.md",
    "wiki/Home.md",
    "wiki/Project-Tracker.md",
)
EXPECTED_OPEN_WORKSTREAMS = {
    "Qwen 3.8 support",
    "Kimi K3 text support",
    "Kimi K3 multimodal support",
    "DeepSeek V4 Flash 0731 support",
}
EXPECTED_OPEN_MODEL_IDS = {
    "qwen_3_8",
    "kimi_k3_text",
    "kimi_k3_multimodal",
    "deepseek_v4_flash_0731",
}


def tracked(text: str, name: str) -> bool:
    plain = text.replace("`", "")
    return any(f"| {name} | {status} |" in plain for status in ALLOWED)


def check_entries(
    failures: list[str], text: str, entries: list[dict[str, object]], kind: str
) -> None:
    for entry in entries:
        name = entry["name"]
        should_track = entry.get("open_tracker")
        if not isinstance(name, str) or not isinstance(should_track, bool):
            failures.append(f"{kind} entry requires name and open_tracker fields")
        elif tracked(text, name) != should_track:
            expectation = "present" if should_track else "absent"
            failures.append(f"{kind} must be {expectation} in open tracker: {name}")


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
    check_entries(failures, text, registry.get("delivery_workstreams", []), "workstream")
    check_entries(failures, text, registry.get("models", []), "model")
    open_workstreams = {
        entry.get("name")
        for entry in registry.get("delivery_workstreams", [])
        if entry.get("open_tracker") is True
    }
    if open_workstreams != EXPECTED_OPEN_WORKSTREAMS:
        failures.append("open model workstream set does not match project scope")
    open_model_ids = {
        entry.get("id")
        for entry in registry.get("models", [])
        if entry.get("open_tracker") is True
    }
    if open_model_ids != EXPECTED_OPEN_MODEL_IDS:
        failures.append("open model ID set does not match project scope")
    for relative in STATUS_SURFACES:
        surface = (ROOT / relative).read_text(encoding="utf-8")
        for retired in RETIRED_TARGETS:
            if retired in surface:
                failures.append(f"{relative}: retired model target remains: {retired}")
    if failures:
        for failure in failures:
            print(f"model-support: {failure}")
        return 1
    print("model-support: registry and canonical project tracker agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
