#!/usr/bin/env python3
"""Check model support tables against the authoritative JSON status source."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = ROOT / "docs/MODEL-SUPPORT.json"


def main() -> int:
    status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    failures = []
    if status.get("schema") != "xaios.model_support.v1":
        failures.append("model support schema mismatch")
    for entry in status.get("entries", []):
        row = f"| {entry['name']} | {entry['status']} |"
        for relative_path in entry.get("documents", []):
            path = ROOT / relative_path
            if not path.is_file():
                failures.append(f"missing support-status document: {relative_path}")
                continue
            if row not in path.read_text(encoding="utf-8"):
                failures.append(f"{relative_path} missing authoritative row: {row}")
    if failures:
        for failure in failures:
            print(f"model-support: {failure}")
        return 1
    print("model-support: README, tracker, and readiness status tables agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
