#!/usr/bin/env python3
from pathlib import Path
from qemu_gate_lib import BUILD, ROOT, now, result, run, status_from_failures, write_report


SCHEMA = "xaios.qemu.developer_ux.v1"
REPORT = BUILD / "qemu-milestone-59-developer-ux.json"

REQUIRED_MAKE_TARGETS = [
    "qemu-regression-suite",
    "qemu-fault-injection",
    "qemu-abi-contract",
    "qemu-boot-loop",
    "qemu-userspace-suite",
    "qemu-network-suite",
    "qemu-cpu-ai-suite",
    "qemu-developer-ux",
    "qemu-post51-gate",
]

REQUIRED_DOC_MARKERS = {
    "README.md": ["wiki/Project-Tracker.md", "tests/README.md", "QEMU"],
    "wiki/Project-Tracker.md": ["P-20", "## Qwen 3.6 27B implementation", "Kimi K3 text"],
    "wiki/Test-Suite.md": ["make qemu-full-os-rc", "tests/scripts/"],
    "HARDWARE-READINESS.md": ["make qemu-post51-gate"],
}


def makefile_has_target(makefile: str, target: str) -> bool:
    return f"{target}:" in makefile or f"{target}: " in makefile


def main() -> int:
    failures = []
    checks = []
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in REQUIRED_MAKE_TARGETS:
        ok = makefile_has_target(makefile, target)
        checks.append(result(f"make_target_{target}", ok))
        if not ok:
            failures.append(f"missing Makefile target {target}")

    for doc, markers in REQUIRED_DOC_MARKERS.items():
        path = ROOT / doc
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        missing = [marker for marker in markers if marker not in text]
        checks.append(result(f"doc_{doc}", not missing, missing_markers=missing))
        failures.extend(f"{doc} missing marker {marker}" for marker in missing)

    dry_run = run(["make", "qemu-dry-run"], timeout=60)
    checks.append(result("qemu_dry_run", dry_run.returncode == 0, exit_code=dry_run.returncode))
    if dry_run.returncode != 0:
        failures.append(f"make qemu-dry-run exited {dry_run.returncode}")

    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 59,
        "created_at_unix": now(),
        "description": "Developer UX gate for post-51 QEMU targets, documentation, and dry-run command availability.",
        "checks": checks,
        "failures": failures,
    }
    write_report(REPORT, report)
    print(dry_run.stdout)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
