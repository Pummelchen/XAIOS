#!/usr/bin/env python3
"""An aggregate step must outlast the gate it runs, or it silences it.

`qemu-core-os-rc` gives each step a budget and kills it at that budget. The
gates it runs have budgets of their own -- `smoke_timeout(arch, base)` waits for
a boot marker, and the RISC-V factor multiplies those by four. When a gate's own
wait is longer than the budget the aggregate allows the step, the gate can never
report anything: the aggregate kills it first and prints `exited 124 after Ns of
an Ns budget`, which names no architecture, no phase and no reason.

That has happened twice. `nvme` had a 1440-second RISC-V row inside a 900-second
budget, and reported an anonymous timeout through two CI runs until B-72 raised
the budget -- at which point it immediately named the row and the missing marker
it had been unable to mention. `fragmentation` had a 720-second RISC-V wait
inside 360, which is B-39: a step that once took at least 3.7x its usual runtime
and could only be recorded as a timeout with nothing attached.

B-39 found this one level up -- the aggregate's own budgets exceeded its CI
job's cap, so a hung step surfaced as an anonymous *job* timeout. This is the
same mistake between the aggregate and its gates.

**What this can and cannot see.** It reads two spellings of a wait out of each
gate's source: `smoke_timeout(arch, <literal>)`, and `smoke_timeout(arch,
int(env.get("VAR", "<literal>")))`, which is how the nvme gate writes it. A wait
built any other way is invisible, and a gate whose slow part is not a
`smoke_timeout` call at all is invisible too. So a pass means "no inversion
among the waits that can be read" -- worth having, and not the same as "no
inversion".

The second spelling is here because the first version of this check did not read
it, and therefore missed `nvme`, which is one of the two inversions that prompted
writing it. Both are covered now and both are exercised as controls: putting
`fragmentation`'s wait back to 180, or `nvme`'s budget back to 300, makes this
fail. A check nobody has watched fail is not a check.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "scripts"))

AGGREGATE = ROOT / "tests" / "scripts" / "qemu-core-os-rc.py"
MAKEFILE = ROOT / "Makefile"
SCRIPTS = ROOT / "tests" / "scripts"


def script_for(target: str) -> str | None:
    """The gate script a make target runs, if it runs exactly one."""
    if target.endswith(".py"):
        return target
    body = re.search(rf"^{re.escape(target)}:.*?\n((?:\t.*\n)+)",
                     MAKEFILE.read_text(encoding="utf-8"), re.M)
    if not body:
        return None
    found = re.search(r"tests/scripts/([a-z0-9_-]+\.py)", body.group(1))
    return found.group(1) if found else None


def main() -> int:
    # The scale is the runner's, because that is where the budgets bite. Read
    # through the same helper the gates use rather than multiplied here.
    os.environ.setdefault("XAIOS_GATE_TIMEOUT_SCALE", "3")
    from qemu_gate_lib import QEMU_ARCHES, smoke_timeout  # noqa: E402

    text = AGGREGATE.read_text(encoding="utf-8")
    steps = re.findall(r'\("([a-z_0-9]+)",\s*\[([^\]]+)\],\s*(\d+)\)', text)
    if not steps:
        raise SystemExit(
            "check-aggregate-budgets: no steps found in "
            f"{AGGREGATE.relative_to(ROOT)}. This check exists to compare two "
            "sets of budgets and cannot do that if it can no longer find one "
            "of them; passing quietly would be worse than stopping.")

    failures: list[str] = []
    compared = 0
    for name, command, budget_text in steps:
        target = re.search(r'"make",\s*"([a-z0-9-]+)"', command) or \
                 re.search(r'"([a-z0-9_-]+\.py)"', command)
        if not target:
            continue
        script_name = script_for(target.group(1))
        if not script_name or not (SCRIPTS / script_name).is_file():
            continue
        gate = (SCRIPTS / script_name).read_text(encoding="utf-8")
        # Two spellings, both real. A literal base, and a base that comes
        # from the environment with a literal default -- which is how the nvme
        # gate writes it, and reading only the first spelling is how the first
        # version of this check missed the very inversion B-72 was about.
        bases = [int(b) for b in
                 re.findall(r"smoke_timeout\(\s*[^,()]+,\s*(\d+)\s*\)", gate)]
        bases += [int(b) for b in re.findall(
            r"smoke_timeout\(\s*[^,()]+,\s*int\(\s*\w+\.get\("
            r"\s*\"[A-Z_0-9]+\"\s*,\s*\"(\d+)\"\s*\)\s*\)\s*\)",
            gate, re.S)]
        if not bases:
            continue
        # Which architectures this gate can reach. QEMU_ARCHES is the usual
        # spelling; a gate naming riscv64 directly reaches it too.
        multi = "QEMU_ARCHES" in gate or "riscv64" in gate
        arches = QEMU_ARCHES if multi else ("aarch64",)
        worst = max(smoke_timeout(a, b) for a in arches for b in bases)
        budget = int(budget_text) * int(os.environ["XAIOS_GATE_TIMEOUT_SCALE"])
        compared += 1
        if worst > budget:
            failures.append(
                f"{name}: the aggregate allows {budget}s and "
                f"{script_name} waits up to {worst}s for one boot "
                f"({'all architectures' if multi else 'aarch64'}, base "
                f"{max(bases)}s). The gate cannot report its own failure -- "
                f"the aggregate kills it first and calls it a timeout with no "
                f"reason attached")

    if failures:
        print("check-aggregate-budgets: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"aggregate-budgets: {compared} steps outlast the gates they run, "
          f"at the runner's timeout scale")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
