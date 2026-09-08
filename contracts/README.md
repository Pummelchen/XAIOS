# Contracts

Machine-readable statements of what the system must do, kept apart from the
code that satisfies them and from the gates that check them.

A contract here is not documentation of current behaviour. It is the fixed
expectation a gate is measured against, so that "the gate passes" means
something a reader can check rather than something the gate defines for
itself. When behaviour and contract disagree, one of them is wrong and the
disagreement is visible.

| File | What it fixes | Who reads it |
|---|---|---|
| `qemu-rc-v1.json` | The release-candidate contract: the capabilities a build must demonstrate, the console size and syscall numbers the ABI pins, and the RISC-V CPU tiers with the validation each one is held to. | `tests/scripts/qemu-core-os-rc.py`, `qemu-cpu-matrix.py`, `qemu-abi-contract.py` and four other gates. |
| `firmware-platform-profiles-v1.json` | The three qualification profiles — the firmware, device inventory and evidence class each one stands for — so that a result collected on one platform cannot be quoted for another. | `tests/repository/check-firmware-platform-profiles.py` and the profile gates. |

## Adding one

A file belongs here when a gate would otherwise carry its own expectations
inline. The point of the separation is that changing what the system must do
becomes a visible edit to a contract, rather than an invisible edit to the
test that happens to check it.

If nothing reads a file in this directory, it is not a contract — it is a
document that looks like one, and it will be believed. `benchmark-baseline-v1.json`
was removed for that reason: it had been added in a single commit, never read
by anything, and held only zeroes and a placeholder timestamp, while sitting
beside two files that genuinely bind. The performance rules it appeared to
state are in [the benchmark contract](../docs/BENCHMARK-CONTRACT.md), which
also explains why emulator timings are never performance evidence here.
