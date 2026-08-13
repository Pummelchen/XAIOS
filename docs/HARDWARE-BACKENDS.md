# Hardware backends

Cross-platform progress is tracked only in
[`wiki/Project-Tracker.md`](../wiki/Project-Tracker.md). Backend descriptions
below are current implementation facts and must not be promoted beyond physical
evidence under the benchmark contract.

The backend boundary is `engine/include/xaios_engine/backend.h`. It covers
capability validation, model preparation, prefill, decode, multi-position
verification, dense projection, state update, routing, expert execution,
reduction, scratch sizing, synchronization and cleanup.

Current status:

| Backend | Status | Evidence |
|---|---|---|
| Scalar reference | Scalar packed-kernel correctness complete | FP32 dense projection plus group-scaled signed INT4/INT6 no-expand GEMV/GEMM pass deterministic randomized and every-tail tests. Full model execution is unsupported. |
| AArch64 NEON | Optimized backend experimental | Native Apple Silicon known-answer startup canaries and scalar differential/tail tests pass for FP32 projection and packed INT4/INT6 GEMV/GEMM. No model parity or benchmark artifact exists. |
| ARM SVE/SVE2 | Interface only | `make qemu-aarch64-sve2-gate` executes an SVE2 known-answer arithmetic canary under QEMU `-cpu max`. No packed kernel, scalable-state scheduler support, model parity, or physical artifact exists, so backend selection still fails closed. |
| macOS Metal | Roadmap only | No native Metal runtime exists. |
| Intel AVX2 | Optimized backend experimental | QEMU TCG executes INT4/INT6 known-answer canaries and the freestanding x86 image links the portable packed kernel. Physical x86 differential tests and benchmarks remain required. |
| Xeon AVX-512/VNNI/AMX | Roadmap only | No portable-engine backend exists. |

Backend selection is capability-gated. The scalar backend is selected only
when no unavailable capability is required, and its known-answer canary runs
before selection. CPUID or a CPU product name alone is never proof that an
optimized kernel is correct. The AVX2 backend additionally requires
OS-managed XMM/YMM state via `XCR0`; XAIOS enables that state only after CPUID
reports XSAVE and AVX.

The AArch64 interrupt frame preserves q0-q31, FPCR and FPSR and a live virtual
timer canary verifies restoration under QEMU. The x86 image sizes XSAVE state
from CPUID leaf `0xD`, validates XSAVE/XRSTOR, and applies the selected XCR0 to
started APs. CPUs without XSAVE use a validated FXSAVE/FXRSTOR FP/SSE fallback.
ZMM/opmask and AMX state remain disabled unless a future backend,
OS context path, and known-answer canary jointly authorize them.
The SVE2 boot canary enables scalable vectors only long enough to validate the
emulated instruction path. Scheduler frames do not preserve Z/P/FFR state, so
SVE/SVE2 application and inference execution remains disabled.

Optimized packed kernels must fuse unpack, scale and dot product in registers;
hot calls may not expand a complete matrix. Every backend must pass scalar
differential tests, randomized tails and unaligned boundaries. Persistent
worker pools and NUMA-domain scratch are required before multithreaded claims.

`engine/include/xaios_engine/packed.h` defines the current portable packed
contract. Weights are signed row-major INT4 or INT6, scales are one float per
row and logical group, and the final group may be short. Decode uses GEMV;
prefill/verification can use the current correctness GEMM wrapper. Both paths
use caller-owned input/output and zero matrix-sized scratch. The current NEON
implementation unpacks four register-resident values at a time, while AVX2
processes eight values per vector after bounded register-local unpacking.
Neither path claims an optimal packing or measured speedup.

The legacy QEMU kernel INT4/INT6 fixture matrix paths also unpack directly in
their dot products and no longer allocate expanded INT8 matrices. Their
compatibility work-unit API is still sequential and is documented as such.

`make engine-cli` builds `build/hosted/xaios-engine` as a native macOS/Linux
process. It probes and inspects packages but fails closed on `serve` while
adapters remain interface-only. Metal is optional and must retain the CPU
fallback. QEMU/HVF remains an OS correctness environment, not an Apple
performance backend. Xeon work must tune worker gangs at the memory-bandwidth
knee and report local/remote NUMA traffic rather than assuming more threads
improve decode.

Generic ARM server scope is UEFI on an SBSA-style AArch64 platform with PSCI,
GICv3 and firmware-discovered topology. Current execution evidence covers QEMU
`virt`; physical Ampere/Neoverse systems, ACPI-on-ARM variants, SVE vector
lengths and server RAS behavior are separate gates.
