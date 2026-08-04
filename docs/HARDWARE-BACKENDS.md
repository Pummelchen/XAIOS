# Hardware backends

The backend boundary is `engine/include/xaios_engine/backend.h`. It covers
capability validation, model preparation, prefill, decode, multi-position
verification, dense projection, state update, routing, expert execution,
reduction, scratch sizing, synchronization and cleanup.

Current status:

| Backend | Status | Evidence |
|---|---|---|
| Scalar reference | Scalar packed-kernel correctness complete | FP32 dense projection plus group-scaled signed INT4/INT6 no-expand GEMV/GEMM pass deterministic randomized and every-tail tests. Full model execution is unsupported. |
| AArch64 NEON | Optimized backend experimental | Native Apple Silicon known-answer startup canaries and scalar differential/tail tests pass for FP32 projection and packed INT4/INT6 GEMV/GEMM. No model parity or benchmark artifact exists. |
| macOS Metal | Roadmap only | No native Metal runtime exists. |
| Intel AVX2 | Optimized backend experimental | QEMU TCG executes INT4/INT6 known-answer canaries and the freestanding x86 image links the portable packed kernel. Physical x86 differential tests and benchmarks remain required. |
| Xeon AVX-512/VNNI/AMX | Roadmap only | No portable-engine backend exists. |

Backend selection is capability-gated. The scalar backend is selected only
when no unavailable capability is required, and its known-answer canary runs
before selection. CPUID or a CPU product name alone is never proof that an
optimized kernel is correct. The AVX2 backend additionally requires
OS-managed XMM/YMM state via `XCR0`; XAIOS enables that state only after CPUID
reports XSAVE and AVX.

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

Native macOS is a hosted engine target. Metal is optional and must retain the
CPU fallback. QEMU/HVF remains an OS correctness environment, not an Apple
performance backend. Xeon work must tune worker gangs at the memory-bandwidth
knee and report local/remote NUMA traffic rather than assuming more threads
improve decode.
