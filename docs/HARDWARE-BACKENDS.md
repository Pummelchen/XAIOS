# Hardware backends

The backend boundary is `engine/include/xaios_engine/backend.h`. It covers
capability validation, model preparation, prefill, decode, multi-position
verification, dense projection, state update, routing, expert execution,
reduction, scratch sizing, synchronization and cleanup.

Current status:

| Backend | Status | Evidence |
|---|---|---|
| Scalar reference | Interface only | Dense-projection known-answer canary passes; full model execution is unsupported. |
| AArch64 NEON | Roadmap only | Existing kernel kernels are prototypes and are not connected to the portable engine. |
| macOS Metal | Roadmap only | No native Metal runtime exists. |
| Intel AVX2 | Roadmap only | No portable-engine backend exists. |
| Xeon AVX-512/VNNI/AMX | Roadmap only | No portable-engine backend exists. |

Backend selection is capability-gated. The scalar backend is selected only
when no unavailable capability is required, and its known-answer canary runs
before selection. CPUID or a CPU product name alone is never proof that an
optimized kernel is correct.

Optimized packed kernels must fuse unpack, scale and dot product in registers;
hot calls may not expand a complete matrix. Every backend must pass scalar
differential tests, randomized tails and unaligned boundaries. Persistent
worker pools and NUMA-domain scratch are required before multithreaded claims.

Native macOS is a hosted engine target. Metal is optional and must retain the
CPU fallback. QEMU/HVF remains an OS correctness environment, not an Apple
performance backend. Xeon work must tune worker gangs at the memory-bandwidth
knee and report local/remote NUMA traffic rather than assuming more threads
improve decode.
