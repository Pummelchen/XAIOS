# Risk Register

This register covers risks that could invalidate correctness, security,
support, or performance claims.

| ID | Risk | Impact | Current mitigation |
|---|---|---|---|
| R-001 | Treating QEMU timing as hardware performance | Misleading platform claims | QEMU is limited to correctness and ABI evidence; physical artifacts must satisfy the benchmark contract. |
| R-002 | Documentation drift | Contributors act on stale architecture or status | Machine-readable support files and `make docs-check` validate README, trackers, readiness, and selected Wiki mirrors. |
| R-003 | x86_64 status overstated | Users expect AArch64 service parity | Every platform page lists the missing userspace, receive-network, SSH, filesystem, security, and runtime services. |
| R-004 | Unreviewed SSH exposure | Credential or remote-code compromise | Passwords are disabled by default, release builds reject them, and QEMU/OpenSSH gates test fail-closed behavior; production exposure remains prohibited. |
| R-005 | Production keys derived from fixtures | Update or ModelFS trust compromise | Development keys are labeled as fixtures; production key custody remains an entry gate. |
| R-006 | Storage correctness inferred from sparse/QEMU tests | Data loss or unusable throughput | Separate address-width, emulated crash, and physical durability/performance evidence. |
| R-007 | Parser arithmetic or ownership error | Memory corruption or package escape | Checked 64-bit arithmetic, bounded buffers, malformed-input tests, sanitizers, and immutable readers. |
| R-008 | Model interfaces advertised as inference support | Incorrect outputs and credibility loss | Status labels distinguish fixture, interface, scalar correctness, physical validation, and production support. |
| R-009 | SIMD capability inferred from CPUID alone | Illegal instruction or incorrect output | Backends require capability gates, operating-system state checks, startup known-answer canaries, and scalar differential tests. |
| R-010 | Fixed limits treated as scale targets | Failure on large servers or fleets | Runtime-size CPU/NUMA structures where implemented; remaining bounded SSH/admin/state limits are explicit. |
| R-011 | AI model scope blocks core OS completion | Platform never reaches a stable base | XAIOS is the only active workstream; Qwen starts after its completion gate. |
| R-012 | Wiki and repository specifications diverge | Broken operations and incorrect acceptance | Source/config remains authoritative; selected Wiki pages are versioned under `wiki/` and checked in CI. |

Review this page whenever a gate fails for an architectural reason, a new
physical platform is selected, or a support claim changes. See
[[Open Decisions|Open-Decisions]] and [[Current Limitations|Current-Limitations]].
