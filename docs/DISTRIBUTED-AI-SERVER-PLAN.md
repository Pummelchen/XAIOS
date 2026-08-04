# Distributed AI Server Plan

This plan evolves XAIOS into an SSH-administered distributed CPU inference
appliance without overstating the current implementation. SSH is the
administrative control plane. A separate authenticated service is required for
production inference traffic. QEMU results are correctness and ABI evidence,
not physical-hardware or performance evidence.

The current 20-item platform boundary is authoritative in
[`PLATFORM-SUPPORT.json`](./PLATFORM-SUPPORT.json).

## Status labels

Only these evidence levels are used: `planned`, `interface-only`,
`fixture-tested`, `reference-tested`, `hardware-tested`, and
`production-qualified`. A later phase can remain `planned` even when its
dependency is blocked; dependency state is recorded separately.

## Dependency order

| Phase | Status | Depends on | Exit gate |
|---:|---|---|---|
| 1. `xaiosctl` foundation | fixture-tested | Current syscall, SSH and telemetry foundations | Seven read-only commands, deterministic human/JSON output, bounded protocol, authorization/malformed tests, QEMU smoke and Debian OpenSSH interoperability. |
| 2. Administrative security | fixture-tested | Phase 1 | Role-mapped keys, revocation, config transactions, audit operations, host-key rotation and secret-redaction tests pass through Debian 13 OpenSSH against QEMU. |
| 3. Large model volume and packer | fixture-tested | Phase 2 mutation/audit rules and model-v2 | Immutable 64-bit volume, signed registration/activation, recovery, logical 100 GB sparse tests, resumable SFTP, cleanup/reuse, scrub and trim pass. Physical storage remains open. |
| 4. Model management | interface-only | Phase 3 | Transactional register/verify/activate/cleanup are implemented; execution load/unload/pin/evict/cache operations remain planned. |
| 5. Local inference | interface-only | Phases 3-4 and real Qwen correctness | The native service owns immutable package readers, async range I/O and transactional session metadata; golden logits/tokens, typed state, bounded scheduling, cancellation, backpressure and real metrics remain. |
| 6. Authenticated cluster control | planned | Phases 2 and 5 | Dedicated mutually authenticated protocol and three-node join/partition/replay tests. |
| 7. Distributed placement/execution | planned | Phase 6 | Transactional dense/MoE placement, deterministic routing and defined node-loss behavior. |
| 8. Benchmarks/diagnostics | planned | Phases 5 and 7 | Reproducible metadata-rich measurements and redacted support bundles. |
| 9. Production inference service | planned | Phase 5 and network reliability gates | Authenticated documented API subset, streaming, cancellation, loss/retransmission and saturation tests. |
| 10. Support qualification/cleanup | interface-only | All earlier phases | Documentation and support matrix match implementation and physical validation artifacts. |

## Phase 1: fixture-tested foundation

The current implementation provides:

- `/bin/xaiosctl` commands `version`, `status`, `health`, `capabilities`,
  `hardware`, `metrics`, and `logs`;
- common `--json`, `--timeout`, and `--node` options, with log cursor,
  component, limit and bounded-follow options;
- `xaios.control.v1`, a bounded binary request/response protocol with typed
  payloads, request IDs, authenticated role context and stable status codes;
- syscall 37 guarded by `XAIOS_CAP_CONTROL_QUERY`; the kernel derives the
  trusted role from process capabilities and ignores privilege claims in the
  untrusted payload;
- one shared userspace parser/renderer used by `/bin/xaiosctl` and the SSH
  daemon; `remote_login.c` does not implement control business logic;
- non-destructive log-ring cursors and line-level sensitive-data redaction;
- measured runtime fields where the kernel has a source and explicit
  `unknown`/JSON `null` values where discovery or services do not exist;
- an exact SSH allowlist boundary for `xaiosctl`, with no arbitrary executable
  launch.

Phase 1 evidence includes hosted deterministic JSON tests, kernel self-tests,
QEMU smoke, ABI/source parity, and the Debian 13 OpenSSH/SFTP/network suite.
Physical hardware and production inference remain outside this evidence.

The userspace loader now allocates image-page tracking from the validated ELF
page count, tracks the stack separately, rolls back partial mappings and covers
a 513-page case. This removes the former fixed 256-page tracking ceiling; it
does not by itself establish production-scale virtual-memory policy.

## Phase 2: fixture-tested administrative security

Existing SSH already has provisioned Ed25519 keys, optional explicit
development password records, fail-closed entropy, persistent host identity,
rekey, bounded concurrent sessions and rate limits. The phase is not complete
at a physical production level, but its QEMU-testable acceptance scope is now
implemented:

1. Strict complete `xaios.config.v1` show/validate/diff/apply with bounded
   values, persistent generations and failed-apply rollback.
2. Persistent observer/operator/administrator mapping from Ed25519 keys,
   key addition/removal and revocation of new authentication attempts.
3. Bounded checksummed audit records with actor, role, operation/result,
   mutation ID and object hash, without operation payloads.
4. Capability-checked, replay-protected mutations and final-administrator
   protection.
5. Secure-entropy-backed host-key rotation, persistent identity, transport
   closure and sensitive-path denial through shell/SFTP.
6. Independent per-connection shell cwd/parser contexts, channel limits,
   command limits, connection/auth rate limits and forced-rekey coverage.

Hosted parser tests, kernel self-tests, QEMU smoke and the Debian 13 client
suite cover valid/invalid/revoked keys, role denials, password build/runtime
modes, concurrent sessions, cwd isolation, config rollback/replay, host-key
persistence/rotation and log/audit redaction. Independent audit, physical NICs,
hostile-network soak and side-channel review remain later release gates.

## Phases 3-4: model storage and lifecycle

MutableFS remains limited to small configuration and state. The separate
content-addressed ModelFS volume provides 64-bit addressing, redundant metadata,
chunk checksums, signed manifests, resumable staging, atomic activation and
offline recovery. QEMU plus concurrent native macOS and Debian 13 OpenSSH
validate signed registration, staging, verify, audited activation, immutable
retrieval, cleanup/reuse, scrub and trim. Async I/O and physical durability
remain open. Extend the streaming host packer only with verified tensor transformations.

Model management starts only after the volume gate. Verify compatibility and
resources before allocation, share immutable weights, keep session state
private, and remove all partial state after failure.

## Phase 5: real local inference

The portable scalar backend remains the correctness authority. Bring up the
first real Qwen target through official tokenizer, tensor, layer, logits and
deterministic decode parity before enabling optimized kernels. Scheduling must
provide bounded queues, admission, cancellation, deadlines, backpressure,
per-session state ownership and measured TTFT/prefill/decode metrics.

The deterministic model-v1 path remains a fixture and production decode must
continue returning unsupported until these gates pass.

The portable service API is now executable in native macOS/Linux builds and
uses caller-owned model/session registries. Model admission retains an immutable
reader rather than copying a package. Aligned asynchronous reads target final
caller buffers and expose completion/cancellation. Session metadata supports
64-bit append, fork, commit, rollback and safe destruction. This is lifecycle
infrastructure only: architecture-specific KV/recurrent state, ragged batching,
speculation and transformer execution remain unsupported.

## Phases 6-7: cluster and placement

Use a dedicated bounded binary cluster protocol, not SSH fan-out. Start with
explicit membership, mutual authentication, replay protection, request IDs,
deadlines, idempotent mutation IDs and partition-aware health. Placement plans
must be separate from application, generation-bound and rejected when stale.

Dense placement and MoE expert ownership must account for architecture, NUMA,
RAM, bandwidth, residency, load and drain/quarantine state. Kimi K3 is not
supported until its actual KDA, MLA, routing, expert and MXFP4 parity gates pass.

## Phases 8-9: evidence and serving

Benchmarks must record build, model/package, backend, topology, placement,
context, batch, quantization, warmup and sample statistics. QEMU benchmark
output remains correctness-only.

The inference data plane requires a separate authenticated service with a
precisely documented API subset, streaming, limits, cancellation, drain and
stable errors. Network reliability, loss, partial I/O, long-lived connection
and multi-client gates must pass first. Prompts, generated text, credentials,
tokens and raw model data must never enter logs or support bundles.

## Phase 10: qualification

Support claims must use the repository's authoritative status source and
distinguish interface, fixture, reference and physical-hardware evidence.
Generic model-v2 or MoE infrastructure does not validate a named model. Full
Kimi K3 multimodal support remains separate from K3 text support.

## Current unresolved dependencies

- No real Qwen checkpoint has tokenizer/logits/decode parity.
- ModelFS has a fixture-tested transactional implementation, but no physical
  storage validation, asynchronous hardware backend or production qualification.
- The x86_64 image links the portable common subset, starts MADT APs, proves
  ring-3/syscall and XSAVE transitions, and operates modern VirtIO block/MSI-X
  plus network TX. It does not yet host the complete ARM userspace, SSH,
  filesystem, security, AI Cell or telemetry service set.
- A native macOS/Linux engine executable, experimental NEON, and experimental
  AVX2 packed kernels exist. Metal, SVE/SVE2, AVX-512/VNNI and AMX execution
  backends do not.
- No authenticated cluster protocol, placement engine or inference service
  exists.
- No qualifying physical Apple or Intel/Xeon benchmark artifact exists.
- Phase 2 uses bounded fixture stores (16 active keys, 16 revoked keys, 64 audit
  records and 16 shell contexts); production identity/audit scale and durable
  replay retention remain to be designed.
