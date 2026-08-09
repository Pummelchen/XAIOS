# Open Decisions

This page tracks decisions that still require hardware evidence, an
authoritative upstream source, or an explicit maintainer choice. Implemented
facts and closed decisions belong in the architecture and status pages instead.

| ID | Area | Decision or evidence required | Required before |
|---|---|---|---|
| OD-001 | Physical ARM target | Select the first supported physical Apple/ARM server target and its firmware, storage, and NIC boundary. | Physical ARM support claim |
| OD-002 | Physical Intel desktop | Select representative AVX2 hardware, hybrid-core policy, NIC, and storage baseline. | Intel desktop support claim |
| OD-003 | Physical Xeon | Select Xeon generation, socket/NUMA topology, memory population, NIC, and NVMe platform. | Xeon support claim |
| OD-004 | Production trust | Define update and ModelFS signing roots, key custody, rotation, revocation, recovery, and compromise response. | Untrusted deployment |
| OD-005 | SSH fleet policy | Define production connection limits, identity store, audit retention, lockout, rate limits, and operator recovery. | Production SSH service |
| OD-006 | Storage durability | Define supported NVMe devices, flush/FUA assumptions, discard policy, repair source, and power-loss acceptance. | Persistent physical deployment |
| OD-007 | Qwen fixtures | Pin official immutable Qwen configuration, tokenizer, SafeTensors, and trusted parity corpus. | Real Qwen implementation |
| OD-008 | Other model sources | Verify and pin official Kimi K3, DeepSeek V4 Flash 0731, and GLM 5.2 revisions and architecture identifiers. | Corresponding adapter work |
| OD-009 | Cluster transport | Select the first expert-parallel interconnect and ownership/failure model. | Multi-machine inference |
| OD-010 | Approximate modes | Define naming, quality reporting, telemetry, and acceptance for any optional approximate execution mode. | First approximate mode |

## Closed decisions

- XAIOS uses the PolyForm Noncommercial License 1.0.0; commercial use requires
  a separate written license.
- The project uses a custom minimal UEFI loader for current bring-up.
- AArch64 QEMU correctness gates default to TCG; HVF is experimental.
- FreeBSD is the primary external Unix behavioral reference, without FreeBSD
  or Linux binary ABI compatibility.
- XAIOS platform completion is the active workstream. Qwen 3.6 27B follows;
  other model families remain later roadmap items.
- Exact target-model semantics are the default. Approximate behavior, if
  introduced, must be explicit and opt-in.

Close an item only with a source commit, issue, design record, or immutable
physical-hardware artifact. See [[Risk Register|Risk-Register]] and
[[Current Limitations|Current-Limitations]].
