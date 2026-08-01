# XAIOS Benchmark Methodology

## Overview

XAIOS QEMU benchmarks measure **correctness**, not raw performance. The QEMU environment validates that subsystems boot, self-test, and produce expected telemetry counters. Physical performance claims must satisfy [`docs/BENCHMARK-CONTRACT.md`](../docs/BENCHMARK-CONTRACT.md) with a relevant tuned baseline.

## What We Measure

### Correctness Gates (QEMU)

Every `make qemu-smoke` run validates 330+ boot markers covering:

- Exception handling and timer self-tests
- Memory management (PMM, VMM, NUMA, kheap, arena)
- SMMU and PCIe enumeration
- Filesystem operations (initramfs, mutable_fs, persistence)
- Network stack (ARP, IPv4, ICMP, UDP, TCP, queue-backed flow)
- Security enforcement (capabilities, sandbox, credential rejection)
- AI cell lifecycle (admission, arena, KV store, conflict detection)
- Service supervisor (start, crash, restart, cleanup)
- Userspace process lifecycle (load, run, exit, reclaim)
- CPU-AI deterministic fixture (model-v1 admission, byte-table tokenization and fixture dispatch)

### Telemetry Metrics (~100 keys)

The kernel emits a JSON telemetry payload at boot completion. Key categories:

| Category | Example Metrics |
|----------|----------------|
| Memory | `pmm_total_pages`, `pmm_free_pages`, `kheap_pages`, `arena_committed_pages` |
| Filesystem | `mutable_fs_files`, `mutable_fs_writes`, `mutable_fs_commits`, `mutable_fs_rollbacks` |
| Network | `network_rx_packets`, `network_tx_packets`, `network_udp_p999`, `network_tcp_p999` |
| Security | `security_denied_ops`, `security_capability_denials`, `security_sandbox_escape_rejects` |
| AI/ML | `cpu_ai_model_loads`, `cpu_ai_runtime_calls`, `ai_cell_transitions` |
| Processes | `user_process_transitions`, `user_process_loaded`, `user_process_exited` |
| Scheduling | `context_switch_total`, `migration_total` (both must be 0 for hot-path guarantee) |

## QEMU Environment

| Parameter | Value |
|-----------|-------|
| Host OS | macOS (Apple Silicon) or Ubuntu Linux |
| Accelerator | TCG (no KVM/HVF for reproducibility) |
| Machine | QEMU `virt` (ARM) |
| CPU | `cortex-a72` × 4 |
| RAM | 512 MB |
| Firmware | AAVMF (UEFI) |
| Timeout | 60s (configurable via `XAIOS_QEMU_SMOKE_TIMEOUT`) |

**Important**: QEMU TCG results are NOT performance indicators. They validate correctness only. A single QEMU TCG instruction may take 10-100x longer than bare metal.

## Linux/BSD Baseline

The `benchmark-baseline.py` script optionally boots a minimal Linux kernel in QEMU for comparison. To enable:

```sh
export XAIOS_LINUX_KERNEL=/path/to/Image.gz
export XAIOS_LINUX_INITRD=/path/to/initrd.cpio
make qemu-baseline
```

For a physical-hardware comparison:
1. Boot the same XAIOS executable/model package described by the artifact.
2. Boot tuned Linux on identical hardware with equivalent isolation, frequency and NUMA placement, for example:
   - `isolcpus=1,2,3` for dedicated AI cores
   - `nohz_full=1,2,3` for tick-less operation
   - CPU governor set to `performance`
   - NUMA pinning via `numactl`
3. Run identical model revisions, quantization, exactness, prompts and warm/cold states and retain repeated raw measurements.

## How to Reproduce

```sh
# Correctness benchmark (always available)
make qemu-benchmark

# Baseline comparison (requires Linux kernel + initrd)
make qemu-baseline

# Custom output path
XAIOS_BENCHMARK_OUTPUT=/tmp/results.json make qemu-baseline
```

## Interpretation Guide

- **Green gates**: All correctness contracts satisfied. System is internally consistent.
- **Red gates**: A subsystem contract is violated. Investigate the failing gate name in `qemu-benchmark.py`.
- **Missing telemetry keys**: A subsystem may not have initialized. Check `klog` output.
- **QEMU vs bare-metal**: Never compare QEMU numbers to Linux bare-metal numbers. They measure different things.

## Baseline Result Format

See `benchmarks/baseline-v1.json` for the JSON schema.
