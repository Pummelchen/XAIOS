# Storage Benchmarking

Status: evidence contract defined; no qualifying physical ModelFS benchmark is
present.

QEMU storage tests establish parser, ABI, ordering, and failure-handling
correctness. Sparse files establish metadata width and bounded memory. Neither
is physical throughput, latency, durability, or power evidence.

## Required artifact identity

Every storage result must record:

- XAIOS source and executable commit hashes;
- model package identity, source revision, exactness mode, and layout ID;
- machine, CPU, memory, NUMA, firmware, storage device, transport, filesystem,
  kernel/OS, queue configuration, and thermal/power state;
- block geometry, volume UUID, chunk size, cache state, working-set size,
  alignment, concurrency, and read/write mix;
- exact command, raw output, repetition count, warm/cold policy, and failures.

## Metrics

At minimum report p50/p95/p99 latency, sustained bytes/s, IOPS where relevant,
CPU time, queue depth, requested/delivered/verified bytes, exposed I/O wait,
cache hit/miss, discard bytes, errors, and cancellation latency. For inference,
also report weight bytes per target pass and accepted token so storage numbers
can be related to verified model work.

## Workloads

- sequential and random aligned reads across resident and cold package ranges;
- chunk-boundary and unaligned logical reads through the real verifier;
- concurrent prefetch plus demand read with cancellation;
- stage, resume, verify, activate, and ENOSPC behavior;
- fsck/scrub over healthy and corrupted packages;
- trim on free extents followed by allocation and integrity verification;
- power-loss/fault injection at every metadata publication boundary;
- local and remote NUMA placement on Xeon hardware.

## Claim rules

Do not extrapolate sparse-fixture speed, QEMU timing, page-cache reads, or one
microbenchmark into end-to-end model throughput. Comparisons require the same
package, quantization, exactness, hardware, cache state, concurrency, and
workload. Report unsupported operations as unsupported, not zero cost.

The broader inference evidence requirements remain in
[`BENCHMARK-CONTRACT.md`](./BENCHMARK-CONTRACT.md).
