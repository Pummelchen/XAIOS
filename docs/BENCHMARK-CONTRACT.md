# Benchmark evidence contract

No XAIOS performance claim is valid without an immutable physical-hardware
artifact. QEMU output proves correctness and ABI behavior only.

## Required identity

Every artifact records the model/package/source revision, executable commit,
backend and layout IDs, exact or named approximate mode, hardware topology,
firmware/OS/toolchain versions, prompt/context, batch size, sampling settings,
and warm/cold state.

## Required measurements

Record raw repeated samples for TTFT, prefill throughput, decode p50/p95/p99,
time and bytes by layer phase, weight bytes per target pass and accepted token,
effective DRAM bandwidth, NUMA-local/remote bytes, router time, expert
frequency/cache/prefetch, unique experts during verification, storage queue
depth/throughput/latency, exposed and overlapped I/O wait, network fan-out and
reduction, PMU counters, frequency, power, thermals and energy where available.

Low-overhead worker trace rings feed out-of-band aggregation. UART logging and
per-token formatted output are forbidden in measured hot paths.

## Comparison rules

A comparative claim requires the same model revision, quantization, exactness,
prompt/context, hardware, and equivalent warm/cold state against a relevant
tuned baseline. Report repeated raw output and the aggregation method. Do not
multiply independent microbenchmark speedups into an end-to-end claim.

The primary optimization metric is effective independent bandwidth divided by
weight bytes moved per verified target pass. Thread count is autotuned against
sustained bandwidth. Speculative results include proposal length, accepted
length, target passes, time per accepted token, expert union and wasted
prefetch.

Claims such as "10x" or "production supported" require checked-in immutable
artifacts satisfying this contract. The existing QEMU benchmark reports set
`performance_claims_allowed=false` and cannot satisfy it.
