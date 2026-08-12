# Physical qualification readiness

XAIOS now has one consolidated pre-physical evidence gate:

```sh
make qemu-qualification-readiness
```

The target builds both test images, then runs the benchmark telemetry gate,
network and SSH operations closure, IPv4/IPv6 fragmentation, NVMe queue and
flush checks, storage crash recovery, the 130-vCPU dynamic-capacity gate,
x86_64 common-runtime boot, and a configurable repeated QEMU soak. The default
soak is five boots; use `XAIOS_QUALIFICATION_SOAK_BOOTS=N` to request a
different deterministic count.

The report is written to
`build/qemu-qualification-readiness-report.json`. It includes the source
commit, command results and log paths, SHA-256 hashes for generated evidence,
and the QEMU/physical boundary. A passing report means:

- QEMU correctness and ABI evidence completed for the listed gates.
- ARM64 and x86_64 evidence was collected through the common runtime and SSH
  readiness paths.
- No physical performance or durability claim is authorized.

## Physical evidence still required

The following values are intentionally reported as
`unavailable-in-qemu`; zero is not a valid substitute:

| Area | Required evidence |
|---|---|
| NUMA | SRAT/SLIT/HMAT topology, worker-to-weight placement, local and remote bytes, and locality under load. |
| Memory | Repeated sustained bandwidth, latency, channel saturation, and NUMA-local versus remote measurements. |
| PMU | Cycles, instructions, cache misses, TLB walks, stalled cycles, and tool/firmware configuration. |
| Thermal | Frequency, power, temperature, throttling, and energy per operation over sustained load. |
| SSH/network | Physical NIC identity and firmware, throughput/latency/loss/reorder, concurrent SSH/SFTP sessions, recovery, and independent crypto review. |
| NVMe | Device identity, queue scaling, interrupt affinity, read/write latency, FUA/flush/discard, reset recovery, power-loss durability, and sustained performance. |

Each physical artifact must identify the hardware, firmware/microcode, driver,
topology, executable commit, toolchain, workload, warm/cold state, and raw
repeated samples. The benchmark contract remains the authority for claims.
QEMU timing, sparse files, virtual CPU counts, and host telemetry from the Mac
must not be substituted for guest hardware measurements.

## Status interpretation

The consolidated report uses `qemu_evidence_pass_physical_open` when all
emulated gates pass. This is evidence readiness, not physical support. N-F3P,
S-11P, D-08, and D-10 remain open in the [[Project Tracker|Project-Tracker]]
until named physical artifacts satisfy their acceptance criteria.
