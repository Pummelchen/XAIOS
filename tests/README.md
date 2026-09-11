# XAIOS test suite

This directory is the authoritative home for test source, test runners, guest
fixtures, network clients, Docker test images, and fuzz seeds. The top-level
`scripts/` directory is reserved for build, image creation, launch, and host
bridge utilities.

## Layout

| Path | Contents |
|---|---|
| `tests/scripts/` | Python and shell gate runners, status validators, QEMU orchestration, fault injection, release checks, and benchmark-evidence generators. The shared helpers other gates build on are `qemu_gate_lib.py` and `riscv64_gate_lib.py`. |
| `tests/repository/` | Checks about the repository rather than about a running system -- platform neutrality, documentation freshness, this layout rule, the Wiki's shape, the user-facing catalogues, and the code-scanning contract. `make docs-check` runs them. |
| `tests/network/` | Debian and FreeBSD interoperability Dockerfiles, client/server scripts, IPv4/IPv6 helpers, keys generated at runtime, and network fixtures. |
| `tests/model_v2/` | Model-v2 round trips, malformed packages, sparse files and memory-bound conversion checks, plus the hosted engine and cluster tests. |
| `tests/storage/` | Hosted C tests for the storage stack: the block device, FAT, GPT, the VFS, xaibootFS v6 and its mirror, xaiFS administration, and large SFTP transfers. |
| `tests/system/` | Hosted C tests for kernel components with no subsystem directory of their own -- ACPI on both x86-64 and AArch64, cpusets, inflate, known-hosts parsing, the screen framework -- and the system-volume test. |
| `tests/xai_fs/` | The xaiFS host reader test and the fixture generators the crash, cache and sparse cases are run against. |
| `tests/security/` | ML-KEM and SSH host-identity tests. |
| `tests/control/` | The hosted control-client test for the administration ABI. |
| `tests/engine/` | The SHA-256 acceleration test. |
| `tests/xapt/` | The host-side test for signed `xapt` repositories and catalogues. |
| `tests/crashtest/` | Deterministic tests for untrusted input boundaries, run under AddressSanitizer and UndefinedBehaviorSanitizer by `make crash-test`. It has its own README, which states what it deliberately does not claim. |
| `tests/libc/` | ISO C99 requirement inventories plus strict language, library, startup and termination probes. |
| `tests/fuzz/` | Parser fuzz entrypoints and corpora. |
| `tests/fixtures/` | Deterministic test inputs that are safe to version, including the throwaway TLS material `tests/fixtures/README.md` explains. |

There is no single directory of hosted tests. A hosted C test sits beside the
subsystem it covers, and `make hosted-test` names each source file explicitly,
so adding one means adding it to that target as well as to a directory.

`tests/repository/check-test-layout.py` rejects test runners in `scripts/`, missing
Docker build inputs, and test-image inputs outside `tests/`. It runs through
`make docs-check`.

## Main commands

| Scope | Command |
|---|---|
| C compile boundary | `make compile-check` |
| Hosted unit tests | `make hosted-test` |
| Hosted sanitizers | `make hosted-sanitizer-test` |
| Hosted ISO C99 contract | `make libc-check` |
| Hosted ISO C99 runtime on all three architectures | `make qemu-libc-gate` |
| Signed xapt repository unit tests | `make xapt-test` |
| xapt app and A/B OS lifecycle on ARM/x86 | `make qemu-xapt-gate` |
| Code-scanning regression contract | `make code-scanning-contract` |
| Documentation and test layout | `make docs-check` |
| Firmware profile contract and documentation | `make firmware-profiles-check` |
| macOS QEMU ARM64 profile evidence | `XAIOS_AAVMF_CODE=/absolute/path/to/edk2-aarch64-code.fd make firmware-profile-macos-qemu-aarch64` |
| macOS VMware Fusion ARM64 profile evidence | `make firmware-profile-macos-vmware-fusion-aarch64` |
| Intel VPS QEMU x86_64 profile evidence | `XAIOS_FIRMWARE_PROFILE_HOST_CLASS=intel-vps XAIOS_OVMF_CODE=/absolute/path/to/OVMF_CODE.fd make firmware-profile-intel-vps-qemu-x86_64` |
| Production-source audit | `make production-source-audit` |
| ABI contract | `make qemu-abi-contract` |
| Primary AArch64 smoke | `make qemu-smoke` |
| x86_64 full-service smoke | `make qemu-x86_64-smoke` |
| USB HID local-console login on ARM64 and x86_64 QEMU | `make qemu-keyboard-input-gate` |
| Aggregate QEMU core OS | `make qemu-core-os-rc` |
| Parser, packet-fault, load/recovery, and three-architecture soak | `make qemu-network-adversarial-gate` |
| IPv4/IPv6 source fragmentation on ARM/x86 | `make qemu-outbound-fragmentation-gate` |
| Async NVMe PRP/SGL, cancellation, malformed completions, and all-queue x86 MSI-X/ARM ITS delivery | `make qemu-nvme-gate` |
| x86_64-only async NVMe evidence for the Intel profile | `make qemu-x86_64-nvme-gate` |
| x86 SRAT/SLIT/HMAT, 1 GiB mapping, targeted TLB invalidation, placement, and accounting | `make qemu-x86_64-numa-gate` |
| ARM SVE2 arithmetic and per-task Z/P/FFR preservation | `make qemu-aarch64-sve2-gate` |
| Power/recovery/operations closure | `make qemu-operations-closure` |
| Debian/OpenSSH interoperability | `make qemu-docker-network-suite` |
| FreeBSD client interoperability | `make qemu-freebsd-network-suite` |
| Bidirectional FreeBSD SSH/SCP and outbound `ssh -J` | `make qemu-freebsd-bidirectional-suite` |
| Four-endpoint network matrix | `XAIOS_INTEL_VPS=root@HOST make qemu-four-endpoint-network-suite` |

The complete command catalog is maintained in `Makefile`; focused runners live
in `tests/scripts/` and are normally entered through a Make target.

The smoke image exercises the in-guest local-DNSSEC resolver wiring
deterministically; it does not require a public resolver. The hosted DNS test
generates a signed root-to-child chain and verifies DNSKEY, DS, RRSIG, signed A,
signature corruption, expiry, NSEC NODATA, and malformed input. Normal images
perform the same local validation. SSH boot readiness depends on neither: it is
reached when the interface holds a usable IPv4 address, and `verify_ipv4_ready`
in `userspace/sshd/sshd.c` deliberately probes no external name or endpoint.

`qemu-operations-closure` builds authenticated AArch64 and x86_64 images and
uses the real guest SSH server to check abrupt-stop detection, persisted clean
reboot/shutdown, service controls, network diagnostics, DNS, ICMP, SNTP,
resource-pressure reporting, update status, configuration export/import, and
redacted support bundles. Before it kills the first guest it waits for that
guest's `lifecycle: record durable` console line, not merely for SSH: a guest
whose state volume never mounted reaches SSH just as fast and keeps its
lifecycle record in memory, and the gate used to report that as the *second*
boot failing to notice an unclean stop. Any other lifecycle verdict fails the
gate at the boot that produced it. By default it also runs a Debian 13 OpenSSH client
from the reproducible Docker image; `--skip-docker` is used by the aggregate
gate where Docker interoperability has a separate required job.

`qemu-docker-network-suite` also invokes every standalone file, text, archive,
and observability utility over the real guest SSH server. It verifies archive
round trips, recursive filesystem work, typed `ps`/`df` snapshots, and nested
transient launches before continuing into SSH, SFTP, rekey, concurrency, IPv6,
UDP, and administration coverage.

The same suite cold-boots xaibootFS v3/v4 migration fixtures into v5 and tests
the v5 limits: exact 256 KiB SFTP round trip, 256 KiB + 1 rejection, 180
directories, and persistence across a second boot. `qemu-parallel-network-load`
holds 32 SSH transports with two channels each across native macOS and Debian,
checks above-capacity rejection, then proves connection reclamation.

## Rebuilding disposable Docker test images

No required test program exists only inside a Docker layer. Every `COPY` input
is versioned below `tests/network/`, and package installation is declared in
the Dockerfile. Rebuild after moving to another Docker host with:

```sh
docker build -f tests/network/Dockerfile.debian13 -t xaios-debian13-network-client:13 .
docker build -f tests/network/Dockerfile.freebsd-qemu -t xaios-freebsd-qemu:15.1 .
```

The FreeBSD container supplies a reproducible QEMU harness; it does not pretend
that a Linux container has a FreeBSD kernel. The gate downloads the official
FreeBSD VM image, verifies its pinned SHA-256 identity, and stores the cache
under `~/.cache/xaios/freebsd/`. Docker images and that cache may be deleted at
any time and reconstructed from the repository plus the official download.

The bidirectional gate includes two complementary jump-host checks: an OpenSSH
client reaches FreeBSD through XAIOS inbound `direct-tcpip`, and XAIOS outbound
`ssh -J` reaches a second XAIOS SSH server through the FreeBSD OpenSSH jump
host. It also rejects malformed `-J` port specifications before any network
connection is opened.

Do not commit downloaded VM images, generated SSH keys, passwords, build
outputs, or reports. Test runners create ephemeral credentials and write
artifacts under `build/`.

## Three verdicts, not two

A gate that can only pass or fail will, sooner or later, report the host's
failure as the guest's defect. Three gates here arrived at that independently
on the same day, so it is written down rather than rediscovered a fourth time.

Every gate that has to *create* a condition before judging it should be able to
say three things:

- **pass** — the condition held and the thing under test behaved;
- **fail** — the condition held and the thing under test did not;
- **inconclusive** — the condition was never created, so nothing was learned.

The third still exits non-zero. An inconclusive run that exits zero is a gate
that cannot fail, which is the defect this repository has now found eight times
and is worse than having no gate at all. What it must not do is name the guest.
It should say what did not happen and which side of the wire it did not happen
on.

The three that needed it, and what each looked like before:

| Gate | The condition | What it reported instead |
|---|---|---|
| `qemu-sshd-transmit-rate-gate` | a peer reading below the floor | the host absorbed 725,203 bytes on the peer's behalf, so the guest was never shown a slow peer, correctly closed nothing — and the gate called that the defect |
| `qemu-ssh-connection-rate-gate` | 121 connections inside the limiter's window | five the host could not open and two accepted-then-silent counted as neither served nor refused, so one run reported both "only 113 of 120 were answered" and "all 121 were served" |
| `qemu-network-poll-cadence-gate` | a measurable gap between polls | avoided the trap by *recording* its number rather than asserting it, because on a shared machine the spread between runs belongs to the machine |

The last one is the cheaper pattern where it applies: if the quantity is
inherently the host's as much as the guest's, record it and assert only the
things that are not — that the instrument works, that the counter advanced,
that the transfers came back byte-identical.

A useful test when writing one: *if this gate ran on a machine with no guest at
all, what would it say?* If the answer is anything other than "inconclusive" or
"the workload never ran", the anti-vacuity floor is missing too.

## Evidence boundary

Hosted and QEMU results prove only the behavior named by each gate. QEMU timing
does not establish physical performance, durability, NUMA behavior, or hardware
support. See `docs/BENCHMARK-CONTRACT.md` and the Wiki
[`Testing XAIOS`](../wiki/Testing-XAIOS.md) page.
