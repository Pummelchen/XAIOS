# Testing XAIOS

All maintained test runners, fixtures, client scripts, and Docker definitions
are versioned under [`tests/`](https://github.com/Pummelchen/XAIOS/tree/main/tests).
The `scripts/` directory contains product build, image, launch, and bridge tools,
not test runners.

Gate orchestration is under `tests/scripts/`; protocol clients and reproducible
Debian/FreeBSD environments are under `tests/network/`.

Host prerequisites are Clang, LLD, Python 3, mtools, QEMU, and the UEFI
firmware for whichever of AArch64, x86_64 and RISC-V is being run. Setup
details are in [[Getting Started|Getting-Started]].

## Core validation

| Command | Purpose |
|---|---|
| `make docs-check` | Wiki/catalog/status and test-layout contracts. |
| `make compile-check` | Freestanding C compile checks with warnings treated as failures. |
| `make hosted-test` | Hosted model-v2, engine, parser, kernel, and utility tests. |
| `make wt-host-test` | The WebTransport C99 TLS 1.3, QUIC packet, framing and certificate suites: 1208 checks against RFC 8446, 8448, 9001, 7301 and 7748, host-side because these are arithmetic over byte strings and the target has no way to print a digest and compare it to an RFC. The code under test is the same code the target builds, over the same vendored BearSSL. `make wt-host-sanitize` is the same suites under AddressSanitizer and UndefinedBehaviorSanitizer -- both memory-safety defects found in this module so far were found by that run and not by the plain one -- and `make wt-vectors-check` recomputes the RFC values with Python and re-verifies both generated fixtures rather than trusting them. All three run on every push in the `wt-host-tests` job. |
| `make libc-check` | Strict hosted C99 headers, 464-function namespace/link, ELF layout, source pin, non-POSIX surface, and syscall-budget contract. |
| `make qemu-libc-gate` | Complete libc contract plus runtime and termination probes on every architecture that carries the library -- AArch64, x86_64 and RISC-V -- and emits the conformance report, which covers the two the contract's `architecture_gates` names. The gate builds every image it boots, from one table that is both the list built and the list booted -- it used to build two and boot three, so the RISC-V leg ran against whatever `build/` happened to hold (`B-31`). `make image-libc-test` is that same table with `--build-only`, and `make qemu-riscv64-libc-gate` is the same gate with `--arch riscv64`. |
| `make qemu-riscv64-gate` | RISC-V rv64gc on the QEMU `virt` board: boots the shared kernel to 100% across four harts and requires PCI and MMIO virtio both carrying a disk, xaiFS mounted at /models, the initial filesystem mounted, `/init` and the service manager run and returned from, the hosted C99 termination probes passed, every control command rendered, a `xaios login:` prompt, sshd listening, and at least 78 self-tests, with no assertion or panic anywhere. Four harts deliberately: firmware picks its own boot hart and it is not always hart 0. Negative control run -- zeroing the filesystem header fails it on six markers. |
| `make qemu-riscv64-boot-media-gate` | The same machine, booted from its own disk instead of from a kernel handed to QEMU: EDK2 firmware with no `-kernel`, requiring that firmware find the loader at the removable-media path, that the loader read the kernel off that same disk, and that the boot reach a login prompt with sshd listening. Needs `acpi=off`, or this EDK2 build publishes no device tree. Negative control run -- deleting the loader from the medium fails it on the loader markers. |
| `make qemu-riscv64-matrix-gate` | RISC-V at 1, 2, 4 and 8 harts: every boot must reach a login prompt, report exactly the harts it was given as scheduling, and answer an SSH login asking for its service state. Four independent boots with fresh firmware variables and fresh volumes each, so none can pass on state a previous run left behind. Hart count is the dimension swept because firmware picks its own boot hart and it is not always hart 0. |
| `make vz-bridged-gate` | V-03: a Virtualization.framework guest on the real LAN through the privileged vmnet relay, rather than through an entitlement Apple will not issue. Requires one root command the gate prints and will not run itself. Checks a lease from the LAN rather than the fallback address, a global IPv6 from a router advertisement, ICMP on both families, and that the guest's address is inside this host's own /24 -- a guest on vmnet's private range is reachable and not bridged. |
| `make vmware-fusion-network-gate` | F-03: the guest's network on the LAN it is bridged to, checked from this host over the same wire -- a real DHCP lease rather than the fallback address, a global IPv6 address from a router advertisement, ICMPv6 answered and the neighbour cache resolving it, SSH on both address families, and an SFTP round trip on the IPv6 address. Negative control: the same reachability check against an unheld address in the same prefix reports nothing. Loss and reordering are not claimed -- the LAN is not a controlled link. |
| `make vmware-fusion-outbound-gate` | F-03: outbound SSH and SCP *from* a bridged Fusion guest, and `direct-tcpip` forwarding through it, against a disposable Debian container published on this host's LAN address -- no Mac account, `authorized_keys` or system setting is touched. Each claim has a control. The SCP one is the instructive one: fetching a copy with a single byte flipped, the client reports success and exits clean, so only comparing content catches it. The forwarding control had to rule out a silently bypassed jump, since this host can reach the container directly -- a forward to a closed port must fail with the guest's own channel-open failure, not a local connection refusal, and the two shapes differ. Local DNSSEC chain validation stays unclaimed: the trust anchors are the compiled IANA root values with no in-guest caller, and the resolver address comes from the bridged lease with no override. |
| `make vmware-fusion-snapshot-gate` | Fusion snapshot and resume semantics: a snapshot is a point in time (pre-snapshot data survives a revert, post-snapshot data does not), a revert boots onto a filesystem the guest trusts, and a suspend is not counted as an unclean boot. Reads files over SFTP rather than the shell -- a habit from B-25, which is now fixed. |
| `make qemu-vmxnet3-gate` | F-02: the paravirtual NIC VMware offers, on a machine that boots in a loop. QEMU implements the same device, so a driver that could previously only be tried by hand on one laptop is held to the same standard as every other: the driver chosen, the device activated, the doorbell given a window of its own, no two drivers sharing a window, a real DHCP lease rather than the address an offer leaves behind, and an SSH key exchange completed from the far end of the wire. The lease is the load-bearing check -- an offer alone does not need the receive ring to work twice, and the acknowledgement does. |
| `make qemu-rss-steering-gate` | E4: the device steering received frames by flow hash, measured on a four-queue tap. Two builds differing only in the indirection table -- sixteen buckets naming four pairs, and one bucket naming queue zero -- driven with identical traffic. The first must spread across every serviced pair; the second must collapse onto pair zero and fail the same assertion, which is what makes the first mean anything. `rss=off` would not do as the control: a multi-queue tap steers by its own hash on the host side and spreads either way. Requiring every pair rather than "more than one" is what caught the two defects behind it -- a hash key whose byte 13 was zero, pinning the low bit of every flow's hash so only even buckets were reachable, and `max_tx_vq` sent as an index where the device reads a count, cutting a four-pair device to three. Linux and root only; macOS offers the feature bits on both transports and has no multi-queue backend for either. |
| `make qemu-ssh-session-exhaustion-gate` | B-25: a guest that boots perfectly and then refuses every command. Opens eighty SSH connections whose command the kernel refuses -- more than the sixty-four session contexts it keeps -- and then asks the guest to do something ordinary. Asserts that the kernel's session table never filled, not merely that commands still work, because the eviction backstop would otherwise hide a leaking sshd; and counts distinct accepted socket handles, because a stack that recycled them would make eighty connections one session repeated. `-x86_64` and `qemu-riscv64-` variants run the same gate on the other two architectures. |
| `make qemu-ssh-connection-rate-gate` | B-28: what refuses a session under sustained load, and whether the guest says why. sshd limits accepts per client address, and a soak round opens two connections, so its round 61 carries connection 121 against a limit of 120 -- closed before a byte of SSH is spoken, which from the far end is `Connection closed` with no banner. The limiter runs on accept, so bare TCP exercises it fast enough that 121 connections fit inside the window, which they must or the counter resets and nothing is proven. Three cases, each with its control: the first 120 must be answered with a banner, or a guest refusing everything would pass; 30 connections must all be served with no marker; and, with the window loaded to one short of the limit, two authenticated sessions must both be served -- the second only is if the first was credited back. Ten sessions would outrun the window and pass against any implementation. |
| `make qemu-outbound-batch-mode-gate` | B-37: the guest's outbound `ssh` and `scp` without a terminal. Nine cases: a plain key works with and without `-o BatchMode=yes` in under a second, an encrypted key in batch mode fails in 0.7 s naming the reason, and an encrypted key with no flag and no terminal ends at 60 s instead of never -- the bound is on *silence* at the prompt, so a person mid-passphrase is never cut off. An unknown `-o` is refused rather than ignored, because an ignored option is how a script believes it asked for something it did not get. Two images, because a private key reaches the guest only by being packed in: the kernel refuses any runtime write whose bytes contain `"BEGIN "`. |
| `make qemu-sftp-binary-passthrough-gate` | B-38: SFTP, forwards and agent channels carry arbitrary bytes and must not pass through the screen framework's alternate-screen filter. Four payloads round-trip byte for byte, three of them carrying `ESC [ ? 1 0 4 9 h`. The control payload passes in the same *red* run, so the harness is proven sound rather than assumed. Gated on what the channel is, because no byte test can work on arbitrary payload. |
| `make qemu-sshd-transmit-rate-gate` | B-40: a peer that trickles, against the one thread that serves everyone. In each 10 s window the peer must take 10 KiB or lose its connection; the assertion is that *other* sessions keep running, not that the slow one survives. Three outcomes, not two: the guest failed to close a genuinely slow peer, or the host absorbed the trickle and the verdict is inconclusive and says so by name, or pass -- the middle case still exits non-zero. That case is real: a run here read 641 B/s at the socket while the guest had already written 725,203 bytes and was never made to wait, so `SO_RCVBUF` is capped before connect. |
| `make qemu-sshd-channel-starvation-gate` | B-41: a channel that fails, and every channel behind it. A second session's forward carried 40 lines in the 20 s after another session's forward failed, against 0 before the fix. It watches the session that should still work, not the one that broke -- a gate checking only that the failing channel closed would pass against a server that then serviced nobody. |
| `make qemu-sshd-close-visibility-gate` | B-43: why a served connection closed, said on the console rather than in an audit file on the durable volume that nothing reads. A silent peer closed at 30.2 s reports `connect-timeout`, an invalid version line reports `client-version-invalid` in 0.2 s, an ordinary round trip reports `client-disconnect`. Two connections that fail *differently* must report differently, so a constant string fails, and an ordinary session's close must also be announced, so a fix that only lights up on the gate's own paths fails. |
| `make qemu-socket-flow-map-gate` | B-47: the socket-to-flow map refusing rather than accepting a connection and dropping it. The map cannot be filled from outside, so the kernel's own network self-test fills all 160 rows, takes the refusal on the next, and hands them back. It also requires that re-mapping an existing descriptor still succeeds on a full table -- the failure a naive "refuse when full" introduces. Red with the defect restored: the guest halts before the login prompt. |
| `make qemu-network-poll-cadence-gate` | B-44: how long the network stack can go unpolled. `network_poll_tick` has no timer, no interrupt and no thread, so the guest's networking runs only while sshd is in its loop. Measured: 55-93 ms idle, 164-297 ms across SFTP round trips and ninety rejected connections, zero gaps past a second. The number is *recorded* rather than asserted, because on a shared host the spread between runs belongs to the host; what is asserted is that the instrument works, the poll count advances, and every transfer came back byte-identical. |
| `make qemu-thread-join-soak` | B-02: a join that has to run a thread inside its own syscall. A process cannot pin a thread to its own CPU, so `/bin/joinnest` has a helper take a worker CPU, pins a victim to that same CPU -- the pinned path never asks whether it is busy -- and has the helper join the victim, which can only return by running it nested with a user process bound. The helper then uses a capability and a user pointer to check the CPU it borrowed came back. Red without the fix, ending at `join lost its process context ... before=11 after=0`. The kernel's own thread log is deliberately not required evidence: two CPUs writing the console can drop a line, so the assertion is a summary printed when nothing else is logging. `-x86_64` and `-riscv64` variants run the same gate on the other two architectures. |
| `make xapt-test` | Host-side signed package/catalog/system-image construction, verification, tamper, and malformed-input tests. |
| `make qemu-xapt-gate` | Pinned TLS, trust rotation/revocation/recovery, install, execute, upgrade, rollback, corruption rejection, OS-slot update, reboot persistence, and removal, on all three architectures. |
| `make code-scanning-contract` | Read-only workflow permissions, loopback-only test port reservation, bounded diagnostics, and integer-width regression checks for resolved CodeQL findings. |
| `make qemu-abi-contract` | Syscall, image, service, telemetry, and fixture ABI contract. |
| `make qemu-smoke` | Primary AArch64 boot and deterministic self-test gate. |
| `make qemu-keyboard-input-gate` | QMP-injected USB HID boot-keyboard login through the local console on both ARM64 and x86_64 QEMU. |
| `make qemu-regression-suite` | Broader process, filesystem, network, and runtime regression suite. |
| `make qemu-network-adversarial-gate` | N-F3Q parser fuzzing, packet-fault handling, concurrent load/recovery, and 20 fresh QEMU boots on each of ARM64, x86_64 and RISC-V. Set `XAIOS_NF3Q_BOOTS` only for bounded development reruns. |
| `make qemu-memory-matrix` | Every architecture at 1024, 2048 and 4096 MiB -- nine boots. Each must report managed memory matching what the machine was given, and the figures must rise across sizes: the three runners read three differently-named memory variables, so a gate setting the wrong one would boot three identical 2 GiB machines and pass every per-boot check. Three equal figures fail. The address-space defects this exists for were all invisible at the single size the gates used to run at. |
| `make hypervisor-memory-matrix` | The same three sizes on VMware Fusion and Virtualization.framework, which had only ever run at 2048 -- the one value where B-06 cannot occur and the only Fusion size whose framebuffer needs no mapping. Records where firmware placed Fusion's framebuffer and whether that is above RAM. |
| `make qemu-slaac-gate` | A global IPv6 address formed from a real router advertisement. Two networks, because either alone proves the wrong thing: on SLIRP's default site-local `fec0::/64` the guest must form a SLAAC address, decline to call it public, and report only its link-local one -- which is what says the public address slot is not handed something unroutable -- and with `XAIOS_QEMU_USER_NET_IPV6` advertising a global `2001:db8::/64` it must report an address inside that prefix, formed from its own interface identifier. A gate that ran only the second would pass against a stack that called every address public. |
| `make qemu-readonly-medium-gate` | A block device that really advertises `VIRTIO_BLK_F_RO`, and the same image on a writable one. Until this existed the read-only branch had never executed (`B-14`); running it found two refusal paths in the driver disagreeing about what a read-only medium is. |
| `make vmware-fusion-load-soak` | One Fusion boot held under continuous 256 KiB SFTP round trips, rather than many boots that each start clean. The assertion only a long run can make is the memory trend, compared first quarter against last. A reproduction harness rather than a gate: it exits non-zero only when it reproduces something. |
| `make vz-framebuffer-gate` | What Virtualization.framework's own display shows at a login prompt, captured through ScreenCaptureKit. Needs Screen Recording permission, which is cached per process at launch, so it must be run by an application that holds it. |
| `make vmware-fusion-framebuffer-gate` | The same question for Fusion, which cannot be answered: `vmrun captureScreen` is a guest operation needing VMware Tools, which XAIOS does not ship. Reports that boundary by name rather than leaving the question open. |
| `make qemu-nvme-gate` | Async PRP/SGL, direct-buffer, cancellation, malformed-completion, stress and backing-byte checks on four rows: four queues with every-queue MSI-X/LPI delivery on AArch64 and x86_64, and RISC-V twice, on both of its boards, required to disagree. QEMU's default `virt` publishes a PLIC, which carries wires and no messages, so its single queue is polled and the row says so positively -- `msix=0` and the skipped self-test -- because a build that quietly stopped configuring interrupts everywhere would otherwise pass by looking exactly like it. `virt,aia=aplic-imsic` publishes an APLIC and an IMSIC, and there the same kernel image must program a vector and be handed its completion by interrupt (`controller=aia-imsic`). The queue count stays one on both, which is an SMP bring-up property and not an interrupt one: the driver asks for one queue per online CPU and the secondary harts are still at the scheduler rendezvous when NVMe initialises (`P-16`). |
| `make qemu-riscv64-aia-gate` | The same claim from the interrupt controller's side, and it covers the wired half that NVMe cannot: an NVMe MSI arrives from PCI and never passes through an APLIC. What is asserted on the AIA board is delivery rather than configuration, because every driver here can also poll and a machine on which nothing is ever delivered boots and passes exactly like one where everything is -- so the required markers are the ones that can only be printed after something arrived: an IMSIC loopback through the trap handler, an APLIC source forwarded as a message, at least one real virtio-mmio device announcing its first delivery, and the NVMe canary. On the default board the same markers are forbidden and the PLIC's own are required. |
| `make qemu-x86_64-numa-gate` | Two boots. Two-node x86 SRAT/SLIT/HMAT, 2 MiB/1 GiB mappings, targeted SMP TLB invalidation, placement, byte accounting, node-aware core leasing and stealing that stops at the node; then a four-node machine with no HMAT, where the SLIT fallback order from node 3 is the reverse of the node-id order and is the only arrangement here that tells a distance-ordered walk from a node-id walk. |
| `make qemu-aarch64-sve2-gate` | SVE2 arithmetic plus per-task Z/P/FFR scheduler/interrupt preservation under QEMU TCG; it does not qualify an inference backend or physical hardware. |
| `make qemu-operations-closure` | Both-architecture abrupt-stop, power, recovery, diagnostics, clock, pressure, update/config, support, and Debian-client gate. |
| `make qemu-qualification-readiness` | Consolidated QEMU evidence packet for SSH/network, NVMe, storage recovery, diagnostics, high-core topology, x86 parity, and repeated soak; physical qualification remains open. |
| `make qemu-full-os-rc` | Aggregate mandatory QEMU core-OS release-candidate gate. |

Focused gates cover boot loops, faults, security, local console, storage,
xaiFS, SMMUv3, NVMe, CPU-count/topology, x86_64, VMware Fusion, and developer
UX. The exact current inventory and prerequisites are maintained in
[`tests/README.md`](https://github.com/Pummelchen/XAIOS/blob/main/tests/README.md).

## Complete validation command set

```sh
make bootstrap
make engine-cli
make compile-check
make hosted-test
make hosted-sanitizer-test
make qemu-libc-gate
make xapt-test
make qemu-xapt-gate
make code-scanning-contract
make production-source-audit
make qemu-abi-contract
make image
make qemu-smoke
make qemu-keyboard-input-gate
make qemu-storage-crash-test
make qemu-cluster-two-node-gate
make qemu-cluster-three-node-gate
make qemu-cluster-partition-gate
make qemu-crash-safety-gate
make qemu-write-ordering-gate
make qemu-power-loss-gate
make qemu-storage-bench
make qemu-readonly-medium-gate
make qemu-smmu-gate
make qemu-nvme-gate
make qemu-riscv64-aia-gate
make qemu-memory-matrix
make qemu-x86_64-numa-gate
make qemu-aarch64-sve2-gate
make qemu-outbound-fragmentation-gate
make qemu-model-sftp-gate
make qemu-slaac-gate
make qemu-network-adversarial-gate
make qemu-freebsd-network-suite
make qemu-freebsd-bidirectional-suite
make qemu-docker-network-suite
make qemu-parallel-network-load
make qemu-core-os-rc
make qemu-high-core-gate
make qemu-x86_64-smoke
make qemu-x86_64-cpu-matrix
make qemu-x86_64-platform-matrix
XAIOS_QEMU_NETWORK_ARCH=x86_64 make qemu-docker-network-suite
XAIOS_QEMU_NETWORK_ARCH=x86_64 make qemu-freebsd-bidirectional-suite
XAIOS_INTEL_VPS=root@VPS make qemu-four-endpoint-network-suite
make vmware-fusion-smoke
```

RISC-V is held to its own set, listed in full on [[RISC-V]]; the short form is:

```sh
make riscv64
make qemu-riscv64-gate
make qemu-riscv64-isa-gate
make qemu-riscv64-boot-media-gate
make qemu-riscv64-matrix-gate
make qemu-riscv64-durability-gate
make qemu-riscv64-release-gate
make qemu-riscv64-aia-gate
make qemu-riscv64-smoke
make qemu-riscv64-regression-suite
make qemu-riscv64-storage-crash-test
make qemu-riscv64-crash-safety-gate
make qemu-riscv64-power-loss-gate
make qemu-riscv64-framebuffer-gate
make qemu-riscv64-keyboard-input-gate
make qemu-riscv64-routing-prefix-gate
make qemu-riscv64-storage-bench
make qemu-riscv64-instruction-cost-gate
make qemu-riscv64-dhcpv6-gate
make qemu-riscv64-outbound-fragmentation-gate
make qemu-riscv64-model-sftp-gate
make qemu-riscv64-boot-loop
make qemu-riscv64-benchmark
make qemu-riscv64-preview
make qemu-riscv64-libc-gate
make qemu-riscv64-fault-matrix
make qemu-riscv64-nvme-gate
make qemu-riscv64-soak-gate
make qemu-riscv64-parallel-network-load
make qemu-riscv64-docker-network-suite
make qemu-riscv64-xapt-gate
make qemu-riscv64-write-ordering-gate
make qemu-riscv64-local-console-gate
make qemu-console-xtop-gate-riscv64
make qemu-riscv64-cluster-gate
make qemu-riscv64-cluster-two-node-gate
make qemu-riscv64-cluster-three-node-gate
make qemu-riscv64-cluster-partition-gate
make qemu-riscv64-cpu-matrix
make qemu-riscv64-installed-disk-gate
make qemu-riscv64-netboot-gate
make qemu-riscv64-setup-gate
make qemu-riscv64-ssh-session-exhaustion-gate
make qemu-riscv64-freebsd-network-suite
make qemu-riscv64-freebsd-bidirectional-suite
```

The last block is the shared gates this architecture gained rather than ones
written for it, so what they assert is the same claim asked of a different
machine. Two of them state it in this port's own words where the machine
differs: `qemu-riscv64-cpu-matrix` requires all twelve CPU models to boot the
kernel, which five of them did not use to do -- `rva22s64`, `rva23s64`,
`sifive-u54`, `thead-c906` and `xiangshan-nanhu` offer Sv39 and nothing more,
and were recorded in the contract as machines XAIOS deliberately refuses,
because userspace sat at 511 GiB and that is not a representable Sv39 address.
The user window moved to 255 GiB, so they boot, and the contract rows became
ordinary boot probes; what the refusal check watches for now is a hart
offering neither mode, which no QEMU model is, but which is worth naming
rather than halting silently. And `qemu-riscv64-installed-disk-gate`
requires the harts that come online plus the ones firmware kept to equal the
capacity, because which hart EDK2 keeps is not the same on two consecutive
boots.

The xaiFS and parallel-network gates require macOS plus Docker because they
run native macOS and Debian 13 clients against one guest. The focused high-core
gate validates runtime-sized SMP/NUMA metadata; it is not a scalability test.

The translated SMMUv3 gate requires QEMU's test-only `iommu-testdev`. Aggregate
CI builds and caches upstream QEMU commit
`6ce361b02c825b4a12a9684c47342859ee967cb2`; the gate does not silently skip
when a distribution QEMU lacks that device. Platform recommendation IDs are
registered in
[`docs/PLATFORM-SUPPORT.json`](https://github.com/Pummelchen/XAIOS/blob/main/docs/PLATFORM-SUPPORT.json),
while their sole human-maintained status is in [[Project Tracker|Project-Tracker]].

The evidence boundary and the physical measurements required after QEMU are
documented in
[`docs/PHYSICAL-QUALIFICATION-READINESS.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/PHYSICAL-QUALIFICATION-READINESS.md).

## External interoperability

```sh
make qemu-docker-network-suite
make qemu-freebsd-network-suite
```

The Debian suite rebuilds from `tests/network/Dockerfile.debian13`. The FreeBSD
suite uses a checksum-pinned official VM image and repository-owned provisioning
under `tests/network/`. Both can be recreated after local Docker images and
caches are deleted; no required script exists only inside a container.

The four-endpoint gate coordinates macOS, Debian 13, FreeBSD 15.1, and the
remote Intel Debian/QEMU endpoint when explicitly configured. Credentials are
runtime inputs and must never be stored in the repository.

## Manual host-platform runs

These targets need macOS on Apple Silicon and, for the Virtualization.framework
ones, a signed harness, so none of them runs in CI and none produces
qualification evidence. They are gates in every other sense -- each asserts and
each can fail -- but the machine they need is a person's laptop.

```sh
make vmware-fusion-smoke
```

```sh
make vz-gate
```

The Virtualization.framework gate boots the current image, waits for the kernel,
the virtio console, a mounted and checked durable volume, a DHCP lease, an IPv6
address and a listening SSH server, and fails on a panic or a missing check. It
writes `build/vz-gate.json`, refreshes every attached volume from the current
build first -- the loader prefers the kernel on the A/B system volume over the
one on the ESP, so a stale copy boots a stale kernel and the run tests nothing
-- and needs macOS on Apple Silicon with a signed harness. It boots four vCPUs
and requires all four, because the defects a secondary CPU can have are
invisible on a single-core boot.

```sh
make vz-stress-gate
```

The stress gate is the same platform under sustained load rather than a single
pass. It boots repeatedly with `/bin/smpstress`, which pins threads across the
cores and runs them to a deadline, then checks invariants that admit no
tolerance: a contended counter against tallies each thread kept privately, and
per-thread words against the neighbours sharing their cache line. It repeats
because the defects it finds are intermittent -- the first one appeared on one
boot in six. See [[Virtualization Framework|Virtualization-Framework]].

```sh
make vz-framebuffer-gate
make vmware-fusion-framebuffer-gate
```

V-06's two host platforms, and the pair is worth reading together because one
of them answers and one of them says why it cannot. `make qemu-framebuffer-gate`
closed the graphical console by reading QEMU's scanout back through
`screendump`, and named its own boundary: that is QEMU's surface, not a
physical display and not one of these two. On Virtualization.framework the
boundary is now crossed. The harness owns the view, an `NSView` can be asked
for its own pixels, and with Screen Recording granted to the launching
application `SCScreenshotManager` returns the guest's screen -- the branded
name, both addresses, `SSH server: up and running (tcp/22)` and a cursor at
`xaios login:`, 6700 lit pixels of 1280x832 and no progress bar. The bar check
is a threshold rather than zero because ScreenCaptureKit captures the window
and its title bar comes too, whose green close button measures about 16
matching pixels against roughly 7200 for a real bar: two orders of magnitude
apart, so a floor between them separates window chrome from a bar and nothing
lands in between. The permission is cached per process at launch, so the gate
has to be run by an application that holds it, and a virtual display on one
Mac is still not a physical monitor. Fusion's half is not reachable and the
gate exists to say so by name rather than leave the question looking open:
`vmrun captureScreen` is classified as a *guest* operation, needing VMware
Tools running inside the machine and a login to it, and XAIOS ships no VMware
Tools. There is no flag and nothing an operator can enable. The two questions
are written and will start answering if a guest agent ever exists; they are
asked together, because "no progress bar on screen" is true of a dead display
and "pixels were drawn" is true of one frozen mid-boot, and a machine that has
finished booting has to show both.

```sh
make vmware-fusion-load-soak
make hypervisor-memory-matrix
```

`vmware-fusion-load-soak` is F-04's remaining shape: one Fusion boot held under
continuous 256 KiB SFTP round trips rather than many boots, because a leak of a
page per operation is invisible in a boot and obvious over a thousand
operations. It is what first gave `B-28` a rate -- round 61 of 586 failed with
`sftp exited 255 ('Connection closed')` and rounds 62 through 586 succeeded.
`hypervisor-memory-matrix` does for Fusion and Virtualization.framework what
`qemu-memory-matrix` does for the three QEMU architectures: both hypervisor
gates had only ever run at 2048 MiB, the one size at which `B-06` cannot occur
and the only Fusion size where the framebuffer lands inside the identity map.

## Update repository validation

`make xapt-repository` creates a deterministic OS-update repository for both
architectures under `build/xapt/repository`. It packages current AArch64 and
x86_64 kernel images and signs architecture-specific catalogs. It does not
invent product applications. `make qemu-xapt-gate` separately compiles the
`tests/fixtures/xapt-test-app.c` package and serves an isolated copy over pinned
TLS 1.2 to verify trust rotation/revocation/recovery, discovery, arguments,
install, upgrade, rollback, corruption rejection, persistence, and removal.

The Caddy deployment and live-origin checks are documented in
[[xapt Package Updates|Xapt-Package-Updates]]. The repository test key is a
public fixture and is not production trust evidence.

## Evidence policy

- QEMU and VMware results are correctness and ABI evidence.
- `make qemu-cluster-two-node-gate` is cluster evidence between two XAIOS
  machines rather than between XAIOS and a program written from the wire
  format. One image is built to listen and one to dial, each guest gets its
  own copy of every volume, and the gate requires the lines only a listening
  XAIOS produces. The same pair has been run across a real network with the
  dialling machine on the Intel VPS; that run is manual, because it needs a
  second host and a tunnel between them.
- `make qemu-cluster-three-node-gate` is failure evidence, which is a
  different claim from the one above. The two-node gate's members announce
  their departures, and machines do not fail that way: they lose power or
  panic and say nothing. Three guests heartbeat to each other every 500ms
  over their own TCP connections; the gate SIGKILLs one emulator outright and
  requires the survivors to notice because a twenty second deadline passed
  with nothing heard, not because anything was said. A run has produced
  `mesh peer-lost node=3 reason=silence silent_for_ms=20004 deadline_ms=20000`
  on both survivors, four milliseconds past the deadline they were built
  with. Three is the smallest number at which quorum means anything, so a
  second kill follows: the last machine reports `live=1 total=3 quorum=0` and
  `owners=withheld`, because a minority that answers ownership questions is
  how one expert ends up with two owners. The gate carries its own controls.
  All three run healthily for thirty seconds -- longer than the deadline --
  before anything is killed, and any death declared in that window fails the
  run, which is what says the detector fires on silence rather than on time
  passing. `XAIOS_CLUSTER_THREE_NODE_SKIP_KILL=1` runs everything and kills
  nothing, and every failure-detection check must then go red. What it does
  not cover: one host, one emulator per node and one user network, so a
  partition here is a process that stopped rather than a network that broke,
  and nothing about a link that drops packets while both machines are alive
  has been tested. Every timing figure in it is a deadline being met, never a
  measurement worth quoting.
- `make qemu-cluster-partition-gate` is partition evidence, and it is a third
  claim again. The gate above kills an emulator, and a killed process stops
  answering AND stops sending, so nobody on the far side of it is deciding
  anything. A partition leaves both machines alive, both heartbeating, each
  hearing nothing from the other, and each having to decide separately. A
  relay stands between the three guests -- `tests/scripts/cluster_fault_relay.py`,
  one TCP listener per ordered pair, with every node built to dial its peers
  through it rather than at them -- so a link can be broken in one direction
  or in both while every machine keeps running. Three faults in one boot.
  Cutting every link to node 3 leaves the other two a majority: `mesh
  peer-lost node=3 reason=silence silent_for_ms=20083 deadline_ms=20000` on
  node 1, both survivors settling on `live=2 total=3 quorum=1 members=1,2
  owners=1,2,1,2,1,1,2,2`, and node 3 on `live=1 total=3 quorum=0` with
  `owners=withheld` while it is still running -- the relay refused ten
  connections from it during that window, which is how the gate tells a
  partitioned node from a dead one without taking the node's own word for it.
  Repairing the links puts all three back on `members=1,2,3` and on the
  ownership map they started with, `3,3,3,2,3,1,3,3`, unchanged. Then only
  node 3's outbound links are cut, so it is heard by nobody and hears
  everybody. That asymmetric case is the one that is not reachable by killing
  anything, and it is the one that found a real defect: the cluster split its
  brain. Node 3 held `live=3 quorum=1 members=1,2,3` while nodes 1 and 2 held
  `live=2 quorum=1 members=1,2`, six of eight experts had two owners, and both
  sides passed a correct strict-majority test at the same instant. The
  arithmetic was never wrong; its input was. `xaios_cluster_quorum` counted any
  peer this node saw as ONLINE, membership came from inbound silence alone, and
  a node whose outbound links are cut still receives every heartbeat -- so it
  counted the whole cluster and was never told whether anyone could hear it.
  Heartbeats carry the sender's member bitmap now and a peer counts toward
  quorum only if we hear it AND it says it hears us, so the isolated node
  learns it has been excluded from the very heartbeats that keep reaching it:
  `node=3 live=1 total=3 quorum=0 members=1,2,3 owners=withheld` -- still
  hearing both peers, counting itself alone -- and after the second heal all
  three return to `live=3 quorum=1` with the identical ownership map. The
  defect and its fix are recorded in D-06, and the check is not to be relaxed
  now that it passes any more than it was while it failed: the reason it was
  worth writing is exactly that it went red against a real defect the day it
  first ran. One distinction the fix had to keep: absent from your view and excluded from it
  are different facts, and exclusion is believed only after inclusion has been
  seen, because a node's first heartbeat goes out before it has heard anybody
  and lists only itself -- treating that as exclusion deadlocked formation at
  `live=1` on three healthy nodes. Its controls: `XAIOS_CLUSTER_PARTITION_SKIP_CUT=1` runs
  every phase and cuts nothing, and the nineteen checks that exist because of
  a cut must all go red -- the run says which ones did not, by name.
  `--self-test` hands the analysis transcripts of runs that never happened,
  one per check, and requires each to go red for the failure it is there to
  catch, which is the only way to show that a check which should now never
  fire in practice -- the split-brain one -- can fail at all. And
  `python3 tests/scripts/cluster_fault_relay.py --self-test` is the fault
  injector's own control, because a relay that does not really cut makes
  every phase above indistinguishable from nothing happening. What it does
  not cover: the cut is a link that REJECTS, so a dial fails fast and a send
  gets an error. It is not a black hole, where connect() hangs for the ten
  seconds the kernel allows and a send returns success into a buffer that
  will never drain -- which is the harsher case for the sender and is
  untested. Nothing here loses, reorders or delays a byte inside a stream
  either; TCP does not do that and a relay cannot fake it. That still needs
  two machines and a switch.
- `make qemu-crash-safety-gate` is power-loss evidence for ordering and
  tearing: it kills the emulator outright at random points while a package is
  being ingested, then hashes every chunk the surviving catalog still calls
  complete. It also constructs two states directly, because a kill almost
  never lands on either: a superblock caught half-written, and a superblock
  that is whole while the catalog it points at was never written — which is
  what a device with a volatile write cache leaves behind if it persists the
  publish before the thing it publishes. Both must be rejected by the slot's
  own hash and the volume must come back from the other slot, a commit lost.
  What it does not do is run against a device that actually acknowledges a
  write and then loses it — the emulator never loses an acknowledged write, so
  those two states are constructed rather than provoked. That is what
  `make qemu-power-loss-gate` is for.
- `make qemu-write-ordering-gate` covers the half the crash gate cannot: it
  has the block driver log every write and every flush, then checks that no
  superblock write — the write that publishes a commit — is issued without a
  flush since the previous write. That ordering is what keeps a device with a
  volatile write cache from persisting a superblock before the catalog it
  points at. Removing the flush makes the gate fail on every commit, which is
  how it was checked to be capable of failing.
- `make qemu-power-loss-gate` is the loop the other two could not close: a
  device that acknowledges writes and then genuinely loses the unflushed ones,
  and a machine that boots what is left. No cache mode does this. `cache=unsafe`
  and `cache.no-flush=on` only make flushes no-ops; a write QEMU has
  acknowledged already went to the host through `pwrite`, and killing QEMU does
  not take the host's page cache with it — measured with `qemu-io` on the same
  block layer, a raw image survives the kill at `writeback` and at `unsafe`
  alike. `make qemu-write-cache-probe` is that measurement, kept runnable so
  the claim can be rechecked against a future QEMU rather than believed. So the models volume is attached through QEMU's `blklogwrites` filter,
  which passes every request through and records header, payload and flush
  markers in issue order; the emulator is killed mid-ingest; and
  `tools/xaios_write_log.py` replays the recording while honouring the one
  promise a volatile cache makes — everything before the last completed flush
  is durable, everything since survived or did not, independently. Every byte
  written is a byte the guest wrote. The volume must come back with no error,
  a surviving superblock, and a generation no lower than the last commit that
  was flushed; then it is booted, and the kernel's reader has to agree with the
  host tool about which commit survived and accept a fresh commit on top. Every
  case is replayed a second time through a device that ignores flushes, which
  must corrupt, or the gate reports itself worthless. Deleting both flushes the
  commit path issues before it publishes makes it fail on a chunk the surviving
  catalog calls complete whose bytes are not there; deleting either one alone
  does not, because each separates the data writes from the superblock and the
  pair is redundant.
- `make qemu-storage-bench` reports throughput rather than asserting it — these
  are emulator figures. What it does assert is that a warm read beats a cold
  one, which is the claim the read cache exists to make and the one that would
  silently stop being true if the cache were bypassed or invalidated on every
  access.
- Sparse files prove address width and bounded memory, not storage throughput.
- High virtual CPU counts prove dynamic metadata sizing, not server speed.
- Performance claims require physical hardware and immutable artifacts meeting
  the [benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md).
- Generated reports, logs, packet captures, and images belong under ignored
  output directories unless an evidence process explicitly publishes them.

See [[Current Limitations|Current-Limitations]] for tests that still require
physical hardware or real model checkpoints.
