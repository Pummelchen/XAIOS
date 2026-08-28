# Project Tracker

Last reviewed: 2026-08-28.

The current QEMU closure revision passes hosted, AArch64/x86_64 smoke, libc,
dual-architecture all-queue NVMe interrupt, SVE2 per-task context, x86 HMAT/
1-GiB/TLB, xaibootFS-v5 migration/scale, TLS xapt, and external network gates.
The final consolidated report deliberately retains
`physical_qualification=false`.

A transmit that never completed used to wedge this stack about one boot in
eighteen. It was caught with the device reporting `DRIVER_OK`, no
`DEVICE_NEEDS_RESET`, and a buffer offered on each queue that it never
consumed -- a device with nothing to react to rather than one that had failed,
because the queue was notified once and then only polled. Every virtio wait now
re-rings while waiting, in all four drivers; the block driver had the same
defect and had lost a filesystem metadata write to it.

Two of the three virtual-platform profiles pass at `b173e42c558e`, which is the
same tree for both: **macOS QEMU ARM64** across boot/CPU/network/SSH, USB
keyboard console, SVE2 per-task context, storage recovery, operations and
shutdown, and repeat boot; and **macOS VMware Fusion ARM64** across its
one-vCPU boot, storage, network and SSH lifecycle. Between them they qualify
the secondary-CPU bring-up, the subsystem serialisation and the virtio
notification work on real firmware rather than on none.

**Intel VPS QEMU x86_64 is still behind, last collected at
`adc0b69a1b4e6eb8f1c123fcc25aa3a73d6a881e`, and must be re-run before its
result is quoted as current.** It needs the designated Intel host; no ARM
result stands in for it.

This is the only human-maintained XAIOS project tracker. Roadmaps, milestones,
phase plans, open decisions, and risks are consolidated here. The Wiki does not
retain previous tracker, roadmap, milestone, or phase-plan pages.

This page tracks open work only. Completed rows are removed after their named
evidence gates pass; implementation history remains available in Git and the
linked test evidence.

## Status codes

| Code | Meaning |
|---|---|
| `TESTING` | Implemented, but the current acceptance run or physical qualification is still underway. |
| `IN PROGRESS` | Active implementation is incomplete. |
| `NOT STARTED` | No qualifying implementation has begun. An interface or fixture alone does not count. |
| `BLOCKED` | Work cannot proceed until the stated external decision or dependency is resolved. |
| `FAILED` | The latest required acceptance gate failed; the failure evidence must be linked in the item. |

QEMU status proves correctness and ABI behavior only. Physical support and
performance require immutable evidence under the
[benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md).

## Supported environments

XAIOS runs on three hypervisors. QEMU covers two architectures, so four
targets exist, but the platform contract is per hypervisor.

Firmware differences below are the hypervisor's, not XAIOS's: the system
behaves identically wherever a capability exists, and where one is absent it
degrades the same way everywhere. See
[Platform neutrality](https://github.com/Pummelchen/XAIOS/blob/main/docs/PLATFORM-NEUTRALITY.md),
which the build enforces.

| Function | QEMU ARM64 | QEMU x86_64 | VMware Fusion ARM64 | Virtualization.framework |
|---|---|---|---|---|
| Boots to a login | yes | yes | yes | yes |
| Durable xaibootFS volume | yes | yes | yes | yes |
| IPv4 by DHCP | yes | yes | yes | yes |
| IPv6 by SLAAC | yes | yes | `F-03` not qualified | yes, unique-local only (`V-03`) |
| IPv6 by DHCPv6 | client present, gated | client present | client present | client present |
| SSH server | yes | yes | yes | yes |
| SSH client, SFTP | yes | yes | yes | yes |
| Reachable from the host | yes | yes | yes | vmnet helper only, one direction at a time |
| Boots at 1, 2 and 4 GiB | yes | yes | yes | yes |
| Multiple vCPUs | yes, 130 gated | yes, 128/256 scenarios | yes, 4/4 | yes, 8/8 |
| Message-signalled interrupts | distributor | yes | PCI | none; every queue polls (`V-02`) |
| Framebuffer console | no, serial | no, serial | yes | yes when a display device is attached (`--gui`), driven directly over virtio-GPU because firmware publishes none; serial otherwise |
| USB keyboard input | yes | yes | provisioned, not gated | console input over virtio |
| Entropy protocol | virtio-rng | virtio-rng | `F-05` none exposed | yes |
| Storage transport | virtio-MMIO | virtio-PCI, NVMe | AHCI | virtio-PCI |
| Network transport | virtio-MMIO | virtio-PCI | E1000E (`F-02` no VMXNET3) | virtio-PCI |
| Applications gated | yes, by name | yes, by name | yes, by name | yes, by name |
| Boots the unified image | yes, gated | yes, gated | yes, gated | yes, gated |
| Automated gate | full CI | full CI | `make vmware-fusion-smoke` | `make vz-gate`, `make vz-stress-gate` |
| Unified-image gate | `make unified-image-gate` covers all four from one file; CI runs the two QEMU rows and reports the hypervisors as skipped | | | |
| Verified by | CI, every push | CI, every push | `make local-gates`, required by `make release-check` | `make local-gates`, required by `make release-check` |
| Evidence class | correctness only | correctness only | Fusion 26H1 lifecycle | development target, not evidence |

Device inventory differs because the hypervisors differ; the kernel discovers
what is present rather than assuming a platform, so those rows are not defects.
The rows carrying an item identifier are.

## Open bugs

Defects with no fix in place. Fixed defects leave this table when their gate
passes; the reasoning stays in the commit that closed them.

| ID | Defect | Affects | Status | Notes |
|---|---|---|---|---|
| B-01 | Outbound ProxyJump failed host key verification | x86_64 builds | `TESTING` | **No longer reproduces, and I cannot say what fixed it.** The full FreeBSD bidirectional suite now passes on emulated x86_64 -- 19 of 19 checks, including `xaios_outbound_proxyjump_to_xaios` and the invalid-spec rejection -- against a FreeBSD 15.1 amd64 guest under `qemu-system-x86`. The entry said reproduction needed a physical x86_64 host; that was wrong, since it failed under emulation, which is what has now been run. Something between the original sighting and now addressed it, plausibly the resolver work, and attributing it to a specific change without evidence would be a guess. Left as `TESTING` rather than closed: an intermittent failure that stops appearing is not the same as one that has been understood. The standing warning still holds -- do not "fix" host key verification by skipping malformed `known_hosts` lines, which falls through to the append path and downgrades verification for a host that already had a key. |
| B-02 | Thread join failed once under load, on QEMU | `OPEN` | One sighting, not reproduced in eight further QEMU boots or in any run since. It may never have been a thread defect: the test joined with a five-second timeout and reported join failure, a wrong result and an expired timeout with one message, so a slow host and a broken join were indistinguishable in the log -- and the sighting was during a firmware profile run, with the host busy. The kernel returns `XAIOS_ERR_BUSY` and logs `threads: user join timeout` when the deadline passes, so the information existed and the test discarded it. `smptest` now reports which of the three happened, with the status and the expected and actual values. Left `OPEN`: the next sighting will say what it is, and until then claiming to know would be inventing a cause. |
| B-07 | Applications were never run on two of the four images | Fusion, Virtualization.framework | `TESTING` | **Fixed.** Only QEMU built with `XAIOS_BOOT_TEST_APPS=1`, so the syscall suite, the network and SMP tests, the agent protocol, the pipe-and-redirect surface and the shell's own command surface had never executed on Fusion or Virtualization.framework. Both gates checked kernel markers -- kernel started, volume mounted, DHCP lease, SSH listening -- and a guest can satisfy every one of those while the programs a person would actually type do not work. Both now build with the applications and assert eight application markers each. |
| B-08 | An unclean-boot marker put the guest into rescue mode | all four | `TESTING` | **Fixed in the gates; the behaviour itself is by design.** The lifecycle record lives at `/state/lifecycle/` on the durable volume, and rescue mode is latched by a marker file there. `build/xaios-persistent.img` is shared: every QEMU boot writes to it, and the hypervisor gates copied it in. Enough hard power-offs across any gate -- which is how gates end, and how a demo VM gets closed -- and the marker is set. The guest then still boots, mounts, takes a DHCP lease and runs sshd, and refuses ordinary commands with \"rescue mode permits diagnostics and filesystem repair commands only\". `vz-gate` now generates a fresh durable volume per run rather than inheriting whatever unrelated gates left behind, and both hypervisor gates treat `rescue=1` as a fault rather than a state a passing boot may be in. Worth knowing for a demo: repeated force-quits do eventually reach this, and that is the system protecting itself, not a defect. |
| B-09 | The `l`, `ll` and `la` aliases dropped their argument | all four | `TESTING` | **Fixed.** The aliases had two implementations selected by `#if XAIOS_BOOT_TEST_APPS`, and only one of them was right. The test-apps branch called `handle_ls(\"-la\", ...)` with the flags alone, so `l /` listed the working directory instead of the root and `ll /tmp` ignored `/tmp` silently; the other branch built the argument string properly. Two configurations of one build disagreeing about what a command does is the thing `docs/PLATFORM-NEUTRALITY.md` exists to prevent. Both branches now build the same argument. |
| B-10 | A rejected shell command reported no reason | all four | `TESTING` | **Fixed.** `/bin/xaios-shell` discarded the output buffer when a command was rejected, printing only \"command failed\". The kernel writes the reason into that buffer before rejecting, so the diagnosis was being thrown away at the last step: B-08 was invisible behind those two words until this was changed, and reading it took one boot afterwards. |
| B-20 | A release image could be assembled from the wrong build | all four | `TESTING` | **Fixed.** The unified builder took whatever kernels `build/` held. Whether the kernel logs to the console or to the boot display is a build-time choice, so an image assembled from a non-verbose build boots perfectly and satisfies none of the markers the gates look for -- the staleness check does not catch it, because the image is not stale, it is a correct image of the wrong build. It happened when `make vmware-fusion-image` rebuilt the kernel in passing. `make unified-image` now builds both architectures itself with the configuration the gates require. |
| B-21 | A release could ship unable to boot one of its four environments | VMware Fusion ARM64 | `TESTING` | **Fixed.** The unified builder warns and continues when the VMware Fusion chainloader is absent, which is right for a developer without Docker and wrong for a release: the image boots three of four and says so in a line that scrolls past. A clean of `build/` took the chainloader with it and the next release build was nearly published that way. `scripts/build-release.sh` now refuses. |
| B-19 | The relocated kernel was placed without its required alignment | all four | `TESTING` | **Fixed, and it is the reason CI was red for twelve commits.** The loader took whatever address firmware returned, which is page-aligned and nothing more, while the kernel's segments declare `p_align 0x10000` and objects inside it need up to 16 KiB -- the SMMU stream table among them. Landing 4 KiB off makes the hardware reject the stream table entry and the guest panics in `smmu_self_test`. The same commit passed locally and failed in CI purely because firmware put the kernel at `0xbc050000` on one machine and `0xbc049000` on the other, so it looked environmental and was not. The loader now takes the strongest `p_align` across the loadable segments and rounds the base up to it. Found by symbolising CI's backtrace against the load base the panic screen prints, which is the diagnostic added for B-15. |
| B-22 | The xaiFS SFTP gate fails on this macOS host | local only | `OPEN` | `make qemu-model-sftp-gate` ends with `sftp batch failed rc=255` while staging a file into `/models/.staging`. It passes in CI on every push, so this is a difference in the host rather than a defect in the guest -- most likely the macOS `sftp` client, since 255 is how OpenSSH reports a connection or authentication failure rather than a transfer error. Found while renaming the filesystems and confirmed to predate that work: the whole change was stashed and it failed identically. Recorded so the next person to run it locally does not spend the hour I nearly did believing they had broken something. |
| B-16 | The unified gate tested whatever image was on disk | all four | `TESTING` | **Fixed.** `make unified-image-gate` rebuilds the image first; running the script directly did not, so it reported results about whatever was there. Three Fusion failures were diagnosed for an hour before the cause turned out to be that the guest under test was not the code under test. The gate now refuses an image older than the kernels or initial filesystems it should contain, and says which one it is behind. |
| B-17 | The unified gate inherited Fusion's accumulated boot state | VMware Fusion ARM64 | `TESTING` | **Fixed.** It reused the VM bundle's data disk across runs, so the lifecycle record accumulated -- every gate run ends by stopping the machine hard -- until the marker that latches rescue mode was set and the guest refused ordinary commands while still booting, mounting and listening. The same trap as B-08, on a path that had not been fixed for it. The data disk is now rebuilt per run, as `vz-gate` rebuilds its durable volume. |
| B-18 | The routing log always claimed a /24 | all four | `TESTING` | **Fixed.** `routing: initialized` printed "/24" unconditionally, so a guest handed 255.255.248.0 by DHCP reported a prefix it was not using. The routing table had the real mask throughout -- this was the log lying about the one thing someone reading it is checking, and it cost a detour into a routing bug that did not exist. |
| B-15 | An intermittent fatal assertion on VMware Fusion | VMware Fusion ARM64 | `OPEN` | Seen once: `System halted`, `assertion failed` and a cyan screen from `vmware-fusion-smoke`. Not reproduced in 17 runs since, including a dedicated soak of 12. Which assertion is still unknown and will stay unknown: the one record was fifteen stack addresses, and the guest console holding the rest was overwritten by later gates in the same run. Two things now make the next occurrence answerable in one step rather than none. `local-gates` keeps each gate's console beside its output. And the panic screen prints the kernel's load base with the backtrace -- the kernel is position-independent, so the same build lands somewhere different every boot and a bare address resolves to nothing without it; verified by forcing a panic and symbolising the trace back to `kmain`. |
| B-14 | The x86_64 guest wrote to the medium it booted from | QEMU x86_64 | `TESTING` | **Partly fixed, and the remaining half is untestable here.** Two separate things were wrong. The runner attached the boot drive writable where the AArch64 runner has always attached it read-only, so booting an image modified it -- that is fixed, and verified by checksumming the image either side of a run with no rebuild in between. The self-test also asserted that a write to the boot device succeeds, which would panic a machine booting a CD or a write-protected stick; it now asks whether the device advertises `VIRTIO_BLK_F_RO` and verifies the refusal instead, running everything that does not depend on having written. That path is unexercised: with `readonly=on` QEMU discards writes but still advertises the device as writable, so the guest reports `medium=writable` and takes the writable branch. Proving the read-only branch needs a device that actually advertises the bit. |
| B-13 | x86_64 asserted on a device self-test when booted from the unified image | QEMU x86_64 | `TESTING` | **Fixed.** The x86 completion canary asks the block device to complete a request and raise an interrupt, and asserts that it can. Booted from the unified image the initial filesystem rides on the boot medium rather than arriving as a separate drive, so the block device is loader memory -- which raises no interrupts, and `virtio_block_interrupt_canary_arm` correctly refuses. The assertion was asserting a property of the boot arrangement rather than of the kernel. It now reports that the test does not apply when the device is memory-backed. The per-architecture image still supplies a real device, so the canary still runs and is still asserted there. |
| B-12 | Fusion faulted on the firmware framebuffer at 4 GiB | VMware Fusion ARM64 | `TESTING` | **Fixed.** The guest took a level-1 translation fault on `far=0xff0000000` in `term_putc` -- the framebuffer. Firmware places it above RAM, so with four gibibytes it lands at 63.75 GiB, well outside what the kernel identity-maps; with one or two it fell inside and worked. Nothing about the framebuffer changed between those cases, only how much memory sat underneath it. Writing to it worked before translation was enabled because firmware's tables covered it, and the kernel's tables map RAM plus the device windows whose addresses it knows -- a firmware framebuffer outside RAM is neither. `kmain` now maps it from `boot->framebuffer_base` immediately after `vmm_init`, before the next line is drawn. |
| B-11 | Userspace and the identity map were the same addresses | all four | `TESTING` | **Fixed.** Userspace began at 4 GiB. The kernel identity-maps physical memory in 1 GiB blocks and the per-CPU roots copy that map, then replace the entry covering the user window with the user directory -- so a machine with 4 GiB of RAM gave the kernel's own 4-5 GiB of physical memory to userspace and lost it. VMware Fusion took a level-1 translation fault on the first access; QEMU ARM64 booted and failed self-tests further in; x86_64 was unaffected only because its identity map stops at 4 GiB, immediately below the window. Which machines noticed depended entirely on how much RAM they had, which is why two years of 2 GiB gates never saw it. Userspace now occupies the last gibibyte the kernel can address and `vmm_init` caps the identity map at `XAIOS_USER_BASE`, so the two cannot grow into each other whatever the machine has. x86_64 carried the old index as a literal `4` in three places -- corrected to derive from the constant, which is what made the first attempt fault on its first userspace instruction fetch. QEMU ARM64 now passes at both 2 GiB and 4 GiB with one image. |
| B-05 | One fixed kernel link address blocked a 1 GiB profile | all four | `TESTING` | **Fixed.** The kernel is built position-independent on AArch64 and the UEFI loader places it where the machine actually has memory, applying the R_AARCH64_RELATIVE relocations it carries -- 384 of them, and nothing else, so no symbol table is needed. Firmware picks the address, bounded below 4 GiB because that is how far the kernel's early identity map reaches. x86_64 stays fixed-address: its code model emits R_X86_64_32, which cannot appear in a position-independent link, and it already boots at every size. The loader accepts both and applies no bias to a fixed-address kernel. |
| B-06 | Virtualization.framework booted to nothing below ~3.5 GiB | Virtualization.framework | `TESTING` | **Fixed, and it was B-05 all along.** The floor was never a property of the platform: the kernel was built to load at a fixed 0x90000000 and Virtualization.framework has no memory there until it has enough of it, so the loader failed before anything could print. Bisecting it produced a number (3584 MiB boots, 3328 does not) that matched no placement model, which should have been the clue that the question was wrong. With a relocatable kernel it boots at 1024, 2048 and 4096 MiB, and the guard `run-vz.sh` carried has been removed. |
| B-04 | Fusion intermittently gets no DHCP offer | VMware Fusion ARM64 | `TESTING` | Recurred after being called fixed. The first fix was real -- every boot of every guest had used one hard-coded transaction id, which a server may ignore as a repeat -- and it was not the whole cause. A later run failed the same way: three DISCOVERs, no offer, the boot continuing without an address. Three attempts is what every occurrence has looked like, and that number was not a coincidence: the budget was split evenly between waiting for an OFFER and waiting for an ACK, which with doubling retransmission is three attempts in the first phase. The failures are all in that phase, so it now gets everything except a fixed reserve for the REQUEST -- a server that answers at all answers that one at once, having already chosen the address; a server still starting up is the case needing patience. Total budget raised from 15 to 30 seconds, paid only where there is no server. |
| B-03 | vmnet-helper spins a core while idle | `TESTING` | The relay returned as soon as it saw no machine attached, without reading the packet that woke it, so vmnet's event never cleared and the callback fired again immediately. The helper held a core busy for as long as anything was on the network, with its counters frozen because nothing was ever read -- 88% of a core with no guest, which is what corrupted the C-03 measurement. It now reads first and drops the frame if there is nowhere to send it, which is what an unattached interface should do. Fixed and rebuilt; unverified, because the running helper is the old binary and restarting it needs root. |

## What ships, and how far along it is

Three bootable deliveries, and the engineering each one waits on. Status is
what has been demonstrated, not what has been designed: `PARTIAL` means some of
it runs and the rest has not been tried, and is never a way of saying nearly
done.

| # | Deliverable | Status | Where it actually stands |
|---:|---|---|---|
| D1 | USB image, every architecture | `PARTIAL` | `xaios_b1.iso` is a hybrid ISO 9660 and GPT disk carrying both an AArch64 and an x86-64 kernel, and firmware picks its own. The GPT and its EFI System Partition are what a stick booted from, so `dd` should produce one. Never written to a stick and booted: nothing physical has run this. |
| D2 | Network boot for blank machines | `NOT STARTED` | Nothing exists -- no PXE, no HTTP boot, no netboot path of any kind. Needs D3's installer to be worth anything, since network boot that cannot install leaves a machine with nothing on its disk. |
| D3 | Ready-to-run images per environment | `PARTIAL` | VMware Fusion has a complete `.vmwarevm` bundle and Virtualization.framework has a disk plus a signed harness, both built and gated. QEMU has runner scripts rather than an image. None of the three is packaged as something a person downloads and starts. |

## Engineering these wait on

| # | Work | Status | Where it actually stands |
|---:|---|---|---|
| E1 | Disk partitioning, formatting and install tooling | `IN PROGRESS` | A machine XAIOS has been installed onto now boots from its own single disk, finds its durable state by partition type and keeps it across reboots. Three assumptions had to go, each correct for the test bench and wrong for an installation, and none of them said so out loud. The PCI slot map reserves ordinal zero for the firmware's boot disk, which on a one-disk machine excludes the only disk there is -- so both transports gained an ordinal-addressed lookup for layouts not known in advance. The PCI matcher accepted only modern virtio device IDs, and QEMU's `virtio-blk-pci` is transitional (`0x1001`) unless asked otherwise, so a disk attached the way a person would attach one was not recognised. And the MMU refused everything above 512 GiB because the kernel had one level-0 entry, which is exactly where QEMU's virt machine puts its 64-bit PCI window and where firmware placed the disk's registers; `TCR_EL1.T0SZ` has been 16 all along, so only the table was missing, and a self-test now maps two pages up there. The scan runs only where the machine has one disk: opening every device it finds takes volumes away from their drivers on the test bench, which cost the smoke gate its shell once. Probe failures now name the device, the capability and what was missing. `scripts/make-installed-disk.sh` and `tools/xaios_write_gpt.py` build such a disk; two boots from a single drive format the state partition, pass the application surface, then reload 15 files at generation 194 and pass it again, with the GPT and ESP untouched. The partition tooling itself is now proven rather than assumed: `storage_admin` could create, delete, resize and repair GPT partitions and the control protocol exposed all of it as `xaiosctl storage partition ...`, but nothing had ever written a partition table to a device -- the hosted tests cover argument parsing against a mock. A boot self-test now plans, creates, verifies, deletes and re-verifies a partition on a blank scratch disk, and the smoke gate attaches one and requires the marker. What remains is the half that makes a disk bootable: XAIOS has no FAT implementation at all, so it cannot write the EFI System Partition its own firmware boots from, and cannot copy the loader and kernel into one. Until that exists, a bootable disk can only be built by a host script, which is what `scripts/make-installed-disk.sh` is. |
| E2 | Instruction-cost metric | `IN PROGRESS` | The metric works and is reproducible: under `-icount shift=0` the guest clock counts instructions, and a syscall costs **494** of them across two identical runs. `make qemu-instruction-cost-gate` is written; the baseline has not been recorded yet, because the boot takes far longer under `-icount` than the gate first allowed. |
| E3 | NUMA correctness | `TESTING` | Done this session. The self-test proved node-0 placement and never checked node 1, so an allocator ignoring its node argument would have passed; it now asserts placement inside node 1's range and that every CPU maps to exactly one node through both lookups. `core_lease` is *not* covered and cannot be: it leases a CPU you name, so there is no topology decision to test until node-aware selection exists. |
| E4 | Multiqueue and RSS networking | `NOT STARTED` | Confirmed absent -- virtio-net sets up queues 0 and 1 only. Blocked first: per-queue interrupts need MSI-X, and ARM64 carries virtio-net on virtio-MMIO, which has one interrupt line. That transport move is a prerequisite, not a detail. Only QEMU x86-64 can demonstrate it today, and there both queues currently share one vector. |
| E5 | xaibootFS and xaiFS at scale | `NOT STARTED` | xaibootFS addresses blocks with 16-bit numbers: 32 MiB per volume, 256 KiB per file, 512 direct blocks and no extents. Reaching the target sizes is a new on-disk format, not tuning. xaiFS is tested to 128 GiB sparse, which derisks xaiFS and nothing about xaibootFS. |
| E6 | Cluster data plane | `NOT STARTED` | `engine/src/cluster.c` has framing, peer state and owner selection, and no transport -- no socket, connect or send. The MacBook-to-VPS topology also needs the Intel VPS, which is 117 commits behind and shared with other services. |

## Delivery order

| Order | Workstream | Status | Current boundary / exit gate |
|---:|---|---|---|
| 1b | Physical Apple/ARM, Intel desktop, and Xeon qualification | `NOT STARTED` | Named hardware must pass firmware, device, durability, security, ISA-state, NUMA, soak, and benchmark contracts. |
| 1c | Disk partitioning, formatting and install tooling | `NOT STARTED` | A Unix-style tool set that partitions a disk, formats xaibootFS and xaiFS on it, and makes it bootable with XAIOS as the only operating system on the machine. Today an image is written whole to a medium and the durable volumes are attached alongside it by the hypervisor; there is no way to take a bare disk and produce a system that boots from it. That is the gap between an image somebody runs and an operating system somebody installs, and physical qualification needs it before it needs anything else. Exit gate: a blank disk partitioned, formatted and booted, on all four environments and on one physical machine. |
| 2 | Qwen 3.8 support | `NOT STARTED` | Begins after physical platform qualification is accepted or explicitly deferred; official tokenizer, layer, logits, 32-step decode, session, and physical gates must pass. |
| 3 | Kimi K3 text support | `NOT STARTED` | Begins after Qwen unless reprioritized; KDA, Gated MLA, exact top-16 MoE, MXFP4, and token parity are mandatory. |
| 4 | Kimi K3 multimodal support | `NOT STARTED` | Separate vision preprocessing/tower/projection/position and golden image gates. |
| 5 | DeepSeek V4 Flash 0731 support | `BLOCKED` | The exact official release label and immutable source must be verified first. |

## Model support boundary

| Model or format | Progress | Support boundary | Completion gate |
|---|---|---|---|
| Qwen 3.8 | `NOT STARTED` | Roadmap target; no architecture adapter is claimed | Pin an immutable official configuration before tokenizer, tensor, layer, prefill-logit, decode, session, backend, and physical parity work. |
| Kimi K3 text | `NOT STARTED` | Interface only | KDA/MLA/MoE/MXFP4/operator and target-token parity on a real checkpoint. |
| Kimi K3 multimodal | `NOT STARTED` | Roadmap only | Separate official vision and multimodal golden acceptance. |
| DeepSeek V4 Flash 0731 | `BLOCKED` | Roadmap only | Verify exact official source before architecture work. |

## Platform recommendations

Only open ARM/Intel/platform recommendations remain here. The complete numbered
catalog stays in `docs/PLATFORM-SUPPORT.json`; no secondary page owns progress
status.

| # | Recommendation | Status | Evidence / remaining gate |
|---:|---|---|---|
| P-05 | Physical Apple NEON evidence | `NOT STARTED` | QEMU cannot satisfy this physical gate. |
| P-07 | SVE/SVE2 backend | `IN PROGRESS` | ARM64 QEMU executes the SVE2 canary and preserves per-task Z/P/FFR state across scheduling and interrupts. Packed inference kernels, scalar-model differential tests, and physical qualification remain; backend selection stays fail closed. |
| P-14 | Physical Intel/Xeon evidence | `NOT STARTED` | Physical firmware, ISA, NUMA, storage, network, thermals, and sustained-load gates remain. |

## VMware Fusion ARM64 remaining work

The qualified Fusion boundary is Apple Silicon VMware Fusion 26H1 (26.0.0),
one vCPU, E1000E, AHCI, DHCP IPv4, and public-key SSH/SFTP. The items below
are intentionally not implied by that passing profile.

| ID | Item | Status | Evidence / remaining gate |
|---|---|---|---|
| F-01 | Fusion multi-vCPU startup | `TESTING` | **Fixed, and it was ours.** Fusion runs four vCPUs: `telemetry: boot_summary cpu_online=4`, full smoke gate passing. Two earlier diagnoses were wrong and the way they were wrong is the useful part. The premise that Fusion would not start secondaries was wrong -- it starts all four. The second, that Fusion refuses atomics and the cause was below the guest, was wrong because it rested on the wrong measurement: the descriptor read back was for an unrelated `.bss` word, not the page that faults, and every green Fusion boot had run with one CPU online, where the spinlock takes a fast path that skips the atomic entirely -- so no passing boot had ever executed one. A probe that forced an atomic showed it working. The real defect: a secondary publishes `online = 1` while its MMU is still off and only activates the kernel's tables after the rendezvous. In that window the boot CPU sees `online > 1` and switches to real atomics, while other live CPUs view the same memory as Device rather than Normal cacheable. An exclusive on a location whose attributes differ between PEs is not architecturally supported, and a platform may refuse it -- Fusion does, with DFSC `0b110101`. QEMU and Apple's hypervisor permit it, which is why nothing else ever showed it. Locks now switch to atomics at `smp_release_secondary_schedulers`, before any secondary enters kernel code, so every CPU agrees on the attributes by the time one is taken. `numvcpus` is 4. |
| F-02 | VMXNET3 networking | `NOT STARTED` | The current profile uses PCI E1000E only. Implement capability-gated VMXNET3 discovery, queue/DMA/interrupt paths, recovery behavior, and IPv4/IPv6 SSH/SFTP interoperability gates. |
| F-03 | Fusion network feature qualification | `NOT STARTED` | Prove IPv6 TCP/UDP, outbound SSH/SCP, local DNSSEC interoperability, forwarding, and constrained loss/reorder behavior on a Fusion guest; existing QEMU evidence does not transfer automatically. |
| F-04 | Fusion snapshot and sustained-load qualification | `NOT STARTED` | Define snapshot/resume semantics and run bounded long-duration storage/network, crash-recovery, and repeat-boot tests against generated VMDKs. QEMU durability evidence is not Fusion evidence. |
| F-05 | Fusion entropy and production-credential boundary | `BLOCKED` | Fusion 26H1 exposes neither `EFI_RNG_PROTOCOL` nor AArch64 RNDR in this profile, so current images use a unique local development seed. Production requires an operator-approved entropy/key-provisioning design and credentials. |
| F-06 | Fusion release-version coverage | `NOT STARTED` | Qualify each additional Fusion release independently. Fusion 26H1 evidence is not a compatibility claim for earlier/later releases, x86_64 guests, or physical Apple hardware. |

## Apple Virtualization.framework ARM64 remaining work

XAIOS boots to a login on this platform with xaibootFS on a durable volume,
DHCP IPv4, SLAAC IPv6, SSH and all four vCPUs online, and the Mac can ssh into
the guest over vmnet
through `platform/virtualization-framework/vmnet-helper`, which is the only route in: the built-in NAT
attachment delivers no host-initiated frame, and bridging needs an entitlement
V-03 also waits on. `make vz-gate` checks that boot and writes
`build/vz-gate.json`. It is a development target: the gate needs macOS on Apple
Silicon and a signed harness, so it cannot run in CI and its result is not
qualification evidence.

| ID | Item | Status | Evidence / remaining gate |
|---|---|---|---|
| V-02 | MSI-X delivery for virtio on PCI | `TESTING` | Exercised by attaching QEMU's virtio devices on PCI, with modern identifiers and the 32-bit window, against a real translation service: every device on the bus receives a distinct vector. Three defects were fixed to get there -- one translation table shared by all devices, identifiers reissued to a second device because the first polls and never registers a handler, and an assertion on any BAR above 512 GiB. Physical ARM PCIe hardware remains the qualifying case; Virtualization.framework still has no ITS, so its queues stay polled. |
| V-03 | Globally routable IPv6 | `BLOCKED` | The NAT attachment advertises the unique-local prefix `fd4a:25c::/64`, so no globally routable address is on offer. A bridged attachment would carry real IPv6 but needs the `com.apple.vm.networking` entitlement, which Apple issues only with a provisioning profile; ad-hoc signing cannot provide it. |
| V-04 | Multi-vCPU qualification | `IN PROGRESS` | Secondaries genuinely run here now, which they never did before: PSCI starts them with translation off, where exclusives are unsupported, so the atomic each one used to announce itself aborted, and everything they published went to memory the boot CPU was not reading. Every boot reported `online cpus=1/4` and most panicked. With that window made coherent, boots come up `1/1`, `4/4` and `8/8`, the secondary worker barrier passes at each, and ten consecutive eight-vCPU boots produce byte-identical `smptest` signatures -- worker sets, kernel-dispatched worker groups and EL0 create/join -- with no panic in any of them. `make vz-gate` boots four vCPUs and requires 4/4. What remains cannot be answered here: this host has eight cores against a 128-256 core target, the platform offers no control over interrupt affinity, and none of this is sustained-load evidence. |
| C-01 | Shared kernel state under genuine parallelism | `TESTING` | Addressed subsystem by subsystem, because the right fix differed per file. The network stack, service records and CPU-AI runtime took a reentrant guard on their syscall-reachable entry points -- reentrant because ten of the network stack's exported functions call other exported ones, which a plain lock at each entry would deadlock on. The resolver shares the network guard rather than holding its own, since it calls tcp_open/send/recv/close while `network_poll_tick` calls back into its timers; a separate guard there was a lock-order inversion, caught and removed before it could bite. `security.c` and `agent_protocol.c` hold no tables at all, so their 48 audit totals became atomics instead: guarding capability checks on the syscall path would have cost far more than it bought. `vfs_xaifs.c` already locked; `update`, `ai_cell`, `persistence` and `sandbox` have no syscall entry points and are covered by guarded callers. Guard order is service before network, one direction, recorded on the primitive along with the rule that it must never be taken from interrupt context. What remains is not correctness but cost: these are coarse locks, network syscalls now serialise against each other and the poll path, and no controlled measurement of that exists yet. The cost of those guards is C-03, and the work to make them finer is C-02; neither is a reason to have waited on correctness. |
| C-02 | network_stack.c state escapes its module | `TESTING` | The obstacle to finer locking was never the lock: it was that tables handed out their rows. The socket map returned interior pointers across the syscall boundary, where callers dereferenced them after the guard had been released -- a live race once secondary CPUs ran -- and now returns a copy. The listener registry leaked rows to seven functions inside the module, all of which now hold its own guard. **No exported function returns a pointer into module state any more**, and the interior lookups that remain -- flows, queues, packet descriptors -- are reached only through guarded entry points. That is the whole of this item. Splitting those tables further was left open pending C-03, and C-03 has since measured it: the socket path costs the same per operation at eight threads as at four, and giving the listener registry its own guard rather than sharing the stack's made no measurable difference, so that split was removed rather than extended. Finer locking is therefore not scheduled -- not because it is hard, but because nothing measured asks for it. Reopen if a workload shows the coarse guard costing something. |
| C-03 | The socket path scales; the finding that said otherwise was noise | `TESTING` | Measured on a quiet machine, three runs per configuration. Socket bind/close costs about 40us per operation at four threads and the same at eight, so throughput rises with cores. That holds whether the listener registry has its own guard or shares the stack's -- 38,761/40,825/32,400 against 41,827/35,453/41,751 at four threads -- so the split bought nothing measurable and has been removed. Both are roughly ten times faster than the 437us that opened this item, which was recorded while `vmnet-helper` held a core busy and an unrelated application ran: that measurement was contention with the host, not serialisation in the stack, and the refactor it justified was built on it. What survives is correctness work that never depended on the number: the socket map returns a copy instead of a pointer into the table, and readers cover their use of a row rather than only the lookup. Nothing here is a performance claim under the benchmark contract. |
| V-06 | Graphical console | `TESTING` | Implemented. The platform's GOP reports `PixelBltOnly` with a zero framebuffer base, so firmware leaves nothing to draw into and `GOP->Blt()` does not outlive `ExitBootServices` -- but the display device is on the PCI bus regardless, and `kernel/dev/virtio/virtio_gpu.c` now claims it: display info queried, a 2-D resource created, the framebuffer attached page by page (1000 pages for 1280x800, because heap pages are not physically contiguous), a scanout pointed at it, and a transfer-and-flush after each draw, since the device copies on demand rather than scanning continuously. `boot_ui` adopts the result through a callback so it stays independent of which device supplied the buffer. The flush is no longer whole-screen: `boot_ui` accumulates a dirty bounding box across every drawing primitive -- they all reach the buffer through `fb_rect`, so one mark covers them and none can be forgotten -- and presents only that region, skipping the device entirely when nothing was drawn. Scoping the flush alone changed nothing measurable, because the boot status repainted the whole screen on every update; that clear is now full-screen only on the first draw, since nothing else is on screen during boot. Counted over a full `--gui` boot: 10 presents, 3,143,680 pixels sent against the 10,240,000 a whole-screen flush per present would have sent, a 69% reduction. What is still unverified is what a person sees on the screen; that needs an operator to look. |

## Core OS, network, and SSH phases

| ID | Item | Status | Evidence / remaining boundary |
|---|---|---|---|
| N-F3P | Physical SSH/network security qualification | `IN PROGRESS` | Consolidated QEMU network/SSH readiness evidence is available through `make qemu-qualification-readiness`; physical lossy-link, sustained-load, side-channel analysis, and independent SSH/cryptography review remain open. QEMU evidence cannot close this item. |

## Storage phases

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| S-11P Physical production NVMe qualification | `IN PROGRESS` | Consolidated QEMU NVMe and crash-recovery evidence is available through `make qemu-qualification-readiness`; named physical devices must still pass queue scaling, interrupt affinity, FUA/flush/discard semantics, reset recovery, power-loss durability, sustained-load, and performance gates. QEMU evidence cannot close this item. |
| S-12 Production xaiFS trust-root and signing-key custody | `BLOCKED` | Offline trusted-replica payload repair is implemented and QEMU/hosted-tested. Production trust-root enrollment, private-key custody, replica authorization, and rotation decisions require named operators and deployment credentials. |

## Distributed AI server phases

| Phase | Status | Exit gate |
|---|---|---|
| D-05 Real local inference | `NOT STARTED` | Real Qwen correctness, typed state, scheduling, cancellation, backpressure, and metrics. |
| D-06 Authenticated cluster control | `IN PROGRESS` | Hosted tests cover directional HMAC framing, receiver/epoch/nonce validation, replay rejection, and membership transitions. The next QEMU-testable tranche is asynchronous transport between independent XAIOS guests plus join, partition, recovery, and ownership-version tests. |
| D-07 Distributed placement/execution | `IN PROGRESS` | Hosted tests cover deterministic expert ownership, grouped routing, simulated node-loss rerouting, and stable node/expert reduction. End-to-end distributed activation execution depends on D-05 real local inference and D-06 guest transport; it cannot be closed by hosted placement tests alone. |
| D-08 Benchmarks/diagnostics | `IN PROGRESS` | QEMU benchmark telemetry and a hashed qualification-readiness report are implemented; physical metadata-rich NUMA, bandwidth, PMU, thermal, storage, network, and redacted support-bundle evidence remain. |
| D-09 Production inference service | `NOT STARTED` | Authenticated API, streaming, cancellation, saturation, loss, and long-lived tests. |
| D-10 Support qualification/cleanup | `IN PROGRESS` | Documentation contracts and the consolidated QEMU qualification-readiness gate exist; physical, model, cluster, thermal, PMU, and durability qualifications remain. |

## Qwen 3.8 implementation

| Item | Status | Acceptance |
|---|---|---|
| Pin immutable official config/tokenizer/SafeTensors and parity corpus | `NOT STARTED` | Hashes and source revisions recorded. |
| Streaming SafeTensors/config/tokenizer importer | `NOT STARTED` | Bounded RSS and deterministic package output. |
| Package-owned tokenizer | `NOT STARTED` | Trusted tokenizer IDs match. |
| Official architecture probe and ordered configuration-derived layer plan | `NOT STARTED` | Unknown fields fail closed. |
| Scalar embedding, RMSNorm, and first projection | `NOT STARTED` | Python reference parity. |
| Every configured attention/recurrent/convolution operator, position encoding, FFN, residual, norm/head | `NOT STARTED` | Complete-layer and prefill-logit parity. |
| Separate prefill/decode plans and real per-layer state | `NOT STARTED` | State and reload continuity. |
| 32-step deterministic decode | `NOT STARTED` | Exact trusted continuation within documented tolerance. |
| Physical AVX2 and tiled prefill/verification kernels | `NOT STARTED` | Physical differential and performance artifacts. |
| Native model-executing macOS process and optional Metal | `NOT STARTED` | Real model plan runs end to end; CPU fallback remains authoritative. |
| AVX-512/VNNI/AMX, SVE/SVE2, persistent worker gangs, NUMA autotuning | `NOT STARTED` | Capability canaries, scalar differential, and physical evidence. |
| Typed paged state, prefix COW, ragged batching, exact speculation | `NOT STARTED` | Target-only and speculative deterministic outputs match. |

## Later model work

| Item | Status | Acceptance |
|---|---|---|
| Separate `kimi_k3` adapter from immutable official config | `NOT STARTED` | Config/tensor roles reject unsupported fields. |
| K3 KDA, Gated MLA, AttnRes, exact top-16 routing, shared experts, SiTU, MXFP4 | `NOT STARTED` | Scalar operator/router/expert parity. |
| K3 independently addressable expert shards and async residency/prefetch | `NOT STARTED` | Authoritative routing is unchanged by prediction. |
| Real K3 text checkpoint | `NOT STARTED` | Tokenizer/operator/router/target-token and production-width physical gates. |
| K3 MoonViT-V2 and multimodal pipeline | `NOT STARTED` | Separate golden image/text cases. |
| DeepSeek V4 Flash 0731 source verification | `BLOCKED` | Maintainer-approved immutable official source. |
| DeepSeek adapter and parity suite | `BLOCKED` | Depends on verified source. |
| Multi-terabyte sparse allocators and large pages | `IN PROGRESS` | Hosted model packages represent sparse offsets above 100 GiB; both QEMU targets cover 2 MiB mappings and x86_64 covers a 1 GiB leaf plus targeted SMP TLB invalidation. Physical capacity and performance qualification remain. |
| SRAT/SLIT/HMAT placement policy and local/remote byte telemetry | `IN PROGRESS` | The two-node x86_64 QEMU gate validates SRAT/SLIT/HMAT parsing, usable-memory intersection, deterministic preferred-node policy, node-local allocation, and local/remote byte accounting. Physical locality/performance qualification remains. |
| AI Cell/secondary-CPU real inference dispatch | `NOT STARTED` | Real model work executes on leased workers. |
| NUMA/machine expert ownership and stable failure-aware reduction | `IN PROGRESS` | Hosted tests validate deterministic owner selection, grouping, simulated owner failure, and stable reduction. Real NUMA/machine transport, remote activation execution, and multi-QEMU exactness remain. |

## Open decisions

| ID | Decision | Status | Required before |
|---|---|---|---|
| OD-001 | Select first physical Apple/ARM target and firmware/storage/NIC boundary | `NOT STARTED` | Physical ARM support. |
| OD-002 | Select representative AVX2 Intel desktop and hybrid-core/device baseline | `NOT STARTED` | Intel desktop support. |
| OD-003 | Select Xeon generation, sockets/NUMA, memory, NIC, and NVMe | `NOT STARTED` | Xeon support. |
| OD-004 | Provision production update/xaiFS trust roots and define custody/authorization procedures | `BLOCKED` | Rotation, revocation, offline recovery, and interrupted-activation rollback are implemented; private operator keys and process are required before untrusted deployment. |
| OD-005 | Define SSH fleet limits, identity, audit retention, lockout, recovery | `NOT STARTED` | Production SSH exposure. |
| OD-006 | Define supported NVMe/FUA/flush/discard/repair/power-loss contract | `NOT STARTED` | Physical persistent deployment. |
| OD-007 | Pin official immutable Qwen 3.8 fixtures | `NOT STARTED` | Qwen implementation. |
| OD-008 | Pin official Kimi/DeepSeek sources | `BLOCKED` | Corresponding adapters; DeepSeek exact label is unresolved. |
| OD-009 | Select expert-parallel interconnect and failure/ownership model | `NOT STARTED` | Cluster inference. |
| OD-010 | Define names, quality reporting, telemetry, and acceptance for opt-in approximate modes | `NOT STARTED` | Any approximate mode. |

## Risk register

Risk status `TESTING` means mitigations exist but the risk remains open and is
checked continuously.

| ID | Risk | Status | Mitigation / closure gate |
|---|---|---|---|
| R-001 | QEMU timing presented as hardware performance | `TESTING` | Evidence vocabulary and benchmark contract; close only with continued claim audits. |
| R-002 | Documentation drift | `TESTING` | One tracker, `make docs-check`, and live-Wiki parity. `check-doc-freshness.py` now also fails the build on the two claims that expire quietly: an evidence commit of ours that has fallen far behind `HEAD` without saying so, and a review date on a page that git shows was edited afterwards. Three such claims were found expired in a single session -- a page saying a target had no automated gate months after two were added, a stale review date, and an evidence commit quoted as current from a hundred commits back -- so the residual risk is prose that is wrong in ways no pattern can see. |
| R-004 | Unreviewed SSH exposure | `TESTING` | Passwords off by default, bounded limits, OpenSSH/FreeBSD gates; independent review remains. |
| R-005 | Fixture keys used as production trust | `TESTING` | Fixtures are labeled; OD-004 blocks production trust. |
| R-006 | Storage durability inferred from sparse/QEMU tests | `TESTING` | Passing emulated async-NVMe and crash-recovery gates remain separate from physical S-11P and trust/repair S-12; only physical evidence can establish durability. |
| R-007 | Parser arithmetic or ownership error | `TESTING` | Checked arithmetic, malformed tests, sanitizers, immutable readers, fuzzing. |
| R-008 | Interfaces advertised as model support | `TESTING` | Separate progress and support-boundary columns plus golden gates. |
| R-009 | SIMD selected from CPUID alone | `TESTING` | OS-state checks, known-answer canaries, and scalar differential tests. |
| R-010 | Bounded fixture limits treated as server-scale targets | `TESTING` | Runtime-sized CPU/NUMA structures and explicit remaining bounded stores. |
| R-012 | Repository Wiki diverges from live Wiki | `TESTING` | Versioned Wiki source, post-push byte comparison, and docs checks. |

## Evidence gates

The default status-changing evidence set is documented in
[[Testing XAIOS|Testing-XAIOS]]. At minimum, source changes require the smallest
relevant compile/hosted/QEMU gates; documentation changes require layout,
status, JSON, link, and live-Wiki checks. A failed required gate changes the
affected item to `FAILED` until a passing rerun is recorded.

GitHub issues and milestones may provide discussion and execution history, but
their descriptive status must link back here rather than becoming another
independent tracker.
