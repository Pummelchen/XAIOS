# Project Tracker

Last reviewed: 2026-09-12.

This is the only human-maintained XAIOS project tracker. Roadmaps, milestones,
phase plans, open decisions and risks are consolidated here, and the Wiki keeps
no other planning page. It records what each item's state is and what would
change it -- not how the work was done. That reasoning belongs in the commit
that did it and in the comments beside the code.

## Where the tree stands

The ten aggregate targets -- `qemu-core-os-rc`, `qemu-full-os-rc`,
`qemu-developer-ux`, `qemu-operations-closure`, `qemu-network-adversarial-gate`,
`qemu-readiness-gate`, `qemu-post51-gate`, `qemu-qualification-readiness`,
`qemu-100-gate` and `qemu-release` -- all passed at `c25b749`, run serially,
because these assert on boot markers and timings and this machine cut a
`qemu-smoke` boot short at load average 30 and passed it at load 9 with no
change in between. The consolidated report deliberately retains
`physical_qualification=false`.

**They have not been re-run since, and shared code has changed underneath
them**: the resolver and DNSSEC verification, the network stack's socket map
and poll accounting, the syscall layer, the lifecycle record, and most of sshd
-- eighteen files across `kernel/` and `userspace/`. Individually green on the
current tree: `compile-check`, `platform-neutrality-check`, `docs-check`,
`code-scanning-contract`, `qemu-smoke`, and every gate named in the rows below.
Re-running the ten is the next thing worth doing, and until it happens no
statement here about aggregate status is current.

That is emulated evidence and nothing more. **No result on this page is
physical-hardware evidence, and no released build has been booted on physical
hardware.**

One step timed out once and did not reproduce; it is `B-39` rather than a
footnote here.

### Firmware profile results

Three profiles carry firmware evidence, and all three **are behind the current
tree and must be re-run** before any of them is quoted as current: shared code
that every profile compiles has changed since each was collected -- the
scheduler and page allocator, the network stack, the cluster engine, and the
RISC-V memory and interrupt path.

| Profile | Collected at | Firmware | Covers |
|---|---|---|---|
| macOS QEMU ARM64 | `8a1a8a9` | AAVMF/EDK2 `47765fe344818cbc464b1c14ae658fb4b854f5c2ceffa982411731eb4865594d` | boot, CPU, network, SSH, USB keyboard console, SVE2 per-task context, storage recovery, operations, shutdown, repeat boot |
| macOS VMware Fusion ARM64 | `8a1a8a9` | Fusion 26.0.0, chainloader `b7fb993edf80e301b148a2076f8a9919c3d31936d2273f592d19c06b5ec1d3a5` | four-vCPU boot, storage, network, SSH lifecycle |
| Intel VPS QEMU x86_64 | `ee9c621edde5315e0da37fb3ae328baf717318ee` | OVMF/EDK2 `624e06de18b4fa535e90db7160d00d3d07d206422b89999bf1e27d920264e4e0`, QEMU 10.0.11 under TCG | all eight profile gates: boot/network/SSH, USB keyboard console, CPU matrix, platform inventory, NUMA firmware, NVMe storage, operations/shutdown, repeat boot |

The Intel profile needs its designated host (`deltasona`, Linux x86_64); no ARM
result stands in for it. Collecting it found nothing wrong with XAIOS and one
thing wrong with a gate: `q35-high-core-256-x2apic` needs about 517 seconds to
boot 256 vCPUs under TCG against a hardcoded 480, so the matrix killed a machine
that was booting correctly. Budgets now scale by
`XAIOS_QEMU_MATRIX_TIMEOUT_SCALE`; unset, nothing changes, and nothing the
scenario asserts was relaxed.

## Released builds

Builds are published on the
[releases page](https://github.com/Pummelchen/XAIOS/releases); each carries a
note recording the hypervisors and firmware it was booted on and what was not
tested. What changed between them is in
[`CHANGELOG.md`](https://github.com/Pummelchen/XAIOS/blob/main/CHANGELOG.md);
this page does not repeat it.

| Build | State | Note |
|---|---|---|
| `b4` | **current** | Cut from a green CI run. Adds first-boot setup, an account and machine name a person chooses, and the fixes below. |
| `b3` | superseded — do not use | A machine configured with SSH keys and no password account refused every key login, and it was cut while CI was red. |
| `b2` | superseded | First build to ship USB and network-boot kits. |
| `b1` | superseded | First released build. |

No released build has been booted on physical hardware.

## Status codes

| Code | Meaning |
|---|---|
| `TESTING` | Implemented, but the current acceptance run or physical qualification is still underway. |
| `IN PROGRESS` | Active implementation is incomplete. |
| `NOT STARTED` | No qualifying implementation has begun. An interface or fixture alone does not count. |
| `BLOCKED` | Work cannot proceed until the stated external decision or dependency is resolved. |
| `FAILED` | The latest required acceptance gate failed; the failure evidence must be linked in the item. |
| `DEFERRED` | Postponed on purpose. Not blocked by anything external and not abandoned -- it is simply not being worked on now, and saying so is more honest than leaving it among the open items. |
| `NEEDS HARDWARE` | Implemented as far as it can be here, and the remaining evidence can only come from physical machines. Not on the active work list: no amount of effort in this environment moves it, and leaving it among the open items makes the list read as further behind than it is. |

Resolved items carry no status code. They move to a **Resolved, kept for
reference** table in their own section, which records what the item was and
what closed it. They are not deleted, because their identifiers are cited
from the code, the gates and the release notes.

QEMU status proves correctness and ABI behavior only. Physical support and
performance require immutable evidence under the
[benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md).

## Supported environments

XAIOS runs on three hypervisors. QEMU covers three architectures, so five
targets exist, but the platform contract is per hypervisor.

Firmware differences below are the hypervisor's, not XAIOS's: the system
behaves identically wherever a capability exists, and where one is absent it
degrades the same way everywhere. See
[Platform neutrality](https://github.com/Pummelchen/XAIOS/blob/main/docs/PLATFORM-NEUTRALITY.md),
which the build enforces.

| Function | QEMU ARM64 | QEMU RISC-V64 | QEMU x86_64 | VMware Fusion ARM64 | Virtualization.framework |
|---|---|---|---|---|---|
| Boots to a login | yes | yes | yes | yes | yes |
| Durable xaibootFS volume | yes | yes | yes | yes | yes |
| IPv4 by DHCP | yes | yes | yes | yes | yes |
| IPv6 by SLAAC | yes (`qemu-slaac-gate`) | yes (`qemu-slaac-gate`) | yes (`qemu-slaac-gate`) | yes, global, from a real router advertisement (`make vmware-fusion-network-gate`) | yes, unique-local only (`V-03`) |
| IPv6 by DHCPv6 | client present, gated | client present, gated | client present | client present | client present |
| SSH server | yes | yes | yes | yes | yes |
| SSH client, SFTP | yes | yes | yes | yes | yes |
| Reachable from the host | yes | yes | yes | yes | vmnet helper only, one direction at a time |
| Boots at 1, 2 and 4 GiB | yes (`qemu-memory-matrix`) | yes (`qemu-memory-matrix`) | yes (`qemu-memory-matrix`) | yes, all three run | yes, all three run |
| Multiple vCPUs | yes, 130 gated | yes, 1/2/4/8 gated | yes, 128/256 scenarios | yes, 4/4 | yes, 8/8 |
| Message-signalled interrupts | distributor | board-dependent: none on the default `virt` (PLIC, everything polls), APLIC+IMSIC on `virt,aia=aplic-imsic` (`qemu-riscv64-aia-gate`) (`P-16`) | yes | PCI | none; every queue polls (`V-02`) |
| Framebuffer console | no, serial | yes with a virtio-GPU attached, gated; serial otherwise | no, serial | yes | yes when a display device is attached (`--gui`), driven directly over virtio-GPU because firmware publishes none; serial otherwise |
| USB keyboard input | yes | yes, gated | yes | provisioned, not gated | console input over virtio |
| Entropy protocol | virtio-rng | virtio-rng (`source=device-rng`) | virtio-rng | `F-05` none exposed | yes |
| Storage transport | virtio-MMIO | virtio-MMIO; NVMe over PCIe in its own gate | virtio-PCI, NVMe | AHCI | virtio-PCI |
| Network transport | virtio-MMIO | virtio-MMIO | virtio-PCI | E1000E qualified; VMXNET3 works (`F-02`) | virtio-PCI |
| Applications gated | yes, by name | yes, by name | yes, by name | yes, by name | yes, by name |
| Boots its release image | yes, gated | yes, gated | yes, gated | yes, gated | yes, gated |
| Automated gate | full CI | full CI (`riscv-bring-up`: smoke, release configuration, CPU tiers) | full CI | `make vmware-fusion-smoke` | `make vz-gate`, `make vz-stress-gate` |
| Release-image gate | `make release-image-gate` covers all five, each booting its own architecture's image; CI runs the three QEMU rows and reports the hypervisors as skipped |  | | | |
| Verified by | CI, every push | CI, every push | CI, every push | `make local-gates`, required by `make release-check` | `make local-gates`, required by `make release-check` |
| Evidence class | correctness only | correctness only | correctness only | Fusion 26H1 lifecycle | development target, not evidence |

Device inventory differs because the hypervisors differ; the kernel discovers
what is present rather than assuming a platform, so those rows are not defects.
The rows carrying an item identifier are.

## Open bugs

Defects with no fix in place, followed by resolved ones kept for reference.

A resolved row is not deleted, because its identifier is cited from the code,
the gate or the release note that closed it -- `B-14` appears in five release
notes and a gate docstring, `B-25` in ten files -- and a citation that resolves
to nothing is worse than a short row. The reasoning behind each fix stays in
the commit that made it and in the comments beside the code; this table records
only what the defect was and what closed it.

| ID | Defect | Affects | Status | Notes |
|---|---|---|---|---|
| B-43 | A session stalls ~19 s and the guest says nothing about it | VMware Fusion ARM64 | `TESTING` | **The premise I wrote into this row was wrong.** It said the server was alive and serving a later connection while an earlier sat untouched. The soak's round is strictly sequential -- `round_trip()` blocks, and the `recovery status` probe only runs after the sftp process has exited -- so `connfd=852` could not begin until `connfd=851`'s client had given up. Two sequential events read as concurrent. With that gone there is no reason to expect a starvation bug, and none is there: the service walk has no early exit, no unhandled state, no per-pass budget, and accept precedes service in the same pass. B-43 is a **pause, not a skip**. The 18 s is not a guest constant either -- no `SSHD_TIMEOUT_*` or TCP timer produces it -- it is the macOS client's own patience, which is why both occurrences show the same duration at two unrelated protocol stages. **What the search did establish is worth more than the row asked for:** `network_poll_tick` has no timer, no interrupt and no thread, and reaches the ring only through the network syscalls and `wait_events`, which only `sshd` and `xtop` call. sshd is the machine's network thread, so any pause anywhere in its loop is a total network outage that fires no timeout and closes nothing -- see `B-44`. **To close:** a recurrence carrying one of the three new console lines, which separate "sshd held the machine" from "sshd was not running" from "the loss was in the network path". Not reproduced in 1281 QEMU connections; one round took 37.2 s against a 2.97 s mean and succeeded, with no loop stall and no guest retransmit. |
| B-48 | Every file write commits the whole metadata region | all four | Found while measuring `B-45`, and it is the correction to that row's cost model. Whatever a write changes -- one appended record or an entire rewritten file -- `write_metadata` writes the volume's entire metadata region and flushes: **1280 sectors, 640 KiB** on a v5 durable volume, roughly forty times the file traffic the old append path moved. B-45 took file bytes to nearly nothing and per-record time did not move: 61.1 us before against 60.4 us after, statistically identical. Its whole 29% improvement came from writing two fewer records per connection, not from any record being cheaper. Total volume bytes per connection fell 4.66 MB to 3.33 MB against a 29.6% time fall, so time here is proportional to bytes written and the bytes are metadata. **To close:** commit only the metadata that changed, or batch commits across records, and prove the durability model still holds under `qemu-power-loss-gate`. |
| B-49 | A data sector number truncates above 32 MiB | all four | `absolute_data_sector(uint16_t block_index)` in `kernel/fs/xaiboot_fs.c` takes a 16-bit block index, while `write_extents`, `read_extents` and `clone_extents` all pass `uint64_t` block numbers. Past 65,536 data blocks -- 32 MiB -- every data sector number silently wraps, and v6 volumes are allowed a gibibyte. Not reachable by the v5 volumes anything currently boots, and the `B-45` append path has exactly the same exposure as the existing paths, no more. Found in passing and deliberately not fixed there: it is one word, but it is a behaviour change to large v6 volumes and deserves its own gate. **To close:** widen the parameter, and gate it with a v6 volume larger than 32 MiB writing and reading back past the boundary. |
| B-50 | `qemu-ssh-connection-rate-gate` cannot reliably open its connections on this host | repository | `TESTING` | The gate opens 121 connections through QEMU's host forwarding inside the limiter's 60 s window. It passed cleanly this morning; it now returns `{banner: 114, silent: 2, unreachable: 5}` -- five the host could not open and two accepted then neither served nor closed. Not ephemeral-port exhaustion (one TIME_WAIT socket on the machine) and not `B-47`'s new refusal (`net-accept-no-flow-slot` is zero; the one exhaustion line per boot is the socket-map self-test's deliberate fill). **The gate's own bug is fixed and was the serious half:** `unreachable` and `silent` counted as neither served nor refused, so one run emitted both "only 113 of the first 120 were answered" and "all 121 were served, so the limit did not fire" -- it accused the guest of a defect the host caused, which is the failure it exists to stop other gates making. It now reports `INCONCLUSIVE, not a guest defect` and names the host, still exiting non-zero. **To close:** find what limits rapid connections through hostfwd -- pacing the opens is the obvious experiment -- so the gate can create its condition here rather than declining to conclude. |
| B-51 | `qemu-fault-matrix` booted the machine's accumulated state, and said the wrong thing when that state failed it | repository | `FIXED` | It was the one gate in `qemu-readiness-gate` that booted `build/xaios-persistent.img` unisolated: roughly twenty sibling gates pass `persistent=` and reset it, this one took the runner's default. On this Mac that volume is 64 boots deep (2030 blocks against 14 on a fresh one) and cannot be snapshotted (`B-52`), so the guest panicked in `update_stage()` long before any fault was injected and the three scenarios `page:boot`, `ro:boot` and `nx:boot` failed. **The reporting was the worse half.** It printed `missing targets: ['exceptions: triggering controlled NX execute fault', ...]` whether the guest faulted wrongly, panicked elsewhere, or never booted -- accusing the fault machinery of a defect the host caused. By the test in `tests/README.md` it failed: on a machine with no guest it would have said the same guest-shaped sentence. **Fixed both halves.** Each scenario now gets its own volume, deleted first so the runner makes a blank one; and a boot that never prints `exceptions: triggering controlled` reports `INCONCLUSIVE, not a guest fault-handling defect` with the reason -- the panic line, or that firmware never reached the loader -- and exits 2, distinct from the 1 a real fault-handling failure returns. Both are non-zero: a gate that cannot conclude has not passed. **Evidence, same machine and same commit:** the unisolated gate failed all three; a fresh volume (`blocks=32 gen=52`) passed all three; the fixed gate passes (`exit=0`); and patched to seed itself from the 64-boot volume it reports `INCONCLUSIVE` for all three naming the assertion, `exit=2`. |
| B-52 | A fragmented durable volume cannot be snapshotted, and two callers disagree about whether that is fatal | all four | `allocate_extents` in `kernel/fs/xaiboot_fs.c` is first-fit and gives up once a file needs more than `XBFS_V6_MAX_EXTENTS` (16) extents, returning `XAIOS_ERR_NO_MEMORY`; `clone_extents` turns that into `XAIOS_ERR_IO` and `commit_snapshot` fails. A v5 volume with 8192 data sectors holding repeatedly rewritten `/var/log/kern.log` reaches that state by ordinary use -- `fsck` reports `errors=0 valid=1`, so the volume is sound and merely unsnapshottable. The kernel then handles the identical `-4` two ways: `operations.c:237` logs `lifecycle persist failed` and continues, `update.c:752` asserts and panics the machine. Latent since at least 2026-06-18; surfaced by `B-51`. **To close:** decide which behaviour is right and make both callers do it, then either compact on allocation failure or raise the extent cap, gated by a volume driven into fragmentation on purpose. |
| B-53 | Nothing stopped a packaging script from shipping a kernel built to fault on purpose | repository | `FIXED` | `make qemu-fault-matrix` compiles three kernels that halt deliberately, each into the same `build/kernel*/kernel.elf` every packaging script reads on trust, and restores a normal image when it finishes. That restoration is a courtesy, not a guarantee: interrupt it, crash it, or run a packaging script beside it, and the tree holds a halting kernel under the name that means "the kernel". Found by doing exactly that -- a netboot binary was built while a fault build was in the tree, and the only thing that caught it was `boot-media-gate` booting the binary and watching it stop at `exceptions: triggering controlled NX execute fault`. Four to twelve minutes of QEMU, and skipped entirely on a host without it. Two of the three fault builds leave a distinctive string behind; the page-fault one calls a helper compiled into every kernel and leaves nothing, so a string search would have caught two cases in three. **Fixed:** `kmain.c` now emits one marker for all three, guarded by the same `#if` so a release kernel cannot contain it, and `build-arch-image.sh` and `build-netboot-image.sh` both refuse a kernel carrying it -- read out of the finished binary, no boot required. `tests/repository/check-fault-test-marker.py` keeps the three copies of that string in step, because a grep that can no longer match is a gate that cannot fail. **Evidence:** built an NX fault kernel; both packagers refused it and named the rebuild command. Renaming the marker in the kernel alone makes the new check fail and name both scripts. |
| B-39 | `core-os-rc`'s fragmentation step timed out once, and has not since | all four | `TESTING` | In a full serial run of the ten aggregates, `qemu-outbound-fragmentation-gate` was killed by a 360 s step budget with `timed_out: true`, having rebuilt its three images and reached all three `testing` lines. Every other step passed. It has not reproduced: 121 s standalone, 120 s from the boot-test image state, 121 s with all three images invalidated, and `core-os-rc` green in 1323 s on a re-run. Two explanations were tried against the exit code alone and both were wrong -- the step does not run concurrently with its neighbours, and the image builds its dependencies force are incremental. **The exit code was the problem:** 124 carries no elapsed time and no idea what else the machine was doing, on a host that has cut a boot short at load 30 and passed it at load 9. Every step now records its elapsed time, its budget, the fraction used and the load either side, and a step past 75% of its budget prints a note while still passing -- that is the one which times out next. Verified against the real code: a 76% step noted, a killed step reporting `exited 124 after 2s of a 2s budget, load 1.56 to 1.56`. **To close:** a recurrence that now says which it was. |

### Resolved, kept for reference

| ID | Defect | Affects | Closed by |
|---|---|---|---|
| B-01 | Outbound ProxyJump failed host key verification | x86_64 builds | `known_hosts` was read through a single 4 KiB buffer, so a host whose entry lay past it looked like a host with no entry. The full FreeBSD bidirectional suite now passes under emulation, 19 of 19. |
| B-03 | `vmnet-helper` spun a core while idle | Virtualization.framework | It returned without reading the packet that woke it, so vmnet's event never cleared. It now reads first and drops the frame if there is nowhere to send it: 20 ms of CPU over 60 idle seconds, measured on the rebuilt binary. |
| B-04 | Fusion intermittently got no DHCP offer | VMware Fusion ARM64 | One hard-coded transaction id on every boot, and a budget split evenly between OFFER and ACK that gave the first phase only three attempts. The budget now goes to the phase that needs patience; total raised 15 s to 30 s, paid only where no server answers. |
| B-05 | One fixed kernel link address blocked a 1 GiB profile | all four | The AArch64 kernel is built position-independent and the loader applies its 384 relative relocations wherever firmware places it. x86-64 stays fixed-address by necessity. `make qemu-memory-matrix` boots all three at 1024 MiB. |
| B-06 | Virtualization.framework booted to nothing below ~3.5 GiB | Virtualization.framework | It was B-05: a kernel fixed at `0x90000000` on a platform with no memory there until it has enough. `vz-gate` reads `XAIOS_VZ_MEMORY_MIB` and passes at 1024, 2048 and 4096 MiB -- it had been pinned at the one value where the defect cannot occur. |
| B-07 | Applications were never run on two of the four images | Fusion, Virtualization.framework | Only QEMU built with `XAIOS_BOOT_TEST_APPS=1`, so both hypervisor gates checked kernel markers a guest can satisfy while every program a person would type is broken. Both now build the applications and assert eight application markers per boot. |
| B-08 | An unclean-boot marker put the guest into rescue mode | all four | The shared durable image accumulated hard power-offs until the rescue marker latched. `vz-gate` generates a fresh volume per run and both hypervisor gates treat `rescue=1` as a fault. The latching itself is by design -- see [[Operations and Recovery|Operations-and-Recovery]]. |
| B-11 | Userspace and the identity map were the same addresses | all four | Userspace began at 4 GiB, inside the kernel's own identity map, so a 4 GiB machine handed the kernel's memory to userspace. The window moved and `vmm_init` caps the identity map at `XAIOS_USER_BASE`. Two years of 2 GiB gates could not have seen it. |
| B-12 | Fusion faulted on the firmware framebuffer at 4 GiB | VMware Fusion ARM64 | Firmware places the framebuffer above RAM, so at 4 GiB it lands outside what the kernel identity-maps. `kmain` maps it from `boot->framebuffer_base` straight after `vmm_init`. `XAIOS_FUSION_MEMSIZE` exists so the gate can run at the size that shows it. |
| B-14 | The x86_64 guest wrote to the medium it booted from | QEMU x86_64 | The runner attached the boot drive writable where AArch64 attaches it read-only. The self-test now asks whether the device advertises `VIRTIO_BLK_F_RO` and verifies the refusal; `make qemu-readonly-medium-gate` exercises that branch, which had never executed. |
| B-15 | An intermittent fatal assertion on VMware Fusion | VMware Fusion ARM64 | One occurrence, never repeated in 217 boots. The remedy this row first claimed did not work: subtracting the load base alone is not enough and the kernel carries no DWARF. The panic screen now names `tests/scripts/resolve-panic.py`, which does the arithmetic against the symbol table. |
| B-19 | The relocated kernel was placed without its required alignment | all four | The loader took firmware's page-aligned address while the kernel's segments declare `p_align 0x10000`; landing 4 KiB off makes the SMMU reject its stream table. The loader now rounds to the strongest `p_align`, and `offset_in_64k` is a required marker in three gates. |
| B-23 | A v6 volume sometimes did not come back from a power cut | all four | The mirror fallback called `set_active_v5()`, so a v6 volume with a torn primary validated whatever data block sat at the v5 mirror offset. It now searches the layouts it knows. Proven by `tests/storage/test_xaiboot_fs_v6.c` with a negative control; the CI failure itself was never reproduced locally. |
| B-24 | Renaming a directory on a v6 volume wrote 191 KiB past a static array | all four | `g_path_transaction` was still declared at the v5 node count while the walk used the v6 one. Fixed by sizing rather than clamping, with a compile-time assertion and a boot-time self-test so a future maximum cannot reintroduce it. Found while fixing B-23; nothing reported it. |
| B-25 | After reverting a Fusion snapshot the guest refused every command | VMware Fusion ARM64 | sshd freed a remote-login session context only after a command succeeded, while every other path allocated one -- and socket handles are never reused. Deterministic at 64 connections, not intermittent. The table now evicts least-recently-used and `make qemu-ssh-session-exhaustion-gate` holds it. |
| B-26 | `qemu-docker-network-suite` failed its native xtop check | all four | Three stale markers and one real defect: `\x1b[42;30m` is the basic-colour form xtop stopped emitting when it moved into the screen framework, and the help title reaches the stream only as changed cells. |
| B-27 | A full-screen program's terminal restore was truncated | all four | A length constant beside a literal had drifted -- 24 written for a 29-byte string -- so five bytes never left the program. Every escape length in the serve path now comes from `sizeof` of a named string. |
| B-29 | A userspace UDP socket could not send | all four | `XAIOS_SYSCALL_NET_SEND` required a flow, and for UDP only an *inbound* datagram ever created one, so a bound socket that had received nothing could not speak first. `network_stack_udp_sendto` creates the flow and transmits; `/bin/netmqtest` was the first program in the tree to try. |
| B-31 | `qemu-libc-gate` booted a RISC-V image its dependency never built | all four | The make dependency built AArch64 and x86-64 while the gate iterated three architectures, so the RISC-V leg booted whatever `build/` held. Shown rather than argued: with `kmain.c` edited so it no longer emits the marker the gate requires, the old gate reported `PASS: hosted runtime executed on riscv64` with the kernel byte-identical afterwards, and the new one rebuilt it and failed on exactly the five `exit_code=` markers that format string produces. Same command, same tree, opposite verdicts. The gate now builds every image it boots from one table that is both the list built and the list booted. Fixing it found RISC-V needs a third build step -- the signed A/B system volume, which the runner copies into its boot state and which carries a kernel the loader prefers -- that no libc target ran, including the one documented as building its own image. |
| B-02 | Thread join failed under load, twice | all four | `user_thread_worker` cleared the CPU to the kernel unconditionally, so a worker entered from inside a process's own `xaios_thread_join` left the outer syscall with no current process and the kernel's address space. It now saves and restores the CPU's process, address space and thread slot. The window is reached deliberately by `/bin/joinnest`: a process cannot pin a thread to its own CPU -- `select_user_cpu` refuses that -- so a helper takes a worker CPU, a victim is pinned to the same CPU (the pinned path never asks whether it is busy), and the helper joins the victim, which only returns by running it nested with a user process bound. `make qemu-thread-join-soak` is green on all three architectures and red with the fix reverted, ending at `join lost its process context id=17 owner=11 cpu=1 before=11 after=0`. Whether that defect produced the two original sightings is still inference; what changed is that a recurrence now fails a gate instead of being noticed twice and explained neither time. |
| B-28 | An SSH session is refused once in several hundred under sustained load | VMware Fusion ARM64 | The refusal was the per-address accept-rate limit: 120 per 60 seconds, and a soak round opens two connections -- the transfer and the status probe after it -- so round 61 carried connection 121 and was closed before a byte of SSH was spoken. `make qemu-ssh-connection-rate-gate` reproduces it deterministically and is red without the fix. Authentication now credits the connection back, since the limit exists to bound a peer that has proved nothing. Confirmed on Fusion at 4.2x the original exposure: **2463 rounds, 1.29 GB, and not one refusal on accept** -- zero rate-limit, capacity or slot-exhaustion markers in the whole run. It was invisible for two years because all three pre-serve refusal paths reported somewhere nobody reads; each now names its reason with a counter. The row conflated two signatures, and the other one is `B-38`. |
| B-34 | `dns_self_test` reported three things it did not test | all four | It printed `dnssec=local-chain tcp-fallback=enabled aaaa=enabled` while exercising only name encoding, decoding and the cache. It now exercises them: walks a committed signed chain (`kernel/net/dns_selftest_chain.h`, regenerable from `generate-dnssec-fixture.py --target kernel`), rejects a forged and an expired signature, validates an AAAA RRset and refuses an A answer offered as AAAA, drives truncation in both directions, and checks both deadlines. It reads no wall clock and transmits nothing, so it runs on a machine with no NIC at boot. Control run here rather than taken on report: with `dnssec_verify_address` accepting everything the boot halts at the address assertion. |
| B-35 | One deadline covered a whole DNSSEC chain | all four | `started_ns` was stamped once per resolve and never by `start_query`, so the root-DNSKEY, DS, child-DNSKEY and answer queries shared a single 15 s budget against a 5 s retransmit timer -- a longer chain spent it and returned a cancellation a caller could not tell from a refusal. Split into `query_started_ns` (per query, a new field rather than a reuse of `sent_ns`, which a retransmit moves) and `walk_started_ns` with a stated 45 s walk budget. Per-query alone would have left a deep name composing `2N+2` timers into a bound nobody wrote down, which is the same defect in a longer form. Both expirations complete as `XAIOS_ERR_CANCELLED` and print `dnssec-timeout`. |
| B-36 | A malformed argument was reported as a DNSSEC failure | all four | `XAIOS_ERR_INVALID` meant both "bad arguments" and "the chain did not validate", and both printed `dnssec-unverified`; `qemu-operations-closure` accepted that string, so a malformed invocation read there as a fail-closed resolver. `nslookup` now validates its own arguments first and `dnssec-unverified` is reserved for a chain that was walked and refused. A fourth case the row missed: a hostname of 64 bytes or more also returned `XAIOS_ERR_INVALID` from the resolver, so `XAIOS_DNS_MAX_HOSTNAME` is published and the shell checks length itself. The gate now rejects all five malformed forms and runs a well-formed lookup afterwards, so it cannot be satisfied by refusing every `nslookup`. |
| B-37 | The outbound SSH client could not run without a terminal | all four | It prompted for the identity file's passphrase on every invocation, including for a key that has none, and `-o` was not a recognised token at all -- so with no PTY it printed `key passphrase:` and blocked indefinitely, measured at 45 s and still going. Three changes: the key is read before deciding, by the loader itself rather than a second parser, so a plain key is never asked about; `-o BatchMode=yes` is understood on both `ssh` and `scp` and **any other `-o` is refused rather than ignored**, since a silently dropped option is a false pass; and because the app cannot tell whether it has a PTY, a 60 s bound on *silence* at the prompt ends an unattended one while every keystroke restarts it, so a person mid-passphrase is never cut off. `make qemu-outbound-batch-mode-gate` holds all nine cases. Two images, because a private key reaches the guest only by being packed in: the kernel refuses any runtime write whose bytes contain `"BEGIN "`, confirmed as policy by bisection rather than assumed. |
| B-33 | Two aggregate gates certified a `printf` for the DNSSEC path | all four | Under `XAIOS_BOOT_TEST_APPS` -- the configuration every QEMU gate uses -- `nettest` had two bare log calls with no code behind them, and the row recorded one gate requiring them. It was two: `qemu-smoke` required both strings, and `qemu-core-os-rc`'s `userspace_dns` capability required the second under a comment claiming "nettest drives the deterministic DNS fixture". Fixed by making the claim true rather than renaming it: the resolver answers `selftest` and `forged.selftest` from the committed chain, boot-test builds only, and `nettest` resolves both for A and AAAA, compares them to the fixture's own addresses, requires the tampered zone to be refused, and requires the repeat to come from cache. When the forged zone does validate the kernel returns the success to userspace rather than swallowing it, so userspace is what calls it a failure. Both marker strings kept byte-identical, so neither gate needed editing and both comments are now true. |
| B-42 | The DNSSEC self-test fixture and its anchors ship in release images | all four | Kept, deliberately, and the reason it can be kept was made checkable. Measured against the same tree with the self-test compiled out: 7,409 bytes of `dns.o` -- 3,008 code, 1,445 fixture chain, and 2,951 of `kassert` and klog strings, so the fixture is not even the largest part -- and 4,640 bytes of `kernel.elf`, 0.44%, with no change to the fixed 64 MiB boot image or the initfs. Guarding it would take release DNSSEC coverage to zero: `kassert` is never compiled out, no gate anywhere greps the marker, and B-33's fixture zone is test-only, so this walk is the only DNSSEC verification a release machine performs. **The real exposure was elsewhere:** that the IANA anchors are restored was true, unasserted and unobservable -- a release image prints no klog to serial, so a surviving test anchor would have shipped silently. The self-test now reads the anchor table after restoring it and panics on the test tag, `dns_configure` logs the anchors in force, and a release boot shows `dns: trust anchors count=2 tags=20326,38696` through `xaiosctl logs --component dns`. Control run here: removing the restore halts the boot at `assertion failed: anchor_count == XAIOS_DNSSEC_MAX_ANCHORS`. Two corrections to this row as I filed it -- `production-source-audit` only rejects unfinished-work markers and says nothing about test data in a shipping binary, and the boot image is fixed-size so it can never move. |
| B-40 | `send_all` could freeze the whole server for as long as a peer trickled | all four | The 10 s bound measured the *gap* between bytes, and `stalled_since` reset on any byte taken, so a peer accepting a slice inside each window renewed it forever. Worse, when the bound did fire it only abandoned the packet -- nothing closed the channel, so the next tick retried the same write and held the single-threaded server another 10 s. Replaced with a rate: in each window the peer must take at least 10 KiB, body and MAC sharing one allowance so it cannot get a fresh one mid-packet. 1 KiB/s is below a 9.6 kbit/s data call, and the trade is stated in `sshd.h` -- a peer slower than that loses its connection rather than every other session losing the server. An aborted transmit is marked silent, or the cure spends a second window writing a disconnect into a socket that just refused a packet. Held by `make qemu-sshd-transmit-rate-gate`: a peer at 641 B/s stops being served after 102 s while 144 ordinary sessions run, and a peer that keeps up moves 14.5 MB untouched. |
| B-41 | A failing channel was logged, never closed, and starved the ones behind it | all four | The row named `sshd.c:3199`; that line logs and continues. The early `return` was inside `ssh_channel_tick()` in `ssh_channel.c`, on the first channel whose `screen_flush` failed -- leaving it active and skipping every later channel. The consequence the row described was right, the location was not. The per-channel body is now its own function returning OK, channel-failed or transport-failed, and the loop closes the failing channel and continues; a forwarded connection whose far end went away gets EOF and CHANNEL_CLOSE and leaves the session healthy. Each closure prints its reason on the console, because `ssh_log` writes only to the audit file on the durable volume, which is the same blind spot that hid B-28. Held by `make qemu-sshd-channel-starvation-gate`: a second session's forward carried 40 lines in the 20 s after another session's forward failed, against 0 before the fix. |
| F-03 | Fusion network feature qualification | The IPv6 half: `e1000e` programmed its receive control with an empty multicast table, so every multicast frame was discarded in the NIC and no router advertisement reached the stack -- IPv4 never noticed, because DHCP is broadcast. `make vmware-fusion-network-gate` passes on the LAN with a real lease, a global SLAAC address, ICMPv6, SSH on both families and an SFTP round trip over IPv6. Outbound SSH and SCP from the guest and `direct-tcpip` forwarding through it: `make vmware-fusion-outbound-gate`, against a disposable container on this host's LAN address rather than the operator's Mac account, each with a control that fires -- a key the guest never held refused, a forward to a closed port failing with the guest's own channel-open failure rather than a local refusal, and a one-byte-corrupted download caught by content, because the client reports success on it. One of those controls was inverted by `B-37`, which stopped the client asking for a passphrase that does not exist. And local DNSSEC, which this row called unstageable for a good reason that `B-33` then removed: the guest now answers `selftest` from the committed chain and `forged.selftest` -- same zone, same key, one bit flipped -- so the pair is its own control, and a bridged Fusion guest returns `10.53.0.7` and `dnssec-unverified` respectively. Loss and reordering are not claimed: the LAN is not a controlled link. |
| B-38 | An SFTP session stalls when the file contains the alternate-screen sequence | all four | `ssh_channel_send_data` ran every channel's bytes through the screen framework's filter, which watches for `ESC [ ? 1 0 4 9 h` and then paints rather than forwards. SFTP carries arbitrary binary, so a file containing those eight bytes had its payload eaten mid-transfer and the length-prefixed framing desynchronised; forwards and agent channels had the same exposure. Fixed by gating on what the channel is, held by `make qemu-sftp-binary-passthrough-gate`, red without the fix with its control payload passing in the same run. **The leak this row alleged does not exist:** a 1658-round soak, idled 330 s past the 300 s reclaim and then tallied, counted 3316 accepts against 3317 closes -- nothing outstanding. The missing `net_close` that suggested orphaning was a 1.4 s console window looking at a 300 s timeout. **The ~19 s stall is a separate defect and is `B-43`:** it recurred after this fix, and the soak payload provably cannot contain `ESC[`, so it was never this. |
| F-04 | Fusion snapshot and sustained-load qualification | `make vmware-fusion-snapshot-gate` states the guarantee as three properties and requires each: a snapshot is a point in time (both halves -- data before it survives a revert, data after it does not), a revert lands on a filesystem the guest trusts, and a suspend is not a power cut. Nine checks, taken with the guest powered off, which is a deliberate choice. The sustained-load half: one boot held under continuous 256 KiB SFTP round trips, **1658 rounds and 869 MB, with free memory moving by zero pages** -- early mean 487777 against late mean 487777 across 1658 samples. That is the assertion only a long run can make. The same run reproduced `B-43`, so `make vmware-fusion-load-soak` exits non-zero: it is a reproduction harness and reporting what it reproduced is its job, not a failure of this item. |
| B-46 | A full-size SSH packet would be refused rather than short-written | all four | `SSH_MAX_PACKET_SIZE` is 35000 and the network syscalls refuse anything over `SOCKET_BUFFER_SIZE`, 16384. Three places that chunk a transfer clamped to `SSH_MAX_PACKET_SIZE - 9` -- 34991 -- so a chunk that size came back `net-send-denied` rather than short-written: the transfer fails instead of taking longer. Unreachable today because `SSH_CHANNEL_MAX_PACKET` is 10240, which is what made it a cliff waiting for the day someone raised the channel maximum for a good reason. The three sites now clamp to `SSH_WIRE_MAX_CHUNK`, and that day is guarded twice: `ssh_channel.h` fails the build if the channel maximum no longer fits -- the same `typedef char x[(cond)?1:-1]` guard `xaiboot_fs.c` uses against a future node count -- and `check-ssh-wire-bound.py`, in `docs-check`, fails if the chunk and the kernel's buffer size drift apart. The literal is written in userspace because `compile-check`'s userspace pass has no `-Ikernel/include` and `userspace/include/xaios/` holds only `types.h`; a number copied across that boundary is how these two disagreed, so the check reads both files. Both controls run: setting the chunk back to 34991 fails the check, and raising the channel maximum to 20480 fails the check and the build. |
| B-44 | sshd is the machine's network thread, and nothing said so | all four | Kept deliberately, and the silence fixed. `kmain` disables preemption and calls `timer_disable()` **before** starting sshd, so sshd is not merely the only network process -- it is the only thing on the boot CPU. A timer cadence would need the stack made interrupt-safe (`xaios_reentrant_lock` identifies its holder by CPU id and its own header forbids taking it from interrupt context) *and* preemption restored, which is a change to the machine's execution model; `network_poll_tick_locked` also begins with `operations_tick()`, which flushes block devices and can call `arch_power_off()`. A dedicated thread costs one of three workers permanently, because the scheduler runs one thread to completion per worker CPU. What could not be defended was that the coupling was invisible. The stack now measures the gap between consecutive polls whenever a listener is registered -- never otherwise, since a metric that fires on an idle machine is one nobody reads -- and prints past one second. Measured: **55-93 ms idle, 164-297 ms under load, zero gaps past a second**, which is consistent with B-43 not reproducing in 1281 connections. Documented in `wiki/Architecture.md`, `kernel/README.md` and `docs/NETWORK-SSH-STATUS.md` with the costed alternatives. |
| B-47 | A full socket map accepted the connection and dropped it silently | all four | **The row said this was unreachable because the map is sized to the flow table. That was wrong.** A row is keyed by *descriptor*, not flow, and `release_tcp_flow` never clears one where `release_udp_flow` does -- so a TCP row outlives its flow, and occupancy is open mapped descriptors, bounded by the kernel socket table's 256 minimum against the map's 160 rows. A process holding descriptors whose flows have died fills the map with an empty flow table; sizing was never the protection. `net_accept` and `net_connect` now refuse rather than returning a descriptor with no flow, UDP recv and sendto log because the datagram is already delivered, and exhaustion prints once then every 64th so a retry loop cannot flood the console. `make qemu-socket-flow-map-gate` fills all 160 rows through the kernel's own self-test -- it cannot be filled from outside -- takes the refusal, and **checks that re-mapping an existing descriptor still succeeds on a full table**, which is the failure a naive refusal would introduce. Red with the defect restored: the guest halts before the login prompt. |
| B-45 | Every 32-byte audit append rewrote the whole log file | all four | `xaiboot_fs_write_fd_locked` read an entire file and wrote it back for each append, so `ssh_log` cost **7.05 whole-file read-modify-writes per connection**, and `load_authorized_keys` re-read the key file on every publickey attempt. Both sit inside sshd's loop, which by `B-44` is the machine's network thread. Fixed: FNV-1a is a resumable fold, so a node's recorded hash is a position in its own hash and an append needs one tail-sector read, one write per touched block, an incremental hash and the metadata commit -- the file is never read and never restaged. Anything the fast path cannot do falls back to the unchanged whole-file path, so the set of writes that succeed is identical. Measured over 40 connections: rewrites 7.05 to **0**, file blocks 47.8 to 0, key-file reads 2.0 to 0. Crash consistency is preserved rather than traded: exactly one block holding committed bytes is touched and only above `size`, so either version hashes to the committed hash. The boot self-test proves 200 appends took the fast path with zero file reads, a mid-file write falls back, a write past `write_limit()` is refused, and a volume filled to its last block refuses an append and leaves the file unchanged. |
| B-30 | `operations-closure` blamed the wrong boot for a missing unclean record | all four | The gate killed boot 1 once it reached SSH and required boot 2 to notice. When it failed with `unclean_boots=0 boots=1` this row blamed a durability race, on the reasoning that the failing run took 72.9 s against 241.9 s so the boot must have been killed sooner. Both halves were wrong. The timing is an artefact of `run_step` measuring the whole step, which aborts after 2 of ~9 boots on failure -- the short run is the consequence, not the cause. And the record is durable at the 52% stage, hundreds of lines before sshd starts, so program order rules the race out. The clue was `boots=1` and nobody read it: `g_boots` starts at 1 and rises only from a record found on disk, so boot 2 found *no record at all* and the fault was in boot 1, which had reached SSH without ever writing one. Reproduced deliberately by giving boot 1 a state volume the kernel refuses, which falls back to memory and reaches SSH just as fast. Boot 1 now waits for the guest's own durability verdict -- `durable`, `volatile`, `unwritten` or `absent`, on the console rather than via klog, which release builds suppress -- and `operations_init` takes a `durable_storage` argument so a memory-backed record cannot report itself durable. |
| B-32 | The CI permissions check could not see a job-level override | repository | It matched the workflow's top-level `permissions:` block and stopped at `jobs:`, so a job could grant itself anything and the check still reported the boundary as read-only. It now parses the workflow, computes each job's effective permissions under GitHub's replacement semantics, and requires every elevation above the default to be named in an allowlist inside the check -- a stale entry fails too. It parses only the subset this workflow uses and refuses to vouch for anything it cannot read, rather than passing. |

## What ships, and how far along it is

Three bootable deliveries, and the engineering each one waits on. Status is
what has been demonstrated, not what has been designed: `PARTIAL` means some of
it runs and the rest has not been tried, and is never a way of saying nearly
done.

| # | Deliverable | Status | Where it actually stands |
|---:|---|---|---|
| D1 | USB image, every architecture | `NEEDS HARDWARE` | Off the active work list: what remains is a physical test, not an implementation. The released image is a hybrid ISO 9660 and GPT disk carrying an AArch64 and an x86-64 kernel, with firmware picking its own, so `dd` should produce a bootable stick. Everything except the stick is exercised: `make unified-image-gate` boots the same image as a disk in four environments, and the installed-disk gate boots the partition layout it relies on twice a run. |
| D2 | Network boot for blank machines | `TESTING` | A blank machine boots over the network and installs itself. `make qemu-netboot-gate` runs four stages: firmware asks DHCP for a boot filename and fetches it over TFTP; a medium holding the loader and nothing else boots the same way; that machine installs onto a blank disk; and that disk boots alone to a login prompt with SSH listening. Only the last two are evidence of an install. **Remaining:** the same sequence on physical hardware. |
| D3 | Ready-to-run images per environment | `TESTING` | Five kits from `scripts/build-vm-packages.sh` and `scripts/build-boot-media.sh`: one per hypervisor plus `-usb` and `-netboot` for the two routes onto hardware. One image between the four that carry one, because the unified image already boots all four and copies would be chances to disagree. The netboot kit is the exception -- a pair of binaries with the system inside them. Kits are release assets, not committed. **Remaining:** physical media (D1). |

## Engineering these wait on

| # | Work | Status | Where it actually stands |
|---:|---|---|---|
| E1 | Disk partitioning, formatting and install tooling | `TESTING` | Works end to end: a running XAIOS partitions a blank disk, formats an EFI System Partition, copies its own loader, kernel, initial filesystem and entropy seed across, and the result boots on its own to a login prompt with SSH up. `kernel/fs/fat.c` is a FAT16 writer with long-name support, chosen over FAT32 because Fusion silently boots nothing from FAT32. `make qemu-installed-disk-gate` boots the installed disk, which is the only evidence that counts -- everything before it is the installer describing its own work. **Remaining:** the same run on physical media (D1). |
| E2 | Instruction-cost metric | `TESTING` | Recorded, committed and checked. Under `-icount shift=0` the guest clock counts instructions, and `make qemu-instruction-cost-gate` compares three single-threaded figures against `tests/fixtures/instruction-cost-baseline.json`. The four-thread figure is printed and never pinned, because under `-icount` the virtual clock advances for every vCPU. **Not a performance measurement:** see the [benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md). |
| E3 | NUMA correctness | `TESTING` | The self-test proved node-0 placement and never checked node 1, so an allocator ignoring its node argument would have passed. It now asserts placement inside node 1's range and that every CPU maps to exactly one node through both lookups, held by `make qemu-x86_64-numa-gate` across a two-node and a four-node machine. **Remaining:** physical NUMA hardware. |
| E4 | Multiqueue and RSS networking | `TESTING` | Per-queue driver state, every advertised pair allocated and polled round-robin so a busy pair cannot starve the others, and `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` sent only after the buffers exist. RSS is now negotiated and configured from the device's own config -- supported hash types, table length and key size read rather than assumed -- and steering is measured by `make qemu-rss-steering-gate` on a four-queue tap: sixteen buckets across four pairs spread `[64, 62, 66, 64]`, and a one-bucket control collapses to `[256, 0, 0, 0]` and fails the same assertion. Two defects were found by insisting on real counts: the hash key's byte 13 was zero, which pinned the low bit of every flow's hash so only even buckets were reachable (512 frames landed `[37, 0, 27, 0]` -- enough spread to pass a gate that asked for "more than one queue"), and `max_tx_vq` was sent as an index where the device reads a count, cutting a four-pair device to three with pair 3 set up, polled and unreachable. **Remaining:** the gate needs Linux, root and a multi-queue tap, so it runs on the Intel host only -- macOS offers the feature bits on both transports and has no multi-queue backend for either, and virtio-mmio multiqueue is unexercised anywhere. Hash report is offered but deliberately not negotiated: it grows every frame's header and forces software hashing for a per-packet value nothing here reads. |
| E5 | xaibootFS and xaiFS at scale | `TESTING` | xaibootFS v6 records a file as extents rather than a block list, which lifts both limits at once and makes a node smaller: 1 GiB per volume against v5's 4 MiB, 1024 nodes against 256, and a format limit of a gibibyte per file. The write path still refuses at 256 KiB, because it stages a whole file through a static buffer that was never raised with the format -- refusing is deliberate until it streams. Resident cost is about 850 KiB for 256 times the capacity. Which version a new volume gets follows the disk rather than a flag day. **Remaining:** scale evidence on physical storage. |
| E6 | Cluster data plane | `TESTING` | A sealed frame crosses a real network between two guests. `make qemu-cluster-two-node-gate` and `-three-node-gate` run join, partition, recovery and ownership, each phase on its own TCP connection so each machine has to be ready on its own schedule. `engine/src/cluster.c` had framing, sealing and peer state since it was written and had never opened a socket. **Remaining:** distributed execution, which waits on D-05. |
| E7 | Storage throughput, caching and power-loss evidence | `TESTING` | The block path moved 512 bytes per virtqueue round trip -- `buffer_size` had always been validated and then ignored. Raising it to a mebibyte and reading each byte once rather than twice changed the figures by orders of magnitude, against a baseline rebuilt from the same tree rather than remembered. Power loss is real: `make qemu-power-loss-gate` replays QEMU's `blklogwrites` journal through `tools/xaios_write_log.py`, because no emulator option loses an acknowledged write on its own. **Remaining:** physical storage; emulator figures are not throughput evidence. |

## Delivery order

| Order | Workstream | Status | Current boundary / exit gate |
|---:|---|---|---|
| 1b | Physical Apple/ARM, Intel desktop, and Xeon qualification | `NOT STARTED` | Named hardware must pass firmware, device, durability, security, ISA-state, NUMA, soak, and benchmark contracts. |
| 1c | Disk partitioning, formatting and install tooling | `TESTING` | A tool set that partitions a disk, formats xaibootFS and xaiFS on it, and makes it bootable with XAIOS as the only operating system on the machine. The tooling exists and installs -- see `E1` for what it is. The gates that prove it, `make qemu-installed-disk-gate` and `make qemu-setup-gate`, run AArch64 QEMU and nothing else, so three of the four environments are untested and x86-64 has no install evidence at all despite running the same code. **Exit gate:** a blank disk partitioned, formatted and booted on all four environments and on one physical machine. |
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
| P-07 | SVE/SVE2 backend | `TESTING` | `make qemu-aarch64-sve2-gate` executes the SVE2 canary and preserves per-task Z/P/FFR across scheduling and interrupts. A packed SVE inference kernel exists -- `xaios_packed_gemv_sve`, runtime-length vectors with `svwhilelt` predicating the final partial vector rather than a hand-written tail -- and is verified against the scalar reference before use (`packed=verified against scalar` on `-cpu max,sve=on`). It is selected ahead of NEON because SVE's width is the machine's. **Remaining:** physical Apple silicon; nothing here is performance evidence. |
| P-15 | RISC-V (rv64gc) as a third architecture | `TESTING` | Functional parity on the QEMU `virt` board, in the release image, gated three ways: `qemu-riscv64-gate`, `qemu-riscv64-boot-media-gate` and `qemu-riscv64-matrix-gate` at 1, 2, 4 and 8 harts. Boots from a kernel handed to QEMU and from its own disk through EDK2 via the signed A/B slot, and the unified release ISO carries it. Sv48 and Sv39, ecall syscalls over a full trap frame, PLIC, PCI over ECAM, both virtio transports, xaiFS at `/models`, IPv6, the hosted C99 library and xapt. **Remaining:** hardware. See [[RISC-V|RISC-V]]. |
| P-16 | RISC-V message-signalled interrupts | `TESTING` | Implemented and gated on QEMU; not qualified on hardware. `kernel/arch/riscv64/aia.c` drives APLIC and IMSIC, discovered from the device tree and selected at run time, so `-machine virt,aia=aplic-imsic` works and the default PLIC board is unchanged. The supervisor-level pair is identified by the interrupt cause an IMSIC raises (9, not 11) and by `msi-parent`, because the machine-level devices carry the same compatible strings. Held by `make qemu-riscv64-aia-gate`, which requires markers that can only be printed after something was delivered. **Remaining:** hardware. |
| P-14 | Physical Intel/Xeon evidence | `NOT STARTED` | Physical firmware, ISA, NUMA, storage, network, thermals, and sustained-load gates remain. |

## VMware Fusion ARM64 remaining work

The qualified Fusion boundary is Apple Silicon VMware Fusion 26H1 (26.0.0),
four vCPUs, E1000E, AHCI, DHCP IPv4, and public-key SSH/SFTP. The items below
are intentionally not implied by that passing profile.

| ID | Item | Status | Evidence / remaining gate |
|---|---|---|---|
| F-06 | Fusion release-version coverage | `DEFERRED` | Postponed deliberately; nothing external blocks it. Fusion 26H1 evidence is not a compatibility claim for earlier or later releases, x86_64 guests, or physical Apple hardware. |

### Resolved, kept for reference

| ID | Item | Closed by |
|---|---|---|
| F-01 | Fusion multi-vCPU startup | Fusion starts all four vCPUs; two earlier diagnoses were wrong, and both rested on measurements taken where the code under suspicion never ran. The real defect was ours: a secondary published `online = 1` with its MMU still off, so the boot CPU switched to real atomics while other live CPUs could not execute them. `cpu_online=4` on a passing smoke gate. |
| F-02 | VMXNET3 networking | The driver's doorbell and control registers were hand-placed at one address shared with AHCI. Both now come out of the device-window arena, and the card carries traffic end to end on Fusion 26.0.0 -- zero transmit timeouts where there were 284, and a real LAN lease. `make qemu-vmxnet3-gate` holds it on QEMU's implementation of the same device. The qualified profile stays E1000E by choice: `XAIOS_FUSION_NIC` defaults to it. |
| F-05 | Fusion entropy and production-credential boundary | Fusion 26H1 exposes neither `EFI_RNG_PROTOCOL` nor RNDR, so images use a unique local development seed. The engineering half is done: a development seed used to be indistinguishable from a hardware one in the boot record, and the kernel now says which it has. **The remaining half is not engineering** -- production needs an operator-approved entropy and key-provisioning design, and credentials. |

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
| V-02 | MSI-X delivery for virtio on PCI | `TESTING` | Exercised by attaching QEMU's virtio devices on PCI against a real translation service: every device on the bus receives a distinct vector. Three defects were fixed to get there -- one translation table shared by all devices, identifiers reissued to a device whose predecessor polls and never registers a handler, and an assertion on any BAR above 512 GiB. **Remaining:** physical ARM PCIe. Virtualization.framework has no ITS, so its queues stay polled. |
| V-03 | Globally routable IPv6 | `TESTING` | The NAT attachment advertises only the unique-local prefix `fd4a:25c::/64`. A bridged attachment needs the `com.apple.vm.networking` entitlement, which Apple issues only with a provisioning profile; ad-hoc signing cannot provide it. **The blocker is now known to be only the entitlement:** the guest half was never proven while `e1000e` discarded every multicast frame, and with that fixed a bridged Fusion guest on the same LAN autoconfigures a routable address from a real advertisement (F-03). |
| V-04 | Multi-vCPU qualification | `IN PROGRESS` | Secondaries genuinely run: PSCI starts them with translation off, where exclusives are unsupported, so the atomic each one used to announce itself aborted and every boot reported `online cpus=1/4`. With that window made coherent, boots come up 1/1, 4/4 and 8/8, and ten consecutive eight-vCPU boots produce byte-identical `smptest` signatures. `make vz-gate` requires 4/4 and `make vz-stress-gate` covers sustained load. **Remaining:** this host has eight cores against a 128-256 core target and the platform offers no interrupt-affinity control. |
| V-06 | Graphical console | `TESTING` | Implemented. The platform's GOP reports `PixelBltOnly` with a zero framebuffer base, so firmware leaves nothing to draw into, but the display device is on the PCI bus regardless and `kernel/dev/virtio/virtio_gpu.c` claims it: resource created, framebuffer attached page by page, scanout pointed at it, transfer-and-flush after each draw. `boot_ui` accumulates a dirty bounding box and presents only that region. `make vz-framebuffer-gate` captures the guest's display through ScreenCaptureKit and requires the boot bar; it needs Screen Recording permission, cached per process at launch. |
| C-01 | Shared kernel state under genuine parallelism | `TESTING` | Addressed per subsystem, because the right fix differed per file. The network stack, service records and CPU-AI runtime took reentrant guards on their syscall-reachable entry points -- reentrant because ten of the network stack's exported functions call other exported ones. The resolver shares the network guard rather than holding its own; a separate one was a lock-order inversion, caught before it could bite. `security.c` and `agent_protocol.c` hold no tables, so their counters became atomics. **Remaining:** sustained multi-core evidence on a machine with more cores than this one. |
| C-02 | `network_stack.c` state escapes its module | `TESTING` | The obstacle to finer locking was never the lock: tables handed out their rows. The socket map returned interior pointers across the syscall boundary, where callers dereferenced them after the guard was released -- a live race once secondary CPUs ran -- and now returns a copy. No exported function returns a pointer into module state. Splitting the tables further was left open pending C-03, which then measured it as worthless. |
| C-03 | The socket path scales; the finding that said otherwise was noise | `TESTING` | Socket bind/close costs about 40 us per operation at four threads and the same at eight, three runs per configuration, so throughput rises with cores. Giving the listener registry its own guard made no measurable difference and that split was removed. The 437 us that opened this item was recorded while `vmnet-helper` held a core busy (B-03) -- contention with the host, not serialisation in the stack. **Nothing here is performance evidence:** see the [benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md). |

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
| D-06 Authenticated cluster control | `TESTING` | The QEMU-testable tranche is done. `make qemu-cluster-two-node-gate` runs join, partition, recovery and ownership across two guests; `-three-node-gate` runs three that heartbeat every 500 ms and kills one emulator outright, so the survivors must notice from silence rather than from a `LEAVE`; `-partition-gate` breaks links instead of machines through `tests/scripts/cluster_fault_relay.py`, so one-way and two-way partitions can be arranged while every machine keeps running. Quorum is what could not exist at two nodes: a minority reports `owners=withheld` rather than deciding, because one expert with two owners is work done twice that nobody reconciles. Each gate carries its own control -- a healthy window longer than the detector's deadline that must declare no death, and a skip-kill mode in which every failure-detection check must go red. **Remaining:** execution across nodes, which waits on D-05. |
| D-07 Distributed placement/execution | `IN PROGRESS` | Hosted tests cover deterministic expert ownership, grouped routing, simulated node-loss rerouting, and stable node/expert reduction. End-to-end distributed activation execution depends on D-05 and D-06 and cannot be closed by hosted placement tests alone. |
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
