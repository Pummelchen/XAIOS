<img width="1122" height="1402" alt="image" src="https://github.com/user-attachments/assets/d1170b39-84b0-40c3-8f3e-c2de85ae9c94" />


# XAIOS

XAIOS is an experimental freestanding Unix-like operating system written in
C99, with a portable inference engine built into it rather than installed on
top. It boots from UEFI to a login prompt with durable storage, dual-stack
networking and an OpenSSH-compatible SSH/SFTP server on three architectures —
AArch64, x86-64 and RISC-V (rv64gc) — under QEMU, and on two macOS
hypervisors, VMware Fusion and Apple Virtualization.framework. What each of
those environments has actually been shown to do differs, and
[Where it runs](#where-it-runs) says which is which. Real-model inference is
not implemented.

**What it is aiming at.** An SSH-administered distributed CPU inference server
where the operating system and the model runtime are one system rather than an
application on a distribution. The kernel owns hardware, isolation,
persistence, networking and service lifecycle; the engine owns model packages,
architecture adapters, backends and sessions; both are built, versioned and
gated together. There is no Linux or BSD underneath, and no Linux or FreeBSD
binary ABI on top.

**Who it is for.** People who want to read, boot or extend a small operating
system that is complete enough to log into and honest about what it has not
proven. It is source-available for noncommercial use. It is not production
software: see [Model support status](#model-support-status) and
[Boundaries worth knowing](#boundaries-worth-knowing-before-you-read-further)
below, and [Current Limitations](./wiki/Current-Limitations.md) in full.

Everything about *what XAIOS does* lives in the
[XAIOS Wiki](https://github.com/Pummelchen/XAIOS/wiki), mirrored under
[`wiki/`](./wiki/) so every claim can be checked against source. Everything
about *what remains* lives in one place, the
[Project Tracker](./wiki/Project-Tracker.md).

## Run it

Two paths. Neither needs the other.

### Boot a released build — no compiler

Released builds are on the
[releases page](https://github.com/Pummelchen/XAIOS/releases); the current one
is [**build 5**](https://github.com/Pummelchen/XAIOS/releases/tag/b5). You do
not need to compile anything to try XAIOS.

Six downloads, and **five of them contain the same image** — what differs is
what is packaged around it:

| To run XAIOS | Take |
|---|---|
| in QEMU | `xaios_b5-qemu.zip` — image plus a launch script for AArch64 and one for x86-64. There is no RISC-V script in the kit: the image carries the RISC-V kernel, but the only RISC-V machine that has booted anything here is QEMU's `virt` board through `platform/qemu/run-qemu-riscv64.sh` in the repository |
| in VMware Fusion | `xaios_b5-vmware-fusion.zip` — image plus a `.vmx` |
| in Apple Virtualization.framework | `xaios_b5-virtualization-framework.zip` — image plus a harness you build and sign |
| on a real machine, from a USB stick | `xaios_b5-usb.zip` — image plus a writer that names the target disk back before it writes |
| on a real machine with no disk, over the network | `xaios_b5-netboot.zip` — two boot binaries plus a DHCP/TFTP server script |
| with your own tooling | `xaios_b5.iso.zip` — the image, and nothing else |

Unzip before use. The image is one file that is an ISO 9660 filesystem, a
GPT-partitioned disk and a bootable USB image at once, which is why one
download covers CD-ROM, hard disk and stick. On first boot there is no account
and no default password; the machine asks how to set itself up.

Each release note records exactly which hypervisors and firmware that build was
booted on, and what was *not* tested — see the
[build 5 note](./release/xaios_b5.md).

### Build from source and boot it

On macOS, from a clean machine to a booted guest:

```sh
brew install llvm lld qemu mtools python3 meson ninja xorriso
git clone --recurse-submodules https://github.com/Pummelchen/XAIOS.git
cd XAIOS
export PATH="$(brew --prefix llvm)/bin:$PATH"
make bootstrap        # verifies the toolchain; it installs nothing
make image            # -> build/xaios-aarch64.img
make qemu             # boot it, four vCPUs, TCG, Ctrl-A X to exit
```

`--recurse-submodules` is not optional: the hosted C99 library is built from
the Picolibc submodule, and without it `make image` stops with
`error: Picolibc submodule is missing`. On an existing clone, run
`git submodule update --init --recursive`. Homebrew LLVM must be on `PATH`
because the libc build resolves `llvm-ar` there and nowhere else; the rest of
the toolchain is located through `brew --prefix`.

`make bootstrap` checks a macOS host. On Linux, skip it and install the
prerequisites listed in [Getting Started](./wiki/Getting-Started.md).

For the other two architectures, `make image-x86_64 && make qemu-x86_64` and
`make qemu-riscv64`.

### What a good boot looks like

`make qemu` shows the firmware's own startup output first — EDK2 prints several
`Error:` lines about images it cannot start, and none of them are XAIOS — and
then an in-place progress display that ends like this:

```text
XAI OS

[########################################] 100%

Loaded: system services
Loading: complete
Remaining: 0 components

IPv4: 10.0.2.15
IPv6: fe80::5054:ff:fe12:3457
SSH server: up and running (tcp/22)

xaios login:
```

`XAI` is purple and `OS` is cyan. `SSH server: up and running (tcp/22)` is the
line that means the listener is really open, not that it was attempted. The
launcher forwards host port 7788 to guest port 22, so from another terminal:

```sh
ssh -p 7788 admin@127.0.0.1
```

The development image's account is `admin` / `xaios` — a public development
credential for isolated networks only; release images package no password and
reject password authentication. [Getting Started](./wiki/Getting-Started.md)
has the key-based path, which is the one to use.

Once in:

```text
admin@xaios:/$ xaiosctl status
uptime_ns=67288432992
init_service=stopped
service_manager=stopped
ssh=running
network=stopped
storage=ready
model=fixture-only
cluster=unsupported
readiness=degraded
readiness_reasons=58
online_cpus=4
worker_count=0
production_models_loaded=0
queue_depth=unknown
active_requests=unknown
physical_pages=512898
managed_pages=512898
free_pages=505846

admin@xaios:/$ df
Filesystem Size Used Avail Capacity Mounted on
xaibootFS 2048K 29K 2018K 2% /
xaiFS 65536K 10312K 55224K 16% /models
```

`model=fixture-only` is not a placeholder for something better that is running
elsewhere. It is the accurate answer, and the reason for the model table below.

## Where the code lives

The first question a change raises is which directory it belongs in.

| Directory | Why it exists |
|---|---|
| `boot/` | The UEFI loader: firmware entry, kernel ELF validation and the boot handoff. |
| `kernel/` | The kernel. Shared code at the top, with `arch/aarch64/`, `arch/x86_64/` and `arch/riscv64/` for the three things that cannot be shared — exceptions, page tables, timers and CPU startup. |
| `userspace/` | Everything that runs at EL0: `init`, the shell, `/bin` applications, the hosted C99 library and sshd. |
| `engine/` | The portable inference engine — model packages, architecture adapters, backends, sessions. Built with the OS, not on it. |
| `platform/<environment>/` | One directory per hypervisor, holding its assets and launchers and nothing else. Naming a platform is this directory's job and no other's. |
| `tests/` | Gates that boot XAIOS (`tests/scripts/`), checks about the repository itself (`tests/repository/`), fixtures and network harnesses. |
| `contracts/` | Versioned machine-readable contracts, `<name>-v<n>.json` — what a gate is allowed to call passing. |
| `docs/` | Versioned specifications, formats and API references. |
| `wiki/` | The published Wiki: what XAIOS does. Mirrored to GitHub's Wiki on merge; edit it here. |
| `scripts/` | Automation the build system invokes. |
| `tools/` | Standalone utilities a person runs by hand. |
| `config/` | Build cross-files, development credentials, deployment configuration. |
| `release/` | One note per numbered build, recording what it was booted on and what was not tested. |
| `third_party/` | Vendored and submoduled upstream code — Picolibc, BearSSL, compiler-rt builtins. |

`scripts/` and `tools/` are not interchangeable: if the build calls it, it is a
script; if you call it, it is a tool. The rules, and the one rule that outranks
the others, are in [CONTRIBUTING.md](./CONTRIBUTING.md).

## Where it runs

| Hypervisor | Qualification profile | Gate | Evidence class |
|---|---|---|---|
| QEMU ARM64 | macOS QEMU ARM64 | full CI | correctness and ABI only |
| QEMU x86_64 | Intel VPS QEMU x86_64 | full CI | correctness and ABI only |
| QEMU RISC-V64 | none; no firmware profile | a bring-up job in CI (smoke, release configuration, CPU tiers); 57 gate targets local | correctness and ABI only, on one emulated board |
| VMware Fusion | macOS VMware Fusion ARM64 | `make vmware-fusion-smoke`, `make hypervisor-memory-matrix`, `make vmware-fusion-load-soak` | Fusion 26H1 four-vCPU lifecycle |
| Apple Virtualization.framework | none; development target | `make vz-gate`, `make vz-stress-gate`, `make vz-framebuffer-gate` | not qualification evidence |

XAIOS behaves the same on all of them. Firmware supplies capabilities, never
identity and never behaviour, and `make platform-neutrality-check` enforces it.
Where a capability is absent the system degrades the same way everywhere. The
per-environment feature matrix is in the
[Project Tracker](./wiki/Project-Tracker.md); no ARM result stands in for Intel
evidence, and each profile records its own firmware hashes, device inventory
and gates — see
[Firmware Platform Profiles](./docs/FIRMWARE-PLATFORM-PROFILES.md).

No result here is physical-hardware evidence. Emulators prove correctness, not
performance or firmware behaviour.

## Boundaries worth knowing before you read further

**Unix compatibility.** FreeBSD is the behavioural reference for commands,
SSH/SFTP and network interoperability. XAIOS is not FreeBSD-derived and offers
no FreeBSD or Linux binary ABI — guest programs use native syscalls, so passing
host-client tests proves wire behaviour only. See
[Unix compatibility](./wiki/Unix-Compatibility.md).

**Architectures.** AArch64, x86_64 and RISC-V (rv64gc). AArch64 and x86_64 run
on real machines and hypervisors; RISC-V runs the same shared kernel on the
QEMU `virt` board, booting to 100% across four harts with a login prompt, a
working SSH server and the hosted C99 library, either from a kernel handed to
QEMU or from its own disk through UEFI firmware. What it does not have is hardware qualification: no
RISC-V machine or hypervisor is in the test set, so its evidence is one board.
See [RISC-V](./wiki/RISC-V.md).

**C99 libc.** A statically linked hosted ISO C99 library for AArch64, x86_64
and RISC-V, with no public POSIX API and no new syscall identifiers. All three
run the runtime and termination probes; the conformance report covers the first
two, because the contract's architecture gates name those, and
`make qemu-riscv64-libc-gate` is the target that builds the RISC-V image before
running them there. See
[C99 libc](./wiki/C99-Libc.md).

## Model support status

Neither the deterministic model-v1 path nor the model-v2 format foundation
executes a transformer. Nothing here is production supported, and the table
says which is which rather than leaving a reader to infer it.

| Path | Status |
| --- | --- |
| model-v1, the deterministic QEMU decode | **Fixture only** — a fixed transform with a known answer, used to prove the runtime boundary rather than to run a model |
| model-v2 format foundation | Format and loader only; no transformer executes |
| Qwen 3.8 | The next real-model correctness target |
| Kimi K3 text | Later |
| Kimi K3 multimodal, DeepSeek V4 | Later still |

XAIOS is built around official architecture adapters rather than a hard-coded
graph. See [Model support](./wiki/Applications.md).

**Updates.** The native [`xapt` updater](./wiki/Xapt-Package-Updates.md)
installs signed applications without rebooting and stages OS images into the
inactive A/B slot. Its trust root is for development use; production key
custody and rotation remain open gates.

## Where to go next

| If you want to | Read |
|---|---|
| build, boot and log in, in detail | [Getting Started](./wiki/Getting-Started.md) |
| know what the boot screen and login policy do | [Boot and Console](./wiki/Boot-and-Console.md) |
| see the shell surface and the `/bin` programs | [Commands](./wiki/Commands.md), [Applications](./wiki/Applications.md) |
| understand how the pieces fit together | [Architecture](./wiki/Architecture.md) |
| know what is *not* claimed | [Current Limitations](./wiki/Current-Limitations.md) |
| find out which gate proves a given claim | [Testing XAIOS](./wiki/Testing-XAIOS.md) |
| answer a quick question | [FAQ](./wiki/FAQ.md) |
| see what is still open, and who owns it | [Project Tracker](./wiki/Project-Tracker.md) |
| submit a change | [CONTRIBUTING.md](./CONTRIBUTING.md) |

## License

Source-available under the
[PolyForm Noncommercial License 1.0.0](./LICENSE): private, personal,
educational and noncommercial research use, including by universities and
public research organisations. It does not grant commercial use, which requires
a separate written licence obtained beforehand — see
[`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md).
