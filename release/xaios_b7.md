# XAIOS build 7

Build 7 is the build where the RISC-V port stopped being the one that boots and
started being the one that behaves: it mediates PCI DMA through the board's
IOMMU, preempts user processes at EL0, restarts on `reboot`, keeps its storage
completions straight, lets a second hart be leased, and comes online with its
secondaries before the tests that need one. It is also the build where the
WebTransport C99 port went from vendored to working — a booted guest completes a
QUIC and TLS 1.3 handshake against a host peer, with the certificate pinned.

And it is the build where no source file in the repository is over 500 lines any
more. That last one changes nothing you can observe: it is a size limit met by
moving code into modules beside it, verbatim, with the gates rather than a clean
diff deciding whether the move was safe. It is worth stating in a release note
because it is the largest single change in the build, and because the repository
enforces it now — a new file over the limit fails `make docs-check`, and a file
that was on the list and comes back under must be removed from it.

## Start here: which file do I download?

First decide which machine you are running it on. The architecture is the first
choice, and it is not reversible by downloading a different kit — an AArch64
image will not boot an x86-64 machine.

| To run XAIOS on | AArch64 | x86-64 | RISC-V 64-bit |
|---|---|---|---|
| QEMU | `xaios_b7-aarch64-qemu.zip` | `xaios_b7-x86_64-qemu.zip` | `xaios_b7-riscv64-qemu.zip` |
| VMware Fusion | `xaios_b7-aarch64-vmware-fusion.zip` | — | — |
| Apple Virtualization.framework | `xaios_b7-aarch64-virtualization-framework.zip` | — | — |
| a real machine, from a USB stick | `xaios_b7-aarch64-usb.zip` | `xaios_b7-x86_64-usb.zip` | `xaios_b7-riscv64-usb.zip` |
| a real machine with no disk, over the network | `xaios_b7-aarch64-netboot.zip` | `xaios_b7-x86_64-netboot.zip` | `xaios_b7-riscv64-netboot.zip` |
| your own tooling | `xaios_b7-aarch64.iso.zip` | `xaios_b7-x86_64.iso.zip` | `xaios_b7-riscv64.iso.zip` |

### What the image itself is

One kernel, one initial filesystem, that architecture's UEFI loader, and an
entropy seed. There is no installer: the image boots to a login prompt with
`sshd` listening. The AArch64 image additionally carries the GRUB chainloader
VMware Fusion's firmware needs, and the XAIOS loader behind it as `XAIOS.EFI`.

### Once it boots

Log in as `admin`. The initial filesystem carries the account the image was
built with; nothing on the medium is writable except the volumes XAIOS creates
for itself.

## What changed in this build

**RISC-V became an administered machine rather than a demonstration.**

- **A PCI function's DMA is translated by the board's IOMMU.** A machine booted
  with `-device riscv-iommu-pci` gets a device directory, command and fault
  queues, and a pass-through context per enumerated function installed in the
  same step that leaves `Bare` — which is what keeps a device that refuses all
  DMA out of reset from stopping the boot. Sv39 and Sv48 first-stage tables
  translate a test device's DMA, and clearing a mapping refuses it.
- **An EL0 process is preempted**, and the proof runs on a real interrupt: a
  spinning user process is taken off the CPU by the timer, and the boot carries
  the measurement rather than a claim about it. Two preempted tasks no longer
  share one floating-point state.
- **`reboot` restarts the machine** instead of stopping it, and the machine can
  be administered over SSH again — the image had been serving a prompt it could
  not answer.
- **Storage completions are read correctly.** The NVMe driver was copying the
  wrong number of bytes out of a completion, which RISC-V was the first
  architecture to hit.
- **A core can be leased, and the harts come online before the tests that need
  one.** Previously every self-test between bring-up and the scheduler
  rendezvous saw a uniprocessor, and the AI cell lifecycle skipped itself — an
  absence of tests reading as an absence of a feature.

**The WebTransport C99 port works, with no OpenSSL anywhere.**

- **A booted guest completes a QUIC and TLS 1.3 handshake** against the host
  peer, pinning its certificate, under `make qemu-quic-handshake-gate`.
- **The vendored library's last OpenSSL file is gone.** The trust policy, the
  SubjectPublicKeyInfo reader and the signature dispatch are this repository's
  code now; the port reaches them through an opaque-key bridge because its
  crypto header and this repository's declare the same names for different
  types. `make wt-interop-test` observes a completed handshake with a pinned
  certificate, plus the negative controls: a wrong fingerprint is refused, and
  so is the development bypass asked for off loopback.

**Faults found and fixed by gates, which is where most of this build came from.**

- **A node that stops answering is now noticed**, and three of them can decide
  what is left: the cluster gate kills an emulator outright and requires the
  survivors to agree on the membership that remains rather than reshuffling
  every expert.
- **A machine with no entropy source no longer panics at boot.**
- **A broken link rather than a broken machine**, and a split brain found by
  asking — the tracker rows `B-43`, `B-50` and the preemption work each record
  what the first hypothesis got wrong.
- **An idle machine costs a fifth less.** Waiting for a socket re-derived
  readiness every millisecond; it now re-derives only when something that could
  have made a socket readable has happened.
- **The format allows sixty-four extents** where sixteen was reachable, a
  32-byte append costs 2 KiB instead of 640, and a data sector number no longer
  truncates above 32 MiB.
- **A datagram socket can be opened on a port the kernel chooses**, and a
  datagram that does not fit is refused with a reason rather than silently.

**And the size limit.**

- **No source file is over 500 lines.** 120 tracked files were, including a
  5,157-line network stack, a 2,121-line image builder and a 1,656-line
  `Makefile`; all three build scripts are now sourced helpers or fragments, and
  the two public control headers were split with every macro, typedef and wire
  value intact. The repository's own ratchet enforces it.

## Checksums

| File | Bytes | SHA-256 |
|---|---|---|
| `xaios_b7-aarch64-netboot.zip` | 2,418,416 | `e4ac90081526a3dba436be656d690e291e6e7247305100b858c65694562b0b46` |
| `xaios_b7-aarch64-qemu.zip` | 14,032,459 | `788d56733cfe562df8a4d6dcad7bfaf8bacfbd648ebccf9d7cba113839a7caab` |
| `xaios_b7-aarch64-usb.zip` | 14,033,438 | `677df2502a2c619e73982ad72f9a1c8dc048010f0edbd9f7fce031bf5184faf6` |
| `xaios_b7-aarch64-virtualization-framework.zip` | 14,040,500 | `8ab2be4150f3ec6791d974963b0211edc42a91d47e269f7f0cbb8d1e45e9b9a6` |
| `xaios_b7-aarch64-vmware-fusion.zip` | 14,033,809 | `a810202f76003cac85c213c46fe4e532f06d011a96be94a7bb55b800945da8e4` |
| `xaios_b7-aarch64.iso` | 219,492,352 | `fee7f9dc0521f20c0a4616184e23fff6bf07d3e5c2b347c444f1a1ef5da2aa14` |
| `xaios_b7-aarch64.iso.zip` | 14,029,155 | `5e053eed1bf1b4b3fa372839cd31b5cc0efb7c3763450a8b63525d9d50829d4c` |
| `xaios_b7-riscv64-netboot.zip` | 4,239,525 | `2d0ffa6b4069a70106c2de1e0a4b8d1345633e88bb72aa81abe39254dd1ddc8c` |
| `xaios_b7-riscv64-qemu.zip` | 12,980,675 | `b8e425f5f9e8be56b6f0c9e282f82ef838eb0a124381b28922c25c2055226d27` |
| `xaios_b7-riscv64-usb.zip` | 12,981,033 | `a84417c0f83e765a958ee760acb21138bb40caed17cf72c84e8afb1eb18efcc5` |
| `xaios_b7-riscv64.iso` | 84,226,048 | `2ee1d42ab72b70df9031214d6be6a46d86ecd6df3283678008158b180f38ad48` |
| `xaios_b7-riscv64.iso.zip` | 12,976,728 | `bc287de2d23bd9d49ccfa5fa02a2d1f6e4150b3acbe029eb67caeb6cf95cdcdc` |
| `xaios_b7-x86_64-netboot.zip` | 2,209,943 | `c4677e1ce26c10f2f55252772d2468d401ebd8798fe4cb9751a621c41b841132` |
| `xaios_b7-x86_64-qemu.zip` | 6,771,485 | `04bbc72af9f7eb66e99efbbb9da4ef633cf3cf923fa42563325d085a40916c4c` |
| `xaios_b7-x86_64-usb.zip` | 6,772,597 | `9f7bb3da13cef4466626501220e679878ea83e1ec3bc3e00039e6b014b4b9b0f` |
| `xaios_b7-x86_64.iso` | 77,934,592 | `370905d3e757fc74a408103a23f745a1a95d2066383a0728113938365539a656` |
| `xaios_b7-x86_64.iso.zip` | 6,768,322 | `a972e80e462d053f1283a2e8f4f7134d9de73bc7b44d9eb7120a084a3cf9e56d` |

## Where this was tested

Every result below is from **this build's own files**, booted the way a
recipient would.

| Environment | Image | Booted to a login with SSH listening |
|---|---|---|
| QEMU, `virt`, `gic-version=3`, TCG | `xaios_b7-aarch64.iso` | yes |
| QEMU, `q35`, `cpu max`, TCG | `xaios_b7-x86_64.iso` | yes |
| QEMU, `virt,acpi=off`, `rv64`, EDK2 RISC-V | `xaios_b7-riscv64.iso` | yes |
| VMware Fusion | `xaios_b7-aarch64.iso` | yes |
| Apple Virtualization.framework | `xaios_b7-aarch64.iso` | **not checked** -- the guest console never attached on this host |

`make release-image-gate` boots each released image on every environment that
can run it: four of the five boot the released files to a login prompt with
SSH listening, and each guest reports this build's number.

The Virtualization.framework row is **not checked**, which is a different
sentence from "checked and passing": the harness ran, the guest produced no
console output at all -- not a panic, not an assertion, not rescue mode -- and
every marker failed together, including `virtio console attached`. That is the
harness's console never coming up on this host rather than the build failing,
and it is recorded here rather than counted as a pass.

Two defects were found and fixed while cutting this build, both by gates rather
than by reading:

- **The VMware Fusion chainloader step hung and the build had no bound.** It
  ran `grub-mkstandalone` in a container with a bind mount of the whole tree,
  and that never returned -- eighty minutes at 0.08s of CPU with the release
  stopped behind it and nothing printed. The container is now fed through a
  pipe instead, with the same tool and the same output, and bounded.
- **A Fusion guest panicked during the memory-management transition**, because
  `klog`'s drop counter was read before the kernel was on its own page tables.
  Fusion places the kernel high in RAM and QEMU does not, which is why only one
  of them showed it. Found by bisecting the 333 commits since build 6, then
  resolving the panic against the kernel's symbols.

## Where this was tested

Every result below is from **this build's own files**, booted the way a
recipient would.

| Kit | Booted to a login with SSH listening | Under |
|---|---|---|
| `xaios_b7-aarch64.iso` | yes | QEMU, `virt`, `gic-version=3`, TCG |
| `xaios_b7-x86_64.iso` | yes | QEMU, `q35`, `cpu max`, TCG |
| `xaios_b7-riscv64.iso` | yes | QEMU, `virt,acpi=off`, `rv64`, EDK2 RISC-V |
| `xaios_b7-aarch64.iso` | **no -- kernel panic** | VMware Fusion |
| `xaios_b7-aarch64.iso` | not run | Apple Virtualization.framework |

**VMware Fusion does not boot this build.** The chainloader loads, the kernel
starts and brings up all four CPUs, and then it panics with a controlled page
fault inside `klog`, in the line `vmm_init` prints immediately after enabling
the MMU. The fault is a data abort on a kernel data address, so the guest stops
at the cyan screen with no shell. This is under investigation and is the reason
this build is not published yet: `make release-image-gate` fails on the
Fusion environment and `make local-gates` depends on it.

The Virtualization.framework row was skipped rather than run -- the harness is
not built on this machine (`make vz-harness` builds it) -- and a skipped check
is not a passing one.

## Where this is not tested

- **No physical hardware, on any of the three architectures.** Every result is
  from an emulator or a hypervisor. This establishes correctness on those
  platforms; it establishes nothing about performance, and nothing about any
  real machine.
- **The USB downloads have never been written to a stick and booted on a real
  machine.**
- **`serve-netboot.sh` has never served a real machine**, on any architecture.
- **x86-64 ran only under emulation**, on an ARM host through QEMU's
  interpreter, never on an Intel or AMD processor executing natively.
- **The network stack is polled**, not interrupt-driven.
- **`B-02`**, **`B-14`**, and the open rows in the
  [project tracker](https://github.com/Pummelchen/XAIOS/blob/main/wiki/Project-Tracker.md)
  stand as written.


## Identifying a running build

    XAIOS Build 7 kernel starting

is the first line on the boot console, and `xaiosctl version` reports the same
string.

## What is in each image

One kernel, one initial filesystem, that architecture's UEFI loader, and an
entropy seed.

A kernel built to fault on purpose cannot be in any of them: `make
qemu-fault-matrix` compiles three such kernels into the same path the packaging
scripts read, and both `build-arch-image.sh` and `build-netboot-image.sh` refuse
a kernel that carries the marker such a build writes into itself.
