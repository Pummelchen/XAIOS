# FAQ

## What is XAIOS, in one paragraph?

A freestanding Unix-like operating system written in C99, with a portable
inference engine built into it rather than installed on top. It boots from UEFI
to a login prompt with durable storage, dual-stack networking and SSH/SFTP on
AArch64, x86_64 and RISC-V under QEMU, and on VMware Fusion and Apple
Virtualization.framework. The target is an SSH-administered distributed CPU
inference server where the kernel and the model runtime are one system. No
transformer executes yet. See [[Home]].

## Is XAIOS a Linux distribution or BSD fork?

No. XAIOS has its own freestanding kernel, userspace ABI, applications, and
filesystems. FreeBSD is its primary reference for portable Unix command and
protocol behavior, not its kernel ABI.

## Can XAIOS run Linux, FreeBSD, or macOS binaries?

No. Programs must be built for the XAIOS ABI and packaged into the image.

## What works today?

The ARM, x86_64 and RISC-V QEMU core-OS paths boot and provide processes, threads,
filesystems, IPv4/IPv6, SSH/SFTP, local and remote shells, administration,
storage lifecycle operations, and diagnostic applications. See [[Home]] and
[[Applications|Applications]].

## What is the shortest path to a booted guest?

On macOS, four commands after the prerequisites:

```sh
git clone --recurse-submodules https://github.com/Pummelchen/XAIOS.git
cd XAIOS
export PATH="$(brew --prefix llvm)/bin:$PATH"
make image
make qemu
```

A good boot ends with a 100% bar, an IPv4 address, `SSH server: up and running
(tcp/22)` and `xaios login:`. Full detail, including the released builds you can
boot without compiling anything, is in [[Getting Started|Getting-Started]].

## `make image` says the Picolibc submodule is missing

```text
error: Picolibc submodule is missing; run git submodule update --init --recursive
```

The hosted C99 library is built from a submodule, and the image build builds
that library. Clone with `--recurse-submodules`, or run the command the error
names.

## `make image` says `required tool not found: llvm-ar`

`scripts/build-libc.sh` resolves `llvm-ar`, `meson`, `ninja` and `python3`
through `PATH` only — unlike the image build and the QEMU launchers, which find
their tools through `brew --prefix`. Put Homebrew LLVM on `PATH`:

```sh
export PATH="$(brew --prefix llvm)/bin:$PATH"
```

## `make bootstrap` fails on Linux

It is a macOS toolchain check and reports `fail: host OS is Linux, expected
macOS/Darwin`. It installs nothing, so skip it and use the Debian package list
in [[Getting Started|Getting-Started]].

## How do I log in?

Provision an Ed25519 public key, boot QEMU, then run:

```sh
ssh -p 7788 -i build/local-ssh/admin admin@127.0.0.1
```

The launcher forwards host port 7788 to guest port 22. See
[[Getting Started|Getting-Started]] for the three commands that provision the
key, and [[Networking and SSH|Networking-and-SSH]] for everything else.

## Is there a default password?

Development images use `admin` / `xaios` for isolated QEMU and Fusion testing.
This is a public development credential. Set `XAIOS_SSH_PASSWORD_AUTH=0` for a
key-only development build. Release images contain no built-in password and
reject password authentication.

## Where does my change go?

`kernel/` for the kernel, with `kernel/arch/<architecture>/` for what cannot be
shared; `userspace/` for init, the shell, `/bin` programs, the C library and
sshd; `engine/` for the inference engine; `boot/` for the UEFI loader;
`platform/<environment>/` for one hypervisor's assets and launchers; `tests/`
for gates; `docs/` for specifications; `wiki/` for these pages. If the build
calls it, it is a script; if you call it, it is a tool. The full table and the
rule that outranks the others — kernel, boot and userspace code may never
behave differently because of which hypervisor it is on — are in
[CONTRIBUTING](https://github.com/Pummelchen/XAIOS/blob/main/CONTRIBUTING.md).

## What does "qualified" mean on these pages?

It is a narrower word here than it usually is. A *qualification profile* has an
entry in `contracts/firmware-platform-profiles-v1.json`, a runner of its own,
and a recorded firmware hash and device inventory; a result belongs to that one
profile and to no other, so no ARM result stands in for Intel evidence. Every
result currently published is emulator or hypervisor evidence: it proves boot,
protocol, ABI and deterministic behaviour, and it proves nothing about physical
hardware performance, firmware behaviour or production security. See
[[Firmware Profiles|Firmware-Profiles]] and
[[Hardware Support|Hardware-Support]].

## Is XAIOS production ready?

No. The declared QEMU core-OS correctness gate passes, but physical hardware,
independent security review, production key management, and real-model parity
remain open. See [[Current Limitations|Current-Limitations]].

## Does XAIOS run Qwen or Kimi models?

Not yet. Model-v2, architecture adapters, backend interfaces, and scalar packed
kernels are foundations. No official checkpoint has completed tokenizer,
logits, deterministic decode, and physical-hardware acceptance. `xaiosctl
status` reports `model=fixture-only` on a running machine, which is the
accurate answer rather than a transitional one.

## Why use QEMU?

QEMU provides reproducible boot, ABI, fault, protocol, CPU-count, and device
correctness tests on ARM, x86_64 and RISC-V. It cannot establish physical performance.

## Can I run the x86_64 build on an Apple Silicon Mac?

Not under Apple Virtualization.framework. It does not emulate a guest CPU
architecture: the guest executes on the host's own cores, so on Apple Silicon
the guest is AArch64 and an x86_64 kernel cannot boot, in any macOS release.

Rosetta in that framework does not change this. It translates x86_64 **Linux
userspace** binaries inside an **AArch64 Linux** guest and needs `binfmt_misc`,
a virtiofs share and the Linux syscall ABI; it does not run a foreign kernel.
Use QEMU x86_64 on the Mac, or an Intel host.

## Where is project progress tracked?

Only in [[Project Tracker|Project-Tracker]]. GitHub issues may hold discussion,
but they are not a second status authority.
