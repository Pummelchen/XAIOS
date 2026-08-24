# FAQ

## Is XAIOS a Linux distribution or BSD fork?

No. XAIOS has its own freestanding kernel, userspace ABI, applications, and
filesystems. FreeBSD is its primary reference for portable Unix command and
protocol behavior, not its kernel ABI.

## Can XAIOS run Linux, FreeBSD, or macOS binaries?

No. Programs must be built for the XAIOS ABI and packaged into the image.

## What works today?

The ARM and x86_64 QEMU core-OS paths boot and provide processes, threads,
filesystems, IPv4/IPv6, SSH/SFTP, local and remote shells, administration,
storage lifecycle operations, and diagnostic applications. See [[Home]] and
[[Applications|Applications]].

## How do I log in?

Provision an Ed25519 public key, boot QEMU, then run:

```sh
ssh -p 7788 -i build/local-ssh/admin admin@127.0.0.1
```

See [[Getting Started|Getting-Started]] and
[[Networking and SSH|Networking-and-SSH]].

## Is there a default password?

Development images use `admin` / `xaios` for isolated QEMU and Fusion testing.
This is a public development credential. Set `XAIOS_SSH_PASSWORD_AUTH=0` for a
key-only development build. Release images contain no built-in password and
reject password authentication.

## Is XAIOS production ready?

No. The declared QEMU core-OS correctness gate passes, but physical hardware,
independent security review, production key management, and real-model parity
remain open. See [[Current Limitations|Current-Limitations]].

## Does XAIOS run Qwen or Kimi models?

Not yet. Model-v2, architecture adapters, backend interfaces, and scalar packed
kernels are foundations. No official checkpoint has completed tokenizer,
logits, deterministic decode, and physical-hardware acceptance.

## Why use QEMU?

QEMU provides reproducible boot, ABI, fault, protocol, CPU-count, and device
correctness tests on ARM and x86_64. It cannot establish physical performance.

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
