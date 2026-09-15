# XAIOS

<!-- agent-harnesses:begin -->
> **One instruction file.** This is it. Codex, DeepSeek Harness, OpenCode,
> Qwen Code, Qoder and Zed read `AGENTS.md` directly, and Claude Code reads it
> through the committed `CLAUDE.md`, which contains nothing but `@AGENTS.md`.
> **Edit only this file** — do not add a second set of instructions anywhere.
>
> Do **not** add `.rules`, `.cursorrules`, `.windsurfrules`, `.clinerules`,
> `.github/copilot-instructions.md` or `AGENT.md`. Zed takes the *first match*
> from that list, **ahead of `AGENTS.md`**, so any one of them silently
> replaces this file for every Zed user.
<!-- agent-harnesses:end -->

An experimental freestanding Unix-like operating system in C99 with a built-in
portable inference engine, for people who want to read, boot or extend a small OS.
It boots from UEFI to a login prompt with durable storage, dual-stack networking
and an OpenSSH-compatible SSH/SFTP server on three guest architectures — AArch64,
x86-64 and RISC-V (rv64gc) — under QEMU, plus VMware Fusion and Apple
Virtualization.framework on AArch64. Real-model inference is not implemented. It is
released through build 6 and is explicitly **not production software**: the syscall
surface is not frozen.

## Layout

- `kernel/` — `arch`, `core`, `dev`, `fs`, `mm`, `net`, `sched`, `storage`,
  `user`, `runtime`, `include`.
- `engine/` — `include`, `src`: the portable inference engine.
- `userspace/` — `libc`, `init`, `apps`, `sshd`, `service-manager`, `worker`, `wt`.
- `scripts/` — the builders: `build-image.sh`, `build-arch-image.sh`,
  `build-riscv64.sh`, `build-boot-media.sh`, `build-vm-packages.sh`,
  `build-release.sh`, `build-libc.sh`, `macos-bootstrap.sh`.
- `tests/` — `repository/`, `scripts/`, `security/`, `libc/`, `engine/`,
  `storage/`, `system/`, `network/`, and more.
- `platform/{qemu,vmware-fusion,virtualization-framework}`, `docs/`, `wiki/`,
  `release/` (the tracked `.iso.zip` plus its notes), `contracts/`, `config/`,
  `third_party/`.
- The 77 KB `Makefile` is the entry point for all of it.

## Build

From a clean macOS host:

```bash
brew install llvm lld qemu mtools python3 meson ninja xorriso
git clone --recurse-submodules https://github.com/Pummelchen/XAIOS.git
export PATH="$(brew --prefix llvm)/bin:$PATH"
make bootstrap      # verifies the toolchain; installs nothing
make image          # -> build/xaios-aarch64.img
```

Other architectures: `XAIOS_TARGET_ARCH=x86_64 ./scripts/build-image.sh` (or
`make image-x86_64`) and `./scripts/build-riscv64.sh` (or `make riscv64`).

## Test and run

```bash
make hosted-test        # engine CLI plus host unit tests
make compile-check      # every freestanding source under clang --target=aarch64-none-elf
make docs-check         # the no-build repository checks
make xapt-test          # python3 -m unittest tests/xapt/test_xapt_repo.py
make test               # aggregate: bootstrap image qemu-dry-run

make qemu               # AArch64; also qemu-x86_64, qemu-riscv64
```

A released build needs no compiler: download the per-architecture kit and unzip.

## Identity

**One integer in `BUILD_NUMBER` at the repository root** (currently `6`) is the
single source of the build's identity. `build-image.sh`, `build-arch-image.sh`,
`build-riscv64.sh`, `build-release.sh`, `build-boot-media.sh` and
`build-vm-packages.sh` all read it; the kernel is compiled with
`-DXAIOS_BUILD_NUMBER=$BUILD_NUMBER`, prints it on its first boot line, and
`xaiosctl version` reports the same string. Every released file is named
`xaios_b<n>-<arch>.iso`.

There is deliberately **no MAJOR.MINOR.PATCH** here — the old `0.1.0` was retired.
Do not introduce a semantic version.

## Gates

- CI (`.github/workflows/ci.yml`): `make qemu-libc-gate`, `make compile-check`,
  `make hosted-test`, `make xapt-test`, `make docs-check`, `make wt-vectors-check`,
  `make wt-host-test`, `make wt-host-sanitize`,
  `python3 tests/scripts/qemu-abi-contract.py`.
- CI boot gates: `make image-qemu-test` followed by `qemu-netboot-gate.py`,
  `qemu-installed-disk-gate.py`, `qemu-smoke.py`; then `make qemu-update-gate` and
  `make qemu-fault-matrix`.
- The local order, cheapest first (`docs/BUILD-PROCESS.md`): `make docs-check`,
  `make compile-check`, `make hosted-test`, `make release-image-gate`,
  `make boot-media-gate`, `make vm-package-gate`, `make local-gates`,
  `make release-check`.

## Traps

- **The Picolibc submodule is mandatory.** Without `--recurse-submodules`,
  `make image` stops with `error: Picolibc submodule is missing; run git submodule
  update --init --recursive` (`scripts/build-libc.sh`).
- **Homebrew LLVM must precede Apple's `clang` on `PATH`** — the libc build
  resolves `llvm-ar` there and nowhere else. The documented `PATH` also needs
  `/usr/sbin` for `lsof`, which several network gates use.
- **Bump `BUILD_NUMBER` and the matching `## Build <n>` in `CHANGELOG.md`
  together**, or `make docs-check` fails. Never renumber a published build.
- **`release-check` is a local-only gate** — no CI job runs it
  (`check-local-gate-record.py`, `check-release-package.py`, `check-ci-status.py`).
  `local-gates` must be recorded against HEAD exactly, on a clean tree: any later
  commit, a README typo included, costs another full run.
- Do not run two things that write `build/` at the same time
  (`docs/BUILD-PROCESS.md`, "Two builders at once").
- Kit builders: leaving `platform/vmware-fusion/XAIOS.vmx.in` placeholders
  (`@@…@@`) unsubstituted produces a VM Fusion that silently refuses to power on;
  the builder now fails on any leftover `@@`. A checksum fallback attached to a
  pipeline (`shasum | cut || sha256sum`) never fires and ships blank checksums.
- **The architecture is not asserted as a hard failure.** `make bootstrap` checks a
  macOS host, but `scripts/macos-bootstrap.sh` only *warns* (`host architecture is
  $HOST_ARCH; Apple Silicon arm64 is the primary macOS target`) when the host is not
  arm64.
- EDK2 prints several `Error:` lines during startup that are not XAIOS's.
- Only `release/xaios_b<n>*.iso.zip` and `release/xaios_b<n>.md` are tracked; kits
  and raw ISOs are gitignored.

<!-- release-rules:begin -->
## Releasing

**Read [`RELEASE.md`](RELEASE.md) before cutting a release.** It carries the
generic rules every Pummelchen repository follows, plus this repository's own
section. Do not improvise a release.

The non-negotiables:

- **Apple Silicon only** — build native `arm64` (M1–M6). Never `--arch x86_64`,
  never `ARCHS=arm64 x86_64`, and never `lipo -create`, which is how a universal
  binary gets made.
- **Assert it** — `lipo -archs <binary>` must report exactly `arm64`. A build that
  silently produced a fat binary is a release defect, not a build option.
- **Every release carries the artifacts.** A tag alone is not a release.
- **Identity is single-sourced and enforced** — never bump one declaration of the
  version or build number on its own; the build or CI must fail on a mismatch.
- **Dry run first**; publish only on an explicit flag.
- **Never fetch a model, dataset or dependency to make a gate pass.** A check that
  cannot run is reported *not checked*, and the release notes must name it.
<!-- release-rules:end -->
