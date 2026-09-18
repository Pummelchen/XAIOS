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
released through build 8 and is explicitly **not production software**: the syscall
surface is not frozen.

## Layout

- `kernel/` — `arch`, `core`, `dev`, `fs`, `mm`, `net`, `sched`, `storage`,
  `user`, `runtime`, `include`.
- `engine/` — `include`, `src`: the portable inference engine.
- `userspace/` — `libc`, `init`, `apps`, `sshd`, `service-manager`, `worker`, `wt`.
- `scripts/` — the builders: `build-image.sh`, `build-arch-image.sh`,
  `build-riscv64.sh`, `build-boot-media.sh`, `build-vm-packages.sh`,
  `build-release.sh`, `build-libc.sh`, `macos-bootstrap.sh`, plus the
  WebTransport port's `build-wt-upstream.sh` (compile the vendored library for
  every guest architecture), `build-wt-peer.sh` (the host handshake endpoint)
  and `build-wt-app.sh` (`/bin/wtqtest`).
- `tests/` — `repository/`, `scripts/`, `security/`, `libc/`, `engine/`,
  `storage/`, `system/`, `network/`, and more.
- `platform/{qemu,vmware-fusion,virtualization-framework}`, `docs/`, `wiki/`,
  `release/` (the tracked `.iso.zip` plus its notes), `contracts/`, `config/`,
  `third_party/` — which holds the hash-pinned vendored trees, including
  `webtransport-c99/` (upstream's C99 WebTransport library, checked by
  `tests/repository/check-webtransport-vendor.py`; a port adds files *beside*
  it, never inside it).
- `wiki/` is the source of truth for the published GitHub Wiki: a push to `main`
  runs the `publish-wiki` CI job, which copies `wiki/*.md` over
  `XAIOS.wiki.git` and then reads it back with `make wiki-parity-check`. An edit
  made on the published pages is overwritten by the next publish.
- `mk/` — the Makefile's fragments (`image-targets.mk`, `release-targets.mk`,
  `qemu-targets.mk`, `hosted-tests.mk`, `repository-targets.mk`, and the rest),
  included by the root `Makefile`, which is the entry point for all of it.
- `scripts/lib/` — the sourced helpers the image builders are split into
  (`aarch64-*.sh`, `riscv64-*.sh`, `kernel-*.sh`); flattening the `source`
  lines reproduces the original builder byte for byte.

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

The WebTransport port has its own gates, and they are the ones to run after
touching `userspace/wt/`, `third_party/webtransport-c99/` or the RISC-V IOMMU:

```bash
make libc                 # the hosted sysroot wt-upstream-compile builds against
make wt-upstream-compile  # the vendored library, every guest architecture
make wt-host-test         # RFC vectors, trust policy, signature checks (host)
make wt-interop-test      # the port's client and server complete a handshake
make qemu-quic-handshake-gate  # ...and a booted guest does the same
```

A released build needs no compiler: download the per-architecture kit and unzip.

## Identity

**One integer in `BUILD_NUMBER` at the repository root** (currently `8`) is the
single source of the build's identity. `build-image.sh`, `build-arch-image.sh`,
`build-riscv64.sh`, `build-release.sh`, `build-boot-media.sh` and
`build-vm-packages.sh` all read it; the kernel is compiled with
`-DXAIOS_BUILD_NUMBER=$BUILD_NUMBER`, prints it on its first boot line, and
`xaiosctl version` reports the same string. Every released file is named
`xaios_b<n>-<arch>.iso`.

There is deliberately **no MAJOR.MINOR.PATCH** here — the old `0.1.0` was retired.
Do not introduce a semantic version.

## Gates

- CI (`.github/workflows/ci.yml`): `make qemu-libc-gate`, `make compile-check`
  (which also runs `make wt-upstream-compile`), `make hosted-test`,
  `make xapt-test`, `make docs-check`, `make wt-vectors-check`,
  `make wt-host-test`, `make wt-host-sanitize`, `make wt-interop-test`,
  `python3 tests/scripts/qemu-abi-contract.py`.
- **The booted-guest handshake gate is the one macOS CI job**
  (`WebTransport Handshake from a Booted Guest`, `macos-14`). Every other job
  is `ubuntu-latest`; that one boots a guest and needs the host side of QEMU's
  user-mode network, and it is the only check in the workflow that does.
- CI boot gates: `make image-qemu-test` followed by `qemu-netboot-gate.py`,
  `qemu-installed-disk-gate.py`, `qemu-smoke.py`; then `make qemu-update-gate`,
  `make qemu-fault-matrix` and `make qemu-quic-handshake-gate`.
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
- **`make qemu-quic-handshake-gate` rebuilds the boot image with
  `XAIOS_BOOT_TEST_APPS=1 XAIOS_WT_HANDSHAKE_TEST=1`.** The second flag is what
  launches `/bin/wtqtest`, and an image carrying it makes every later boot-test
  gate wait ~20 s for a peer that is not there. Run this gate *after* the other
  boot gates, or rebuild with `make image-qemu-test` before them.
- **`make wt-upstream-compile` needs the hosted sysroot** (`make libc`, which
  `make compile-check` builds as a dependency). The port itself is excluded from
  `compile-check`'s freestanding sweep on purpose: it builds against the vendored
  headers and the hosted libc, so the freestanding flags would only prove it
  cannot be built the way nothing builds it.
- Kit builders: leaving `platform/vmware-fusion/XAIOS.vmx.in` placeholders
  (`@@…@@`) unsubstituted produces a VM Fusion that silently refuses to power on;
  the builder now fails on any leftover `@@`. A checksum fallback attached to a
  pipeline (`shasum | cut || sha256sum`) never fires and ships blank checksums.
- **The initial filesystem's directory is finite.** `scripts/create-initfs.py` and
  `kernel/fs/initramfs.c` each carry the entry ceiling (`MAX_FILES` and
  `INITFS_MAX_FILES`), and the builder prints how full the image is --
  `initfs: 65 of 80 entries used`. The RISC-V image reached 64 of 64, so the next
  file -- the SSH authorized-keys file, which is what turns a machine serving SSH
  into one an operator can administer -- failed the build with `too many initfs
  files`. Raise both numbers together, never one: `qemu-abi-contract` compares
  them and fails when they disagree.
- **The architecture is not asserted as a hard failure.** `make bootstrap` checks a
  macOS host, but `scripts/macos-bootstrap.sh` only *warns* (`host architecture is
  $HOST_ARCH; Apple Silicon arm64 is the primary macOS target`) when the host is not
  arm64.
- **The Fusion kit's chainloader is built in a Docker container.**
  `platform/vmware-fusion/build-vmware-fusion.sh` needs a working `docker` *and*
  a way to pull a public image: on a host whose `~/.docker/config.json` names a
  credential helper that wants the login keychain, a headless session cannot
  unlock it and the build fails with `error getting credentials`. Point
  `DOCKER_CONFIG` at a copy of the config with `credsStore` removed; the image is
  public and needs no credentials. The kit and the chainloader digest are the
  same either way.
- EDK2 prints several `Error:` lines during startup that are not XAIOS's.
- Only `release/xaios_b<n>*.iso.zip` and `release/xaios_b<n>.md` are tracked; kits
  and raw ISOs are gitignored.

## Task tracker

Open work lives in exactly one place: the wiki's **[Project Tracker](https://github.com/Pummelchen/XAIOS/wiki/Project-Tracker)**.
It is a single table under `## Tasks`, and it is the only backlog — no Open/Blocked/
Parked sections, no second list, status is a column rather than a heading.

The rules that govern the table — the columns, the four types, the three statuses, the
S/M/L sizes, ownership, and the ordering that *is* the priority — are defined once in
[`docs/task-table-standard.md`](docs/task-table-standard.md). Read it before adding,
changing or closing a row.

- **An epic is a project, not a row.** Split it until each row is one independently
  closable outcome.
- **IDs are stable and never reused.** Closing deletes the row; the gap is correct.
- **Every row has a next step.** If you cannot name one, split it, block it or park it.
- **History does not live in the table.** What was tried, measured or rejected goes to
  `CHANGELOG.md` and the closing commit; the open row links to the evidence.
- **Update a row the moment its state changes**, and read the table top to bottom
  before starting work — the top Open row is the default next task.

## Releasing

**Read [`RELEASE.md`](RELEASE.md) before cutting a release.** It is this repository's
own release standard — edited here, not deployed from anywhere — and it carries both
the general rules and this repository's own section. Do not improvise a release.

The non-negotiables:

- **Apple Silicon only** — build native `arm64` (M1–M6). Never `--arch x86_64`,
  never `ARCHS=arm64 x86_64`, and never `lipo -create`, which is how a universal
  binary gets made.
- **Assert it** — `lipo -archs <binary>` must report exactly `arm64`. A build that
  silently produced a fat binary is a release defect, not a build option.
- **Every release carries the artifacts.** A tag alone is not a release.
  This repository commits them: `release/xaios_b<n>-<arch>.iso.zip` beside
  `release/xaios_b<n>.md`, whose checksum table `check-release-package`
  cross-checks against the files, and the same files are attached to the
  GitHub Release with a `SHA256SUMS` beside them.
- **Identity is single-sourced and enforced** — never bump one declaration of the
  version or build number on its own; the build or CI must fail on a mismatch.
- **Dry run first**; publish only on an explicit flag.
- **Never fetch a model, dataset or dependency to make a gate pass.** A check that
  cannot run is reported *not checked*, and the release notes must name it.
