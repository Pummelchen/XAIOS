# Test Suite

All XAIOS test programs, runners, guest fixtures, network clients, Docker test
images, and fuzz inputs are versioned below
[`tests/`](https://github.com/Pummelchen/XAIOS/tree/main/tests). The repository
[`tests/README.md`](https://github.com/Pummelchen/XAIOS/blob/main/tests/README.md)
is the file-level inventory; this page is the operational guide.

## Repository contract

- `tests/scripts/` contains Python and shell gate runners.
- `tests/network/` contains the Debian and FreeBSD interoperability harnesses
  and every file copied into their Docker images.
- `tests/hosted/`, `tests/model_v2/`, `tests/fuzz/`, and `tests/fixtures/`
  contain compiled tests, format tests, fuzzing code, and deterministic inputs.
- `scripts/` contains product build, image-generation, launcher, and SSH bridge
  utilities only.
- `make docs-check` runs `tests/scripts/check-test-layout.py` and rejects a
  misplaced test runner or missing Docker input.

## Acceptance commands

| Area | Command |
|---|---|
| Cross-architecture compile | `make compile-check` |
| Hosted runtime and format tests | `make hosted-test` |
| Hosted sanitizers | `make hosted-sanitizer-test` |
| Documentation/status/layout contracts | `make docs-check` |
| Production source completeness | `make production-source-audit` |
| ABI and initfs contract | `make qemu-abi-contract` |
| AArch64 primary smoke | `make qemu-smoke` |
| x86_64 full-service smoke | `make qemu-x86_64-smoke` |
| Full QEMU-testable core OS | `make qemu-core-os-rc` |
| Debian 13 OpenSSH/SFTP/network | `make qemu-docker-network-suite` |
| FreeBSD 15.1 client interoperability | `make qemu-freebsd-network-suite` |
| Bidirectional FreeBSD SSH/SCP | `make qemu-freebsd-bidirectional-suite` |
| macOS, Debian, FreeBSD, Intel VPS | `XAIOS_INTEL_VPS=root@HOST make qemu-four-endpoint-network-suite` |

See [[Testing and Benchmarking|Testing-and-Benchmarking]] for focused QEMU
gates and the evidence vocabulary.

## Recreate Docker clients elsewhere

The test images contain no hand-installed or unversioned test script. From the
repository root on a new Docker host:

```sh
docker build -f tests/network/Dockerfile.debian13 -t xaios-debian13-network-client:13 .
docker build -f tests/network/Dockerfile.freebsd-qemu -t xaios-freebsd-qemu:15.1 .
```

`Dockerfile.debian13` installs Debian 13 OpenSSH, SFTP, archive, IPv4/IPv6, and
diagnostic dependencies and copies its clients from `tests/network/`.
`Dockerfile.freebsd-qemu` installs the Linux-hosted QEMU harness and copies
`freebsd-qemu-server.sh` from the same directory. FreeBSD itself runs from the
official VM image under QEMU; the gate verifies the pinned SHA-256 identity and
caches it at `~/.cache/xaios/freebsd/`.

Docker layers, downloaded VM images, build artifacts, generated host keys, and
test credentials are disposable. They are deliberately excluded from Git; all
logic needed to recreate them is committed.

## Evidence policy

Hosted tests prove portable component behavior. QEMU gates prove emulated
correctness and ABI behavior. External clients prove the bounded wire protocol
cases named in their reports. None of these are physical performance,
durability, thermal, NUMA, or production-security evidence.

Project progress and failed gates are recorded only in
[[Project Tracker|Project-Tracker]].
