# Four-Endpoint Network Interoperability

This is the QEMU-testable network and SSH release matrix for XAIOS. It uses
four independently identified endpoint environments and records each
direction separately. Passing this matrix establishes bounded protocol
correctness under emulation. It is not a physical-network performance result,
an Internet-exposure approval, or an independent security audit.

## Endpoint contract

| Endpoint | Runtime | Required direction |
|---|---|---|
| macOS | Native Apple OpenSSH/SFTP client on the test Mac | macOS to AArch64 XAIOS, including concurrent load and recovery. |
| Debian 13 | Official `debian:13` Docker image with OpenSSH/SFTP tools | Debian to AArch64 XAIOS full protocol suite; concurrent Debian/macOS load. |
| FreeBSD 15.1 | Official checksum-pinned cloud image, booted with QEMU TCG inside a Debian 13 Docker harness | FreeBSD to XAIOS SSH/SFTP/SCP/UDP and XAIOS to FreeBSD SSH/SCP, including recursive transfers and wrong-password rejection. |
| Intel Debian VPS | Native Debian host running x86_64 XAIOS and amd64 FreeBSD 15.1 as separate QEMU guests | Debian to x86_64 XAIOS full suite plus bidirectional XAIOS/FreeBSD SSH/SCP checks. |

Docker Desktop cannot run a FreeBSD kernel as a normal container because
containers share the Linux VM kernel. `Dockerfile.freebsd-qemu` therefore
provides only the reproducible QEMU process and network relay. The endpoint
under test is a real FreeBSD kernel and base system from the official FreeBSD
cloud image, not a Linux image with FreeBSD-named tools.

## Direction matrix

The aggregate gate requires all of the following:

| Source | Destination | Checks |
|---|---|---|
| macOS | XAIOS AArch64 | Authorized and rejected authentication, SFTP, UDP, connection/channel saturation, reconnect, and post-load recovery. |
| Debian 13 Docker | XAIOS AArch64 | Full SSH/SFTP/control/rekey/persistence/malformed-packet suite and the same parallel-load health contract as macOS. |
| FreeBSD AArch64 | XAIOS AArch64 | Public-key command, PTY shell, unauthorized-key rejection, `xaiosctl`, SFTP, SCP and UDP echo. |
| XAIOS AArch64 | FreeBSD AArch64 | Password-authenticated command, wrong-password rejection, Ed25519 TOFU host-key reuse, file SCP, and recursive upload/download. |
| Debian 13 VPS | XAIOS x86_64 | The complete Debian/OpenSSH suite against the common x86_64 XAIOS image. |
| FreeBSD amd64 | XAIOS x86_64 | The same FreeBSD client contract used on AArch64. |
| XAIOS x86_64 | FreeBSD amd64 | The same outbound SSH and recursive SCP contract used on AArch64. |

SSH and SCP already carry payload bytes in both directions. A separate
XAIOS-to-macOS password-authenticated SSH direction is intentionally not
created: the gate does not enable Remote Login, create a macOS account, or
handle the developer's host password. macOS remains a native client endpoint;
the isolated FreeBSD and Debian servers exercise XAIOS active-open behavior.

## Commands

Run the local FreeBSD bidirectional gate:

```sh
make qemu-freebsd-bidirectional-suite
```

Run the same gate for x86_64 on an Intel host:

```sh
XAIOS_QEMU_NETWORK_ARCH=x86_64 make qemu-freebsd-bidirectional-suite
```

Run and aggregate the complete local and VPS matrix after key-based SSH access
to the VPS is configured:

```sh
XAIOS_INTEL_VPS=root@VPS make qemu-four-endpoint-network-suite
```

The aggregate runner copies the current tracked and untracked non-ignored
source into a content-addressed directory below `/var/xaios` on the VPS. It
does not reset or overwrite the VPS's existing checkout. The runner passes the
validated 40-character local HEAD as build provenance; the streamed working
tree remains labeled `xaios-admin-control-dirty` because it may include
uncommitted files from the requested test run.

After individually validated child reports already exist, assemble them
without repeating the expensive emulated runs:

```sh
python3 tests/scripts/qemu-four-endpoint-network-suite.py \
  --vps root@VPS --reuse-local --reuse-remote
```

## Evidence

The expected machine-readable artifacts are:

- `build/qemu-docker-network-suite.json`
- `build/qemu-parallel-network-load.json`
- `build/qemu-freebsd-bidirectional-aarch64.json`
- `build/four-endpoint-vps/qemu-docker-network-suite-x86_64.json`
- `build/four-endpoint-vps/qemu-freebsd-bidirectional-x86_64.json`
- `build/qemu-four-endpoint-network-suite.json`

FreeBSD serial output is retained in
`build/qemu-freebsd-docker-ARCHITECTURE.log`; the paired XAIOS serial output is
retained in `build/qemu-freebsd-bidirectional-xaios-ARCHITECTURE.log`.

## Current execution status

**Passed on 2026-08-11.** The aggregate
`build/qemu-four-endpoint-network-suite.json` report records `status: pass`
for all required directions. The verified matrix used AArch64 XAIOS with
native macOS, Debian 13 Docker, and FreeBSD 15.1 arm64 clients on the local
Apple Silicon host, plus x86_64 XAIOS with Debian 13 and FreeBSD 15.1 amd64 on
the Intel VPS.

The local parallel-load artifact records four simultaneous SSH connections,
two channels per connection, 40 SFTP cycles, 40 reconnects, 330 UDP round
trips, IPv4 and IPv6 fragment reassembly under load, capacity rejection and
reclamation, and post-load recovery. Both FreeBSD reports record successful
bidirectional SSH and SCP, rejected invalid credentials, SFTP, PTY, UDP, and
recursive transfer checks. These results remain QEMU correctness and
interoperability evidence only.
