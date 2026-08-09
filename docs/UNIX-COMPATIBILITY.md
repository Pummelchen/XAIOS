# Unix Compatibility Boundary

XAIOS is a freestanding Unix-like operating system. FreeBSD is the primary
external behavioral reference for portable command, SSH/SFTP and network
interoperability work. This is a design and test-policy statement, not a claim
that XAIOS is derived from FreeBSD or implements the FreeBSD kernel ABI.

## Compatibility Matrix

| Surface | Status | Boundary |
|---|---|---|
| XAIOS kernel and userspace | Native freestanding ABI | C99 code uses XAIOS syscalls and services. It does not depend on glibc, Linux syscalls, FreeBSD libc or either host kernel. |
| Unix command behavior | Partial, QEMU-tested | The bounded shell and image utilities exercise composable command, pipe and redirection behavior. XAIOS is not POSIX-certified and does not provide a general POSIX process environment. |
| FreeBSD client interoperability | QEMU-tested subset | An official FreeBSD 15.1 AArch64 VM uses base-system OpenSSH/SFTP and `nc` to test XAIOS public-key login/rejection, `xaiosctl`, SFTP operations, interactive PTY ANSI `htop`, and UDP echo. |
| Linux client interoperability | QEMU-tested subset | A disposable Debian 13 container remains an independent OpenSSH/SFTP/network client and exercises the broader administration, password, rekey, concurrency and malformed-traffic suite. |
| Linux binary ABI | Not implemented | XAIOS does not run Linux ELF programs or implement Linux syscalls, procfs, namespaces, cgroups or distribution package semantics. |
| FreeBSD binary ABI | Not implemented | XAIOS does not run FreeBSD ELF programs or implement FreeBSD syscalls, jails, rc.d, ports/pkg or kernel interfaces. |
| Hosted inference engine | macOS/Linux hosts | The portable engine currently builds as a native process on macOS and Linux. That host support does not define the XAIOS guest ABI. |

Protocol interoperability is intentionally operating-system independent. A
FreeBSD or Linux OpenSSH client passing a gate proves the tested wire behavior;
it does not make XAIOS binary-compatible with that client OS.

## FreeBSD Gate

Run:

```sh
make qemu-freebsd-network-suite
```

The gate downloads the official FreeBSD 15.1 AArch64
`BASIC-CLOUDINIT-ufs.qcow2.xz` image into
`~/.cache/xaios/freebsd`, verifies its pinned SHA-256 before use, creates a
disposable copy-on-write overlay and `cidata` disk, and boots it beside one
XAIOS guest. Set `XAIOS_FREEBSD_IMAGE` to a previously verified uncompressed
QCOW2 image to bypass the download.

The seed disables FreeBSD's two first-boot updater services for deterministic,
bounded testing. It does not modify the cached vendor image. XAIOS itself
remains on TCG for correctness; the FreeBSD client defaults to HVF on macOS and
TCG elsewhere. Generated logs and the machine-readable result are:

- `build/qemu-freebsd-client.log`
- `build/qemu-freebsd-xaios.log`
- `build/qemu-freebsd-network-suite.json`

The image and provisioning behavior are grounded in the official
[FreeBSD VM images](https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/aarch64/Latest/)
and [`nuageinit(7)`](https://man.freebsd.org/cgi/man.cgi?query=nuageinit&sektion=7&manpath=FreeBSD+15.1-RELEASE+and+Ports)
contracts.

## Design Rule

New guest code should use XAIOS interfaces or a deliberately documented,
portable Unix semantic. Do not import Linux-only APIs merely because Linux is a
CI host, and do not copy FreeBSD internals merely because FreeBSD is the
behavioral reference. Any future POSIX, FreeBSD or Linux compatibility layer
must be explicit, separately versioned and tested rather than inferred from
command names or protocol interoperability.
