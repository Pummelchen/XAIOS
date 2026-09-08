# Unix Compatibility

XAIOS is a freestanding Unix-like operating system with its own syscall and
userspace ABI. FreeBSD is the primary external behavioral reference for
portable command, SSH/SFTP and network work.

That is a design and test policy, not a lineage claim. XAIOS is not derived
from FreeBSD, does not implement the FreeBSD kernel ABI, and does not implement
a Linux binary ABI either. Protocol interoperability is deliberately
operating-system independent: a FreeBSD or Linux OpenSSH client passing a gate
proves the tested wire behavior and nothing about binary compatibility with
that client's OS.

## What is and is not implemented

| Surface | Status | Boundary |
|---|---|---|
| XAIOS kernel and userspace | Native freestanding ABI | C99 code uses XAIOS syscalls and services. It depends on neither glibc, Linux syscalls, FreeBSD libc, nor either host kernel. |
| Unix command behavior | Portable subset, QEMU-tested | Local and SSH sessions are stateful: independent working directory, prompt, command errors, recursive trees, interactive `nano`, alternate-screen `less`. Pipes and redirection are bounded shell features. XAIOS is not POSIX-certified and provides no general POSIX process environment. |
| FreeBSD client interoperability | QEMU-tested subset | An official FreeBSD 15.1 AArch64 VM uses base-system OpenSSH/SFTP and `nc` against XAIOS public-key login and rejection, `xaiosctl`, SFTP operations, interactive PTY ANSI `xtop`, and UDP echo. |
| Linux client interoperability | QEMU-tested subset | A disposable Debian 13 container is an independent OpenSSH/SFTP/network client for the broader administration, password, stateful shell, interactive nano, recursive filesystem, rekey, concurrency and malformed-traffic suite. |
| Linux binary ABI | Not implemented | XAIOS runs no Linux ELF programs and implements no Linux syscalls, procfs, namespaces, cgroups or distribution package semantics. |
| FreeBSD binary ABI | Not implemented | XAIOS runs no FreeBSD ELF programs and implements no FreeBSD syscalls, jails, rc.d, ports/pkg or kernel interfaces. |
| Hosted inference engine | macOS and Linux hosts | The portable engine builds as a native process on macOS and Linux. That host support does not define the XAIOS guest ABI. |

## Current evidence

| Client | Current QEMU evidence |
|---|---|
| FreeBSD 15.1 AArch64 | Official checksum-pinned VM; OpenSSH public-key acceptance and rejection, `xaiosctl`, SFTP write/stat/read/rename/remove, interactive PTY ANSI `xtop`, and UDP echo. |
| macOS | Native OpenSSH/SFTP administration and one-guest parallel load coverage. |
| Debian 13 | Independent Linux/OpenSSH cross-client coverage for password policy, stateful shell prompts, interactive `nano`, recursive filesystem operations, command errors, rekey, administration, persistence, concurrency, interactive PTY `xtop` and malformed network traffic. |

The command subset covers `ls`, `cd`, `pwd`, `mkdir`, `rm`, `cp`, `mv`, `cat`,
alternate-screen `less`, `grep`, `find`, `ps`, `df`, `du`, `tar`, `cpio`,
`zip`, `unzip`, outbound `ssh`, and recursive `scp`. The exact options each one
accepts are on [[Applications|Applications]]; the session commands the kernel
itself owns are on [[Commands|Commands]]. Those two pages are the command
surface, and this page does not restate them.

What matters here is the shape of the subset rather than its contents. An
option that is not implemented fails explicitly; nothing is silently accepted
and ignored, because a flag that appears to work and does nothing is worse than
one that is refused. `--` ends option parsing where a Unix reader expects it.
`grep` implements basic regular expressions — `.`, `*`, `^`, `$` and escapes —
not extended or Perl syntax, and `find` matches `*` and `?` in a filename
rather than a full glob language. Outbound `ssh` supports one
password-authenticated `-J` hop; multi-hop `-J`, `-J` with agent
authentication, `ProxyCommand`, and the complete OpenSSH algorithm matrix are
not implemented.

## Archives, and the limits underneath them

POSIX ustar and PAX paths, GNU long-name records, validated single-member
gzip/DEFLATE, and stored or Deflate ZIP entries from Unix, Windows and macOS
tools are all read. Creation is ustar, `newc` cpio, and stored ZIP with CRC32
and Unix attributes. Multi-member gzip, gzip creation, encryption, ZIP64,
symlinks and device nodes are rejected rather than partially handled.
Extraction also rejects absolute paths, `..`, Windows drive prefixes,
backslashes, checksum failures, integer overflow and unsupported entry types.

The container limits people meet in practice are XAIOS storage limits, not
archive-format limits, and it is worth keeping the two apart when a transfer
fails. xaibootFS bounds paths to 256 bytes and open handles to 256, and the
file API caps a write at 256 KiB — below what the on-disk format itself allows
— so an archive has to fit in a 256 KiB file whatever `tar` would otherwise
accept. [[Filesystem and Storage|Filesystem-and-Storage]] carries the current
figures.

Interoperability evidence includes exact-content round trips for XAIOS-created
ustar and ZIP through macOS and Debian 13 readers, macOS PAX tar and Debian
GNU long-name tar into XAIOS, Windows-origin ZIP metadata with Deflate data
into XAIOS, and recursive XAIOS-to-Debian and Debian-to-XAIOS `scp` over
OpenSSH SFTP. The Windows case validates the standard container contract only;
no physical Windows OpenSSH client was available for that gate.

## The FreeBSD reference gate

```sh
make qemu-freebsd-network-suite
make qemu-freebsd-bidirectional-suite
```

The first target downloads the official FreeBSD 15.1 AArch64
`BASIC-CLOUDINIT-ufs.qcow2.xz` into `~/.cache/xaios/freebsd`, verifies the
pinned SHA-256 of both the compressed archive and the decompressed image before
use, creates a disposable copy-on-write overlay and a `cidata` disk, and boots
that beside one XAIOS guest. Set `XAIOS_FREEBSD_IMAGE` to an already-verified
uncompressed QCOW2 to skip the download.

The seed disables FreeBSD's two first-boot updater services so the run is
deterministic and bounded; it does not modify the cached vendor image. XAIOS
stays on TCG for correctness, while the FreeBSD client defaults to HVF on
macOS and TCG elsewhere. The run leaves `build/qemu-freebsd-client.log`,
`build/qemu-freebsd-xaios.log` and `build/qemu-freebsd-network-suite.json`.

The bidirectional gate puts the same FreeBSD VM inside a Dockerized QEMU
harness, starts base-system `sshd`, and drives XAIOS's own outbound SSH and
recursive SFTP-backed SCP client in both transfer directions. Docker supplies
process isolation and repeatable QEMU dependencies there; it does not
substitute a Linux kernel for FreeBSD. See
[[Networking and SSH|Networking-and-SSH]] for the complete local and Intel VPS
contract.

## The rule for new code

Guest code should use XAIOS interfaces, or a Unix semantic chosen and
documented deliberately. Do not import a Linux-only API because Linux happens
to be a CI host, and do not copy FreeBSD internals because FreeBSD happens to
be the behavioral reference. A future POSIX, FreeBSD or Linux compatibility
layer has to be explicit, separately versioned and separately tested — never
inferred from matching command names or from protocol interoperability that
already works.
