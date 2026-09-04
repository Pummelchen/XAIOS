# Unix Compatibility

XAIOS is a freestanding Unix-like operating system with its own syscall and
userspace ABI. FreeBSD is the primary external behavioral reference for
portable command, SSH/SFTP and network work.

This does **not** mean that XAIOS is FreeBSD-derived or FreeBSD binary
compatible. XAIOS also does not implement a Linux binary ABI. Passing a client
gate establishes only the tested command or wire behavior.

## Current Evidence

| Client | Current QEMU evidence |
|---|---|
| FreeBSD 15.1 AArch64 | Official checksum-pinned VM; OpenSSH public-key acceptance and rejection, `xaiosctl`, SFTP write/stat/read/rename/remove, interactive PTY ANSI `xtop`, and UDP echo. |
| macOS | Native OpenSSH/SFTP administration and one-guest parallel load coverage. |
| Debian 13 | Independent Linux/OpenSSH cross-client coverage for password policy, stateful shell prompts, interactive `nano`, recursive filesystem operations, command errors, rekey, administration, persistence, concurrency, interactive PTY `xtop` and malformed network traffic. |

The core command subset now includes `ls`, `cd`, `pwd`, `mkdir`, `rm`, `cp`,
`mv`, `cat`, alternate-screen `less`, `grep`, `find`, `ps`, `df`, `du`, `tar`,
`zip`, `unzip`, outbound `ssh`, and recursive `scp`. POSIX ustar/PAX, GNU
long-name tar, gzip-wrapped tar, stored/Deflate ZIP and Unix/Windows ZIP origin
metadata are validated within xaibootFS limits. XAIOS-created archives pass
macOS and Debian readers. Recursive SFTP-backed `scp` passes in both directions
against Debian OpenSSH.

This is a documented portable subset, not a complete FreeBSD base system. See
the repository document below for exact options, limits, unsupported archive
features, and outbound SSH authentication constraints.

Run the FreeBSD reference gate with:

```sh
make qemu-freebsd-network-suite
make qemu-freebsd-bidirectional-suite
```

The first run downloads the official compressed FreeBSD image into
`~/.cache/xaios/freebsd`. Both the compressed archive and decompressed image
are SHA-256 checked. Tests use a disposable overlay; the cached vendor image is
not modified.

The bidirectional gate additionally places the real FreeBSD VM inside a
Dockerized QEMU harness, starts base-system `sshd`, and validates XAIOS's
password-authenticated outbound SSH and recursive SFTP-backed SCP client in
both transfer directions. Docker supplies process isolation and repeatable
QEMU dependencies; it does not substitute a Linux kernel for FreeBSD. See the
[[network interoperability summary|Networking-and-SSH]] for the complete local
and Intel VPS contract.

See the authoritative repository document:
[Unix compatibility boundary](https://github.com/Pummelchen/XAIOS/blob/main/docs/UNIX-COMPATIBILITY.md).
