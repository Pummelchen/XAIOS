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
| FreeBSD 15.1 AArch64 | Official checksum-pinned VM; OpenSSH public-key acceptance and rejection, `xaiosctl`, SFTP write/stat/read/rename/remove, interactive PTY ANSI `htop`, and UDP echo. |
| macOS | Native OpenSSH/SFTP administration and one-guest parallel load coverage. |
| Debian 13 | Independent Linux/OpenSSH cross-client coverage for password policy, rekey, administration, persistence, concurrency, interactive PTY `htop` and malformed network traffic. |

Run the FreeBSD reference gate with:

```sh
make qemu-freebsd-network-suite
```

The first run downloads the official compressed FreeBSD image into
`~/.cache/xaios/freebsd`. Both the compressed archive and decompressed image
are SHA-256 checked. Tests use a disposable overlay; the cached vendor image is
not modified.

See the authoritative repository document:
[Unix compatibility boundary](https://github.com/Pummelchen/XAIOS/blob/main/docs/UNIX-COMPATIBILITY.md).
