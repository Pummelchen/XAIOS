# Unix Compatibility Boundary

XAIOS is a freestanding Unix-like operating system. FreeBSD is the primary
external behavioral reference for portable command, SSH/SFTP and network
interoperability work. This is a design and test-policy statement, not a claim
that XAIOS is derived from FreeBSD or implements the FreeBSD kernel ABI.

## Compatibility Matrix

| Surface | Status | Boundary |
|---|---|---|
| XAIOS kernel and userspace | Native freestanding ABI | C99 code uses XAIOS syscalls and services. It does not depend on glibc, Linux syscalls, FreeBSD libc or either host kernel. |
| Unix command behavior | Portable subset, QEMU-tested | Stateful local/SSH shells provide independent cwd, prompts, command errors, the command matrix below, recursive trees, interactive `nano` and alternate-screen `less`. Pipes and redirection remain bounded shell features. XAIOS is not POSIX-certified and does not provide a general POSIX process environment. |
| FreeBSD client interoperability | QEMU-tested subset | An official FreeBSD 15.1 AArch64 VM uses base-system OpenSSH/SFTP and `nc` to test XAIOS public-key login/rejection, `xaiosctl`, SFTP operations, interactive PTY ANSI `htop`, and UDP echo. |
| Linux client interoperability | QEMU-tested subset | A disposable Debian 13 container remains an independent OpenSSH/SFTP/network client and exercises the broader administration, password, stateful shell, interactive nano, recursive filesystem, rekey, concurrency and malformed-traffic suite. |
| Linux binary ABI | Not implemented | XAIOS does not run Linux ELF programs or implement Linux syscalls, procfs, namespaces, cgroups or distribution package semantics. |
| FreeBSD binary ABI | Not implemented | XAIOS does not run FreeBSD ELF programs or implement FreeBSD syscalls, jails, rc.d, ports/pkg or kernel interfaces. |
| Hosted inference engine | macOS/Linux hosts | The portable engine currently builds as a native process on macOS and Linux. That host support does not define the XAIOS guest ABI. |

Protocol interoperability is intentionally operating-system independent. A
FreeBSD or Linux OpenSSH client passing a gate proves the tested wire behavior;
it does not make XAIOS binary-compatible with that client OS.

## Core Command Matrix

The names and options below are the supported contract. Unsupported options
fail explicitly rather than being silently ignored.

| Command | Implemented portable subset |
|---|---|
| `pwd`, `cd` | Print or change the per-session working directory; absolute, relative, `.` and `..` paths are normalized. |
| `ls` | File or directory listing with `-a`, `-l`, combined `-la`/`-al`, and `--`. Aliases `l`, `la`, and `ll` are available. |
| `mkdir` | Multiple operands, `-p`, and `--`; parent creation is bounded by the filesystem path limit. |
| `rm` | Multiple operands, `-f`, `-r`/`-R`, combined flags, and `--`; `/` cannot be removed. `rmdir` removes empty directories. |
| `cp` | Files or recursive directory trees with `-r`/`-R`, multiple sources into a directory, and `--`. Full-file expansion is not used. |
| `mv` | Atomic file or tree rename, existing-directory destination semantics, multiple sources into a directory, and `--`. Moving a tree into itself is rejected. |
| `cat`, `less` | `cat [-n] [--] FILE...`; PTY `less [-N] FILE` uses an alternate screen with line/page/start/end movement, forward search and clean terminal restoration. Non-PTY `less` is bounded stream output. |
| `grep` | Multiple files, basic regular expressions (`.`, `*`, `^`, `$`, escapes), and `-i`, `-n`, `-v`, `-c`, `-F`, `-H`, `-h`. No-match returns failure status. |
| `find` | Recursive path walk with optional `-name` and `*`/`?` filename matching. |
| `ps` | Active-process view by default; `-A`, `-a`, `-ax`, `aux`, and `-l` expose the bounded XAIOS process table. |
| `df`, `du` | `df -h`/`-k`/`-P` over mounted XAIOS filesystems; recursive `du -a`/`-s`/`-h`/`-k`. |
| `tar` | Create/list/extract POSIX ustar (`-cf`, `-tf`, `-xf`, optional `v`, extraction `-C`). Reading also accepts POSIX PAX paths, GNU long-name records and validated single-member gzip/DEFLATE archives (`z` accepted for read operations). Symlinks, devices, multi-member gzip and gzip creation are rejected. |
| `zip`, `unzip` | `zip [-r] ARCHIVE PATH...` writes standards-compliant stored ZIP entries with CRC32 and Unix attributes. `unzip [-l] ARCHIVE [-d DIR]` reads stored or Deflate entries from Unix, Windows or macOS tools. Encryption and ZIP64 are rejected. |
| `ssh`, `scp` | Dedicated PTY outbound `ssh [-A] [-i KEY] [-p PORT] [-J user@host[:port]] user@host [command]` and SFTP-backed `scp [-r] [-A] [-i KEY] [-P PORT] SOURCE DESTINATION`. Password, Ed25519 identity-file and forwarded-agent authentication, encrypted OpenSSH private keys, persistent Ed25519 TOFU checks, IPv4/IPv6 literals and DNS A/AAAA are implemented. `-J` supports one password-authenticated jump host and a separately password- or identity-authenticated target over `direct-tcpip`; multi-hop `-J`, agent authentication with `-J`, `ProxyCommand`, and the complete OpenSSH matrix are not. |

MutableFS v5 bounds this surface to 256 nodes, 256 open handles, 256 KiB per
file, 4 MiB data capacity and 256-byte paths. Archive containers must fit in a
256 KiB file. These are explicit XAIOS storage limits, not tar/ZIP format
limits. Extraction rejects absolute paths, `..`, Windows drive prefixes,
backslashes, checksum failures, integer overflow and unsupported entry types.

Interoperability evidence includes exact-content round trips for XAIOS-created
ustar/ZIP through macOS and Debian 13 readers, macOS PAX tar and Debian GNU
long-name tar into XAIOS, Windows-origin ZIP metadata with Deflate data into
XAIOS, and recursive XAIOS-to-Debian and Debian-to-XAIOS `scp` over OpenSSH
SFTP. The Windows archive test validates the standard container contract; no
physical Windows OpenSSH client was available for this gate.

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
