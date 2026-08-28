# Filesystem and Storage

XAIOS separates immutable boot content, bounded writable system state, and
large immutable model packages. These domains have different formats and
security rules.

## Mounted filesystems

| Surface | Purpose | Current boundary |
|---|---|---|
| Initramfs | `/init`, `/bin`, configuration, and service descriptors | Built into the image and immutable at runtime. |
| xaibootFS v5 | `/`, `/state`, `/config`, `/logs`, `/tmp`, and `/home` state | 256 nodes, 256 handles, 256 KiB per file, 4 MiB data capacity, 256-byte paths. |
| xaiFS | `/models` package catalog and immutable active model extents | Signed registration, resumable staging, verification, activation, scrub, quarantine, cleanup, and free-only trim. |

xaibootFS is intended for configuration, logs, shell files, and compact
archives. It is not a general bulk filesystem and must not hold model weights.

## Everyday file operations

The local and SSH shells support directory navigation, recursive creation,
copy, move, deletion, text inspection, search, usage reporting, and editing:

```sh
mkdir -p /home/admin/project/input
echo example > /home/admin/project/input/data.txt
cp -R /home/admin/project /tmp/project-copy
mv /tmp/project-copy/input/data.txt /tmp/project-copy/input/renamed.txt
find /tmp/project-copy -name '*.txt'
du -h /tmp/project-copy
rm -r /tmp/project-copy
```

`nano` edits files up to its 32 KiB buffer. `less` pages regular files through
the utility's documented bounded buffer. See [[Commands|Commands]] for exact
options.

## Archive exchange

XAIOS creates POSIX ustar and stored ZIP archives. It reads ustar/PAX, GNU long
names, one gzip/DEFLATE member, and stored/Deflate ZIP files produced by common
macOS, FreeBSD, Debian, and Windows tools. Extraction rejects traversal,
absolute paths, Windows drive prefixes, links, devices, encrypted ZIP, ZIP64,
bad checksums, and unsupported required features.

Archive files remain subject to the 256 KiB xaibootFS file limit.

## Persistence and integrity

xaibootFS uses checksum-protected metadata, journal replay, bounded rollback
snapshots, and negotiated block flushes. xaiFS uses signed metadata,
copy-on-write publication, per-extent integrity, and immutable active mappings.
QEMU crash gates cover selected interruption points; they do not prove physical
controller-cache or power-loss behavior.

The current QEMU VirtIO block path is interrupt-driven and supports
eight-request block batching, indirect descriptors, and event-index
notification suppression. The AArch64/x86_64 emulated-NVMe gate negotiates
four I/O queues and exercises four-page PRP 16 KiB write, flush, read, and host
backing-byte verification across repeated async rounds. It also covers SGL,
direct aligned buffers, cancellation, malformed completions, and queue
affinity. Both architectures require interrupt delivery for every negotiated
queue: x86_64 through APIC/MSI-X and AArch64 through GICv3 ITS LPIs.

Persistent images are formatted as xaibootFS v5. Mounting a valid v3 or v4
image performs a checked in-place migration to v5 before normal operation.
The Debian/OpenSSH integration gate verifies exact 256 KiB upload/download,
rejects a one-byte overflow, creates 180 directories, cold-boots the same disk,
and checks content hashes and directory persistence.

Storage administration is documented in [[Administration|Administration]].
Detailed formats and recovery procedures remain in the repository
[`docs/`](https://github.com/Pummelchen/XAIOS/tree/main/docs).
