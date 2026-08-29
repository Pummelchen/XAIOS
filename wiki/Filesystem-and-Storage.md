# Filesystem and Storage

XAIOS separates immutable boot content, bounded writable system state, and
large immutable model packages. These domains have different formats and
security rules.

## Mounted filesystems

| Surface | Purpose | Current boundary |
|---|---|---|
| Initramfs | `/init`, `/bin`, configuration, and service descriptors | Built into the image and immutable at runtime. |
| xaibootFS v6 | `/`, `/state`, `/config`, `/logs`, `/tmp`, and `/home` state | 1024 nodes, 256 handles, 1 GiB data capacity, 256-byte paths. Writes through the file API are capped at 256 KiB per file by the staging buffer, below the format's own limit. |
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

Persistent images are formatted as xaibootFS v6, which records extents rather
than a fixed block list and raises the volume to a gibibyte. Mounting an older
image performs a checked in-place migration before normal operation. The file
read/write API stages a whole file in one buffer and therefore still refuses
writes past 256 KiB, whatever the volume format allows; a write that would
exceed it is rejected rather than truncated.
The Debian/OpenSSH integration gate verifies exact 256 KiB upload/download,
rejects a one-byte overflow, creates 180 directories, cold-boots the same disk,
and checks content hashes and directory persistence.

Storage administration is documented in [[Administration|Administration]].
Detailed formats and recovery procedures remain in the repository
[`docs/`](https://github.com/Pummelchen/XAIOS/tree/main/docs).

## Throughput

Measured on QEMU/TCG, so the absolute figures belong to an emulator rather than
to a disk. What they compare is real: each pair was rebuilt from the same
commit with one thing changed.

| Path | Figure | Notes |
|---|---|---|
| Block write | ~1.8 GB/s | One request carries up to 1 MiB; it used to carry one 512-byte sector, at 4.1 MB/s. |
| Block read | ~1.7 GB/s | Up to eight requests in flight, direct to the caller's memory. |
| `/models` read, cold | ~150 MB/s | Every byte hashed against the checksum its signed manifest fixed. |
| `/models` read, warm | ~1.8 GB/s | Served from the read cache, which is what makes the difference: a hit skips the hash. |
| `/models` 256 KiB window, cold | ~42 MB/s | A partial read hashes the whole chunk, because that is what the checksum covers. |
| `/models` 256 KiB window, warm | ~640 MB/s | The chunk is resident, so every window after the first costs a copy. |

`make qemu-storage-bench` reproduces these and writes
`build/qemu-storage-bench.json`.

## What lives in RAM

XAIOS runs from memory. Every file in `/bin` — each application, the C library,
every utility — is read off the boot medium once at start-up, checked against
the hash the image recorded for it, and served from RAM afterwards. Nothing
reads an executable off a disk after boot.

That residency is budgeted rather than merely spent. It starts at 64 MiB and
grows in steps to 128 and then 256 MiB when a system genuinely needs more,
saying so each time; past the ceiling it refuses and names the file that asked.
A current image holds about 7.5 MiB across 55 files, so roughly 12% of the
first step. `XAIOS_RESIDENT_BUDGET_MB` and `XAIOS_RESIDENT_CEILING_MB` move the
figures at build time.

## The `/models` read cache

Reads of active model packages are cached in RAM, a chunk at a time. The chunk
is the unit because it is the unit of verification: a chunk's SHA-256 covers
all of it, so nothing smaller can be checked on its own and nothing smaller can
be admitted. A chunk goes in only after it has been read and verified, so a hit
serves bytes that were checked once instead of checking them again — and since
the verified read path is bounded by hashing rather than by the disk, that is
where the time goes.

- **Budget.** 256 MiB by default, set with `XAIOS_MODEL_CACHE_MB` at build
  time; 512 and 1024 are the expected larger settings. Whatever is asked for is
  clamped to a quarter of free memory, so a generous figure on a small guest is
  an intention rather than a failure. Memory is taken as chunks earn it and
  handed back as they lose it, so a volume nobody reads costs nothing.
- **Policy.** Most often, not most recently. Each chunk carries a use count; a
  chunk is admitted on its second read, so a single pass over a package cannot
  evict a working set to hold bytes nothing will ask for again, and the chunk
  read least is the one given up. Counts decay, and decay faster among resident
  chunks while admissions are being refused, so a cache cannot freeze around
  whatever was busy first.
- **Staging packages are never cached.** They are being written and their
  chunks change underneath; the cache refuses them rather than tracking
  mutations it cannot see.
- **A new catalog drops everything.** A commit can move a chunk, so every entry
  is discarded when the volume's generation changes rather than guessing which
  survived.
- **A hit is not re-verified.** That is the whole of the performance gain, and
  the cost is that corruption of the cached copy in RAM would not be caught
  until it was re-read from the volume. Corruption on the volume still is.

`model-cache:` lines in the boot log report hits, misses, hit rate, resident
bytes, admissions, evictions and refusals.
