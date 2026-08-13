# Large-Model Upload

Status: authenticated dynamic registration and resumable guest upload are
implemented and QEMU-tested concurrently with native macOS and Debian 13
OpenSSH clients. A physical 100+ GiB transfer is not claimed.

## Guest workflow

The operator obtains the package identity and Ed25519 signature from the model
compiler. For a new package:

1. Register the bounded signed identity with `xaiosctl model register ...
   --operation-id ID`; ModelFS allocates or reuses aligned staging extents.
2. Upload to `/models/.staging/<64-hex-package-id>` with OpenSSH `sftp`.
3. After interruption, use `reput`; `stat` reports the largest contiguous,
   checksum-complete prefix, so OpenSSH resumes only at a committed chunk
   boundary.
4. Run `xaiosctl model verify PACKAGE_ID` as an administrator.
5. Run `xaiosctl model activate PACKAGE_ID --operation-id ID`.
6. Read the immutable package from `/models/PACKAGE_ID`.

Registration requires the model UUID, signer public key, signature, source
revision, architecture, target layout, logical size and expected package ID.
ModelFS derives bounded 2-16 MiB chunk records and records each digest only after
the corresponding bytes are durably written. Final verification recomputes the
package identity and validates the supplied signature.

Each write must match the predeclared chunk offset and length. ModelFS verifies
its SHA-256 before publishing a new copy-on-write catalog generation. `fsync`
flushes package bytes, the catalog, and the alternate superblock in commit
order. Activation repeats complete package identity, signature and chunk
verification and refuses activation while writable staging handles remain.

The QEMU gate is:

```sh
make qemu-model-sftp-gate
```

It first validates interrupted upload/resume on a signed fixture. It then
registers two new packages, uploads and downloads them concurrently from native
macOS and a Debian 13 Docker container, compares every byte, verifies and
activates both, cleans an incomplete package, proves free-extent reuse, completes
online scrub, and checks dry-run plus real VirtIO discard accounting. This is
protocol, ABI, recovery-ordering and correctness evidence only.

## Host/offline workflow

The hosted `tools/xaios_model_volume.py` path provides equivalent offline image
creation, registration and recovery administration:

1. Produce a signed package manifest and package file.
2. Format or open a dedicated offline ModelFS image.
3. Run `stage`; the tool processes one configured 2-16 MiB chunk at a time.
4. Re-run `stage` after interruption; committed chunks are not rewritten.
5. Run `verify`, then `activate`.
6. Boot XAIOS with that image as `XAIOS_MODEL_VOLUME_IMAGE`.

## SFTP boundary

The SFTP v3 server supports unsigned 64-bit offsets, partial-I/O loops, 64-bit
stat sizes, OpenSSH write attributes, append/resume semantics, close durability,
and `fsync@openssh.com`. Hosted packet tests cover offsets above 4 GiB,
32 KiB writes, malformed ranges, short backend I/O and error-versus-EOF
handling. Writable access is restricted to `/models/.staging`; active packages
and the rest of `/models` reject mutation.

If an online upload is abandoned, an administrator can run `xaiosctl model
cleanup PACKAGE_ID --operation-id ID`. Cleanup accepts staging packages only,
publishes a new catalog generation, coalesces the released extents, and refuses
while ModelFS handles or maintenance operations are active.

## Remaining hardware limits

- QEMU VirtIO block I/O is interrupt-dispatched with an eight-request queue,
  direct-or-bounce DMA, event-index suppression and indirect descriptors. A
  AArch64/x86_64 emulated-NVMe gate negotiates four I/O queues and validates
  repeated four-page PRP/SGL 16 KiB write/flush/read operations, direct aligned
  buffers, cancellation, malformed completion rejection, and backing bytes.
  x86_64 also verifies queue-0 MSI-X delivery. AArch64 uses bounded polling
  pending a GICv3 ITS path. Physical-device durability is not established.
- Registration and cleanup are administrator-controlled and capacity-checked,
  but there is no fleet-wide tenant quota or background expiry policy.
- ModelFS activation and the MutableFS audit append are separately durable.
  If audit persistence fails after ModelFS publication, activation cannot be
  rolled back; the kernel logs this explicit cross-filesystem failure.
- The sparse hosted 128 GiB fixture proves 64-bit addressing and bounded memory,
  not physical capacity, throughput, media flush behavior, or a real 100+ GiB
  network transfer.
