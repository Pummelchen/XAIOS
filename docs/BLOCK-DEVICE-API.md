# Block Device API

Status: synchronous and asynchronous correctness APIs are implemented and
tested with hosted mocks, QEMU VirtIO-blk, and emulated NVMe. This does not
claim physical storage performance or durability.

## Interface

`kernel/include/xaios/block_device.h` defines the backend-neutral interface:

```c
block_device_list(...);
block_device_open(...);
block_device_close(...);
block_device_info(...);
block_read(...);
block_write(...);
block_flush(...);
block_discard(...);
block_write_zeroes(...);
block_async_submit(...);
block_async_poll(...);
block_async_cancel(...);
block_async_complete(...);
```

Devices register an explicit stable identifier such as `/dev/vblk0`, a backend
name, 64-bit geometry, optional-operation capabilities, transfer limits, and
backend callbacks. The registry is bounded to 32 boot-time devices; file and
volume capacity is not coupled to that registry size.

An asynchronous request has an explicit operation, state, byte range,
caller-owned buffer, completion status, token, callback, and backend-private
slot. Submit validates the same geometry and capability rules as synchronous
I/O. Backends may complete immediately, remain pending until polling or an
interrupt, or acknowledge cancellation and drain the hardware completion before
slot reuse. Devices without async operations use the synchronous fallback.

The UEFI-provided initramfs is registered as a read-only `boot-memory` device.
Its self-test verifies reads, async completion, flush reporting and write
rejection. Destructive write/read verification is restricted to the dedicated
writable VirtIO test disk and restores the original sector afterward.

The deterministic VirtIO fixture reserves sector `2999` for the block write
probe and sectors `3000..3185` for persistence and MutableFS diagnostics.
Immutable initramfs payloads start at sector `4096`. The ABI gate enforces this
separation so repeated boot tests cannot overwrite executable data.

## Geometry and ranges

All public offsets and lengths are bytes represented by `uint64_t`.
`capacity_logical_sectors * logical_sector_size` must equal `capacity_bytes`
without overflow. Logical sector size must be a power of two. Physical block
size must be a whole multiple of the logical size.

Read/write ranges must be nonempty, logical-sector aligned, non-wrapping, and
fully inside capacity. The caller owns the transfer buffer. The core splits a
request at `max_transfer_bytes`, so backend scratch memory remains bounded.
Statistics count completed backend operations and bytes, not merely submitted
top-level calls.

## Flush, discard, and write-zeroes

Optional operations are capability gated. If a backend did not advertise an
operation, the API returns `XAIOS_ERR_UNSUPPORTED` before calling it. Read-only
devices also reject all mutations.

Discard additionally enforces the advertised granularity and alignment. Long
ranges are split at `max_discard_bytes`; each submitted range is independently
counted. Write-zeroes is split at its corresponding limit. A backend error is
reported as an error and increments `io_errors`.

Discard means that the contents are no longer needed. It is not a promise that
later reads return zero and is not an inference optimization. Write-zeroes is
the explicit zeroing operation.

## VirtIO backend

The current VirtIO-blk adapter negotiates only features it implements:

- read-only device state;
- reported logical block size and topology;
- flush;
- discard;
- write-zeroes;
- VirtIO 1 transport.

VirtIO requests use 512-byte sectors internally as required by the VirtIO block
protocol. The generic API reports and enforces the configured logical sector
size. The current driver submits one copied 512-byte data request at a time;
larger generic operations are streamed through that bounded buffer. Discard
and write-zeroes use their standard range payload and are never issued unless
negotiated.

QEMU 2026-08-03 evidence: the test device reported 512-byte logical and
physical blocks and advertised flush, discard, and write-zeroes. This proves
emulated feature negotiation and boot compatibility only.

The focused NVMe adapter uses four 16-entry queues, caller-aligned direct
buffers, reusable PRP lists, native single-descriptor SGL where advertised,
and persistent request slots. Its QEMU gate covers cancellation, malformed
completion fields, repeated concurrent queue stress, flush, and host backing
bytes. x86_64 verifies one MSI-X completion after interrupt activation;
AArch64 currently polls because no GICv3 ITS backend exists.

The model-volume drive defaults to conservative file semantics. Set
`XAIOS_QEMU_MODEL_DISCARD=unmap` to launch QEMU with
`discard=unmap,detect-zeroes=unmap`; any other non-default value is rejected.
`make qemu-model-sftp-gate` uses this explicit mode and requires the guest's
discarded-byte counter to increase after free-only trim.

## Tests

`tests/storage/test_block_device.c` verifies:

- reads and writes above 4 GiB on an 8 TiB logical mock device;
- capacity multiplication and range-addition overflow rejection;
- logical-sector alignment;
- transfer splitting;
- flush accounting;
- discard alignment, maximum-range splitting, and accounting;
- write-zeroes splitting;
- unsupported discard/write-zeroes making no backend call or data change;
- read-only mutation rejection;
- explicit discovery/open/close and duplicate-identity rejection.

`virtio_block_self_test()` verifies QEMU discovery and geometry through the
same generic API while retaining the existing read/write/reset checks.
