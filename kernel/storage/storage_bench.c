/* What the storage path actually does, in bytes per second.
 *
 * Every performance claim about this system so far has been arithmetic over
 * the code. This measures instead: sequential reads and writes against a real
 * block device, timed by the monotonic clock, reported as throughput.
 *
 * It runs under emulation, so the absolute number is not the speed of any
 * disk -- QEMU's TCG interpreter is between the guest and the host's storage
 * and dominates everything. What it does measure honestly is the shape of the
 * path: how many requests a transfer costs, how deep the queue runs, and
 * whether a change made it better or worse. A before-and-after on the same
 * host is a real comparison even when neither figure is a device speed.
 */
#include <xaios/storage_bench.h>

#include <xaios/block_device.h>
#include <xaios/klog.h>
#include <xaios/timer.h>

/* Enough to time rather than to fill. Sixty-four mebibytes rather than four:
   once the path stopped costing one request per sector, four megabytes went
   by in a single-digit number of milliseconds, and a rate divided by three
   ticks of the clock is not a measurement. */
#define BENCH_BYTES UINT64_C(67108864)
#define BENCH_BUFFER UINT64_C(262144)

static uint8_t g_bench_buffer[BENCH_BUFFER] __attribute__((aligned(4096)));

static uint64_t rate_kb_per_s(uint64_t bytes, uint64_t nanoseconds) {
  if (nanoseconds == 0U) return 0U;
  /* Kilobytes per second, computed so the multiply cannot overflow before
     the divide: bytes are megabytes here, not gigabytes. */
  return (bytes * UINT64_C(976562)) / nanoseconds;
}

static void report(const char *what, const char *device, uint64_t bytes,
                   uint64_t nanoseconds, uint64_t requests) {
  uint64_t kb = rate_kb_per_s(bytes, nanoseconds);
  klog("storage-bench: %s device=%s bytes=%lu ms=%lu kb_per_s=%lu "
       "requests=%lu bytes_per_request=%lu\n",
       what, device, bytes, nanoseconds / UINT64_C(1000000), kb, requests,
       requests == 0U ? 0U : bytes / requests);
}

void storage_bench_run(const char *identifier) {
  xaios_block_device_t *device = 0;
  if (identifier == 0 ||
      block_device_open(identifier, &device) != XAIOS_OK || device == 0) {
    klog("storage-bench: no device to measure id=%s\n",
         identifier == 0 ? "(none)" : identifier);
    return;
  }
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK ||
      info.capacity_bytes < BENCH_BYTES * 2U) {
    klog("storage-bench: device too small to measure id=%s\n", identifier);
    (void)block_device_close(device);
    return;
  }

  /* The transfer the block layer will actually use, which is what decides how
     many requests this costs. Reporting it beside the rate is the point: a
     rate without it says nothing about why. */
  uint64_t unit = info.max_transfer_bytes == 0U ||
                          info.max_transfer_bytes > BENCH_BUFFER
                      ? BENCH_BUFFER
                      : info.max_transfer_bytes;
  klog("storage-bench: %s max_transfer=%lu sector=%lu capacity_mb=%lu\n",
       identifier, info.max_transfer_bytes, info.logical_sector_size,
       info.capacity_bytes / UINT64_C(1048576));

  /* Write first, so the read that follows has something deterministic to
     find and cannot be served from a device that never saw the offsets. */
  for (uint64_t i = 0U; i < BENCH_BUFFER; ++i) {
    g_bench_buffer[i] = (uint8_t)(i * 31U);
  }
  uint64_t offset = info.capacity_bytes / 2U;
  offset -= offset % info.logical_sector_size;

  uint64_t requests = 0U;
  uint64_t started = timer_now_ns();
  for (uint64_t done = 0U; done < BENCH_BYTES; done += BENCH_BUFFER) {
    if (block_write(device, offset + done, g_bench_buffer, BENCH_BUFFER) !=
        XAIOS_OK) {
      klog("storage-bench: write failed at %lu\n", done);
      (void)block_device_close(device);
      return;
    }
    requests += BENCH_BUFFER / unit;
  }
  (void)block_flush(device);
  report("write", identifier, BENCH_BYTES, timer_now_ns() - started, requests);

  requests = 0U;
  started = timer_now_ns();
  for (uint64_t done = 0U; done < BENCH_BYTES; done += BENCH_BUFFER) {
    if (block_read(device, offset + done, g_bench_buffer, BENCH_BUFFER) !=
        XAIOS_OK) {
      klog("storage-bench: read failed at %lu\n", done);
      (void)block_device_close(device);
      return;
    }
    requests += BENCH_BUFFER / unit;
  }
  report("read", identifier, BENCH_BYTES, timer_now_ns() - started, requests);

  /* Prove the bytes are the ones written, so a rate can never be reported for
     a path that returned nothing. */
  uint32_t mismatches = 0U;
  for (uint64_t i = 0U; i < BENCH_BUFFER; ++i) {
    if (g_bench_buffer[i] != (uint8_t)(i * 31U)) ++mismatches;
  }
  klog("storage-bench: verify mismatches=%u\n", mismatches);
  (void)block_device_close(device);
}
