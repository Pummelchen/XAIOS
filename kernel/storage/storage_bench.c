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
#include <xaios/vfs.h>
#include <xaios/virtio_blk.h>

/* Enough to time rather than to fill. Sixty-four mebibytes rather than four:
   once the path stopped costing one request per sector, four megabytes went
   by in a single-digit number of milliseconds, and a rate divided by three
   ticks of the clock is not a measurement. */
#define BENCH_BYTES UINT64_C(67108864)
#define BENCH_BUFFER UINT64_C(262144)

#if !XAIOS_STORAGE_BENCH

/* Not a benchmark build, so nothing here is compiled but these two stubs.
   The measurement writes to a device and takes time, and neither belongs in
   an ordinary boot -- and neither do its buffers, which used to sit in .bss
   unconditionally. On x86_64 the kernel is linked at a fixed address, so
   every byte of .bss is a byte of low memory it has to win from firmware. */
void storage_bench_run(const char *identifier) { (void)identifier; }
void storage_bench_model(void) {}

#else

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
  /* Whether those requests went straight to the device out of this buffer or
     were copied through the driver's staging sector. A benchmark that does
     not say which is measuring an unknown path. */
  virtio_block_report_transfers();
  (void)block_device_close(device);
}

/* What a model actually reads at, which is not what the block device reads at.
 *
 * Every byte handed out of /models is hashed on the way past: the chunk it
 * came from is verified against the checksum the signed manifest fixed, so a
 * bit that rotted on the disk is a failed read rather than a wrong answer.
 * That is the property worth having and it is not free, and the raw device
 * figure above says nothing about it.
 *
 * Two numbers, because the difference between them is the whole story. A read
 * that covers a whole chunk hashes each byte once. A read of a small window
 * inside a chunk still has to hash the entire chunk, because that is what the
 * checksum covers -- so a 256 KiB window inside a 2 MiB chunk pays eight times
 * over. Anything streaming a model should be reading chunk-aligned, and the
 * gap between these two lines is what it costs not to.
 */
#define BENCH_MODEL_CHUNK UINT64_C(2097152)
#define BENCH_MODEL_ROUNDS 4U

static uint8_t g_model_buffer[BENCH_MODEL_CHUNK] __attribute__((aligned(4096)));

#define MODEL_OWNER UINT32_C(0x4d4f444c)

static void bench_model_window(const char *path, uint64_t size, uint64_t window,
                               const char *label) {
  if (window > sizeof(g_model_buffer)) return;
  int64_t fd = vfs_open(path, XAIOS_VFS_OPEN_READ, MODEL_OWNER);
  if (fd <= 0) {
    klog("storage-bench: model open failed path=%s status=%d\n", path,
         (int)fd);
    return;
  }
  uint64_t delivered = 0U;
  uint64_t requests = 0U;
  uint64_t started = timer_now_ns();
  for (uint32_t round = 0U; round < BENCH_MODEL_ROUNDS; ++round) {
    for (uint64_t at = 0U; at + window <= size; at += window) {
      int64_t count = vfs_pread((uint32_t)fd, MODEL_OWNER, g_model_buffer,
                                window, at);
      if (count != (int64_t)window) {
        klog("storage-bench: model read failed offset=%lu status=%d\n", at,
             (int)count);
        (void)vfs_close((uint32_t)fd, MODEL_OWNER);
        return;
      }
      delivered += (uint64_t)count;
      ++requests;
    }
  }
  uint64_t elapsed = timer_now_ns() - started;
  (void)vfs_close((uint32_t)fd, MODEL_OWNER);
  klog("storage-bench: model-%s bytes=%lu ms=%lu kb_per_s=%lu requests=%lu "
       "window=%lu\n",
       label, delivered, elapsed / UINT64_C(1000000),
       rate_kb_per_s(delivered, elapsed), requests, window);
}

void storage_bench_model(void) {
  char listing[256];
  uint64_t listing_size = 0U;
  if (vfs_list("/models", listing, sizeof(listing), &listing_size) !=
          XAIOS_OK ||
      listing_size < 74U) {
    klog("storage-bench: no active model package to measure\n");
    return;
  }
  /* The listing starts with a nine-byte header before the first name; the
     self-test in vfs_xaifs.c reads it the same way. */
  char path[73];
  for (uint32_t index = 0U; index < 8U; ++index) path[index] = "/models/"[index];
  for (uint32_t index = 0U; index < 64U; ++index) {
    path[8U + index] = listing[9U + index];
  }
  path[72] = '\0';
  xaios_vfs_stat_t stat;
  if (vfs_stat(path, &stat) != XAIOS_OK || stat.size < BENCH_MODEL_CHUNK) {
    klog("storage-bench: model package too small to measure path=%s\n", path);
    return;
  }
  klog("storage-bench: model package=%s bytes=%lu\n", path, stat.size);
  bench_model_window(path, stat.size, BENCH_MODEL_CHUNK, "aligned");
  bench_model_window(path, stat.size, BENCH_BUFFER, "window");
}

#endif
