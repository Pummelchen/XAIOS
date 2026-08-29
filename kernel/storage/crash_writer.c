/* Ingest a staged package chunk by chunk, so a gate can cut power mid-write.
 *
 * The crash-safety claim xaiFS makes is structural: a commit writes a whole
 * new catalog at a fresh offset, flushes, then flips the superblock to the
 * other slot and flushes again. Either the flip landed or it did not, and a
 * superblock that landed half-written fails its own hash and is discarded in
 * favour of the other slot. So a reader arriving after a power cut sees a
 * consistent catalog whose complete chunks are all genuinely on the volume,
 * and at worst loses the chunk that was in flight.
 *
 * That is a claim about a design. This is what makes it a claim about the
 * build: it writes one chunk, fsyncs -- which is the commit -- logs that it
 * did, and repeats. The gate kills the machine at an arbitrary moment and
 * then asks fsck whether every chunk still marked complete hashes to what its
 * record says. Nothing here checks anything itself; it exists to be
 * interrupted, and the log line is what tells the gate how far it got.
 */
#include <xaios/crash_writer.h>

#include <xaios/klog.h>
#include <xaios/vfs.h>

#include <stdint.h>

/* Has to match tests/xai_fs/create_crash_fixture.py. The fixture signed the
   manifest over these exact bytes, so a mismatch shows up as a rejected
   commit rather than as a wrong answer. */
#define CRASH_CHUNK_BYTES UINT64_C(2097152)
#define CRASH_PATTERN_PERIOD 256U
#define MODEL_PACKAGE_NAME_LENGTH 64U
#define MODEL_OWNER UINT32_C(0x4d4f444c)

/* One period, expanded by the write loop rather than held whole: a two
   mebibyte staging buffer in .bss is real memory the rest of the kernel does
   not get, and the write path takes any length. */
static uint8_t g_period[CRASH_PATTERN_PERIOD];
static uint8_t g_block[65536];

static void fill_block(uint64_t chunk_index) {
  for (uint32_t position = 0U; position < CRASH_PATTERN_PERIOD; ++position) {
    g_period[position] =
        (uint8_t)(((uint64_t)position * 31U + chunk_index * 97U + 17U) & 0xffU);
  }
  for (uint32_t offset = 0U; offset < sizeof(g_block); ++offset) {
    g_block[offset] = g_period[offset % CRASH_PATTERN_PERIOD];
  }
}

void crash_writer_run(void) {
  char listing[MODEL_PACKAGE_NAME_LENGTH * 4U + 8U];
  uint64_t listing_size = 0U;
  if (vfs_list("/models/.staging", listing, sizeof(listing), &listing_size) !=
          XAIOS_OK ||
      listing_size < MODEL_PACKAGE_NAME_LENGTH) {
    klog("crash-writer: no staging package to ingest\n");
    return;
  }
  /* The crash fixture stages exactly one package, so the first name is it. */
  char path[17U + MODEL_PACKAGE_NAME_LENGTH + 1U];
  for (uint32_t index = 0U; index < 17U; ++index) {
    path[index] = "/models/.staging/"[index];
  }
  for (uint32_t index = 0U; index < MODEL_PACKAGE_NAME_LENGTH; ++index) {
    path[17U + index] = listing[index];
  }
  path[17U + MODEL_PACKAGE_NAME_LENGTH] = '\0';

  int64_t fd = vfs_open(path, XAIOS_VFS_OPEN_WRITE, MODEL_OWNER);
  if (fd <= 0) {
    klog("crash-writer: open failed path=%s status=%d\n", path, (int)fd);
    return;
  }
  klog("crash-writer: ingest started path=%s chunk_bytes=%lu\n", path,
       CRASH_CHUNK_BYTES);

  for (uint64_t chunk = 0U;; ++chunk) {
    fill_block(chunk);
    uint64_t base = chunk * CRASH_CHUNK_BYTES;
    uint64_t written = 0U;
    while (written < CRASH_CHUNK_BYTES) {
      int64_t count = vfs_pwrite((uint32_t)fd, MODEL_OWNER, g_block,
                                 sizeof(g_block), base + written);
      if (count != (int64_t)sizeof(g_block)) {
        /* Past the end of the package, or the volume ran out of room for
           another catalog. Either way the ingest is over; the gate reads the
           chunk count from the log lines that already went out. */
        klog("crash-writer: ingest finished chunks=%lu status=%d\n", chunk,
             (int)count);
        (void)vfs_close((uint32_t)fd, MODEL_OWNER);
        return;
      }
      written += (uint64_t)count;
    }
    /* The commit. Everything before this point is bytes on the volume that no
       catalog refers to; this is what publishes them. */
    xaios_status_t sync_status = vfs_fsync((uint32_t)fd, MODEL_OWNER);
    if (sync_status != XAIOS_OK) {
      klog("crash-writer: commit failed chunk=%lu status=%d\n", chunk,
           (int)sync_status);
      (void)vfs_close((uint32_t)fd, MODEL_OWNER);
      return;
    }
    klog("crash-writer: committed chunk=%lu\n", chunk);
  }
}
