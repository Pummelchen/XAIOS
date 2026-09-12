/* A v6 volume used past 32 MiB, which is where the sector number used to wrap.
 *
 * `absolute_data_sector` took a `uint16_t`. Block 65536 is 32 MiB into the data
 * region and a v6 volume is allowed a gibibyte, so every caller -- all of which
 * pass a 64-bit block number out of an extent -- had its argument truncated at
 * the call. A read or a write past that point went to a sector near the start
 * of the region instead. No error and no short count: the wrong bytes, at the
 * wrong place, silently.
 *
 * Nothing reachable by the v5 volumes anything currently boots, which is why it
 * survived. v6 raised the ceiling to a gibibyte and made it reachable. B-49.
 *
 * The test fills past the boundary with whole files rather than one enormous
 * one, because the whole-file path stages through a 256 KiB buffer and that is
 * the largest single write the filesystem takes. Every file is written, then
 * every file is read back at the end -- the second pass is the one that
 * matters, because a wrapped write corrupts a file written earlier and only
 * re-reading everything finds it.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xaios/block_device.h>
#include <xaios/xaiboot_fs.h>

void klog(const char *fmt, ...) { (void)fmt; }
uint32_t smp_online_count(void) { return 1U; }
uint32_t xaios_translation_enabled(void) { return 1U; }
uint32_t smp_locking_active(void) { return 0U; }
void panic_at(const char *file, int line, const char *fmt, ...) {
  (void)fmt;
  fprintf(stderr, "panic at %s:%d\n", file, line);
  __builtin_trap();
}
xaios_status_t virtio_block_read_sector(uint64_t s, void *b, uint64_t n) {
  (void)s; (void)b; (void)n; return XAIOS_ERR_IO;
}
xaios_status_t virtio_block_write_sector(uint64_t s, const void *b,
                                         uint64_t n) {
  (void)s; (void)b; (void)n; return XAIOS_ERR_IO;
}
xaios_status_t virtio_block_flush(void) { return XAIOS_ERR_IO; }
uint64_t virtio_block_capacity_sectors(void) { return 0U; }

#define SECTOR 512U
/* A full v6 volume: the start offset, two metadata copies, the journal, and a
   gibibyte of data. The size is what selects v6 at format time. */
/* 3584 is XBFS_V6_METADATA_SECTORS, twice for the two mirror slots. It is
   repeated here because the constant lives in the implementation rather
   than the header; a disk too small for two slots formats as v5 instead,
   and the version assertion below is what catches that. */
#define DISK_SECTORS (3072U + 3584U * 2U + 2U + 1U + 2097152U)
#define DISK_BYTES ((uint64_t)DISK_SECTORS * SECTOR)

/* 256 KiB is the largest single write the whole-file path stages. 140 of them
   is 35 MiB, which puts the last of them past block 65536 -- 32 MiB -- with
   room to spare on either side of the boundary. */
#define FILE_BYTES (256U * 1024U)
#define FILE_COUNT 140U
#define BOUNDARY_BLOCK 65536U

static uint8_t *g_disk;
static xaios_block_device_t g_device;

static xaios_status_t disk_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  (void)context;
  if (offset + length > DISK_BYTES) return XAIOS_ERR_INVALID;
  memcpy(buffer, g_disk + offset, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t disk_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  (void)context;
  if (offset + length > DISK_BYTES) return XAIOS_ERR_INVALID;
  memcpy(g_disk + offset, buffer, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t disk_flush(void *context) {
  (void)context;
  return XAIOS_OK;
}

static const xaios_block_backend_ops_t k_ops = {disk_read, disk_write,
                                                disk_flush, 0, 0};

static void register_disk(const char *name, uint64_t sectors) {
  xaios_block_device_info_t info;
  memset(&info, 0, sizeof(info));
  memset(&g_device, 0, sizeof(g_device));
  snprintf(info.identifier, sizeof(info.identifier), "%s", name);
  snprintf(info.backend, sizeof(info.backend), "test");
  info.capacity_bytes = sectors * SECTOR;
  info.capacity_logical_sectors = sectors;
  info.logical_sector_size = SECTOR;
  info.physical_block_size = SECTOR;
  info.max_transfer_bytes = SECTOR;
  info.flush_supported = 1U;
  assert(block_device_register(&g_device, &info, &k_ops, 0) == XAIOS_OK);
}

/* Distinct per file and per offset, so a block that lands at the wrong sector
   cannot coincidentally match what belongs there. */
static void fill(uint8_t *buffer, uint64_t bytes, unsigned index) {
  for (uint64_t i = 0U; i < bytes; ++i) {
    buffer[i] = (uint8_t)((i * 31U) ^ (i >> 9U) ^ (index * 97U) ^ 0x5AU);
  }
}

int main(void) {
  g_disk = calloc(DISK_BYTES, 1U);
  assert(g_disk != 0);
  register_disk("/dev/bigdisk", DISK_SECTORS);
  assert(xaiboot_fs_mount_device("/dev/bigdisk") == XAIOS_OK);

  xaios_xbfs_fsck_result_t fsck = xaiboot_fs_fsck();
  assert(fsck.valid == 1U);
  assert(fsck.version == 6U);

  uint8_t *written = malloc(FILE_BYTES);
  uint8_t *read_back = malloc(FILE_BYTES);
  assert(written != 0 && read_back != 0);

  char path[64];
  for (unsigned i = 0U; i < FILE_COUNT; ++i) {
    fill(written, FILE_BYTES, i);
    snprintf(path, sizeof(path), "/state/big%03u.bin", i);
    assert(xaiboot_fs_write(path, written, FILE_BYTES) == XAIOS_OK);
  }

  /* The pass that matters. A wrapped write lands on a sector belonging to a
     file written earlier, so the damage is behind you by the time it happens
     and only a full re-read finds it. */
  unsigned mismatched = 0U;
  for (unsigned i = 0U; i < FILE_COUNT; ++i) {
    fill(written, FILE_BYTES, i);
    snprintf(path, sizeof(path), "/state/big%03u.bin", i);
    uint64_t out = 0U;
    memset(read_back, 0, FILE_BYTES);
    assert(xaiboot_fs_read(path, read_back, FILE_BYTES, &out) == XAIOS_OK);
    assert(out == FILE_BYTES);
    if (memcmp(written, read_back, FILE_BYTES) != 0) {
      if (mismatched < 4U) {
        fprintf(stderr, "file %u read back different from what was written\n",
                i);
      }
      ++mismatched;
    }
  }
  assert(mismatched == 0U);

  /* And the volume still describes itself correctly afterwards. */
  fsck = xaiboot_fs_fsck();
  assert(fsck.valid == 1U);
  assert(fsck.errors == 0U);

  free(written);
  free(read_back);
  free(g_disk);
  printf("xaiboot-fs large volume: %u files of %u KiB, %llu MiB total, every "
         "one read back byte-for-byte past the %u-block boundary\n",
         FILE_COUNT, FILE_BYTES / 1024U,
         (unsigned long long)((uint64_t)FILE_COUNT * FILE_BYTES / (1024U * 1024U)),
         BOUNDARY_BLOCK);
  return 0;
}
