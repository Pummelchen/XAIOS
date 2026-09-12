/* A file that needs more than sixteen extents, which is what B-55 raised.
 *
 * `XBFS_V6_MAX_EXTENTS` was sixteen and is now sixty-four. The row that raised
 * it said plainly that it was **not claimed as tested** -- the arithmetic said
 * sixteen was reachable and nothing exercised the new depth, so the change
 * rested on reasoning alone. This is the test that was missing.
 *
 * Reaching the depth needs free space that is *only* small holes, which means
 * the volume has to be full first. On a v6 volume it cannot be: 2,097,152
 * blocks against a whole-file write path that carries at most 512 blocks and a
 * node table of 1024 means the volume cannot be filled through the API at all.
 * On the v5 geometry -- 8192 blocks, 256 nodes, which is what every machine
 * here actually boots -- it can, and that is the volume the defect was reached
 * on in the first place.
 *
 * So: fill it exactly, in alternating runs of sixteen and forty-eight blocks,
 * then delete every sixteen-block file. What is left is a hundred and twenty
 * holes of sixteen blocks each and no run longer than sixteen anywhere on the
 * volume. A 512-block file placed into that cannot be held in fewer than
 * thirty-two extents -- there is no arrangement of sixteen runs of sixteen
 * blocks that covers 512 -- so a write that succeeds has used more than the old
 * ceiling, and one that fails under the old ceiling fails here.
 *
 * The arithmetic is the assertion. There is no public call that reports how
 * many extents a file occupies, and there does not need to be: 512 blocks drawn
 * from holes of at most 16 is at least 32 runs however they are chosen.
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
/* The v5 shape: the volume every machine here boots, and the only one that can
 * be filled through the ordinary write path. */
#define DATA_SECTORS 8192U
#define DISK_SECTORS (3072U + 3584U * 2U + 2U + 1U + DATA_SECTORS)
#define DISK_BYTES ((uint64_t)DISK_SECTORS * SECTOR)

/* 120 pairs of 16 + 48 blocks is 7680; one 512-block file takes the rest. */
#define PAIRS 120U
#define SMALL_BLOCKS 16U
#define LARGE_BLOCKS 48U
#define TAIL_BLOCKS 512U

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

static uint8_t *pattern(uint64_t bytes, uint64_t seed) {
  uint8_t *buffer = malloc((size_t)bytes);
  assert(buffer != 0);
  for (uint64_t i = 0U; i < bytes; ++i) {
    buffer[i] = (uint8_t)((i * 17U) ^ (i >> 7U) ^ seed);
  }
  return buffer;
}

int main(void) {
  g_disk = calloc(DISK_BYTES, 1U);
  assert(g_disk != 0);
  register_disk("/dev/extentdisk", DISK_SECTORS);
  assert(xaiboot_fs_mount_device("/dev/extentdisk") == XAIOS_OK);
  assert(xaiboot_fs_fsck().valid == 1U);

  char path[64];
  uint8_t *small = pattern(SMALL_BLOCKS * SECTOR, 3U);
  uint8_t *large = pattern(LARGE_BLOCKS * SECTOR, 5U);

  /* Fill the volume exactly, alternating short and long runs so that deleting
   * the short ones leaves holes of a known size with used blocks between. */
  for (unsigned i = 0U; i < PAIRS; ++i) {
    snprintf(path, sizeof(path), "/state/s%03u.bin", i);
    assert(xaiboot_fs_write(path, small, SMALL_BLOCKS * SECTOR) == XAIOS_OK);
    snprintf(path, sizeof(path), "/state/l%03u.bin", i);
    assert(xaiboot_fs_write(path, large, LARGE_BLOCKS * SECTOR) == XAIOS_OK);
  }
  uint8_t *tail = pattern(TAIL_BLOCKS * SECTOR, 9U);
  assert(xaiboot_fs_write("/state/tail.bin", tail, TAIL_BLOCKS * SECTOR) ==
         XAIOS_OK);

  /* With the volume full, there is now no free run at all. */
  uint8_t *probe = pattern(SECTOR, 1U);
  assert(xaiboot_fs_write("/state/nospace.bin", probe, SECTOR) != XAIOS_OK);

  /* Free the short runs only: 120 holes of 16 blocks, nothing longer. */
  for (unsigned i = 0U; i < PAIRS; ++i) {
    snprintf(path, sizeof(path), "/state/s%03u.bin", i);
    assert(xaiboot_fs_delete(path) == XAIOS_OK);
  }

  /* 512 blocks out of holes of at most 16 is at least 32 extents, whichever
   * runs are chosen. At the old ceiling of 16 this write could not be placed;
   * that is the whole of what B-55 changed. */
  uint8_t *deep = pattern(TAIL_BLOCKS * SECTOR, 13U);
  assert(xaiboot_fs_write("/state/deep.bin", deep, TAIL_BLOCKS * SECTOR) ==
         XAIOS_OK);

  /* It reads back, so the extents it was written to are the extents recorded.
   * A placement that lost or reordered a run passes the line above and fails
   * here. */
  uint8_t *read_back = malloc((size_t)(TAIL_BLOCKS * SECTOR));
  assert(read_back != 0);
  uint64_t out = 0U;
  assert(xaiboot_fs_read("/state/deep.bin", read_back, TAIL_BLOCKS * SECTOR,
                         &out) == XAIOS_OK);
  assert(out == TAIL_BLOCKS * SECTOR);
  assert(memcmp(deep, read_back, (size_t)(TAIL_BLOCKS * SECTOR)) == 0);

  /* A file this deep must also survive the paths that copy its extent list:
   * fsck, a snapshot, and a remount reading it off the disk rather than out of
   * memory. commit_snapshot walking a 32-extent file is the case B-52 showed
   * halts a machine at boot when it fails. */
  assert(xaiboot_fs_fsck().valid == 1U);

  /* xaiboot_fs_commit snapshots the whole filesystem, so it needs room for a
   * second copy of everything -- which a volume filled on purpose does not
   * have. Half the long files go, which frees 2880 blocks and leaves the deep
   * file exactly as it was placed. Snapshotting it is the point: commit walks
   * the extent list to copy it, and B-52 is the case where that fails on a
   * filesystem fsck calls sound and halts the machine at its next boot. */
  for (unsigned i = 0U; i < PAIRS / 2U; ++i) {
    snprintf(path, sizeof(path), "/state/l%03u.bin", i);
    assert(xaiboot_fs_delete(path) == XAIOS_OK);
  }
  assert(xaiboot_fs_commit("extent-depth") == XAIOS_OK);
  assert(xaiboot_fs_fsck().valid == 1U);
  xaiboot_fs_unmount();
  assert(xaiboot_fs_mount_device("/dev/extentdisk") == XAIOS_OK);
  memset(read_back, 0, (size_t)(TAIL_BLOCKS * SECTOR));
  out = 0U;
  assert(xaiboot_fs_read("/state/deep.bin", read_back, TAIL_BLOCKS * SECTOR,
                         &out) == XAIOS_OK);
  assert(out == TAIL_BLOCKS * SECTOR);
  assert(memcmp(deep, read_back, (size_t)(TAIL_BLOCKS * SECTOR)) == 0);
  assert(xaiboot_fs_fsck().valid == 1U);

  printf("xaiboot-fs extent depth: a 512-block file drawn from 16-block holes "
         "needs at least 32 extents, and places, reads back, snapshots and "
         "remounts\n");
  free(small); free(large); free(tail); free(probe); free(deep);
  free(read_back); free(g_disk);
  return 0;
}
