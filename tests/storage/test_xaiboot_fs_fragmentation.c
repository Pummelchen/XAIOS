/* A volume that is sound, has room, and cannot hold the next file.
 *
 * A file is at most XBFS_V6_MAX_EXTENTS runs of blocks -- sixteen -- and the
 * allocator used to take the first sixteen free runs it found, in address
 * order. On a volume that has been written and rewritten for a while the low
 * blocks are the most broken up, so first-fit collected sixteen short runs out
 * of the rubble at the bottom and never reached the long runs above them. The
 * write was then refused with plenty of free space on the volume.
 *
 * That is not merely a refused write. The same path snapshots a file, so
 * `xaiboot_fs_commit` fails; `update_stage` writes a snapshot; and
 * `update_self_test` runs on every boot with a writable persistent filesystem
 * and asserts that staging worked. A volume aged this far therefore stops the
 * machine booting -- `fsck` clean, disk two-thirds empty, cyan screen. This is
 * B-52, and it was found on the machine this repository is developed on, whose
 * own persistent volume had reached exactly that state after 64 boots.
 *
 * So this ages a volume on purpose and requires the write to succeed. The
 * point of the arrangement below is that the free space is deliberately in the
 * wrong shape: many short holes at low addresses, the long runs further up.
 * A policy that reads the volume in address order cannot see past the holes.
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
/* The same shape as the durable volume every machine here boots with: a v5
 * volume with 8192 data sectors. Testing the size the real thing uses is the
 * whole point -- the defect is reached by ordinary use of exactly this volume,
 * and a larger one would take proportionally longer to age.
 */
#define DATA_SECTORS 8192U
#define DISK_SECTORS (3072U + 2560U * 2U + 2U + 1U + DATA_SECTORS)
#define DISK_BYTES ((uint64_t)DISK_SECTORS * SECTOR)

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
    buffer[i] = (uint8_t)((i * 31U) ^ (i >> 9U) ^ seed);
  }
  return buffer;
}

int main(void) {
  g_disk = calloc(DISK_BYTES, 1U);
  assert(g_disk != 0);
  register_disk("/dev/agedisk", DISK_SECTORS);
  assert(xaiboot_fs_mount_device("/dev/agedisk") == XAIOS_OK);

  xaios_xbfs_fsck_result_t fsck = xaiboot_fs_fsck();
  assert(fsck.valid == 1U);

  /* Age the low end of the volume.
   *
   * Forty small files laid down in order, then every other one deleted. That
   * leaves twenty holes of one block each, separated by twenty used blocks, in
   * the lowest forty blocks of the data region -- more short holes than a file
   * is allowed extents, before the scan has got anywhere.
   *
   * This is what repeated rewriting produces on a real volume; doing it on
   * purpose only makes it quick and exact. */
  char path[64];
  uint8_t *small = pattern(SECTOR, 7U);
  for (unsigned i = 0U; i < 40U; ++i) {
    snprintf(path, sizeof(path), "/state/small%02u.bin", i);
    assert(xaiboot_fs_write(path, small, SECTOR) == XAIOS_OK);
  }
  for (unsigned i = 0U; i < 40U; i += 2U) {
    snprintf(path, sizeof(path), "/state/small%02u.bin", i);
    assert(xaiboot_fs_delete(path) == XAIOS_OK);
  }

  /* A file that no run at the bottom can hold and that twenty one-block holes
   * cannot cover in sixteen extents. There is far more than this free further
   * up the volume, which is the whole point: the space exists and the shape of
   * it is what the old policy could not get past. */
  const uint64_t large = 64U * SECTOR;
  uint8_t *written = pattern(large, 11U);
  xaios_status_t status = xaiboot_fs_write("/state/large.bin", written, large);
  assert(status == XAIOS_OK);

  /* And it reads back, so the extents it was split across are the ones it was
   * written to. A placement policy that produced the wrong extents would pass
   * the line above and fail here. */
  uint8_t *read_back = malloc((size_t)large);
  assert(read_back != 0);
  uint64_t out = 0U;
  assert(xaiboot_fs_read("/state/large.bin", read_back, large, &out) ==
         XAIOS_OK);
  assert(out == large);
  assert(memcmp(written, read_back, (size_t)large) == 0);

  /* The reason this matters: the same allocation snapshots a file, and a
   * volume that cannot be snapshotted is a machine that will not boot. */
  assert(xaiboot_fs_commit("fragmentation") == XAIOS_OK);

  fsck = xaiboot_fs_fsck();
  assert(fsck.valid == 1U);
  assert(fsck.errors == 0U);

  /* Survives a remount: the extents recorded are the extents read back after
   * the node table has been through the disk rather than memory. */
  xaiboot_fs_unmount();
  assert(xaiboot_fs_mount_device("/dev/agedisk") == XAIOS_OK);
  memset(read_back, 0, (size_t)large);
  out = 0U;
  assert(xaiboot_fs_read("/state/large.bin", read_back, large, &out) ==
         XAIOS_OK);
  assert(out == large);
  assert(memcmp(written, read_back, (size_t)large) == 0);

  free(small);
  free(written);
  free(read_back);
  free(g_disk);
  printf("xaiboot-fs fragmentation: a volume aged past sixteen first-fit "
         "runs still places, reads back, snapshots and remounts a file\n");
  return 0;
}
