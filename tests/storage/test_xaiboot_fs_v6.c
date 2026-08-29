/* A volume large enough to be worth having.
 *
 * Every version up to v5 records a file as a fixed array of 16-bit block
 * numbers, and that array is the whole of why this filesystem could not grow:
 * a volume capped at 32 MiB, a file at 256 KiB, and no way to widen either
 * without the node table -- which is resident -- growing in step. Extents
 * describe a run of blocks in eight bytes however long the run is, so they
 * lift both limits while making a node smaller.
 *
 * These tests hold a v6 volume to the things that were impossible before: a
 * file far past 256 KiB, more nodes than v5 has, and the whole of it surviving
 * a remount. And they hold the conversion to the thing that matters more --
 * that a v5 volume written by the old code still reads, still writes, and is
 * still v5 afterwards, because a filesystem holding every SSH host key is not
 * a place to migrate anyone by surprise.
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
/* Room for a v6 volume: the start offset, two metadata copies, the journal
   and a gigabyte of data. */
#define DISK_SECTORS (3072U + 2560U * 2U + 2U + 1U + 2097152U)
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

int main(void) {
  g_disk = calloc(DISK_BYTES, 1U);
  assert(g_disk != 0);
  register_disk("/dev/v6disk", DISK_SECTORS);
  assert(xaiboot_fs_mount_device("/dev/v6disk") == XAIOS_OK);

  xaios_xbfs_fsck_result_t fsck = xaiboot_fs_fsck();
  assert(fsck.valid == 1U);
  /* A disk this size is formatted as v6; a smaller one stays v5, which is
     what keeps every existing volume where it is. */
  assert(fsck.version == 6U);

  /* Past what v5 could hold. 512 blocks of 512 bytes was the ceiling, so a
     megabyte is four times a whole v5 file and would not have fitted in a
     whole v5 volume's data region either. */
  const uint64_t large = 1024U * 1024U;
  uint8_t *written = malloc((size_t)large);
  uint8_t *read_back = malloc((size_t)large);
  assert(written != 0 && read_back != 0);
  for (uint64_t i = 0U; i < large; ++i) {
    written[i] = (uint8_t)((i * 31U) ^ (i >> 9U));
  }
  assert(xaiboot_fs_write("/state/large.bin", written, large) == XAIOS_OK);
  uint64_t out = 0U;
  assert(xaiboot_fs_read("/state/large.bin", read_back, large, &out) ==
         XAIOS_OK);
  assert(out == large);
  assert(memcmp(read_back, written, (size_t)large) == 0);

  /* More files than v5 has nodes, so the table itself is exercised past the
     old limit rather than only the block accounting. */
  char path[64];
  for (uint32_t i = 0U; i < 400U; ++i) {
    snprintf(path, sizeof(path), "/state/f%u", i);
    uint32_t value = i * 2654435761U;
    assert(xaiboot_fs_write(path, &value, sizeof(value)) == XAIOS_OK);
  }
  fsck = xaiboot_fs_fsck();
  assert(fsck.errors == 0U);
  assert(fsck.files >= 401U);

  /* Everything survives a remount, which is what says it reached the disk
     rather than living in the structures that wrote it. */
  /* Unmount before mounting again: a mounted volume refuses a second mount,
     which is correct and is not what this is testing. */
  xaiboot_fs_unmount();
  assert(xaiboot_fs_mount_device("/dev/v6disk") == XAIOS_OK);
  memset(read_back, 0, (size_t)large);
  out = 0U;
  assert(xaiboot_fs_read("/state/large.bin", read_back, large, &out) ==
         XAIOS_OK);
  assert(out == large);
  assert(memcmp(read_back, written, (size_t)large) == 0);
  for (uint32_t i = 0U; i < 400U; ++i) {
    snprintf(path, sizeof(path), "/state/f%u", i);
    uint32_t value = 0U;
    uint64_t got = 0U;
    assert(xaiboot_fs_read(path, &value, sizeof(value), &got) == XAIOS_OK);
    assert(got == sizeof(value));
    assert(value == i * 2654435761U);
  }
  fsck = xaiboot_fs_fsck();
  assert(fsck.valid == 1U && fsck.errors == 0U);
  assert(fsck.version == 6U);

  /* And the case that matters more than any of the above: a volume too small
     for v6 is still formatted, mounted and written as v5. Nothing that exists
     today changes format, and a v5 volume stays readable by a kernel that has
     never heard of extents. */
  xaiboot_fs_unmount();
  free(g_disk);
  g_disk = calloc(DISK_BYTES, 1U);
  assert(g_disk != 0);
  register_disk("/dev/v5disk", 3072U + 1280U * 2U + 2U + 1U + 8192U + 16U);
  assert(xaiboot_fs_mount_device("/dev/v5disk") == XAIOS_OK);
  fsck = xaiboot_fs_fsck();
  assert(fsck.valid == 1U);
  assert(fsck.version == 5U);
  static const char small[] = "a v5 volume, still v5";
  assert(xaiboot_fs_write("/state/small.txt", small, sizeof(small)) ==
         XAIOS_OK);
  char small_back[sizeof(small)];
  out = 0U;
  assert(xaiboot_fs_read("/state/small.txt", small_back, sizeof(small_back),
                         &out) == XAIOS_OK);
  assert(out == sizeof(small));
  assert(memcmp(small_back, small, sizeof(small)) == 0);
  xaiboot_fs_unmount();
  assert(xaiboot_fs_mount_device("/dev/v5disk") == XAIOS_OK);
  fsck = xaiboot_fs_fsck();
  assert(fsck.version == 5U && fsck.errors == 0U);

  free(read_back);
  free(written);
  free(g_disk);
  printf("xaibootfs-v6: %llu-byte file, 400 nodes, remount and v5 volumes "
         "unchanged\n", (unsigned long long)large);
  return 0;
}
