/* A/B metadata recovery.
 *
 * The metadata region is rewritten in place, so a write interrupted by power
 * loss leaves it neither valid nor blank, and mount refuses to continue
 * rather than format over a volume that might still hold data. That made an
 * interrupted metadata write unrecoverable. A second copy is kept past the
 * data region and writes alternate between the two, so mount can fall back.
 *
 * These tests damage a copy the way a torn write would and require the volume
 * to keep mounting with its contents intact.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <xaios/block_device.h>
#include <xaios/xaiboot_fs.h>

/* Kernel dependencies the filesystem pulls in, reduced to what a hosted run
   needs. The virtio path is unreachable here: this test mounts a registered
   block device, never the in-image volume. */
void klog(const char *fmt, ...) { (void)fmt; }
/* The kernel ticket lock has a fast path for the cases where it cannot or need
   not spin: one CPU online, or translation still off, where exclusives are
   unsupported. Both questions are answered by the kernel proper. The hosted
   test links only the filesystem translation unit, so it answers them here --
   one CPU, translation on -- which is the configuration these tests run in. */
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
xaios_status_t virtio_block_write_sector(uint64_t s, const void *b, uint64_t n) {
  (void)s; (void)b; (void)n; return XAIOS_ERR_IO;
}
xaios_status_t virtio_block_flush(void) { return XAIOS_ERR_IO; }
uint64_t virtio_block_capacity_sectors(void) { return 0U; }

#define SECTOR 512U
/* Room for metadata + journal + data + the mirror that follows them. */
#define DISK_SECTORS (3072U + 1280U + 2U + 8192U + 1280U + 64U)

static uint8_t g_disk[(uint64_t)DISK_SECTORS * SECTOR];
static xaios_block_device_t g_device;

static xaios_status_t disk_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  (void)context;
  if (offset + length > sizeof(g_disk)) return XAIOS_ERR_INVALID;
  memcpy(buffer, g_disk + offset, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t disk_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  (void)context;
  if (offset + length > sizeof(g_disk)) return XAIOS_ERR_INVALID;
  memcpy(g_disk + offset, buffer, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t disk_flush(void *context) {
  (void)context;
  return XAIOS_OK;
}

static const xaios_block_backend_ops_t k_ops = {
    disk_read, disk_write, disk_flush, 0, 0,
};

static void register_disk(void) {
  xaios_block_device_info_t info;
  memset(&info, 0, sizeof(info));
  snprintf(info.identifier, sizeof(info.identifier), "/dev/mirror0");
  snprintf(info.backend, sizeof(info.backend), "test");
  info.capacity_bytes = sizeof(g_disk);
  info.capacity_logical_sectors = DISK_SECTORS;
  info.logical_sector_size = SECTOR;
  info.physical_block_size = SECTOR;
  info.max_transfer_bytes = SECTOR;
  info.flush_supported = 1U;
  info.read_only = 0U;
  assert(block_device_register(&g_device, &info, &k_ops, 0) == XAIOS_OK);
}

/* Overwrite a metadata copy the way an interrupted write would: some sectors
 * carry the new image, the rest still hold the old one, so the region is
 * self-inconsistent without being blank. */
static void tear_slot(uint64_t start_sector) {
  for (uint32_t i = 0U; i < 8U; ++i) {
    memset(g_disk + ((uint64_t)start_sector + i) * SECTOR, 0xA5, SECTOR);
  }
}

static uint64_t primary_start(void) { return 3072U; }
static uint64_t mirror_start(void) { return 3072U + 1280U + 2U + 8192U; }

static void mount_fresh(void) {
  assert(xaiboot_fs_mount_device("/dev/mirror0") == XAIOS_OK);
}

int main(void) {
  register_disk();

  /* Create a volume with real content and commit it. */
  mount_fresh();
  assert(xaiboot_fs_mkdir("/state") == XAIOS_OK);
  assert(xaiboot_fs_write("/state/keep", "durable", 7U) == XAIOS_OK);
  assert(xaiboot_fs_commit("initial") == XAIOS_OK);
  /* Several writes, so the slots have alternated and both hold real images. */
  for (uint32_t i = 0U; i < 4U; ++i) {
    assert(xaiboot_fs_write("/state/keep", "durable", 7U) == XAIOS_OK);
  }
  xaiboot_fs_unmount();

  /* A torn primary must not stop the volume mounting. */
  tear_slot(primary_start());
  mount_fresh();
  char buffer[32];
  uint64_t read_bytes = 0U;
  assert(xaiboot_fs_read("/state/keep", buffer, sizeof(buffer), &read_bytes) ==
         XAIOS_OK);
  assert(read_bytes == 7U && memcmp(buffer, "durable", 7U) == 0);
  printf("mutable-fs-mirror: torn primary recovered, contents intact\n");

  /* Writing after that recovery must restore a good second copy, so the
     volume is not left one tear away from being unmountable. */
  assert(xaiboot_fs_write("/state/keep", "durable", 7U) == XAIOS_OK);
  assert(xaiboot_fs_commit("after-recovery") == XAIOS_OK);
  xaiboot_fs_unmount();

  /* Now tear the other copy and require the same outcome. */
  tear_slot(mirror_start());
  mount_fresh();
  read_bytes = 0U;
  assert(xaiboot_fs_read("/state/keep", buffer, sizeof(buffer), &read_bytes) ==
         XAIOS_OK);
  assert(read_bytes == 7U && memcmp(buffer, "durable", 7U) == 0);
  printf("mutable-fs-mirror: torn mirror recovered, contents intact\n");
  xaiboot_fs_unmount();

  /* Both copies damaged must still refuse rather than format over the
     volume: falling back is a recovery, not a licence to discard data. */
  tear_slot(primary_start());
  tear_slot(mirror_start());
  assert(xaiboot_fs_mount_device("/dev/mirror0") != XAIOS_OK);
  printf("mutable-fs-mirror: both copies damaged still refuses to format\n");

  printf("mutable-fs-mirror: all A/B metadata recovery tests passed\n");
  return 0;
}
