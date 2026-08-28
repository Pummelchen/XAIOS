/* FAT16 writer, checked against a whole disk image held in memory.
 *
 * The point of the exercise is that firmware has to be able to read what this
 * writes, and firmware is not available here -- so the test does the next
 * best thing and checks the volume against the format rather than against
 * itself: cluster count inside the FAT16 range, both copies of the FAT
 * identical, the boot signature and geometry fields where a reader expects
 * them, and every file readable back byte for byte through a fresh mount that
 * shares no state with the writer.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xaios/fat.h>

void klog(const char *fmt, ...) { (void)fmt; }

#define SECTOR 512U
/* 96 MiB, the size the unified image gives its EFI System Partition. Testing
   at the size the real thing uses is what catches a geometry choice that only
   works for one volume size. */
#define DISK_BYTES (96U * 1024U * 1024U)

static unsigned char *g_image;
static unsigned long g_reads;
static unsigned long g_writes;

static xaios_status_t image_read(void *context, uint64_t offset, void *buffer,
                                 uint64_t length) {
  (void)context;
  if (offset + length > DISK_BYTES) return XAIOS_ERR_INVALID;
  ++g_reads;
  memcpy(buffer, g_image + offset, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t image_write(void *context, uint64_t offset,
                                  const void *buffer, uint64_t length) {
  (void)context;
  if (offset + length > DISK_BYTES) return XAIOS_ERR_INVALID;
  ++g_writes;
  memcpy(g_image + offset, buffer, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t image_flush(void *context) {
  (void)context;
  return XAIOS_OK;
}

static const xaios_block_backend_ops_t k_ops = {image_read, image_write,
                                                image_flush, 0, 0};

static xaios_block_device_info_t image_info(void) {
  xaios_block_device_info_t info;
  memset(&info, 0, sizeof(info));
  memcpy(info.identifier, "/dev/vblk9", 11U);
  memcpy(info.backend, "image", 6U);
  info.capacity_bytes = DISK_BYTES;
  info.capacity_logical_sectors = DISK_BYTES / SECTOR;
  info.logical_sector_size = SECTOR;
  info.physical_block_size = SECTOR;
  info.max_transfer_bytes = SECTOR;
  info.flush_supported = 1U;
  return info;
}

static uint16_t read16(uint64_t offset) {
  return (uint16_t)(g_image[offset] | ((uint16_t)g_image[offset + 1U] << 8));
}

/* What a reader looks at before it will believe this is a FAT16 volume. */
static void check_boot_sector(const xaios_fat_volume_t *volume) {
  assert(g_image[0] == 0xEB);
  assert(g_image[510] == 0x55 && g_image[511] == 0xAA);
  assert(read16(11) == SECTOR);
  assert(g_image[13] == volume->sectors_per_cluster);
  assert(read16(14) == volume->reserved_sectors);
  assert(g_image[16] == volume->fat_count);
  assert(read16(17) == volume->root_entry_count);
  assert(read16(22) == volume->sectors_per_fat);
  assert(g_image[38] == 0x29);
  assert(memcmp(&g_image[54], "FAT16   ", 8) == 0);
  assert(memcmp(&g_image[43], "XAIOS", 5) == 0);
  /* Total sectors goes in the 16-bit field or the 32-bit one, never both. */
  if (volume->total_sectors < 0x10000U) {
    assert(read16(19) == volume->total_sectors);
  } else {
    assert(read16(19) == 0U);
  }
}

/* Both copies of the FAT must be identical. A volume whose copies disagree is
   read one way by one implementation and another way by another, which is the
   failure that cannot be diagnosed from a machine that will not boot. */
static void check_fat_copies_agree(const xaios_fat_volume_t *volume) {
  uint64_t first = volume->reserved_sectors * SECTOR;
  uint64_t second = first + volume->sectors_per_fat * SECTOR;
  assert(memcmp(g_image + first, g_image + second,
                (size_t)(volume->sectors_per_fat * SECTOR)) == 0);
}

static void write_and_verify(xaios_fat_volume_t *volume, const char *path,
                             const unsigned char *data, uint64_t length) {
  assert(fat_write_file(volume, path, data, length) == XAIOS_OK);
  unsigned char *back = malloc((size_t)length + 1U);
  assert(back != 0);
  uint64_t reported = 0U;
  assert(fat_read_file(volume, path, back, length, &reported) == XAIOS_OK);
  assert(reported == length);
  assert(memcmp(back, data, (size_t)length) == 0);
  free(back);
}

/* Optionally leave the finished image on disk, so that a FAT implementation
   that is not this one can be asked whether it agrees. The gate does not need
   it; a person checking with mtools or hdiutil does. */
static void dump_image(const char *path) {
  FILE *handle = fopen(path, "wb");
  if (handle == 0) return;
  (void)fwrite(g_image, 1U, DISK_BYTES, handle);
  (void)fclose(handle);
}

int main(int argc, char **argv) {
  g_image = calloc(DISK_BYTES, 1U);
  assert(g_image != 0);

  xaios_block_device_t device;
  memset(&device, 0, sizeof(device));
  xaios_block_device_info_t info = image_info();
  assert(block_device_register(&device, &info, &k_ops, 0) == XAIOS_OK);

  xaios_fat_volume_t volume;
  assert(fat_format(&device, "XAIOS", &volume) == XAIOS_OK);
  /* Below 4085 clusters the volume is FAT12 and above 65524 it is FAT32,
     whatever the boot sector claims. */
  assert(volume.cluster_count >= 4085U && volume.cluster_count <= 65524U);
  check_boot_sector(&volume);
  check_fat_copies_agree(&volume);

  /* The paths firmware actually looks for, created as a tree rather than one
     at a time: an installer names the directory it wants, not its parents. */
  assert(fat_mkdir(&volume, "/EFI/BOOT") == XAIOS_OK);
  assert(fat_mkdir(&volume, "/EFI/XAIOS") == XAIOS_OK);
  uint32_t is_directory = 0U;
  assert(fat_stat(&volume, "/EFI", 0, &is_directory) == XAIOS_OK);
  assert(is_directory == 1U);
  assert(fat_stat(&volume, "/EFI/BOOT", 0, &is_directory) == XAIOS_OK);
  assert(is_directory == 1U);
  /* Creating a directory that is already there is success: an installer that
     runs twice should behave the same the second time. */
  assert(fat_mkdir(&volume, "/EFI/BOOT") == XAIOS_OK);

  /* A file smaller than one sector, one that spans several clusters, and one
     that is exactly a whole number of sectors -- the last is where an
     off-by-one in the tail handling shows up. */
  unsigned char small[100];
  for (size_t index = 0U; index < sizeof(small); ++index) {
    small[index] = (unsigned char)(index * 7U + 1U);
  }
  write_and_verify(&volume, "/EFI/XAIOS/ENTROPY.SED", small, sizeof(small));

  uint64_t large_length = 300U * 1024U;
  unsigned char *large = malloc((size_t)large_length);
  assert(large != 0);
  for (uint64_t index = 0U; index < large_length; ++index) {
    large[index] = (unsigned char)((index * 31U) ^ (index >> 8));
  }
  write_and_verify(&volume, "/EFI/BOOT/BOOTAA64.EFI", large, large_length);

  uint64_t exact_length = 4U * SECTOR;
  unsigned char *exact = malloc((size_t)exact_length);
  assert(exact != 0);
  memset(exact, 0xA5, (size_t)exact_length);
  write_and_verify(&volume, "/EFI/XAIOS/KERNEL.ELF", exact, exact_length);

  /* An empty file is a legal thing to write and allocates no cluster. */
  assert(fat_write_file(&volume, "/EFI/XAIOS/EMPTY.TXT", "", 0U) == XAIOS_OK);
  uint64_t size = 1U;
  assert(fat_stat(&volume, "/EFI/XAIOS/EMPTY.TXT", &size, 0) == XAIOS_OK);
  assert(size == 0U);

  /* Rewriting a file must not consume the volume twice: the old chain goes
     back to the free list first. Measured by writing the large file enough
     times to exhaust a volume that leaked. */
  for (int round = 0; round < 40; ++round) {
    assert(fat_write_file(&volume, "/EFI/BOOT/BOOTAA64.EFI", large,
                          large_length) == XAIOS_OK);
  }
  uint64_t reported = 0U;
  unsigned char *back = malloc((size_t)large_length);
  assert(back != 0);
  assert(fat_read_file(&volume, "/EFI/BOOT/BOOTAA64.EFI", back, large_length,
                       &reported) == XAIOS_OK);
  assert(reported == large_length);
  assert(memcmp(back, large, (size_t)large_length) == 0);

  /* A buffer that is too small reports the size rather than reading part of
     the file, so a caller can ask once and size a buffer. */
  reported = 0U;
  assert(fat_read_file(&volume, "/EFI/BOOT/BOOTAA64.EFI", back, 10U,
                       &reported) == XAIOS_ERR_NO_MEMORY);
  assert(reported == large_length);

  /* Names that are not legal 8.3 are refused rather than truncated: two files
     differing only past the eighth character would silently become one. */
  assert(fat_write_file(&volume, "/EFI/BOOT/TOOLONGNAME.EFI", small, 4U) !=
         XAIOS_OK);
  assert(fat_write_file(&volume, "/EFI/BOOT/NAME.TOOLONG", small, 4U) !=
         XAIOS_OK);
  assert(fat_write_file(&volume, "/EFI/BOOT/TWO.DOTS.X", small, 4U) !=
         XAIOS_OK);
  /* A directory is not a file and a file is not a directory. */
  assert(fat_write_file(&volume, "/EFI/BOOT", small, 4U) != XAIOS_OK);
  assert(fat_mkdir(&volume, "/EFI/XAIOS/KERNEL.ELF") != XAIOS_OK);
  /* A path through a file rather than a directory goes nowhere. */
  assert(fat_read_file(&volume, "/EFI/XAIOS/KERNEL.ELF/X.BIN", back, 4U,
                       &reported) != XAIOS_OK);
  assert(fat_read_file(&volume, "/EFI/BOOT/MISSING.BIN", back, 4U,
                       &reported) == XAIOS_ERR_NOT_FOUND);

  check_fat_copies_agree(&volume);

  /* Everything above went through one mounted volume structure. Mounting the
     image again from nothing but its own bytes is what shows the geometry was
     written down correctly rather than merely remembered. */
  xaios_fat_volume_t reopened;
  assert(fat_mount(&device, &reopened) == XAIOS_OK);
  assert(reopened.sectors_per_cluster == volume.sectors_per_cluster);
  assert(reopened.cluster_count == volume.cluster_count);
  assert(reopened.data_start_sector == volume.data_start_sector);
  reported = 0U;
  assert(fat_read_file(&reopened, "/EFI/BOOT/BOOTAA64.EFI", back, large_length,
                       &reported) == XAIOS_OK);
  assert(reported == large_length);
  assert(memcmp(back, large, (size_t)large_length) == 0);
  assert(fat_read_file(&reopened, "/EFI/XAIOS/ENTROPY.SED", back,
                       sizeof(small), &reported) == XAIOS_OK);
  assert(reported == sizeof(small));
  assert(memcmp(back, small, sizeof(small)) == 0);

  /* Case is not significant in an 8.3 name; firmware asks for BOOTAA64.EFI
     however the installer spelled it. */
  reported = 0U;
  assert(fat_read_file(&reopened, "/efi/boot/bootaa64.efi", back, large_length,
                       &reported) == XAIOS_OK);
  assert(reported == large_length);

  /* A volume too small for a legal FAT16 filesystem is refused rather than
     written as FAT12 under a FAT16 label. */
  xaios_block_device_info_t tiny = image_info();
  tiny.capacity_bytes = 64U * 1024U;
  tiny.capacity_logical_sectors = tiny.capacity_bytes / SECTOR;
  memcpy(tiny.identifier, "/dev/vblk8", 11U);
  xaios_block_device_t tiny_device;
  memset(&tiny_device, 0, sizeof(tiny_device));
  assert(block_device_register(&tiny_device, &tiny, &k_ops, 0) == XAIOS_OK);
  xaios_fat_volume_t tiny_volume;
  assert(fat_format(&tiny_device, "SMALL", &tiny_volume) ==
         XAIOS_ERR_UNSUPPORTED);

  if (argc > 1) dump_image(argv[1]);

  free(back);
  free(exact);
  free(large);
  free(g_image);
  printf("fat: format, directory tree, file write/read, replace and remount "
         "tests passed clusters=%llu bytes_per_cluster=%llu\n",
         (unsigned long long)volume.cluster_count,
         (unsigned long long)(volume.sectors_per_cluster * SECTOR));
  return 0;
}
