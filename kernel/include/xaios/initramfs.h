#ifndef XAIOS_INITRAXBFS_H
#define XAIOS_INITRAXBFS_H

#include <xaios/status.h>
#include <xaios/types.h>

typedef struct xaios_initramfs_file {
  const char *path;
  void *base;
  uint64_t size;
  uint32_t executable;
  uint32_t manifest;
  uint64_t content_hash;
} xaios_initramfs_file_t;

typedef struct xaios_initramfs_config {
  const char *service_path;
  const char *service_manager_path;
  const char *service_descriptor_path;
  const char *mode;
  const char *child_service_path;
  const char *child_service_parent;
  const char *child_service_restart;
  uint32_t valid;
} xaios_initramfs_config_t;

xaios_status_t initramfs_init(void);

/* Read-only enumeration of the loaded image, for directory listings. The
   table is immutable after initramfs_init, so no locking is involved. */
uint32_t initramfs_file_count(void);
const xaios_initramfs_file_t *initramfs_file_at(uint32_t index);

/* Derived directory shape over the image's flat path table. A directory
   exists when any file path extends it; children are first components. */
int initramfs_child_at(const char *directory, uint32_t index, char *name,
                       uint64_t name_capacity, int *is_directory);
int initramfs_directory_exists(const char *directory);

/* Mount the image read-only into the VFS at the given directory, typically
   "/bin", so userspace utilities can list and read what the kernel loads. */
xaios_status_t vfs_mount_initramfs(const char *mount_path);
xaios_status_t initramfs_lookup(const char *path,
                               const xaios_initramfs_file_t **file);
const xaios_initramfs_config_t *initramfs_config(void);
void initramfs_self_test(void);

#endif
