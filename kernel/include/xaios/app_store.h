#ifndef XAIOS_APP_STORE_H
#include <xaios/version.h>

#define XAIOS_APP_STORE_H

#include <xaios/initramfs.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_APP_FORMAT_VERSION 1U
#define XAIOS_APP_NAME_MAX 32U
#define XAIOS_APP_VERSION_MAX 24U
#define XAIOS_APP_ARCH_MAX 16U
#define XAIOS_APP_MANIFEST_MAX 512U
#define XAIOS_APP_CATALOG_MAX 131072U
/* The build a package must be able to run on. Packages declare a minimum as
   a whole number, which is what XAIOS is versioned by; their own versions stay
   MAJOR.MINOR.PATCH, because a package's history is its own. */
#define XAIOS_APP_OS_BUILD XAIOS_BUILD_NUMBER
#define XAIOS_APP_KERNEL_ABI_VERSION 1U

typedef struct xaios_app_manifest {
  char name[XAIOS_APP_NAME_MAX];
  char version[XAIOS_APP_VERSION_MAX];
  char architecture[XAIOS_APP_ARCH_MAX];
  char minimum_os[XAIOS_APP_VERSION_MAX];
  uint32_t minimum_abi;
  uint64_t capabilities;
  uint64_t binary_size;
  uint8_t binary_hash[32];
} xaios_app_manifest_t;

typedef struct xaios_app_image {
  xaios_initramfs_file_t file;
  char path[96];
  uint64_t capabilities;
  char version[XAIOS_APP_VERSION_MAX];
} xaios_app_image_t;

void app_store_init(void);
xaios_status_t app_store_activate(const char *name);
xaios_status_t app_store_remove(const char *name);
xaios_status_t app_store_rollback(const char *name);
xaios_status_t app_store_activate_catalog(void);
xaios_status_t app_store_load(const char *name, xaios_app_image_t *image);
void app_store_release(xaios_app_image_t *image);

#endif
