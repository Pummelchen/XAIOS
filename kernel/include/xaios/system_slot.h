#ifndef XAIOS_SYSTEM_SLOT_H
#define XAIOS_SYSTEM_SLOT_H

#include <xaios/boot_info.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_SYSTEM_MAGIC "XAIOS-SYSTEM-V2"
#define XAIOS_SYSTEM_VERSION UINT32_C(2)
#define XAIOS_SYSTEM_METADATA_BYTES UINT32_C(4096)
#define XAIOS_SYSTEM_METADATA_PRIMARY_LBA UINT64_C(0)
#define XAIOS_SYSTEM_METADATA_BACKUP_LBA UINT64_C(8)
#define XAIOS_SYSTEM_SLOT_COUNT UINT32_C(2)
#define XAIOS_SYSTEM_SLOT_NONE UINT32_MAX
#define XAIOS_SYSTEM_SIGNATURE_MAX UINT32_C(320)
#define XAIOS_SYSTEM_SLOT0_LBA UINT64_C(64)
#define XAIOS_SYSTEM_SLOT_SECTORS UINT64_C(32768)
#define XAIOS_SYSTEM_VOLUME_SECTORS                                      \
  (XAIOS_SYSTEM_SLOT0_LBA +                                             \
   (XAIOS_SYSTEM_SLOT_COUNT * XAIOS_SYSTEM_SLOT_SECTORS))

typedef struct xaios_system_slot_descriptor {
  uint32_t valid;
  uint32_t reserved;
  uint64_t generation;
  uint64_t offset_lba;
  uint64_t image_size;
  uint8_t sha256[32];
  char signature[XAIOS_SYSTEM_SIGNATURE_MAX];
  uint8_t padding[128];
} xaios_system_slot_descriptor_t;

#define XAIOS_SYSTEM_METADATA_FIXED_BYTES                                \
  (16U + 8U + 8U + 16U +                                                \
   (XAIOS_SYSTEM_SLOT_COUNT * sizeof(xaios_system_slot_descriptor_t)) +  \
   32U)

typedef struct xaios_system_metadata {
  char magic[16];
  uint32_t version;
  uint32_t header_size;
  uint64_t sequence;
  uint32_t active_slot;
  uint32_t pending_slot;
  uint32_t pending_attempted;
  uint32_t flags;
  xaios_system_slot_descriptor_t slots[XAIOS_SYSTEM_SLOT_COUNT];
  uint8_t padding[XAIOS_SYSTEM_METADATA_BYTES -
                  XAIOS_SYSTEM_METADATA_FIXED_BYTES];
  uint8_t metadata_sha256[32];
} xaios_system_metadata_t;

typedef char xaios_system_metadata_size_check[
    sizeof(xaios_system_metadata_t) == XAIOS_SYSTEM_METADATA_BYTES ? 1 : -1];

xaios_status_t system_slot_init(const xaios_boot_info_t *boot);
xaios_status_t system_slot_begin(uint64_t generation, uint64_t image_size,
                                 const uint8_t hash[32],
                                 const char *signature);
xaios_status_t system_slot_write(uint64_t offset, const void *data,
                                 uint32_t size);
xaios_status_t system_slot_finish(void);
xaios_status_t system_slot_activate(void);
xaios_status_t system_slot_cancel_pending(void);
xaios_status_t system_slot_mark_boot_success(const xaios_boot_info_t *boot);
uint32_t system_slot_available(void);
void system_slot_self_test(void);

#endif
