#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/spinlock.h>
#include <xaios/virtio_blk.h>

#define XBFS_MAGIC "XAIOSMFS2"
#define XBFS_JOURNAL_MAGIC "XAIOSMFJ1"
#define XBFS_MAGIC_LEN 8U
#define XBFS_VERSION 2U
#define XBFS_JOURNAL_VERSION 1U
#define XBFS_SECTOR_SIZE UINT64_C(512)
#define XBFS_START_SECTOR UINT64_C(3072)
#define XBFS_METADATA_SECTORS UINT64_C(16)
/* A/B metadata.

   The metadata region is written in place, so a write torn by power loss
   leaves it neither valid nor blank. Mount then refuses to continue, because
   formatting would destroy the volume, and the result is a filesystem that
   cannot be mounted or repaired. A second copy removes that: writes alternate
   between the two, so a tear can only ever damage the copy that is not
   currently authoritative, and mount falls back to the survivor.

   The mirror lives past the data region, so every existing offset is
   unchanged and an existing volume keeps mounting. The write sequence sits in
   the slack at the end of the region for the same reason: appending a header
   field would have shifted the bitmap and every node after it. A volume
   written before this reads sequence 0, which simply makes it the older copy.

   Alternating rather than writing both copies each time keeps the write cost
   identical to before. The trade is that a torn write falls back to the
   previous commit instead of the one being written, which is the same
   guarantee an interrupted commit already had. */
#define XBFS_METADATA_SLOTS 2U
#define XBFS_SEQUENCE_TAIL_BYTES UINT64_C(16)
#define XBFS_JOURNAL_SECTORS UINT64_C(2)
#define XBFS_CHECKSUM_OFFSET UINT64_C(80)
#define XBFS_DATA_SECTORS 96U
#define XBFS_MAX_NODES 32U
#define XBFS_V3_PATH_MAX 96U
#define XBFS_PATH_MAX 256U
#define XBFS_FILE_MAX_BLOCKS 16U
#define XBFS_MAX_FILE_BYTES (XBFS_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE)
#define XBFS_V3_METADATA_SECTORS 32U
#define XBFS_V3_DATA_SECTORS 256U
#define XBFS_V3_MAX_NODES 64U
#define XBFS_V3_FILE_MAX_BLOCKS 16U
#define XBFS_V3_MAX_FILE_BYTES (XBFS_V3_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE)
#define XBFS_V3_VERSION 3U
#define XBFS_V4_METADATA_SECTORS 384U
#define XBFS_V4_DATA_SECTORS 4096U
#define XBFS_V4_MAX_NODES 128U
#define XBFS_V4_FILE_MAX_BLOCKS 256U
#define XBFS_V4_MAX_FILE_BYTES (XBFS_V4_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE)
#define XBFS_V4_VERSION 4U
#define XBFS_V5_METADATA_SECTORS 1280U
#define XBFS_V5_DATA_SECTORS 8192U
#define XBFS_V5_MAX_NODES 256U
#define XBFS_V5_FILE_MAX_BLOCKS 512U
#define XBFS_V5_MAX_FILE_BYTES (XBFS_V5_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE)
#define XBFS_V5_VERSION 5U
#define XBFS_MAX_OPEN_FILES 256U
#define XBFS_NODE_FREE 0U
#define XBFS_NODE_DIR 1U
#define XBFS_NODE_FILE 2U
#define XBFS_MOUNT_READ_WRITE 1U
#define XBFS_JOURNAL_EMPTY 0U
#define XBFS_JOURNAL_PENDING 1U
#define XBFS_JOURNAL_OP_WRITE_FILE 1U
#define FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define FNV1A64_PRIME UINT64_C(1099511628211)

typedef struct xaios_xbfs_node_v3 {
  uint32_t active;
  uint32_t snapshot_active;
  uint32_t type;
  uint32_t snapshot_type;
  uint64_t size;
  uint64_t content_hash;
  uint64_t generation;
  uint64_t snapshot_size;
  uint64_t snapshot_hash;
  uint64_t snapshot_generation;
  uint16_t block_count;
  uint16_t snapshot_block_count;
  uint16_t blocks[XBFS_FILE_MAX_BLOCKS];
  uint16_t snapshot_blocks[XBFS_FILE_MAX_BLOCKS];
  char path[XBFS_V3_PATH_MAX];
} xaios_xbfs_node_v3_t;

typedef struct xaios_xbfs_node_v4 {
  uint32_t active;
  uint32_t snapshot_active;
  uint32_t type;
  uint32_t snapshot_type;
  uint64_t size;
  uint64_t content_hash;
  uint64_t generation;
  uint64_t snapshot_size;
  uint64_t snapshot_hash;
  uint64_t snapshot_generation;
  uint16_t block_count;
  uint16_t snapshot_block_count;
  uint16_t blocks[XBFS_V4_FILE_MAX_BLOCKS];
  uint16_t snapshot_blocks[XBFS_V4_FILE_MAX_BLOCKS];
  char path[XBFS_PATH_MAX];
} xaios_xbfs_node_v4_t;

typedef struct xaios_xbfs_node {
  uint32_t active;
  uint32_t snapshot_active;
  uint32_t type;
  uint32_t snapshot_type;
  uint64_t size;
  uint64_t content_hash;
  uint64_t generation;
  uint64_t snapshot_size;
  uint64_t snapshot_hash;
  uint64_t snapshot_generation;
  uint16_t block_count;
  uint16_t snapshot_block_count;
  uint16_t blocks[XBFS_V5_FILE_MAX_BLOCKS];
  uint16_t snapshot_blocks[XBFS_V5_FILE_MAX_BLOCKS];
  char path[XBFS_PATH_MAX];
} xaios_xbfs_node_t;

typedef struct xaios_xbfs_disk {
  char magic[XBFS_MAGIC_LEN];
  uint32_t version;
  uint32_t sector_size;
  uint32_t metadata_sectors;
  uint32_t max_nodes;
  uint64_t start_sector;
  uint64_t journal_header_sector;
  uint64_t journal_data_sector;
  uint64_t data_start_sector;
  uint64_t data_sectors;
  uint64_t generation;
  uint64_t committed_generation;
  uint64_t checksum;
  uint8_t block_bitmap[XBFS_DATA_SECTORS];
  xaios_xbfs_node_v3_t nodes[XBFS_MAX_NODES];
} xaios_xbfs_disk_t;

typedef struct xaios_xbfs_state {
  char magic[XBFS_MAGIC_LEN];
  uint32_t version;
  uint32_t sector_size;
  uint32_t metadata_sectors;
  uint32_t max_nodes;
  uint64_t start_sector;
  uint64_t journal_header_sector;
  uint64_t journal_data_sector;
  uint64_t data_start_sector;
  uint64_t data_sectors;
  uint64_t generation;
  uint64_t committed_generation;
  uint64_t checksum;
  uint8_t block_bitmap[XBFS_V5_DATA_SECTORS];
  xaios_xbfs_node_t nodes[XBFS_V5_MAX_NODES];
} xaios_xbfs_state_t;

typedef struct xaios_xbfs_journal_v3 {
  char magic[XBFS_MAGIC_LEN];
  uint32_t version;
  uint32_t state;
  uint32_t op;
  uint32_t reserved;
  uint64_t size;
  uint64_t content_hash;
  uint64_t checksum;
  char path[XBFS_V3_PATH_MAX];
  uint8_t padding[368];
} xaios_xbfs_journal_v3_t;

typedef struct xaios_xbfs_journal {
  char magic[XBFS_MAGIC_LEN];
  uint32_t version;
  uint32_t state;
  uint32_t op;
  uint32_t reserved;
  uint64_t size;
  uint64_t content_hash;
  uint64_t checksum;
  char path[XBFS_PATH_MAX];
  uint8_t padding[208];
} xaios_xbfs_journal_t;

typedef struct xaios_xbfs_file_handle {
  uint32_t in_use;
  uint32_t flags;
  uint64_t cursor;
  char path[XBFS_PATH_MAX];
} xaios_xbfs_file_handle_t;

static xaios_xbfs_state_t g_xbfs;
static xaios_xbfs_file_handle_t g_open_files[XBFS_MAX_OPEN_FILES];
static uint32_t g_mounted;
static uint32_t g_mount_flags;
static uint64_t g_mount_count;
static uint64_t g_format_count;
static uint64_t g_boot_load_count;
static uint64_t g_write_count;
static uint64_t g_read_count;
static uint64_t g_delete_count;
static uint64_t g_commit_count;
static uint64_t g_rollback_count;
static uint64_t g_reject_count;
static uint64_t g_checksum_error_count;
static uint64_t g_allocation_count;
static uint64_t g_free_count;
static uint64_t g_directory_count;
static uint64_t g_replay_count;
static uint64_t g_journal_write_count;
static uint64_t g_multi_sector_file_count;
static uint64_t g_state_record_count;
static uint64_t g_rename_count;
static uint64_t g_list_count;
static uint64_t g_stat_count;
static uint64_t g_open_count;
static uint64_t g_close_count;

static uint64_t g_metadata_verified_checksum;
/* Slot the live metadata was loaded from; the next write targets the other. */
static uint32_t g_metadata_slot;
static uint32_t g_metadata_mirror_enabled;
static uint64_t g_metadata_sequence;
static uint64_t g_metadata_mirror_recoveries;

static uint8_t g_metadata_buffer[XBFS_V5_METADATA_SECTORS * XBFS_SECTOR_SIZE];
static xaios_spinlock_t g_xaiboot_fs_lock = XAIOS_SPINLOCK_INIT;
static uint8_t g_file_buffer[XBFS_V5_MAX_FILE_BYTES];
static char g_path_transaction[XBFS_V5_MAX_NODES][XBFS_PATH_MAX];

static uint32_t g_active_metadata_sectors = XBFS_METADATA_SECTORS;
static uint32_t g_active_max_nodes = XBFS_MAX_NODES;
static uint32_t g_active_file_max_blocks = XBFS_FILE_MAX_BLOCKS;
static uint64_t g_active_max_file_bytes = XBFS_MAX_FILE_BYTES;
static uint32_t g_active_data_sectors = XBFS_DATA_SECTORS;
static uint32_t g_active_version = XBFS_VERSION;
static uint32_t g_active_path_max = XBFS_V3_PATH_MAX;
static xaios_block_device_t *g_persistent_device;
static uint64_t g_persistent_mount_count;

static const char k_config_v1[] = "mode=full-os\nmutable=true\n";
static const char k_service_running[] =
    "service=/svc/source-index\nstate=running\n";
static const char k_service_restarting[] =
    "service=/svc/source-index\nstate=restarting\n";
static const char k_update_state[] =
    "policy=signed-update-required\nrollback=enabled\n";
static const char k_boot_log[] = "boot=ok\n";
static const char k_replayed_state[] =
    "service=/svc/replayed\nstate=recovered\n";

static xaios_status_t restore_snapshot_node(xaios_xbfs_node_t *node);

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static void set_active_v2(void) {
  g_active_metadata_sectors = XBFS_METADATA_SECTORS;
  g_active_max_nodes = XBFS_MAX_NODES;
  g_active_file_max_blocks = XBFS_FILE_MAX_BLOCKS;
  g_active_max_file_bytes = XBFS_MAX_FILE_BYTES;
  g_active_data_sectors = XBFS_DATA_SECTORS;
  g_active_version = XBFS_VERSION;
  g_active_path_max = XBFS_V3_PATH_MAX;
}

static void set_active_v3(void) {
  g_active_metadata_sectors = XBFS_V3_METADATA_SECTORS;
  g_active_max_nodes = XBFS_V3_MAX_NODES;
  g_active_file_max_blocks = XBFS_V3_FILE_MAX_BLOCKS;
  g_active_max_file_bytes = XBFS_V3_MAX_FILE_BYTES;
  g_active_data_sectors = XBFS_V3_DATA_SECTORS;
  g_active_version = XBFS_V3_VERSION;
  g_active_path_max = XBFS_V3_PATH_MAX;
}

static void set_active_v4(void) {
  g_active_metadata_sectors = XBFS_V4_METADATA_SECTORS;
  g_active_max_nodes = XBFS_V4_MAX_NODES;
  g_active_file_max_blocks = XBFS_V4_FILE_MAX_BLOCKS;
  g_active_max_file_bytes = XBFS_V4_MAX_FILE_BYTES;
  g_active_data_sectors = XBFS_V4_DATA_SECTORS;
  g_active_version = XBFS_V4_VERSION;
  g_active_path_max = XBFS_PATH_MAX;
}

static void set_active_v5(void) {
  g_active_metadata_sectors = XBFS_V5_METADATA_SECTORS;
  g_active_max_nodes = XBFS_V5_MAX_NODES;
  g_active_file_max_blocks = XBFS_V5_FILE_MAX_BLOCKS;
  g_active_max_file_bytes = XBFS_V5_MAX_FILE_BYTES;
  g_active_data_sectors = XBFS_V5_DATA_SECTORS;
  g_active_version = XBFS_V5_VERSION;
  g_active_path_max = XBFS_PATH_MAX;
}

static uint64_t active_journal_header_sector(void) {
  return XBFS_START_SECTOR + g_active_metadata_sectors;
}

static uint64_t active_journal_data_sector(void) {
  return active_journal_header_sector() + 1U;
}

static uint64_t active_data_start_sector(void) {
  return active_journal_header_sector() + XBFS_JOURNAL_SECTORS;
}

/* The mirror sits immediately after the data region, so nothing that an
   existing volume already uses moves. */
static uint64_t metadata_mirror_start_sector(void) {
  return active_data_start_sector() + g_active_data_sectors;
}

static uint64_t metadata_slot_start_sector(uint32_t slot) {
  return slot == 0U ? XBFS_START_SECTOR : metadata_mirror_start_sector();
}

static uint64_t metadata_sequence_offset(void) {
  return (uint64_t)g_active_metadata_sectors * XBFS_SECTOR_SIZE -
         XBFS_SEQUENCE_TAIL_BYTES;
}

static xaios_status_t blk_read(uint64_t sector, void *buf, uint64_t sz) {
  if (g_persistent_device != 0) {
    if (sector > UINT64_MAX / XBFS_SECTOR_SIZE) return XAIOS_ERR_INVALID;
    return block_read(g_persistent_device, sector * XBFS_SECTOR_SIZE, buf, sz);
  }
  return virtio_block_read_sector(sector, buf, sz);
}

static xaios_status_t blk_write(uint64_t sector, const void *buf, uint64_t sz) {
  if (g_persistent_device != 0) {
    if (sector > UINT64_MAX / XBFS_SECTOR_SIZE) return XAIOS_ERR_INVALID;
    return block_write(g_persistent_device, sector * XBFS_SECTOR_SIZE, buf, sz);
  }
  return virtio_block_write_sector(sector, buf, sz);
}

static xaios_status_t blk_flush(void) {
  if (g_persistent_device != 0) {
    return block_flush(g_persistent_device);
  }
  return virtio_block_flush();
}

static uint64_t blk_capacity(void) {
  if (g_persistent_device != 0) {
    return g_persistent_device->info.capacity_bytes / XBFS_SECTOR_SIZE;
  }
  return virtio_block_capacity_sectors();
}

static void reset_open_files(void) {
  for (uint32_t i = 0; i < XBFS_MAX_OPEN_FILES; ++i) {
    g_open_files[i].in_use = 0;
    g_open_files[i].flags = 0;
    g_open_files[i].cursor = 0;
    g_open_files[i].path[0] = '\0';
  }
}

static int bytes_eq(const void *a, const void *b, uint64_t size) {
  const uint8_t *left = (const uint8_t *)a;
  const uint8_t *right = (const uint8_t *)b;
  for (uint64_t i = 0; i < size; ++i) {
    if (left[i] != right[i]) {
      return 0;
    }
  }
  return 1;
}

static uint64_t cstr_len(const char *value) {
  uint64_t len = 0;
  while (value[len] != '\0') {
    ++len;
  }
  return len;
}

static int str_eq(const char *a, const char *b) {
  while (*a != '\0' && *b != '\0') {
    if (*a != *b) {
      return 0;
    }
    ++a;
    ++b;
  }
  return *a == '\0' && *b == '\0';
}

static int node_is_visible(const xaios_xbfs_node_t *node) {
  return node != 0 && (node->active != 0 || node->snapshot_active != 0);
}

static xaios_status_t append_char(char *buffer, uint64_t capacity,
                                 uint64_t *offset, char value) {
  if (buffer == 0 || offset == 0 || *offset + 1U >= capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  buffer[*offset] = value;
  ++(*offset);
  buffer[*offset] = '\0';
  return XAIOS_OK;
}

static xaios_status_t append_cstr(char *buffer, uint64_t capacity,
                                 uint64_t *offset, const char *value) {
  if (value == 0) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; value[i] != '\0'; ++i) {
    if (append_char(buffer, capacity, offset, value[i]) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t append_u32(char *buffer, uint64_t capacity,
                                uint64_t *offset, uint32_t value) {
  char digits[10];
  uint32_t count = 0;
  if (value == 0) {
    return append_char(buffer, capacity, offset, '0');
  }
  while (value != 0 && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count > 0) {
    --count;
    if (append_char(buffer, capacity, offset, digits[count]) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

static uint64_t fnv1a64(const void *buffer, uint64_t size) {
  const uint8_t *bytes = (const uint8_t *)buffer;
  uint64_t hash = FNV1A64_OFFSET;
  for (uint64_t i = 0; i < size; ++i) {
    hash ^= bytes[i];
    hash *= FNV1A64_PRIME;
  }
  return hash;
}

static uint64_t mfs_checksum(const void *data, uint64_t size) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint64_t hash = FNV1A64_OFFSET;
  for (uint64_t i = 0; i < size; ++i) {
    uint8_t value = (i >= XBFS_CHECKSUM_OFFSET &&
                     i < XBFS_CHECKSUM_OFFSET + sizeof(uint64_t))
                        ? 0U
                        : bytes[i];
    hash ^= value;
    hash *= FNV1A64_PRIME;
  }
  return hash;
}

static int metadata_header_is_blank(void) {
  for (uint32_t i = 0U; i < XBFS_SECTOR_SIZE; ++i) {
    if (g_metadata_buffer[i] != 0U) return 0;
  }
  return 1;
}

static uint64_t journal_checksum(xaios_xbfs_journal_t *journal) {
  uint64_t saved = journal->checksum;
  journal->checksum = 0;
  uint64_t checksum = fnv1a64(journal, sizeof(*journal));
  journal->checksum = saved;
  return checksum;
}

static void copy_path(char dst[XBFS_PATH_MAX], const char *src) {
  uint32_t i = 0;
  while (i + 1U < XBFS_PATH_MAX && src[i] != '\0') {
    dst[i] = src[i];
    ++i;
  }
  dst[i] = '\0';
}

static const char *basename_of(const char *path) {
  const char *base = path;
  if (path == 0) {
    return 0;
  }
  for (uint32_t i = 0; path[i] != '\0'; ++i) {
    if (path[i] == '/' && path[i + 1U] != '\0') {
      base = &path[i + 1U];
    }
  }
  return base;
}

static xaios_status_t validate_path(const char *path) {
  if (path == 0 || path[0] != '/') {
    return XAIOS_ERR_INVALID;
  }
  uint32_t len = 0;
  uint32_t last_slash = 1;
  for (uint32_t i = 0; i < g_active_path_max; ++i) {
    char c = path[i];
    if (c == '\0') {
      if (len == 0 || (len > 1U && last_slash != 0)) {
        return XAIOS_ERR_INVALID;
      }
      return XAIOS_OK;
    }
    if (c < '!' || c > '~' || c == ':' || c == '*' || c == '?' ||
        c == '"' || c == '<' || c == '>' || c == '|') {
      return XAIOS_ERR_INVALID;
    }
    if (c == '/' && last_slash != 0 && i != 0) {
      return XAIOS_ERR_INVALID;
    }
    last_slash = c == '/' ? 1U : 0U;
    ++len;
  }
  return XAIOS_ERR_INVALID;
}

static xaios_status_t normalize_path(const char *path,
                                    char normalized[XBFS_PATH_MAX]) {
  if (validate_path(path) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  copy_path(normalized, path);
  return XAIOS_OK;
}

static void parent_path_of(const char *path, char parent[XBFS_PATH_MAX]) {
  uint32_t last_slash = 0;
  for (uint32_t i = 0; i < XBFS_PATH_MAX && path[i] != '\0'; ++i) {
    if (path[i] == '/') {
      last_slash = i;
    }
  }
  if (last_slash == 0) {
    parent[0] = '/';
    parent[1] = '\0';
    return;
  }
  for (uint32_t i = 0; i < last_slash; ++i) {
    parent[i] = path[i];
  }
  parent[last_slash] = '\0';
}

static uint64_t node_count_by_type(uint32_t type) {
  uint64_t count = 0;
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    if (g_xbfs.nodes[i].active != 0 && g_xbfs.nodes[i].type == type) {
      ++count;
    }
  }
  return count;
}

static uint64_t block_count_used(void) {
  uint64_t count = 0;
  for (uint32_t i = 0; i < g_active_data_sectors; ++i) {
    if (g_xbfs.block_bitmap[i] != 0) {
      ++count;
    }
  }
  return count;
}

static xaios_xbfs_node_t *find_node(const char *path, uint32_t include_snapshot) {
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[i];
    if ((node->active != 0 ||
         (include_snapshot != 0 && node->snapshot_active != 0)) &&
        str_eq(node->path, path)) {
      return node;
    }
  }
  return 0;
}

static xaios_xbfs_node_t *find_free_node(void) {
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    if (g_xbfs.nodes[i].active == 0 && g_xbfs.nodes[i].snapshot_active == 0) {
      return &g_xbfs.nodes[i];
    }
  }
  return 0;
}

static void import_legacy_node(xaios_xbfs_node_t *node,
                               const xaios_xbfs_node_v3_t *legacy) {
  bytes_zero(node, sizeof(*node));
  node->active = legacy->active;
  node->snapshot_active = legacy->snapshot_active;
  node->type = legacy->type;
  node->snapshot_type = legacy->snapshot_type;
  node->size = legacy->size;
  node->content_hash = legacy->content_hash;
  node->generation = legacy->generation;
  node->snapshot_size = legacy->snapshot_size;
  node->snapshot_hash = legacy->snapshot_hash;
  node->snapshot_generation = legacy->snapshot_generation;
  node->block_count = legacy->block_count;
  node->snapshot_block_count = legacy->snapshot_block_count;
  bytes_copy(node->blocks, legacy->blocks, sizeof(legacy->blocks));
  bytes_copy(node->snapshot_blocks, legacy->snapshot_blocks,
             sizeof(legacy->snapshot_blocks));
  for (uint32_t i = 0; i < XBFS_V3_PATH_MAX; ++i) {
    node->path[i] = legacy->path[i];
    if (legacy->path[i] == '\0') {
      return;
    }
  }
  node->path[XBFS_V3_PATH_MAX] = '\0';
}

static void import_v4_node(xaios_xbfs_node_t *node,
                           const xaios_xbfs_node_v4_t *legacy) {
  bytes_zero(node, sizeof(*node));
  node->active = legacy->active;
  node->snapshot_active = legacy->snapshot_active;
  node->type = legacy->type;
  node->snapshot_type = legacy->snapshot_type;
  node->size = legacy->size;
  node->content_hash = legacy->content_hash;
  node->generation = legacy->generation;
  node->snapshot_size = legacy->snapshot_size;
  node->snapshot_hash = legacy->snapshot_hash;
  node->snapshot_generation = legacy->snapshot_generation;
  node->block_count = legacy->block_count;
  node->snapshot_block_count = legacy->snapshot_block_count;
  bytes_copy(node->blocks, legacy->blocks, sizeof(legacy->blocks));
  bytes_copy(node->snapshot_blocks, legacy->snapshot_blocks,
             sizeof(legacy->snapshot_blocks));
  bytes_copy(node->path, legacy->path, sizeof(legacy->path));
}

static void export_v4_node(xaios_xbfs_node_v4_t *legacy,
                           const xaios_xbfs_node_t *node) {
  bytes_zero(legacy, sizeof(*legacy));
  legacy->active = node->active;
  legacy->snapshot_active = node->snapshot_active;
  legacy->type = node->type;
  legacy->snapshot_type = node->snapshot_type;
  legacy->size = node->size;
  legacy->content_hash = node->content_hash;
  legacy->generation = node->generation;
  legacy->snapshot_size = node->snapshot_size;
  legacy->snapshot_hash = node->snapshot_hash;
  legacy->snapshot_generation = node->snapshot_generation;
  legacy->block_count = node->block_count;
  legacy->snapshot_block_count = node->snapshot_block_count;
  bytes_copy(legacy->blocks, node->blocks, sizeof(legacy->blocks));
  bytes_copy(legacy->snapshot_blocks, node->snapshot_blocks,
             sizeof(legacy->snapshot_blocks));
  bytes_copy(legacy->path, node->path, sizeof(legacy->path));
}

static void export_legacy_node(xaios_xbfs_node_v3_t *legacy,
                               const xaios_xbfs_node_t *node) {
  bytes_zero(legacy, sizeof(*legacy));
  legacy->active = node->active;
  legacy->snapshot_active = node->snapshot_active;
  legacy->type = node->type;
  legacy->snapshot_type = node->snapshot_type;
  legacy->size = node->size;
  legacy->content_hash = node->content_hash;
  legacy->generation = node->generation;
  legacy->snapshot_size = node->snapshot_size;
  legacy->snapshot_hash = node->snapshot_hash;
  legacy->snapshot_generation = node->snapshot_generation;
  legacy->block_count = node->block_count;
  legacy->snapshot_block_count = node->snapshot_block_count;
  bytes_copy(legacy->blocks, node->blocks, sizeof(legacy->blocks));
  bytes_copy(legacy->snapshot_blocks, node->snapshot_blocks,
             sizeof(legacy->snapshot_blocks));
  for (uint32_t i = 0; i + 1U < XBFS_V3_PATH_MAX && node->path[i] != '\0';
       ++i) {
    legacy->path[i] = node->path[i];
  }
}

static xaios_status_t read_metadata_slot(uint32_t slot) {
  uint8_t first_sector[XBFS_SECTOR_SIZE];
  uint64_t start = metadata_slot_start_sector(slot);
  if (blk_read(start, first_sector, sizeof(first_sector)) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint32_t version = 0;
  bytes_copy(&version, first_sector + XBFS_MAGIC_LEN, sizeof(version));
  if (version == XBFS_V5_VERSION) {
    set_active_v5();
  } else if (version == XBFS_V4_VERSION) {
    set_active_v4();
  } else if (version == XBFS_V3_VERSION) {
    set_active_v3();
  } else {
    set_active_v2();
  }
  uint32_t sectors = g_active_metadata_sectors;
  bytes_zero(g_metadata_buffer, sizeof(g_metadata_buffer));
  bytes_copy(g_metadata_buffer, first_sector, XBFS_SECTOR_SIZE);
  for (uint32_t i = 1; i < sectors; ++i) {
    if (blk_read(start + i,
                 g_metadata_buffer + i * XBFS_SECTOR_SIZE,
                 XBFS_SECTOR_SIZE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  bytes_copy(&g_metadata_sequence,
             g_metadata_buffer + metadata_sequence_offset(), 8);
  uint64_t total_bytes = (uint64_t)sectors * XBFS_SECTOR_SIZE;
  g_metadata_verified_checksum = mfs_checksum(g_metadata_buffer, total_bytes);
  bytes_zero(&g_xbfs, sizeof(g_xbfs));
  uint64_t p = 0;
  bytes_copy(g_xbfs.magic, g_metadata_buffer + p, XBFS_MAGIC_LEN); p += XBFS_MAGIC_LEN;
  bytes_copy(&g_xbfs.version, g_metadata_buffer + p, 4); p += 4;
  bytes_copy(&g_xbfs.sector_size, g_metadata_buffer + p, 4); p += 4;
  bytes_copy(&g_xbfs.metadata_sectors, g_metadata_buffer + p, 4); p += 4;
  bytes_copy(&g_xbfs.max_nodes, g_metadata_buffer + p, 4); p += 4;
  bytes_copy(&g_xbfs.start_sector, g_metadata_buffer + p, 8); p += 8;
  bytes_copy(&g_xbfs.journal_header_sector, g_metadata_buffer + p, 8); p += 8;
  bytes_copy(&g_xbfs.journal_data_sector, g_metadata_buffer + p, 8); p += 8;
  bytes_copy(&g_xbfs.data_start_sector, g_metadata_buffer + p, 8); p += 8;
  bytes_copy(&g_xbfs.data_sectors, g_metadata_buffer + p, 8); p += 8;
  bytes_copy(&g_xbfs.generation, g_metadata_buffer + p, 8); p += 8;
  bytes_copy(&g_xbfs.committed_generation, g_metadata_buffer + p, 8); p += 8;
  bytes_copy(&g_xbfs.checksum, g_metadata_buffer + p, 8); p += 8;
  bytes_copy(g_xbfs.block_bitmap, g_metadata_buffer + p,
             g_active_data_sectors);
  p += g_active_data_sectors;
  if (version == XBFS_V5_VERSION) {
    for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
      bytes_copy(&g_xbfs.nodes[i], g_metadata_buffer + p,
                 sizeof(xaios_xbfs_node_t));
      p += sizeof(xaios_xbfs_node_t);
    }
  } else if (version == XBFS_V4_VERSION) {
    for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
      xaios_xbfs_node_v4_t legacy;
      bytes_copy(&legacy, g_metadata_buffer + p, sizeof(legacy));
      p += sizeof(legacy);
      import_v4_node(&g_xbfs.nodes[i], &legacy);
    }
  } else {
    for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
      xaios_xbfs_node_v3_t legacy;
      bytes_copy(&legacy, g_metadata_buffer + p, sizeof(legacy));
      p += sizeof(legacy);
      import_legacy_node(&g_xbfs.nodes[i], &legacy);
    }
  }
  if (p > total_bytes) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

/* A slot is usable when it parses and its stored checksum matches what its
   own bytes hash to. Structural validation stays with the caller, which
   applies it to whichever slot wins. */
static int metadata_slot_probe(uint32_t slot, uint64_t *out_sequence) {
  if (read_metadata_slot(slot) != XAIOS_OK) return 0;
  if (g_xbfs.checksum != g_metadata_verified_checksum) return 0;
  if (!bytes_eq(g_xbfs.magic, XBFS_MAGIC, XBFS_MAGIC_LEN)) return 0;
  *out_sequence = g_metadata_sequence;
  return 1;
}

/* Load the newer of the two copies that is intact. */
static xaios_status_t read_metadata(void) {
  uint64_t sequence[XBFS_METADATA_SLOTS] = {0U, 0U};
  int usable[XBFS_METADATA_SLOTS] = {0, 0};
  uint32_t chosen;
  usable[0] = metadata_slot_probe(0U, &sequence[0]);
  if (g_metadata_mirror_enabled != 0U) {
    /* The mirror's position depends on the geometry, which normally comes
       from the primary. A torn primary is exactly the case this exists for,
       and its version field is unreadable then, so assume the only layout
       that ever has a mirror rather than giving up on the copy that is
       still intact. */
    if (usable[0] == 0) set_active_v5();
    if (g_active_version == XBFS_V5_VERSION) {
      usable[1] = metadata_slot_probe(1U, &sequence[1]);
    }
  }
  if (usable[0] == 0 && usable[1] == 0) {
    /* Neither copy is intact. Reload the primary so the caller sees the
       original bytes and can apply its own blank-versus-damaged judgement. */
    g_metadata_slot = 0U;
    return read_metadata_slot(0U);
  }
  if (usable[0] != 0 && usable[1] != 0) {
    chosen = sequence[1] > sequence[0] ? 1U : 0U;
  } else {
    chosen = usable[0] != 0 ? 0U : 1U;
  }
  if (usable[chosen ^ 1U] == 0) {
    ++g_metadata_mirror_recoveries;
    klog("xaibootfs: metadata slot %u unusable; continuing from slot %u seq=%lu\n",
         (unsigned)(chosen ^ 1U), (unsigned)chosen, sequence[chosen]);
  }
  g_metadata_slot = chosen;
  return read_metadata_slot(chosen);
}

static xaios_status_t write_metadata(void) {
  bytes_zero(g_metadata_buffer, sizeof(g_metadata_buffer));
  uint64_t p = 0;
  bytes_copy(g_metadata_buffer + p, g_xbfs.magic, XBFS_MAGIC_LEN); p += XBFS_MAGIC_LEN;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.version, 4); p += 4;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.sector_size, 4); p += 4;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.metadata_sectors, 4); p += 4;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.max_nodes, 4); p += 4;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.start_sector, 8); p += 8;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.journal_header_sector, 8); p += 8;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.journal_data_sector, 8); p += 8;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.data_start_sector, 8); p += 8;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.data_sectors, 8); p += 8;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.generation, 8); p += 8;
  bytes_copy(g_metadata_buffer + p, &g_xbfs.committed_generation, 8); p += 8;
  uint64_t checksum_offset = p;
  uint64_t zero_cksum = 0;
  bytes_copy(g_metadata_buffer + p, &zero_cksum, 8); p += 8;
  bytes_copy(g_metadata_buffer + p, g_xbfs.block_bitmap,
             g_active_data_sectors);
  p += g_active_data_sectors;
  if (g_active_version == XBFS_V5_VERSION) {
    for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
      bytes_copy(g_metadata_buffer + p, &g_xbfs.nodes[i],
                 sizeof(xaios_xbfs_node_t));
      p += sizeof(xaios_xbfs_node_t);
    }
  } else if (g_active_version == XBFS_V4_VERSION) {
    for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
      xaios_xbfs_node_v4_t legacy;
      export_v4_node(&legacy, &g_xbfs.nodes[i]);
      bytes_copy(g_metadata_buffer + p, &legacy, sizeof(legacy));
      p += sizeof(legacy);
    }
  } else {
    for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
      xaios_xbfs_node_v3_t legacy;
      export_legacy_node(&legacy, &g_xbfs.nodes[i]);
      bytes_copy(g_metadata_buffer + p, &legacy, sizeof(legacy));
      p += sizeof(legacy);
    }
  }
  uint64_t total_bytes = (uint64_t)g_active_metadata_sectors * XBFS_SECTOR_SIZE;
  if (p > total_bytes) {
    ++g_reject_count;
    return XAIOS_ERR_NO_MEMORY;
  }
  /* Stamp the write sequence before hashing so the checksum covers it; a
     tear that damages the sequence therefore invalidates the copy too. */
  uint64_t next_sequence = g_metadata_sequence + 1U;
  bytes_copy(g_metadata_buffer + metadata_sequence_offset(), &next_sequence, 8);
  g_xbfs.checksum = mfs_checksum(g_metadata_buffer, total_bytes);
  bytes_copy(g_metadata_buffer + checksum_offset, &g_xbfs.checksum, 8);
  /* Alternate slots so the copy being overwritten is never the one mount
     would currently choose. Without a mirror this degrades to the previous
     in-place behaviour. */
  uint32_t target = g_metadata_mirror_enabled != 0U ? (g_metadata_slot ^ 1U)
                                                    : g_metadata_slot;
  uint64_t start = metadata_slot_start_sector(target);
  uint8_t sector[XBFS_SECTOR_SIZE];
  for (uint32_t i = 0; i < g_active_metadata_sectors; ++i) {
    bytes_copy(sector, g_metadata_buffer + (uint64_t)i * XBFS_SECTOR_SIZE,
               XBFS_SECTOR_SIZE);
    if (blk_write(start + i, sector, sizeof(sector)) != XAIOS_OK) {
      klog("xaibootfs: metadata write failed sector=%lu capacity=%lu\n",
           start + i, blk_capacity());
      ++g_reject_count;
      return XAIOS_ERR_IO;
    }
  }
  xaios_status_t flushed = blk_flush();
  if (flushed != XAIOS_OK) return flushed;
  /* Only once the new copy is durable does it become the one to read, and
     the other becomes the next target. */
  g_metadata_slot = target;
  g_metadata_sequence = next_sequence;
  return XAIOS_OK;
}

static xaios_status_t clear_journal(void) {
  uint8_t sector[XBFS_SECTOR_SIZE];
  bytes_zero(sector, sizeof(sector));
  if (blk_write(active_journal_header_sector(), sector,
                                sizeof(sector)) != XAIOS_OK ||
      blk_write(active_journal_data_sector(), sector,
                                sizeof(sector)) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

static xaios_status_t read_journal(xaios_xbfs_journal_t *journal) {
  if (blk_read(active_journal_header_sector(), journal,
                               sizeof(*journal)) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

static xaios_status_t write_journal(xaios_xbfs_journal_t *journal) {
  journal->checksum = journal_checksum(journal);
  if (blk_write(active_journal_header_sector(), journal,
                                sizeof(*journal)) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  ++g_journal_write_count;
  return XAIOS_OK;
}

static uint64_t absolute_data_sector(uint16_t block_index) {
  return active_data_start_sector() + (uint64_t)block_index;
}

static xaios_status_t allocate_blocks(uint16_t count,
                                     uint16_t blocks[XBFS_V5_FILE_MAX_BLOCKS]) {
  if (count > g_active_file_max_blocks) {
    return XAIOS_ERR_INVALID;
  }
  if (g_active_data_sectors > (uint32_t)UINT16_MAX + 1U) {
    return XAIOS_ERR_INVALID;
  }
  if (count == 0) {
    return XAIOS_OK;
  }
  uint16_t found = 0;
  for (uint32_t i = 0; i < g_active_data_sectors && found < count; ++i) {
    if (g_xbfs.block_bitmap[i] == 0) {
      g_xbfs.block_bitmap[i] = 1;
      blocks[found++] = (uint16_t)i;
      ++g_allocation_count;
    }
  }
  if (found != count) {
    for (uint16_t i = 0; i < found; ++i) {
      g_xbfs.block_bitmap[blocks[i]] = 0;
      ++g_free_count;
    }
    ++g_reject_count;
    return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

static void free_blocks(uint16_t count,
                        const uint16_t blocks[XBFS_V5_FILE_MAX_BLOCKS]) {
  for (uint16_t i = 0; i < count; ++i) {
    if (blocks[i] < g_active_data_sectors && g_xbfs.block_bitmap[blocks[i]] != 0) {
      g_xbfs.block_bitmap[blocks[i]] = 0;
      ++g_free_count;
    }
  }
}

static xaios_status_t validate_disk(uint64_t expected_checksum) {
  if (!bytes_eq(g_xbfs.magic, XBFS_MAGIC, XBFS_MAGIC_LEN) ||
      g_xbfs.version != g_active_version ||
      g_xbfs.sector_size != XBFS_SECTOR_SIZE ||
      g_xbfs.metadata_sectors != g_active_metadata_sectors ||
      g_xbfs.max_nodes != g_active_max_nodes ||
      g_xbfs.start_sector != XBFS_START_SECTOR ||
      g_xbfs.journal_header_sector != active_journal_header_sector() ||
      g_xbfs.journal_data_sector != active_journal_data_sector() ||
      g_xbfs.data_start_sector != active_data_start_sector() ||
      g_xbfs.data_sectors != g_active_data_sectors) {
    return XAIOS_ERR_INVALID;
  }
  if (g_xbfs.checksum != expected_checksum) {
    ++g_checksum_error_count;
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[i];
    if ((node->active != 0 || node->snapshot_active != 0) &&
        validate_path(node->path) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (node->active != 0 &&
        node->type != XBFS_NODE_DIR && node->type != XBFS_NODE_FILE) {
      return XAIOS_ERR_INVALID;
    }
    if (node->snapshot_active != 0 &&
        node->snapshot_type != XBFS_NODE_DIR &&
        node->snapshot_type != XBFS_NODE_FILE) {
      return XAIOS_ERR_INVALID;
    }
    if (node->block_count > g_active_file_max_blocks ||
        node->snapshot_block_count > g_active_file_max_blocks ||
        node->size > g_active_max_file_bytes ||
        node->snapshot_size > g_active_max_file_bytes) {
      return XAIOS_ERR_INVALID;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t format_volume(void) {
  bytes_zero(&g_xbfs, sizeof(g_xbfs));
  bytes_copy(g_xbfs.magic, XBFS_MAGIC, XBFS_MAGIC_LEN);
  g_xbfs.version = g_active_version;
  g_xbfs.sector_size = (uint32_t)XBFS_SECTOR_SIZE;
  g_xbfs.metadata_sectors = g_active_metadata_sectors;
  g_xbfs.max_nodes = g_active_max_nodes;
  g_xbfs.start_sector = XBFS_START_SECTOR;
  g_xbfs.journal_header_sector = active_journal_header_sector();
  g_xbfs.journal_data_sector = active_journal_data_sector();
  g_xbfs.data_start_sector = active_data_start_sector();
  g_xbfs.data_sectors = g_active_data_sectors;
  g_xbfs.generation = 1;
  g_xbfs.committed_generation = 0;
  ++g_format_count;
  g_metadata_sequence = 0U;
  g_metadata_slot = 0U;
  if (clear_journal() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  /* Fill both copies at format time. Writing only one would leave a fresh
     volume with a single valid copy until its second metadata write, which
     is exactly the window this is meant to remove. The two writes alternate
     slots, so both end up holding a complete, self-consistent image. */
  if (write_metadata() != XAIOS_OK) return XAIOS_ERR_IO;
  if (g_metadata_mirror_enabled == 0U) return XAIOS_OK;
  return write_metadata();
}

static xaios_status_t migrate_volume_to_v5(void) {
  if (g_active_version == XBFS_V5_VERSION) {
    return XAIOS_OK;
  }
  uint32_t old_version = g_active_version;
  uint64_t old_data_start = g_xbfs.data_start_sector;
  uint64_t new_data_start = XBFS_START_SECTOR + XBFS_V5_METADATA_SECTORS +
                            XBFS_JOURNAL_SECTORS;
  uint8_t sector[XBFS_SECTOR_SIZE];
  for (uint32_t remaining = g_active_data_sectors; remaining != 0U;
       --remaining) {
    uint32_t i = remaining - 1U;
    if (g_xbfs.block_bitmap[i] == 0U) {
      continue;
    }
    if (blk_read(old_data_start + i, sector, sizeof(sector)) != XAIOS_OK ||
        blk_write(new_data_start + i, sector, sizeof(sector)) != XAIOS_OK) {
      ++g_reject_count;
      return XAIOS_ERR_IO;
    }
  }
  if (blk_flush() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  set_active_v5();
  g_xbfs.version = XBFS_V5_VERSION;
  g_xbfs.metadata_sectors = XBFS_V5_METADATA_SECTORS;
  g_xbfs.max_nodes = XBFS_V5_MAX_NODES;
  g_xbfs.journal_header_sector = active_journal_header_sector();
  g_xbfs.journal_data_sector = active_journal_data_sector();
  g_xbfs.data_start_sector = active_data_start_sector();
  g_xbfs.data_sectors = XBFS_V5_DATA_SECTORS;
  ++g_xbfs.generation;
  if (clear_journal() != XAIOS_OK || write_metadata() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  klog("xaibootfs: migrated v%u to v5 nodes=%u sectors=%u\n", old_version,
       g_active_max_nodes, g_active_data_sectors);
  return XAIOS_OK;
}

static xaios_status_t write_file(const char *path, const void *data,
                                uint64_t size);
static xaios_status_t create_dir(const char *path);

static xaios_status_t replay_journal(void) {
  xaios_xbfs_journal_t journal;
  if (read_journal(&journal) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  if (!bytes_eq(journal.magic, XBFS_JOURNAL_MAGIC, XBFS_MAGIC_LEN) ||
      journal.state == XBFS_JOURNAL_EMPTY) {
    return XAIOS_OK;
  }
  uint64_t expected = journal.checksum;
  if (journal.version != XBFS_JOURNAL_VERSION ||
      journal.state != XBFS_JOURNAL_PENDING ||
      journal.op != XBFS_JOURNAL_OP_WRITE_FILE ||
      journal.size == 0 || journal.size > XBFS_SECTOR_SIZE ||
      journal_checksum(&journal) != expected ||
      validate_path(journal.path) != XAIOS_OK) {
    ++g_checksum_error_count;
    ++g_reject_count;
    return clear_journal();
  }

  uint8_t sector[XBFS_SECTOR_SIZE];
  if (blk_read(active_journal_data_sector(), sector,
                               sizeof(sector)) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  if (fnv1a64(sector, journal.size) != journal.content_hash) {
    ++g_checksum_error_count;
    ++g_reject_count;
    return clear_journal();
  }
  if (write_file(journal.path, sector, journal.size) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  if (clear_journal() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  ++g_replay_count;
  klog("xaibootfs: journal replay path=%s size=%lu\n",
       journal.path, journal.size);
  return XAIOS_OK;
}

static xaios_status_t mount_volume(uint32_t mount_flags) {
  set_active_v2();
  /* The in-image volume is sized to the boot image and has no room for a
     mirror. Clear it explicitly: this global outlives a previous device
     mount, and inheriting its setting here would send writes to a slot that
     does not exist on this volume. */
  g_metadata_mirror_enabled = 0U;
  g_metadata_slot = 0U;
  if (blk_capacity() < active_data_start_sector() + g_active_data_sectors) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }

  g_mount_flags = mount_flags;
  if (read_metadata() != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  uint64_t saved_checksum = g_xbfs.checksum;
  if (validate_disk(g_metadata_verified_checksum) == XAIOS_OK &&
      saved_checksum == g_metadata_verified_checksum) {
    ++g_boot_load_count;
    klog("xaibootfs: existing state loaded files=%lu directories=%lu blocks=%lu generation=%lu committed=%lu\n",
         node_count_by_type(XBFS_NODE_FILE), node_count_by_type(XBFS_NODE_DIR),
         block_count_used(), g_xbfs.generation, g_xbfs.committed_generation);
  } else {
    klog("xaibootfs: no valid filesystem at sector=%lu; formatting\n",
         XBFS_START_SECTOR);
    if (format_volume() != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }

  g_mounted = 1;
  ++g_mount_count;
  if (replay_journal() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }

  if ((g_mount_flags & XBFS_MOUNT_READ_WRITE) != 0U) {
    xaios_xbfs_node_t *root = find_node("/", 1);
    if (root == 0) {
      if (create_dir("/") != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    } else if (root->active == 0) {
      if (restore_snapshot_node(root) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    } else if (root->type != XBFS_NODE_DIR) {
      ++g_reject_count;
      return XAIOS_ERR_INVALID;
    }
  }

  klog("xaibootfs: mounted start=%lu metadata=%lu journal=%lu data=%lu sectors=%u nodes=%u policy=%s\n",
       XBFS_START_SECTOR, (uint64_t)g_active_metadata_sectors, XBFS_JOURNAL_SECTORS,
       active_data_start_sector(), g_active_data_sectors, g_active_max_nodes,
       (g_mount_flags & XBFS_MOUNT_READ_WRITE) != 0 ? "rw" : "ro");
  return XAIOS_OK;
}

static int parent_exists_for(const char *path) {
  char parent[XBFS_PATH_MAX];
  parent_path_of(path, parent);
  if (str_eq(parent, "/")) {
    return 1;
  }
  xaios_xbfs_node_t *node = find_node(parent, 0);
  return node != 0 && node->active != 0 && node->type == XBFS_NODE_DIR;
}

static xaios_status_t create_dir(const char *path) {
  if (g_mounted == 0 || (g_mount_flags & XBFS_MOUNT_READ_WRITE) == 0 ||
      validate_path(path) != XAIOS_OK || !parent_exists_for(path)) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = find_node(path, 1);
  if (node != 0 && node->active != 0) {
    return node->type == XBFS_NODE_DIR ? XAIOS_OK : XAIOS_ERR_INVALID;
  }
  if (node == 0) {
    node = find_free_node();
  }
  if (node == 0) {
    ++g_reject_count;
    return XAIOS_ERR_NO_MEMORY;
  }
  if (node->snapshot_active == 0) {
    bytes_zero(node, sizeof(*node));
  }
  node->active = 1;
  node->type = XBFS_NODE_DIR;
  node->size = 0;
  node->content_hash = 0;
  node->generation = g_xbfs.generation++;
  node->block_count = 0;
  bytes_zero(node->blocks, sizeof(node->blocks));
  copy_path(node->path, path);
  ++g_directory_count;
  klog("xaibootfs: mkdir path=%s generation=%lu\n",
       node->path, node->generation);
  return write_metadata();
}

static xaios_status_t ensure_base_directories(void) {
  static const char *const paths[] = {
      "/", "/etc", "/bin", "/state", "/state/services",
      "/state/workspaces", "/state/updates", "/config", "/logs",
      "/workspaces", "/models", "/tmp", "/home", "/home/admin",
  };
  for (uint32_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
    if (create_dir(paths[i]) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  return XAIOS_OK;
}

static uint16_t block_count_for_size(uint64_t size) {
  return (uint16_t)((size + XBFS_SECTOR_SIZE - 1U) / XBFS_SECTOR_SIZE);
}

static xaios_status_t write_blocks(const uint16_t blocks[XBFS_V5_FILE_MAX_BLOCKS],
                                  uint16_t block_count, const void *data,
                                  uint64_t size) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint8_t sector[XBFS_SECTOR_SIZE];
  for (uint16_t i = 0; i < block_count; ++i) {
    bytes_zero(sector, sizeof(sector));
    uint64_t offset = (uint64_t)i * XBFS_SECTOR_SIZE;
    uint64_t remaining = size - offset;
    uint64_t copy = remaining < XBFS_SECTOR_SIZE ? remaining : XBFS_SECTOR_SIZE;
    bytes_copy(sector, bytes + offset, copy);
    if (blk_write(absolute_data_sector(blocks[i]), sector,
                                  sizeof(sector)) != XAIOS_OK) {
      ++g_reject_count;
      return XAIOS_ERR_IO;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t read_blocks(const uint16_t blocks[XBFS_V5_FILE_MAX_BLOCKS],
                                 uint16_t block_count, void *buffer,
                                 uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  uint8_t sector[XBFS_SECTOR_SIZE];
  for (uint16_t i = 0; i < block_count; ++i) {
    uint64_t offset = (uint64_t)i * XBFS_SECTOR_SIZE;
    uint64_t remaining = size - offset;
    uint64_t copy = remaining < XBFS_SECTOR_SIZE ? remaining : XBFS_SECTOR_SIZE;
    if (blk_read(absolute_data_sector(blocks[i]), sector,
                                 sizeof(sector)) != XAIOS_OK) {
      ++g_reject_count;
      return XAIOS_ERR_IO;
    }
    bytes_copy(bytes + offset, sector, copy);
  }
  return XAIOS_OK;
}

static xaios_status_t clone_blocks(
    const uint16_t source[XBFS_V5_FILE_MAX_BLOCKS], uint16_t block_count,
    uint16_t destination[XBFS_V5_FILE_MAX_BLOCKS]) {
  uint8_t sector[XBFS_SECTOR_SIZE];
  bytes_zero(destination,
             sizeof(uint16_t) * (uint64_t)XBFS_V5_FILE_MAX_BLOCKS);
  if (allocate_blocks(block_count, destination) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint16_t i = 0; i < block_count; ++i) {
    if (blk_read(absolute_data_sector(source[i]), sector, sizeof(sector)) !=
            XAIOS_OK ||
        blk_write(absolute_data_sector(destination[i]), sector,
                  sizeof(sector)) != XAIOS_OK) {
      free_blocks(block_count, destination);
      bytes_zero(destination,
                 sizeof(uint16_t) * (uint64_t)XBFS_V5_FILE_MAX_BLOCKS);
      ++g_reject_count;
      return XAIOS_ERR_IO;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t write_file(const char *path, const void *data,
                                uint64_t size) {
  if (g_mounted == 0 || (g_mount_flags & XBFS_MOUNT_READ_WRITE) == 0 ||
      validate_path(path) != XAIOS_OK || !parent_exists_for(path) ||
      (data == 0 && size != 0) || size > g_active_max_file_bytes) {
    klog("xaibootfs: write rejected path=%s mounted=%u flags=0x%x parent=%u size=%lu\n",
         path == 0 ? "<null>" : path, g_mounted, g_mount_flags,
         path == 0 ? 0U : (uint32_t)parent_exists_for(path), size);
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }

  uint16_t new_count = block_count_for_size(size);
  uint16_t new_blocks[XBFS_V5_FILE_MAX_BLOCKS];
  bytes_zero(new_blocks, sizeof(new_blocks));
  if (allocate_blocks(new_count, new_blocks) != XAIOS_OK) {
    klog("xaibootfs: write allocation failed path=%s blocks=%u used=%lu\n",
         path, new_count, block_count_used());
    return XAIOS_ERR_NO_MEMORY;
  }
  if (write_blocks(new_blocks, new_count, data, size) != XAIOS_OK) {
    klog("xaibootfs: write block IO failed path=%s blocks=%u\n",
         path, new_count);
    free_blocks(new_count, new_blocks);
    return XAIOS_ERR_IO;
  }

  xaios_xbfs_node_t *node = find_node(path, 1);
  if (node != 0 && node->active != 0 && node->type != XBFS_NODE_FILE) {
    klog("xaibootfs: write rejected existing non-file path=%s type=%u\n",
         path, node->type);
    free_blocks(new_count, new_blocks);
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  if (node == 0) {
    node = find_free_node();
  }
  if (node == 0) {
    klog("xaibootfs: write no free node path=%s files=%lu directories=%lu\n",
         path, node_count_by_type(XBFS_NODE_FILE),
         node_count_by_type(XBFS_NODE_DIR));
    free_blocks(new_count, new_blocks);
    ++g_reject_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  if (node->active != 0 && node->type == XBFS_NODE_FILE) {
    free_blocks(node->block_count, node->blocks);
  }
  node->active = 1;
  node->type = XBFS_NODE_FILE;
  node->size = size;
  node->content_hash = fnv1a64(data, size);
  node->generation = g_xbfs.generation++;
  node->block_count = new_count;
  copy_path(node->path, path);
  bytes_zero(node->blocks, sizeof(node->blocks));
  bytes_copy(node->blocks, new_blocks, sizeof(new_blocks));
  if (new_count > 1U) {
    ++g_multi_sector_file_count;
  }
  ++g_write_count;
  klog("xaibootfs: write path=%s size=%lu blocks=%u generation=%lu\n",
       node->path, node->size, node->block_count, node->generation);
  return write_metadata();
}

static xaios_status_t read_file(const char *path, void *buffer,
                               uint64_t buffer_size, uint64_t *out_size) {
  if (g_mounted == 0 || validate_path(path) != XAIOS_OK || buffer == 0 ||
      out_size == 0) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = find_node(path, 0);
  if (node == 0 || node->active == 0 || node->type != XBFS_NODE_FILE ||
      node->size > buffer_size) {
    ++g_reject_count;
    return XAIOS_ERR_NOT_FOUND;
  }
  if (read_blocks(node->blocks, node->block_count, buffer, node->size) !=
      XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  if (fnv1a64(buffer, node->size) != node->content_hash) {
    ++g_checksum_error_count;
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  *out_size = node->size;
  ++g_read_count;
  klog("xaibootfs: read path=%s size=%lu blocks=%u generation=%lu\n",
       node->path, node->size, node->block_count, node->generation);
  return XAIOS_OK;
}

static int has_active_children(const char *path) {
  uint64_t parent_len = cstr_len(path);
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[i];
    if (node->active == 0 || str_eq(node->path, path)) {
      continue;
    }
    if (bytes_eq(node->path, path, parent_len) && node->path[parent_len] == '/') {
      return 1;
    }
  }
  return 0;
}

static int path_is_at_or_below(const char *path, const char *root) {
  uint64_t root_len = cstr_len(root);
  return str_eq(path, root) ||
         (bytes_eq(path, root, root_len) && path[root_len] == '/');
}

static xaios_status_t delete_node(const char *path) {
  if (g_mounted == 0 || (g_mount_flags & XBFS_MOUNT_READ_WRITE) == 0 ||
      validate_path(path) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = find_node(path, 0);
  if (node == 0 || node->active == 0) {
    ++g_reject_count;
    return XAIOS_ERR_NOT_FOUND;
  }
  if (node->type == XBFS_NODE_DIR && has_active_children(path)) {
    ++g_reject_count;
    return XAIOS_ERR_BUSY;
  }
  if (node->type == XBFS_NODE_FILE) {
    free_blocks(node->block_count, node->blocks);
    node->block_count = 0;
  }
  node->active = 0;
  node->generation = g_xbfs.generation++;
  ++g_delete_count;
  klog("xaibootfs: delete path=%s generation=%lu\n",
       node->path, node->generation);
  return write_metadata();
}

static xaios_status_t delete_tree(const char *path) {
  char normalized[XBFS_PATH_MAX];
  if (g_mounted == 0 || (g_mount_flags & XBFS_MOUNT_READ_WRITE) == 0 ||
      normalize_path(path, normalized) != XAIOS_OK ||
      str_eq(normalized, "/")) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *root = find_node(normalized, 0);
  if (root == 0 || root->active == 0) {
    ++g_reject_count;
    return XAIOS_ERR_NOT_FOUND;
  }
  uint32_t deleted = 0;
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[i];
    if (node->active == 0 || !path_is_at_or_below(node->path, normalized)) {
      continue;
    }
    if (node->type == XBFS_NODE_FILE) {
      free_blocks(node->block_count, node->blocks);
      node->block_count = 0;
      bytes_zero(node->blocks, sizeof(node->blocks));
    }
    node->active = 0;
    node->generation = g_xbfs.generation++;
    ++deleted;
  }
  for (uint32_t i = 0; i < XBFS_MAX_OPEN_FILES; ++i) {
    if (g_open_files[i].in_use != 0 &&
        path_is_at_or_below(g_open_files[i].path, normalized)) {
      g_open_files[i].in_use = 0;
      g_open_files[i].path[0] = '\0';
    }
  }
  g_delete_count += deleted;
  klog("xaibootfs: delete-tree path=%s nodes=%u generation=%lu\n",
       normalized, deleted, g_xbfs.generation);
  return write_metadata();
}

static xaios_status_t rename_node(const char *old_path, const char *new_path) {
  char normalized_old[XBFS_PATH_MAX];
  char normalized_new[XBFS_PATH_MAX];
  if (g_mounted == 0 || (g_mount_flags & XBFS_MOUNT_READ_WRITE) == 0 ||
      normalize_path(old_path, normalized_old) != XAIOS_OK ||
      normalize_path(new_path, normalized_new) != XAIOS_OK ||
      !parent_exists_for(normalized_new)) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = find_node(normalized_old, 0);
  if (node == 0 || node->active == 0) {
    ++g_reject_count;
    return XAIOS_ERR_NOT_FOUND;
  }
  if (find_node(normalized_new, 0) != 0) {
    ++g_reject_count;
    return XAIOS_ERR_BUSY;
  }
  if (str_eq(normalized_old, "/") ||
      (node->type == XBFS_NODE_DIR &&
       path_is_at_or_below(normalized_new, normalized_old))) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }

  uint64_t old_len = cstr_len(normalized_old);
  uint64_t new_len = cstr_len(normalized_new);
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    g_path_transaction[i][0] = '\0';
    xaios_xbfs_node_t *candidate = &g_xbfs.nodes[i];
    if (candidate->active == 0 ||
        !path_is_at_or_below(candidate->path, normalized_old)) {
      continue;
    }
    const char *suffix = candidate->path + old_len;
    uint64_t suffix_len = cstr_len(suffix);
    if (new_len + suffix_len + 1U > g_active_path_max) {
      ++g_reject_count;
      return XAIOS_ERR_INVALID;
    }
    copy_path(g_path_transaction[i], normalized_new);
    bytes_copy(g_path_transaction[i] + new_len, suffix, suffix_len + 1U);
    if (validate_path(g_path_transaction[i]) != XAIOS_OK) {
      ++g_reject_count;
      return XAIOS_ERR_INVALID;
    }
  }
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    if (g_path_transaction[i][0] == '\0') {
      continue;
    }
    for (uint32_t j = 0; j < g_active_max_nodes; ++j) {
      if (g_path_transaction[j][0] == '\0' && g_xbfs.nodes[j].active != 0 &&
          str_eq(g_path_transaction[i], g_xbfs.nodes[j].path)) {
        ++g_reject_count;
        return XAIOS_ERR_BUSY;
      }
    }
  }
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    if (g_path_transaction[i][0] != '\0') {
      copy_path(g_xbfs.nodes[i].path, g_path_transaction[i]);
      g_xbfs.nodes[i].generation = g_xbfs.generation++;
    }
  }
  for (uint32_t i = 0; i < XBFS_MAX_OPEN_FILES; ++i) {
    if (g_open_files[i].in_use == 0 ||
        !path_is_at_or_below(g_open_files[i].path, normalized_old)) {
      continue;
    }
    char suffix[XBFS_PATH_MAX];
    copy_path(suffix, g_open_files[i].path + old_len);
    copy_path(g_open_files[i].path, normalized_new);
    bytes_copy(g_open_files[i].path + new_len, suffix,
               cstr_len(suffix) + 1U);
  }
  ++g_rename_count;
  klog("xaibootfs: rename old=%s new=%s generation=%lu\n",
       normalized_old, normalized_new, g_xbfs.generation);
  return write_metadata();
}

static xaios_status_t stat_node(const char *path, xaios_xbfs_stat_t *stat) {
  char normalized[XBFS_PATH_MAX];
  if (stat == 0 || normalize_path(path, normalized) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = find_node(normalized, 1);
  if (!node_is_visible(node)) {
    ++g_reject_count;
    return XAIOS_ERR_NOT_FOUND;
  }
  stat->type = node->type;
  stat->block_count = node->block_count;
  stat->size = node->size;
  stat->generation = node->generation;
  stat->content_hash = node->content_hash;
  ++g_stat_count;
  klog("xaibootfs: stat path=%s type=%u size=%lu generation=%lu\n",
       normalized, stat->type, stat->size, stat->generation);
  return XAIOS_OK;
}

static int direct_child_of(const char *parent, const char *child,
                           const char **name) {
  uint64_t parent_len = cstr_len(parent);
  if (str_eq(parent, "/")) {
    if (child[0] != '/' || child[1] == '\0') {
      return 0;
    }
    const char *tail = &child[1];
    for (uint64_t i = 0; tail[i] != '\0'; ++i) {
      if (tail[i] == '/') {
        return 0;
      }
    }
    *name = tail;
    return 1;
  }
  if (!bytes_eq(parent, child, parent_len) || child[parent_len] != '/') {
    return 0;
  }
  const char *tail = &child[parent_len + 1U];
  if (*tail == '\0') {
    return 0;
  }
  for (uint64_t i = 0; tail[i] != '\0'; ++i) {
    if (tail[i] == '/') {
      return 0;
    }
  }
  *name = tail;
  return 1;
}

static xaios_status_t list_dir(const char *path, char *buffer,
                              uint64_t buffer_size, uint64_t *out_size) {
  char normalized[XBFS_PATH_MAX];
  uint64_t offset = 0;
  xaios_status_t append_status = XAIOS_OK;
  if (buffer == 0 || out_size == 0 || buffer_size == 0 ||
      normalize_path(path, normalized) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }

  xaios_xbfs_node_t *dir = find_node(normalized, 1);
  if (!node_is_visible(dir) || dir->type != XBFS_NODE_DIR) {
    if (!str_eq(normalized, "/")) {
      ++g_reject_count;
      return XAIOS_ERR_NOT_FOUND;
    }
  }

  buffer[0] = '\0';
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[i];
    const char *name = 0;
    if (!node_is_visible(node) || str_eq(node->path, normalized) ||
        !direct_child_of(normalized, node->path, &name)) {
      continue;
    }
    append_status = append_cstr(buffer, buffer_size, &offset, name);
    if (append_status == XAIOS_OK) {
      append_status = append_char(buffer, buffer_size, &offset, '\n');
    }
    if (append_status != XAIOS_OK) {
      if (out_size != 0) {
        *out_size = offset;
      }
      ++g_reject_count;
      return append_status;
    }
  }

  if (str_eq(normalized, "/") && offset == 0U) {
    ++g_reject_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  *out_size = offset;
  ++g_list_count;
  klog("xaibootfs: list path=%s bytes=%lu\n", normalized, offset);
  return XAIOS_OK;
}

static xaios_status_t commit_snapshot(const char *label) {
  (void)label;
  if (g_mounted == 0 || (g_mount_flags & XBFS_MOUNT_READ_WRITE) == 0) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[i];
    if (node->snapshot_active != 0 && node->snapshot_type == XBFS_NODE_FILE) {
      free_blocks(node->snapshot_block_count, node->snapshot_blocks);
    }
    node->snapshot_active = 0;
    node->snapshot_type = XBFS_NODE_FREE;
    node->snapshot_size = 0;
    node->snapshot_hash = 0;
    node->snapshot_generation = 0;
    node->snapshot_block_count = 0;
    bytes_zero(node->snapshot_blocks, sizeof(node->snapshot_blocks));
    if (node->active == 0) {
      continue;
    }
    node->snapshot_active = 1;
    node->snapshot_type = node->type;
    node->snapshot_size = node->size;
    node->snapshot_hash = node->content_hash;
    node->snapshot_generation = node->generation;
    if (node->type == XBFS_NODE_FILE) {
      uint16_t snapshot_blocks[XBFS_V5_FILE_MAX_BLOCKS];
      bytes_zero(snapshot_blocks, sizeof(snapshot_blocks));
      if (clone_blocks(node->blocks, node->block_count, snapshot_blocks) !=
          XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      node->snapshot_block_count = node->block_count;
      bytes_copy(node->snapshot_blocks, snapshot_blocks,
                 sizeof(snapshot_blocks));
    }
  }
  g_xbfs.committed_generation = g_xbfs.generation;
  ++g_commit_count;
  klog("xaibootfs: snapshot committed generation=%lu files=%lu directories=%lu blocks=%lu\n",
       g_xbfs.committed_generation, node_count_by_type(XBFS_NODE_FILE),
       node_count_by_type(XBFS_NODE_DIR), block_count_used());
  return write_metadata();
}

static xaios_status_t restore_snapshot_node(xaios_xbfs_node_t *node) {
  if (node->snapshot_active == 0) {
    return XAIOS_OK;
  }
  if (node->active != 0 && node->type == XBFS_NODE_FILE) {
    free_blocks(node->block_count, node->blocks);
  }
  node->active = 1;
  node->type = node->snapshot_type;
  node->size = node->snapshot_size;
  node->content_hash = node->snapshot_hash;
  node->generation = node->snapshot_generation;
  node->block_count = 0;
  bytes_zero(node->blocks, sizeof(node->blocks));
  if (node->snapshot_type == XBFS_NODE_FILE) {
    uint16_t restored_blocks[XBFS_V5_FILE_MAX_BLOCKS];
    bytes_zero(restored_blocks, sizeof(restored_blocks));
    if (clone_blocks(node->snapshot_blocks, node->snapshot_block_count,
                     restored_blocks) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    node->block_count = node->snapshot_block_count;
    bytes_copy(node->blocks, restored_blocks, sizeof(restored_blocks));
  }
  return XAIOS_OK;
}

static xaios_status_t rollback_snapshot(void) {
  if (g_mounted == 0 || (g_mount_flags & XBFS_MOUNT_READ_WRITE) == 0) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[i];
    if (node->snapshot_active == 0 && node->active != 0 &&
        node->generation >= g_xbfs.committed_generation) {
      if (node->type == XBFS_NODE_FILE) {
        free_blocks(node->block_count, node->blocks);
      }
      node->active = 0;
      node->block_count = 0;
      bytes_zero(node->blocks, sizeof(node->blocks));
    }
  }
  for (uint32_t pass = 0; pass < 2U; ++pass) {
    for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
      xaios_xbfs_node_t *node = &g_xbfs.nodes[i];
      if (node->snapshot_active == 0) {
        continue;
      }
      if ((pass == 0 && node->snapshot_type == XBFS_NODE_DIR) ||
          (pass == 1 && node->snapshot_type == XBFS_NODE_FILE)) {
        if (restore_snapshot_node(node) != XAIOS_OK) {
          return XAIOS_ERR_IO;
        }
      }
    }
  }
  ++g_xbfs.generation;
  ++g_rollback_count;
  klog("xaibootfs: snapshot rollback committed=%lu files=%lu directories=%lu blocks=%lu\n",
       g_xbfs.committed_generation, node_count_by_type(XBFS_NODE_FILE),
       node_count_by_type(XBFS_NODE_DIR), block_count_used());
  return write_metadata();
}

static xaios_status_t write_pending_journal_file(const char *path,
                                                const void *data,
                                                uint64_t size) {
  if (validate_path(path) != XAIOS_OK || data == 0 || size == 0 ||
      size > XBFS_SECTOR_SIZE) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint8_t sector[XBFS_SECTOR_SIZE];
  bytes_zero(sector, sizeof(sector));
  bytes_copy(sector, data, size);
  if (blk_write(active_journal_data_sector(), sector,
                                sizeof(sector)) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  xaios_xbfs_journal_t journal;
  bytes_zero(&journal, sizeof(journal));
  bytes_copy(journal.magic, XBFS_JOURNAL_MAGIC, XBFS_MAGIC_LEN);
  journal.version = XBFS_JOURNAL_VERSION;
  journal.state = XBFS_JOURNAL_PENDING;
  journal.op = XBFS_JOURNAL_OP_WRITE_FILE;
  journal.size = size;
  journal.content_hash = fnv1a64(data, size);
  copy_path(journal.path, path);
  klog("xaibootfs: journal pending path=%s size=%lu\n", path, size);
  return write_journal(&journal);
}

static xaios_status_t xaiboot_fs_record_service_state_locked(const char *name, const char *state) {
  char path[XBFS_PATH_MAX];
  char record[256];
  uint64_t path_offset = 0;
  uint64_t record_offset = 0;
  const char *base = basename_of(name);
  bytes_zero(path, sizeof(path));
  bytes_zero(record, sizeof(record));
  if (base == 0 || *base == '\0' || state == 0 ||
      append_cstr(path, sizeof(path), &path_offset, "/state/services/") !=
          XAIOS_OK ||
      append_cstr(path, sizeof(path), &path_offset, base) != XAIOS_OK ||
      append_cstr(path, sizeof(path), &path_offset, ".state") != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "service=") !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, name) != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "\nstate=") !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, state) != XAIOS_OK ||
      append_char(record, sizeof(record), &record_offset, '\n') != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = write_file(path, record, record_offset + 1U);
  if (status == XAIOS_OK) {
    ++g_state_record_count;
  }
  return status;
}

static xaios_status_t xaiboot_fs_record_workspace_state_locked(uint32_t workspace_id, const char *revision) {
  char path[XBFS_PATH_MAX];
  char record[256];
  uint64_t path_offset = 0;
  uint64_t record_offset = 0;
  bytes_zero(path, sizeof(path));
  bytes_zero(record, sizeof(record));
  if (revision == 0 ||
      append_cstr(path, sizeof(path), &path_offset, "/state/workspaces/workspace-") !=
          XAIOS_OK ||
      append_u32(path, sizeof(path), &path_offset, workspace_id) != XAIOS_OK ||
      append_cstr(path, sizeof(path), &path_offset, ".state") != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "workspace=") !=
          XAIOS_OK ||
      append_u32(record, sizeof(record), &record_offset, workspace_id) !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset,
                  "\npath=/repo/workspaces/source-index\nrevision=") !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, revision) !=
          XAIOS_OK ||
      append_char(record, sizeof(record), &record_offset, '\n') != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = write_file(path, record, record_offset + 1U);
  if (status == XAIOS_OK) {
    ++g_state_record_count;
  }
  return status;
}

static xaios_status_t xaiboot_fs_record_update_state_locked(const char *policy) {
  char record[256];
  uint64_t record_offset = 0;
  bytes_zero(record, sizeof(record));
  if (policy == 0 ||
      append_cstr(record, sizeof(record), &record_offset, "policy=") !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, policy) != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset,
                  "\nrollback=enabled\n") != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = write_file("/state/updates/update.state",
                                    record, record_offset + 1U);
  if (status == XAIOS_OK) {
    ++g_state_record_count;
  }
  return status;
}

static xaios_status_t xaiboot_fs_record_update_transaction_locked(uint32_t generation, const char *state, const char *target, const char *rollback_label) {
  char record[256];
  uint64_t record_offset = 0;
  bytes_zero(record, sizeof(record));
  if (state == 0 || target == 0 || rollback_label == 0 ||
      append_cstr(record, sizeof(record), &record_offset,
                  "policy=signed-update-required\n") != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset,
                  "transaction_generation=") != XAIOS_OK ||
      append_u32(record, sizeof(record), &record_offset, generation) !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "\nstate=") !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, state) != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "\ntarget=") !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, target) != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "\nrollback=") !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, rollback_label) !=
          XAIOS_OK ||
      append_char(record, sizeof(record), &record_offset, '\n') != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = write_file("/state/updates/update.state",
                                    record, record_offset + 1U);
  if (status == XAIOS_OK) {
    ++g_state_record_count;
  }
  return status;
}

static xaios_status_t xaiboot_fs_record_admin_status_locked(const char *service, const char *state, uint32_t starts, uint32_t restarts, uint32_t logs) {
  char record[256];
  uint64_t record_offset = 0;
  bytes_zero(record, sizeof(record));
  if (service == 0 || state == 0 ||
      append_cstr(record, sizeof(record), &record_offset,
                  "admin=ssh-only\nservice=") != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, service) !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "\nstate=") !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, state) != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "\nstarts=") !=
          XAIOS_OK ||
      append_u32(record, sizeof(record), &record_offset, starts) != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "\nrestarts=") !=
          XAIOS_OK ||
      append_u32(record, sizeof(record), &record_offset, restarts) !=
          XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset, "\nlogs=") !=
          XAIOS_OK ||
      append_u32(record, sizeof(record), &record_offset, logs) != XAIOS_OK ||
      append_cstr(record, sizeof(record), &record_offset,
                  "\nremote_safe=allowlist\n") != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status =
      write_file("/state/services/admin.state", record, record_offset + 1U);
  if (status == XAIOS_OK) {
    ++g_state_record_count;
  }
  return status;
}

static xaios_status_t xaiboot_fs_commit_locked(const char *label) {
  return commit_snapshot(label);
}

static xaios_status_t xaiboot_fs_rollback_locked(void) {
  return rollback_snapshot();
}

static xaios_status_t xaiboot_fs_mkdir_locked(const char *path) {
  return create_dir(path);
}

static xaios_status_t xaiboot_fs_write_locked(const char *path, const void *data, uint64_t size) {
  return write_file(path, data, size);
}

static xaios_status_t xaiboot_fs_read_locked(const char *path, void *buffer, uint64_t buffer_size, uint64_t *out_size) {
  return read_file(path, buffer, buffer_size, out_size);
}

static xaios_status_t xaiboot_fs_delete_locked(const char *path) {
  return delete_node(path);
}

static xaios_status_t xaiboot_fs_delete_tree_locked(const char *path) {
  return delete_tree(path);
}

static xaios_status_t xaiboot_fs_rename_locked(const char *old_path, const char *new_path) {
  return rename_node(old_path, new_path);
}

static xaios_status_t xaiboot_fs_stat_locked(const char *path, xaios_xbfs_stat_t *stat) {
  return stat_node(path, stat);
}

static xaios_status_t xaiboot_fs_list_locked(const char *path, char *buffer, uint64_t buffer_size, uint64_t *out_size) {
  return list_dir(path, buffer, buffer_size, out_size);
}

static xaios_xbfs_file_handle_t *handle_for_fd(uint32_t fd) {
  if (fd == 0 || fd > XBFS_MAX_OPEN_FILES) {
    return 0;
  }
  xaios_xbfs_file_handle_t *handle = &g_open_files[fd - 1U];
  return handle->in_use != 0 ? handle : 0;
}

static int64_t xaiboot_fs_open_locked(const char *path, uint32_t flags) {
  char normalized[XBFS_PATH_MAX];
  if (normalize_path(path, normalized) != XAIOS_OK ||
      (flags & (XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE)) == 0 ||
      (flags & ~(XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE |
                 XAIOS_XBFS_OPEN_CREATE | XAIOS_XBFS_OPEN_TRUNCATE)) != 0) {
    ++g_reject_count;
    return (int64_t)XAIOS_ERR_INVALID;
  }

  xaios_xbfs_node_t *node = find_node(normalized, 0);
  if (node == 0 || node->active == 0) {
    if ((flags & XAIOS_XBFS_OPEN_CREATE) == 0) {
      ++g_reject_count;
      return (int64_t)XAIOS_ERR_NOT_FOUND;
    }
    if ((flags & XAIOS_XBFS_OPEN_WRITE) == 0 || !parent_exists_for(normalized)) {
      ++g_reject_count;
      return (int64_t)XAIOS_ERR_INVALID;
    }
  } else if (node->type != XBFS_NODE_FILE) {
    ++g_reject_count;
    return (int64_t)XAIOS_ERR_INVALID;
  }

  if ((flags & XAIOS_XBFS_OPEN_CREATE) != 0 && node == 0) {
    if (write_file(normalized, 0, 0) != XAIOS_OK) {
      return (int64_t)XAIOS_ERR_IO;
    }
    node = find_node(normalized, 0);
  }
  if ((flags & XAIOS_XBFS_OPEN_TRUNCATE) != 0 && node != 0 &&
      node->active != 0) {
    if (write_file(normalized, 0, 0) != XAIOS_OK) {
      return (int64_t)XAIOS_ERR_IO;
    }
  }

  for (uint32_t i = 0; i < XBFS_MAX_OPEN_FILES; ++i) {
    if (g_open_files[i].in_use == 0) {
      g_open_files[i].in_use = 1;
      g_open_files[i].flags = flags;
      g_open_files[i].cursor = 0;
      copy_path(g_open_files[i].path, normalized);
      ++g_open_count;
      klog("xaibootfs: open fd=%u path=%s flags=0x%x\n", i + 1U,
           normalized, flags);
      return (int64_t)(i + 1U);
    }
  }

  ++g_reject_count;
  return (int64_t)XAIOS_ERR_NO_MEMORY;
}

static int64_t xaiboot_fs_read_fd_locked(uint32_t fd, void *buffer, uint64_t size) {
  xaios_xbfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0 || buffer == 0 || size == 0 ||
      (handle->flags & XAIOS_XBFS_OPEN_READ) == 0) {
    ++g_reject_count;
    return (int64_t)XAIOS_ERR_INVALID;
  }
  uint64_t file_size = 0;
  xaios_status_t read_status =
      read_file(handle->path, g_file_buffer, sizeof(g_file_buffer), &file_size);
  if (read_status != XAIOS_OK) {
    klog("xaibootfs: read-fd failed fd=%u path=%s status=%d\n", fd,
         handle->path, (int)read_status);
    return (int64_t)XAIOS_ERR_IO;
  }
  if (handle->cursor >= file_size) {
    return 0;
  }
  uint64_t available = file_size - handle->cursor;
  uint64_t copy = available < size ? available : size;
  bytes_copy(buffer, g_file_buffer + handle->cursor, copy);
  handle->cursor += copy;
  klog("xaibootfs: read-fd fd=%u bytes=%lu cursor=%lu\n", fd, copy,
       handle->cursor);
  return (int64_t)copy;
}

static int64_t xaiboot_fs_write_fd_locked(uint32_t fd, const void *buffer, uint64_t size) {
  xaios_xbfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0 || buffer == 0 || size == 0 ||
      (handle->flags & XAIOS_XBFS_OPEN_WRITE) == 0 ||
      handle->cursor > g_active_max_file_bytes ||
      size > g_active_max_file_bytes - handle->cursor) {
    ++g_reject_count;
    return (int64_t)XAIOS_ERR_INVALID;
  }

  uint64_t file_size = 0;
  if (find_node(handle->path, 0) != 0) {
    if (read_file(handle->path, g_file_buffer, sizeof(g_file_buffer), &file_size) !=
        XAIOS_OK) {
      return (int64_t)XAIOS_ERR_IO;
    }
  }
  uint64_t new_size = handle->cursor + size;
  if (new_size < file_size) {
    new_size = file_size;
  }
  /* Only a cursor seeked past the end leaves a hole, and only that hole has to
     read back as zeros. Everything below file_size was just read back, and
     everything from the cursor on is about to be overwritten, so clearing the
     whole buffer meant a 256 KiB memset for every append -- the audit log paid
     roughly 21 MiB of it to write 3 KiB of lines. Nothing above new_size is
     written out, so stale bytes there cannot reach the volume. */
  if (handle->cursor > file_size) {
    bytes_zero(g_file_buffer + file_size, handle->cursor - file_size);
  }
  bytes_copy(g_file_buffer + handle->cursor, buffer, size);
  if (write_file(handle->path, g_file_buffer, new_size) != XAIOS_OK) {
    return (int64_t)XAIOS_ERR_IO;
  }
  handle->cursor += size;
  klog("xaibootfs: write-fd fd=%u bytes=%lu cursor=%lu\n", fd, size,
       handle->cursor);
  return (int64_t)size;
}

static xaios_status_t xaiboot_fs_seek_locked(uint32_t fd, uint64_t offset) {
  xaios_xbfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0 || offset > g_active_max_file_bytes) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  handle->cursor = offset;
  return XAIOS_OK;
}

static xaios_status_t xaiboot_fs_close_locked(uint32_t fd) {
  xaios_xbfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  klog("xaibootfs: close fd=%u path=%s\n", fd, handle->path);
  handle->in_use = 0;
  handle->flags = 0;
  handle->cursor = 0;
  handle->path[0] = '\0';
  ++g_close_count;
  return XAIOS_OK;
}

uint64_t xaiboot_fs_mount_count(void) { return g_mount_count; }
uint64_t xaiboot_fs_metadata_recoveries(void) {
  return g_metadata_mirror_recoveries;
}

uint64_t xaiboot_fs_format_count(void) { return g_format_count; }
uint64_t xaiboot_fs_boot_load_count(void) { return g_boot_load_count; }
uint64_t xaiboot_fs_file_count(void) { return node_count_by_type(XBFS_NODE_FILE); }
uint64_t xaiboot_fs_directory_count(void) { return node_count_by_type(XBFS_NODE_DIR); }
uint64_t xaiboot_fs_write_count(void) { return g_write_count; }
uint64_t xaiboot_fs_read_count(void) { return g_read_count; }
uint64_t xaiboot_fs_delete_count(void) { return g_delete_count; }
uint64_t xaiboot_fs_commit_count(void) { return g_commit_count; }
uint64_t xaiboot_fs_rollback_count(void) { return g_rollback_count; }
uint64_t xaiboot_fs_reject_count(void) { return g_reject_count; }
uint64_t xaiboot_fs_checksum_error_count(void) { return g_checksum_error_count; }
uint64_t xaiboot_fs_allocation_count(void) { return g_allocation_count; }
uint64_t xaiboot_fs_free_count(void) { return g_free_count; }
uint64_t xaiboot_fs_replay_count(void) { return g_replay_count; }
uint64_t xaiboot_fs_journal_write_count(void) { return g_journal_write_count; }
uint64_t xaiboot_fs_multi_sector_file_count(void) { return g_multi_sector_file_count; }
uint64_t xaiboot_fs_state_record_count(void) { return g_state_record_count; }
uint64_t xaiboot_fs_rename_count(void) { return g_rename_count; }
uint64_t xaiboot_fs_list_count(void) { return g_list_count; }
uint64_t xaiboot_fs_stat_count(void) { return g_stat_count; }
uint64_t xaiboot_fs_open_count(void) { return g_open_count; }
uint64_t xaiboot_fs_close_count(void) { return g_close_count; }
uint64_t xaiboot_fs_persistent_mount_count(void) { return g_persistent_mount_count; }

static xaios_status_t mount_failure(xaios_block_device_t *device,
                                    xaios_status_t status) {
  g_persistent_device = 0;
  g_mounted = 0;
  g_mount_flags = 0;
  set_active_v2();
  (void)block_device_close(device);
  return status;
}

static xaios_status_t xaiboot_fs_mount_device_locked(const char *identifier) {
  if (g_persistent_device != 0) return XAIOS_ERR_BUSY;
  xaios_block_device_t *device = 0;
  xaios_status_t status = block_device_open(identifier, &device);
  if (status != XAIOS_OK) {
    klog("xaibootfs: persistent block device not found id=%s\n",
         identifier != 0 ? identifier : "(null)");
    return status;
  }
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK) {
    (void)block_device_close(device);
    return XAIOS_ERR_IO;
  }
  if (info.read_only != 0U ||
      info.logical_sector_size != XBFS_SECTOR_SIZE ||
      info.capacity_bytes % XBFS_SECTOR_SIZE != 0U ||
      info.flush_supported == 0U) {
    klog("xaibootfs: device rejected id=%s sector=%lu read_only=%u flush=%u\n",
         identifier, info.logical_sector_size, info.read_only,
         info.flush_supported);
    (void)block_device_close(device);
    return XAIOS_ERR_UNSUPPORTED;
  }
  set_active_v5();
  g_metadata_slot = 0U;
  g_metadata_sequence = 0U;
  /* The mirror is optional: a volume sized exactly for the old layout keeps
     working single-copy rather than being refused. */
  g_metadata_mirror_enabled =
      info.capacity_bytes / XBFS_SECTOR_SIZE >=
              metadata_mirror_start_sector() + g_active_metadata_sectors
          ? 1U
          : 0U;
  if (info.capacity_bytes / XBFS_SECTOR_SIZE <
      active_data_start_sector() + XBFS_V5_DATA_SECTORS) {
    klog("xaibootfs: persistent disk too small capacity=%lu needed=%lu\n",
         info.capacity_bytes / XBFS_SECTOR_SIZE,
         active_data_start_sector() + XBFS_V5_DATA_SECTORS);
    set_active_v2();
    (void)block_device_close(device);
    return XAIOS_ERR_IO;
  }
  g_persistent_device = device;
  g_mounted = 0;
  g_mount_flags = 0;
  if (read_metadata() != XAIOS_OK) return mount_failure(device, XAIOS_ERR_IO);
  uint64_t saved_checksum = g_xbfs.checksum;
  uint32_t loaded_version = g_active_version;
  int valid_existing =
      validate_disk(g_metadata_verified_checksum) == XAIOS_OK &&
      saved_checksum == g_metadata_verified_checksum;
  if (valid_existing) {
    ++g_boot_load_count;
    klog("xaibootfs: persistent loaded files=%lu dirs=%lu blocks=%lu gen=%lu\n",
         node_count_by_type(XBFS_NODE_FILE), node_count_by_type(XBFS_NODE_DIR),
         block_count_used(), g_xbfs.generation);
  } else {
    if (!metadata_header_is_blank()) {
      klog("xaibootfs: persistent metadata invalid; refusing destructive format\n");
      return mount_failure(device, XAIOS_ERR_INVALID);
    }
    set_active_v5();
    klog("xaibootfs: persistent disk no valid fs; formatting v5\n");
    if (format_volume() != XAIOS_OK) {
      return mount_failure(device, XAIOS_ERR_IO);
    }
  }
  g_mounted = 1;
  g_mount_flags = XBFS_MOUNT_READ_WRITE;
  ++g_mount_count;
  ++g_persistent_mount_count;
  if (replay_journal() != XAIOS_OK) {
    return mount_failure(device, XAIOS_ERR_IO);
  }
  if (valid_existing && loaded_version != XBFS_V5_VERSION &&
      migrate_volume_to_v5() != XAIOS_OK) {
    return mount_failure(device, XAIOS_ERR_IO);
  }
  xaios_xbfs_node_t *root = find_node("/", 1);
  if (root == 0) {
    if (create_dir("/") != XAIOS_OK) {
      return mount_failure(device, XAIOS_ERR_IO);
    }
  }
  if (ensure_base_directories() != XAIOS_OK) {
    return mount_failure(device, XAIOS_ERR_IO);
  }
  klog("xaibootfs: persistent mounted v5 nodes=%u sectors=%u\n",
       g_active_max_nodes, g_active_data_sectors);
  return XAIOS_OK;
}

static xaios_status_t xaiboot_fs_mount_persistent_locked(uint32_t slot) {
  char identifier[16] = "/dev/vblk";
  uint32_t value = slot;
  uint32_t digits = 1U;
  while (value >= 10U) {
    value /= 10U;
    ++digits;
  }
  if (9U + digits + 1U > sizeof(identifier)) return XAIOS_ERR_INVALID;
  identifier[9U + digits] = '\0';
  for (uint32_t index = 0U; index < digits; ++index) {
    identifier[9U + digits - 1U - index] = (char)('0' + slot % 10U);
    slot /= 10U;
  }
  return xaiboot_fs_mount_device_locked(identifier);
}

static void fsck_count_file_blocks(
    uint16_t block_count, const uint16_t blocks[XBFS_V5_FILE_MAX_BLOCKS],
    uint8_t references[XBFS_V5_DATA_SECTORS],
    xaios_xbfs_fsck_result_t *result) {
  if (block_count > g_active_file_max_blocks) {
    ++result->errors;
    return;
  }
  for (uint16_t b = 0; b < block_count; ++b) {
    uint16_t block = blocks[b];
    if (block >= g_active_data_sectors || references[block] != 0U) {
      ++result->errors;
    } else {
      references[block] = 1U;
    }
  }
}

static xaios_xbfs_fsck_result_t xaiboot_fs_fsck_locked(void) {
  xaios_xbfs_fsck_result_t result;
  uint8_t references[XBFS_V5_DATA_SECTORS];
  bytes_zero(&result, sizeof(result));
  bytes_zero(references, sizeof(references));
  result.version = g_active_version;
  result.files = node_count_by_type(XBFS_NODE_FILE);
  result.directories = node_count_by_type(XBFS_NODE_DIR);
  result.blocks_used = block_count_used();
  result.errors = 0;

  for (uint32_t n = 0; n < g_active_max_nodes; ++n) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[n];
    if (node->active != 0 && node->type == XBFS_NODE_FILE) {
      fsck_count_file_blocks(node->block_count, node->blocks, references,
                             &result);
    }
    if (node->snapshot_active != 0 &&
        node->snapshot_type == XBFS_NODE_FILE) {
      fsck_count_file_blocks(node->snapshot_block_count,
                             node->snapshot_blocks, references, &result);
    }
  }

  for (uint32_t i = 0; i < g_active_data_sectors; ++i) {
    int in_use = g_xbfs.block_bitmap[i] != 0;
    int referenced = references[i] != 0U;
    if (in_use != referenced) {
      ++result.errors;
    }
  }
  result.valid = (result.errors == 0) ? 1U : 0U;
  klog("xaibootfs: fsck v%u files=%lu dirs=%lu blocks=%lu errors=%lu valid=%u\n",
       result.version, result.files, result.directories,
       result.blocks_used, result.errors, result.valid);
  return result;
}


/* Serialised public entry points.
   The volume is reachable from every CPU through the filesystem syscalls and
   from kernel services, yet its node table, open-file table and block bitmap
   were mutated with no mutual exclusion at all. Each entry point now runs
   under one lock. The bodies above assume the lock is already held and must
   not be called directly. xaiboot_fs_self_test stays outside deliberately: it
   drives these same entry points and runs single threaded during boot. */
xaios_status_t xaiboot_fs_record_service_state(const char *name, const char *state) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_service_state_locked(name, state);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_record_workspace_state(uint32_t workspace_id, const char *revision) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_workspace_state_locked(workspace_id, revision);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_record_update_state(const char *policy) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_update_state_locked(policy);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_record_update_transaction(uint32_t generation, const char *state, const char *target, const char *rollback_label) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_update_transaction_locked(generation, state, target, rollback_label);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_record_admin_status(const char *service, const char *state, uint32_t starts, uint32_t restarts, uint32_t logs) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_admin_status_locked(service, state, starts, restarts, logs);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_commit(const char *label) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_commit_locked(label);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_rollback(void) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_rollback_locked();
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_mkdir(const char *path) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_mkdir_locked(path);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_write(const char *path, const void *data, uint64_t size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_write_locked(path, data, size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_read(const char *path, void *buffer, uint64_t buffer_size, uint64_t *out_size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_read_locked(path, buffer, buffer_size, out_size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_delete(const char *path) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_delete_locked(path);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_delete_tree(const char *path) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_delete_tree_locked(path);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_rename(const char *old_path, const char *new_path) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_rename_locked(old_path, new_path);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_stat(const char *path, xaios_xbfs_stat_t *stat) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_stat_locked(path, stat);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_list(const char *path, char *buffer, uint64_t buffer_size, uint64_t *out_size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_list_locked(path, buffer, buffer_size, out_size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

int64_t xaiboot_fs_open(const char *path, uint32_t flags) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  int64_t result = xaiboot_fs_open_locked(path, flags);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

int64_t xaiboot_fs_read_fd(uint32_t fd, void *buffer, uint64_t size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  int64_t result = xaiboot_fs_read_fd_locked(fd, buffer, size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

int64_t xaiboot_fs_write_fd(uint32_t fd, const void *buffer, uint64_t size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  int64_t result = xaiboot_fs_write_fd_locked(fd, buffer, size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_seek(uint32_t fd, uint64_t offset) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_seek_locked(fd, offset);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_close(uint32_t fd) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_close_locked(fd);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_mount_device(const char *identifier) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_mount_device_locked(identifier);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

/* Release a mounted device, flushing first. The slot bookkeeping is reset so
   a later mount re-derives which copy is authoritative from the volume rather
   than from whatever the previous mount happened to leave behind. */
xaios_status_t xaiboot_fs_unmount(void) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  if (g_persistent_device == 0) {
    xaios_spin_unlock(&g_xaiboot_fs_lock);
    return XAIOS_ERR_INVALID;
  }
  (void)blk_flush();
  xaios_block_device_t *device = g_persistent_device;
  g_persistent_device = 0;
  g_mounted = 0;
  g_mount_flags = 0;
  g_metadata_slot = 0U;
  g_metadata_sequence = 0U;
  g_metadata_mirror_enabled = 0U;
  set_active_v2();
  (void)block_device_close(device);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return XAIOS_OK;
}

xaios_status_t xaiboot_fs_mount_persistent(uint32_t slot) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_mount_persistent_locked(slot);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_xbfs_fsck_result_t xaiboot_fs_fsck(void) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_xbfs_fsck_result_t result = xaiboot_fs_fsck_locked();
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

void xaiboot_fs_self_test(void) {
  kassert(sizeof(xaios_xbfs_journal_t) == XBFS_SECTOR_SIZE);
  kassert(sizeof(xaios_xbfs_disk_t) <= XBFS_METADATA_SECTORS * XBFS_SECTOR_SIZE);
  g_mounted = 0;
  g_mount_flags = 0;
  g_persistent_device = 0;
  set_active_v2();
  g_mount_count = 0;
  g_format_count = 0;
  g_boot_load_count = 0;
  g_write_count = 0;
  g_read_count = 0;
  g_delete_count = 0;
  g_commit_count = 0;
  g_rollback_count = 0;
  g_reject_count = 0;
  g_checksum_error_count = 0;
  g_allocation_count = 0;
  g_free_count = 0;
  g_directory_count = 0;
  g_replay_count = 0;
  g_journal_write_count = 0;
  g_multi_sector_file_count = 0;
  g_state_record_count = 0;
  g_rename_count = 0;
  g_list_count = 0;
  g_stat_count = 0;
  g_open_count = 0;
  g_close_count = 0;
  reset_open_files();

  kassert(mount_volume(XBFS_MOUNT_READ_WRITE) == XAIOS_OK);
  kassert(format_volume() == XAIOS_OK);
  kassert(ensure_base_directories() == XAIOS_OK);
  xaios_xbfs_node_t *base_node = find_node("/tmp", 1);
  kassert(base_node != 0 && base_node->type == XBFS_NODE_DIR);
  base_node = find_node("/home/admin", 1);
  kassert(base_node != 0 && base_node->type == XBFS_NODE_DIR);

  kassert(xaiboot_fs_record_service_state("/svc/source-index", "running") ==
          XAIOS_OK);
  kassert(xaiboot_fs_record_workspace_state(0, "boot") == XAIOS_OK);
  kassert(xaiboot_fs_record_update_state("signed-update-required") == XAIOS_OK);
  kassert(xaiboot_fs_record_admin_status("/svc/source-index", "running", 1, 0,
                                         0) == XAIOS_OK);
  kassert(write_file("/config/xaios.conf", k_config_v1,
                     sizeof(k_config_v1)) == XAIOS_OK);

  uint8_t large[XBFS_SECTOR_SIZE * 3U];
  for (uint64_t i = 0; i < sizeof(large); ++i) {
    large[i] = (uint8_t)('A' + (i % 23U));
  }
  kassert(write_file("/state/services/large.state", large, sizeof(large)) ==
          XAIOS_OK);

  uint8_t buffer[XBFS_MAX_FILE_BYTES];
  uint64_t size = 0;
  kassert(read_file("/state/services/large.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(large));
  kassert(bytes_eq(buffer, large, sizeof(large)) != 0);

  char listing[XAIOS_XBFS_MAX_LIST_BYTES];
  xaios_xbfs_stat_t stat;
  kassert(list_dir("/state", listing, sizeof(listing), &size) == XAIOS_OK);
  kassert(size > 0);
  kassert(stat_node("/state/services/large.state", &stat) == XAIOS_OK);
  kassert(stat.type == XBFS_NODE_FILE);
  kassert(stat.size == sizeof(large));
  kassert(rename_node("/config/xaios.conf", "/config/xaios-renamed.conf") ==
          XAIOS_OK);
  kassert(stat_node("/config/xaios-renamed.conf", &stat) == XAIOS_OK);
  kassert(read_file("/config/xaios.conf", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);

  static const char k_fd_payload[] = "fd-api=ok\n";
  int64_t fd = xaiboot_fs_open("/logs/fd-api.log",
                               XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE |
                                   XAIOS_XBFS_OPEN_CREATE);
  kassert(fd > 0);
  kassert(xaiboot_fs_write_fd((uint32_t)fd, k_fd_payload,
                              sizeof(k_fd_payload)) ==
          (int64_t)sizeof(k_fd_payload));
  kassert(xaiboot_fs_seek((uint32_t)fd, 3U) == XAIOS_OK);
  kassert(handle_for_fd((uint32_t)fd)->cursor == 3U);
  kassert(xaiboot_fs_seek((uint32_t)fd, 0U) == XAIOS_OK);
  kassert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  fd = xaiboot_fs_open("/logs/fd-api.log", XAIOS_XBFS_OPEN_READ);
  kassert(fd > 0);
  kassert(xaiboot_fs_read_fd((uint32_t)fd, buffer, sizeof(k_fd_payload)) ==
          (int64_t)sizeof(k_fd_payload));
  kassert(bytes_eq(buffer, k_fd_payload, sizeof(k_fd_payload)) != 0);
  kassert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  fd = xaiboot_fs_open("/logs/fd-api.log",
                       XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE |
                           XAIOS_XBFS_OPEN_TRUNCATE);
  kassert(fd > 0);
  kassert(stat_node("/logs/fd-api.log", &stat) == XAIOS_OK);
  kassert(stat.size == 0);
  kassert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  kassert(xaiboot_fs_open("/missing/nope", XAIOS_XBFS_OPEN_READ) ==
          (int64_t)XAIOS_ERR_NOT_FOUND);
  kassert(commit_snapshot("mfs-snapshot-v2") == XAIOS_OK);

  kassert(write_file("/state/services/source-index.state",
                     k_service_restarting,
                     sizeof(k_service_restarting)) == XAIOS_OK);
  kassert(delete_node("/state/updates/update.state") == XAIOS_OK);
  kassert(write_file("/logs/boot.log", k_boot_log, sizeof(k_boot_log)) ==
          XAIOS_OK);
  kassert(write_pending_journal_file("/state/services/replayed.state",
                                     k_replayed_state,
                                     sizeof(k_replayed_state)) == XAIOS_OK);
  g_mounted = 0;
  kassert(mount_volume(XBFS_MOUNT_READ_WRITE) == XAIOS_OK);
  kassert(read_file("/state/services/replayed.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(k_replayed_state));
  kassert(bytes_eq(buffer, k_replayed_state, sizeof(k_replayed_state)) != 0);
  xaios_xbfs_fsck_result_t snapshot_fsck = xaiboot_fs_fsck();
  kassert(snapshot_fsck.valid != 0);

  kassert(rollback_snapshot() == XAIOS_OK);
  kassert(read_file("/state/services/source-index.state", buffer,
                    sizeof(buffer), &size) == XAIOS_OK);
  kassert(size == sizeof(k_service_running));
  kassert(bytes_eq(buffer, k_service_running, sizeof(k_service_running)) != 0);
  kassert(read_file("/state/updates/update.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(k_update_state));
  kassert(bytes_eq(buffer, k_update_state, sizeof(k_update_state)) != 0);
  kassert(read_file("/logs/boot.log", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);
  kassert(read_file("/state/services/replayed.state", buffer, sizeof(buffer),
                    &size) == XAIOS_ERR_NOT_FOUND);

  kassert(write_file("/bad/missing-parent", k_config_v1,
                     sizeof(k_config_v1)) == XAIOS_ERR_INVALID);
  kassert(create_dir("/state/services/bad") == XAIOS_OK);
  kassert(delete_node("/state/services") == XAIOS_ERR_BUSY);
  uint8_t too_large[XBFS_MAX_FILE_BYTES + 1U];
  kassert(write_file("/state/services/too-large", too_large,
                     sizeof(too_large)) == XAIOS_ERR_INVALID);
  kassert(read_file("/state/missing.state", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);

  kassert(xaiboot_fs_mount_count() == 2);
  kassert(xaiboot_fs_format_count() >= 1);
  kassert(xaiboot_fs_format_count() <= 2);
  kassert(xaiboot_fs_file_count() >= 6);
  kassert(xaiboot_fs_directory_count() >= 11);
  kassert(xaiboot_fs_write_count() >= 12);
  kassert(xaiboot_fs_read_count() >= 5);
  kassert(xaiboot_fs_delete_count() == 1);
  kassert(xaiboot_fs_commit_count() == 1);
  kassert(xaiboot_fs_rollback_count() == 1);
  kassert(xaiboot_fs_replay_count() == 1);
  kassert(xaiboot_fs_journal_write_count() == 1);
  kassert(xaiboot_fs_multi_sector_file_count() >= 1);
  kassert(xaiboot_fs_state_record_count() == 4);
  kassert(xaiboot_fs_reject_count() >= 7);
  kassert(xaiboot_fs_checksum_error_count() == 0);
  kassert(xaiboot_fs_rename_count() == 1);
  kassert(xaiboot_fs_list_count() == 1);
  kassert(xaiboot_fs_stat_count() == 3);
  kassert(xaiboot_fs_open_count() == 3);
  kassert(xaiboot_fs_close_count() == 3);
  klog("xaibootfs: allocator self-test passed allocations=%lu frees=%lu blocks=%lu\n",
       xaiboot_fs_allocation_count(), xaiboot_fs_free_count(),
       block_count_used());
  klog("xaibootfs: directory tree self-test passed directories=%lu\n",
       xaiboot_fs_directory_count());
  klog("xaibootfs: multi-sector file self-test passed files=%lu multi_sector=%lu\n",
       xaiboot_fs_file_count(), xaiboot_fs_multi_sector_file_count());
  klog("xaibootfs: journal replay self-test passed replays=%lu journal_writes=%lu\n",
       xaiboot_fs_replay_count(), xaiboot_fs_journal_write_count());
  klog("xaibootfs: public API self-test passed list=%lu stat=%lu rename=%lu open=%lu close=%lu\n",
       xaiboot_fs_list_count(), xaiboot_fs_stat_count(),
       xaiboot_fs_rename_count(), xaiboot_fs_open_count(),
       xaiboot_fs_close_count());
  klog("xaibootfs: subsystem records self-test passed records=%lu\n",
       xaiboot_fs_state_record_count());
  klog("xaibootfs: self-test passed files=%lu directories=%lu writes=%lu reads=%lu deletes=%lu commits=%lu rollbacks=%lu replays=%lu rejects=%lu checksum_errors=%lu\n",
       xaiboot_fs_file_count(), xaiboot_fs_directory_count(),
       xaiboot_fs_write_count(), xaiboot_fs_read_count(),
       xaiboot_fs_delete_count(), xaiboot_fs_commit_count(),
       xaiboot_fs_rollback_count(), xaiboot_fs_replay_count(),
       xaiboot_fs_reject_count(), xaiboot_fs_checksum_error_count());
}
