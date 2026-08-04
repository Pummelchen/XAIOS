#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/mutable_fs.h>
#include <xaios/virtio_blk.h>

#define MFS_MAGIC "XAIOSMFS2"
#define MFS_JOURNAL_MAGIC "XAIOSMFJ1"
#define MFS_MAGIC_LEN 8U
#define MFS_VERSION 2U
#define MFS_JOURNAL_VERSION 1U
#define MFS_SECTOR_SIZE UINT64_C(512)
#define MFS_START_SECTOR UINT64_C(3072)
#define MFS_METADATA_SECTORS UINT64_C(16)
#define MFS_JOURNAL_SECTORS UINT64_C(2)
#define MFS_CHECKSUM_OFFSET UINT64_C(80)
#define MFS_DATA_SECTORS 96U
#define MFS_MAX_NODES 32U
#define MFS_PATH_MAX 96U
#define MFS_FILE_MAX_BLOCKS 16U
#define MFS_MAX_FILE_BYTES (MFS_FILE_MAX_BLOCKS * MFS_SECTOR_SIZE)
#define MFS_MAX_OPEN_FILES 8U
#define MFS_V3_METADATA_SECTORS 32U
#define MFS_V3_DATA_SECTORS 256U
#define MFS_V3_MAX_NODES 64U
#define MFS_V3_FILE_MAX_BLOCKS 16U
#define MFS_V3_MAX_FILE_BYTES (MFS_V3_FILE_MAX_BLOCKS * MFS_SECTOR_SIZE)
#define MFS_V3_VERSION 3U
#define MFS_NODE_FREE 0U
#define MFS_NODE_DIR 1U
#define MFS_NODE_FILE 2U
#define MFS_MOUNT_READ_WRITE 1U
#define MFS_JOURNAL_EMPTY 0U
#define MFS_JOURNAL_PENDING 1U
#define MFS_JOURNAL_OP_WRITE_FILE 1U
#define FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define FNV1A64_PRIME UINT64_C(1099511628211)

typedef struct xaios_mfs_node {
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
  uint16_t blocks[MFS_FILE_MAX_BLOCKS];
  uint16_t snapshot_blocks[MFS_FILE_MAX_BLOCKS];
  char path[MFS_PATH_MAX];
} xaios_mfs_node_t;

typedef struct xaios_mfs_disk {
  char magic[MFS_MAGIC_LEN];
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
  uint8_t block_bitmap[MFS_DATA_SECTORS];
  xaios_mfs_node_t nodes[MFS_MAX_NODES];
} xaios_mfs_disk_t;

typedef struct xaios_mfs_state {
  char magic[MFS_MAGIC_LEN];
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
  uint8_t block_bitmap[MFS_V3_DATA_SECTORS];
  xaios_mfs_node_t nodes[MFS_V3_MAX_NODES];
} xaios_mfs_state_t;

typedef struct xaios_mfs_journal {
  char magic[MFS_MAGIC_LEN];
  uint32_t version;
  uint32_t state;
  uint32_t op;
  uint32_t reserved;
  uint64_t size;
  uint64_t content_hash;
  uint64_t checksum;
  char path[MFS_PATH_MAX];
  uint8_t padding[368];
} xaios_mfs_journal_t;

typedef struct xaios_mfs_file_handle {
  uint32_t in_use;
  uint32_t flags;
  uint64_t cursor;
  char path[MFS_PATH_MAX];
} xaios_mfs_file_handle_t;

static xaios_mfs_state_t g_mfs;
static xaios_mfs_file_handle_t g_open_files[MFS_MAX_OPEN_FILES];
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

static uint32_t g_active_metadata_sectors = MFS_METADATA_SECTORS;
static uint32_t g_active_max_nodes = MFS_MAX_NODES;
static uint32_t g_active_file_max_blocks = MFS_FILE_MAX_BLOCKS;
static uint64_t g_active_max_file_bytes = MFS_MAX_FILE_BYTES;
static uint32_t g_active_data_sectors = MFS_DATA_SECTORS;
static uint32_t g_active_version = MFS_VERSION;
static virtio_block_handle_t *g_persistent_handle;
static uint64_t g_persistent_mount_count;

static const char k_config_v1[] = "mode=qemu-full-os\nmutable=true\n";
static const char k_service_running[] =
    "service=/svc/source-index\nstate=running\n";
static const char k_service_restarting[] =
    "service=/svc/source-index\nstate=restarting\n";
static const char k_update_state[] =
    "policy=signed-update-required\nrollback=enabled\n";
static const char k_boot_log[] = "boot=ok\n";
static const char k_replayed_state[] =
    "service=/svc/replayed\nstate=recovered\n";

static xaios_status_t restore_snapshot_node(xaios_mfs_node_t *node);

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
  g_active_metadata_sectors = MFS_METADATA_SECTORS;
  g_active_max_nodes = MFS_MAX_NODES;
  g_active_file_max_blocks = MFS_FILE_MAX_BLOCKS;
  g_active_max_file_bytes = MFS_MAX_FILE_BYTES;
  g_active_data_sectors = MFS_DATA_SECTORS;
  g_active_version = MFS_VERSION;
}

static void set_active_v3(void) {
  g_active_metadata_sectors = MFS_V3_METADATA_SECTORS;
  g_active_max_nodes = MFS_V3_MAX_NODES;
  g_active_file_max_blocks = MFS_V3_FILE_MAX_BLOCKS;
  g_active_max_file_bytes = MFS_V3_MAX_FILE_BYTES;
  g_active_data_sectors = MFS_V3_DATA_SECTORS;
  g_active_version = MFS_V3_VERSION;
}

static uint64_t active_journal_header_sector(void) {
  return MFS_START_SECTOR + g_active_metadata_sectors;
}

static uint64_t active_journal_data_sector(void) {
  return active_journal_header_sector() + 1U;
}

static uint64_t active_data_start_sector(void) {
  return active_journal_header_sector() + MFS_JOURNAL_SECTORS;
}

static xaios_status_t blk_read(uint64_t sector, void *buf, uint64_t sz) {
  if (g_persistent_handle != 0) {
    return virtio_block_read_sector_h(g_persistent_handle, sector, buf, sz);
  }
  return virtio_block_read_sector(sector, buf, sz);
}

static xaios_status_t blk_write(uint64_t sector, const void *buf, uint64_t sz) {
  if (g_persistent_handle != 0) {
    return virtio_block_write_sector_h(g_persistent_handle, sector, buf, sz);
  }
  return virtio_block_write_sector(sector, buf, sz);
}

static xaios_status_t blk_flush(void) {
  if (g_persistent_handle != 0) {
    return virtio_block_flush_h(g_persistent_handle);
  }
  return virtio_block_flush();
}

static uint64_t blk_capacity(void) {
  if (g_persistent_handle != 0) {
    return virtio_block_capacity_sectors_h(g_persistent_handle);
  }
  return virtio_block_capacity_sectors();
}

static void reset_open_files(void) {
  for (uint32_t i = 0; i < MFS_MAX_OPEN_FILES; ++i) {
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

static int node_is_visible(const xaios_mfs_node_t *node) {
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
  uint8_t temp[MFS_V3_METADATA_SECTORS * MFS_SECTOR_SIZE];
  uint64_t copy_size = size < sizeof(temp) ? size : sizeof(temp);
  bytes_copy(temp, data, copy_size);
  bytes_zero(temp + MFS_CHECKSUM_OFFSET, sizeof(uint64_t));
  return fnv1a64(temp, size);
}

static uint64_t journal_checksum(xaios_mfs_journal_t *journal) {
  uint64_t saved = journal->checksum;
  journal->checksum = 0;
  uint64_t checksum = fnv1a64(journal, sizeof(*journal));
  journal->checksum = saved;
  return checksum;
}

static void copy_path(char dst[MFS_PATH_MAX], const char *src) {
  uint32_t i = 0;
  while (i + 1U < MFS_PATH_MAX && src[i] != '\0') {
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
  for (uint32_t i = 0; i < MFS_PATH_MAX; ++i) {
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
                                    char normalized[MFS_PATH_MAX]) {
  if (validate_path(path) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  copy_path(normalized, path);
  return XAIOS_OK;
}

static void parent_path_of(const char *path, char parent[MFS_PATH_MAX]) {
  uint32_t last_slash = 0;
  for (uint32_t i = 0; i < MFS_PATH_MAX && path[i] != '\0'; ++i) {
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
    if (g_mfs.nodes[i].active != 0 && g_mfs.nodes[i].type == type) {
      ++count;
    }
  }
  return count;
}

static uint64_t block_count_used(void) {
  uint64_t count = 0;
  for (uint32_t i = 0; i < g_active_data_sectors; ++i) {
    if (g_mfs.block_bitmap[i] != 0) {
      ++count;
    }
  }
  return count;
}

static xaios_mfs_node_t *find_node(const char *path, uint32_t include_snapshot) {
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_mfs_node_t *node = &g_mfs.nodes[i];
    if ((node->active != 0 ||
         (include_snapshot != 0 && node->snapshot_active != 0)) &&
        str_eq(node->path, path)) {
      return node;
    }
  }
  return 0;
}

static xaios_mfs_node_t *find_free_node(void) {
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    if (g_mfs.nodes[i].active == 0 && g_mfs.nodes[i].snapshot_active == 0) {
      return &g_mfs.nodes[i];
    }
  }
  return 0;
}

static xaios_status_t read_metadata(void) {
  uint8_t first_sector[MFS_SECTOR_SIZE];
  if (blk_read(MFS_START_SECTOR, first_sector, sizeof(first_sector)) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint32_t version = 0;
  bytes_copy(&version, first_sector + MFS_MAGIC_LEN, sizeof(version));
  uint32_t sectors = (version == MFS_V3_VERSION) ? MFS_V3_METADATA_SECTORS
                                                 : MFS_METADATA_SECTORS;
  uint8_t raw[MFS_V3_METADATA_SECTORS * MFS_SECTOR_SIZE];
  bytes_zero(raw, sizeof(raw));
  bytes_copy(raw, first_sector, MFS_SECTOR_SIZE);
  for (uint32_t i = 1; i < sectors; ++i) {
    if (blk_read(MFS_START_SECTOR + i, raw + i * MFS_SECTOR_SIZE,
                 MFS_SECTOR_SIZE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  /* compute and store checksum over raw data before deserializing */
  uint64_t total_bytes = (uint64_t)sectors * MFS_SECTOR_SIZE;
  g_metadata_verified_checksum = mfs_checksum(raw, total_bytes);
  uint32_t disk_max_nodes = (version == MFS_V3_VERSION) ? MFS_V3_MAX_NODES
                                                       : MFS_MAX_NODES;
  uint32_t disk_bitmap = (version == MFS_V3_VERSION) ? MFS_V3_DATA_SECTORS
                                                    : MFS_DATA_SECTORS;
  uint64_t p = 0;
  bytes_copy(g_mfs.magic, raw + p, MFS_MAGIC_LEN); p += MFS_MAGIC_LEN;
  bytes_copy(&g_mfs.version, raw + p, 4); p += 4;
  bytes_copy(&g_mfs.sector_size, raw + p, 4); p += 4;
  bytes_copy(&g_mfs.metadata_sectors, raw + p, 4); p += 4;
  bytes_copy(&g_mfs.max_nodes, raw + p, 4); p += 4;
  bytes_copy(&g_mfs.start_sector, raw + p, 8); p += 8;
  bytes_copy(&g_mfs.journal_header_sector, raw + p, 8); p += 8;
  bytes_copy(&g_mfs.journal_data_sector, raw + p, 8); p += 8;
  bytes_copy(&g_mfs.data_start_sector, raw + p, 8); p += 8;
  bytes_copy(&g_mfs.data_sectors, raw + p, 8); p += 8;
  bytes_copy(&g_mfs.generation, raw + p, 8); p += 8;
  bytes_copy(&g_mfs.committed_generation, raw + p, 8); p += 8;
  bytes_copy(&g_mfs.checksum, raw + p, 8); p += 8;
  bytes_copy(g_mfs.block_bitmap, raw + p, disk_bitmap); p += disk_bitmap;
  for (uint32_t i = 0; i < disk_max_nodes; ++i) {
    bytes_copy(&g_mfs.nodes[i], raw + p, sizeof(xaios_mfs_node_t));
    p += sizeof(xaios_mfs_node_t);
  }
  for (uint32_t i = disk_max_nodes; i < MFS_V3_MAX_NODES; ++i) {
    bytes_zero(&g_mfs.nodes[i], sizeof(xaios_mfs_node_t));
  }
  for (uint32_t i = disk_bitmap; i < MFS_V3_DATA_SECTORS; ++i) {
    g_mfs.block_bitmap[i] = 0;
  }
  return XAIOS_OK;
}

static xaios_status_t write_metadata(void) {
  uint8_t raw[MFS_V3_METADATA_SECTORS * MFS_SECTOR_SIZE];
  bytes_zero(raw, sizeof(raw));
  uint64_t p = 0;
  bytes_copy(raw + p, g_mfs.magic, MFS_MAGIC_LEN); p += MFS_MAGIC_LEN;
  bytes_copy(raw + p, &g_mfs.version, 4); p += 4;
  bytes_copy(raw + p, &g_mfs.sector_size, 4); p += 4;
  bytes_copy(raw + p, &g_mfs.metadata_sectors, 4); p += 4;
  bytes_copy(raw + p, &g_mfs.max_nodes, 4); p += 4;
  bytes_copy(raw + p, &g_mfs.start_sector, 8); p += 8;
  bytes_copy(raw + p, &g_mfs.journal_header_sector, 8); p += 8;
  bytes_copy(raw + p, &g_mfs.journal_data_sector, 8); p += 8;
  bytes_copy(raw + p, &g_mfs.data_start_sector, 8); p += 8;
  bytes_copy(raw + p, &g_mfs.data_sectors, 8); p += 8;
  bytes_copy(raw + p, &g_mfs.generation, 8); p += 8;
  bytes_copy(raw + p, &g_mfs.committed_generation, 8); p += 8;
  uint64_t checksum_offset = p;
  uint64_t zero_cksum = 0;
  bytes_copy(raw + p, &zero_cksum, 8); p += 8;
  uint32_t disk_bitmap = (g_active_version == MFS_V3_VERSION)
                             ? MFS_V3_DATA_SECTORS : MFS_DATA_SECTORS;
  uint32_t disk_max_nodes = (g_active_version == MFS_V3_VERSION)
                                ? MFS_V3_MAX_NODES : MFS_MAX_NODES;
  bytes_copy(raw + p, g_mfs.block_bitmap, disk_bitmap); p += disk_bitmap;
  for (uint32_t i = 0; i < disk_max_nodes; ++i) {
    bytes_copy(raw + p, &g_mfs.nodes[i], sizeof(xaios_mfs_node_t));
    p += sizeof(xaios_mfs_node_t);
  }
  uint64_t total_bytes = (uint64_t)g_active_metadata_sectors * MFS_SECTOR_SIZE;
  g_mfs.checksum = mfs_checksum(raw, total_bytes);
  bytes_copy(raw + checksum_offset, &g_mfs.checksum, 8);
  uint8_t sector[MFS_SECTOR_SIZE];
  for (uint32_t i = 0; i < g_active_metadata_sectors; ++i) {
    bytes_copy(sector, raw + (uint64_t)i * MFS_SECTOR_SIZE, MFS_SECTOR_SIZE);
    if (blk_write(MFS_START_SECTOR + i, sector, sizeof(sector)) != XAIOS_OK) {
      klog("mutable-fs: metadata write failed sector=%lu capacity=%lu\n",
           MFS_START_SECTOR + i, blk_capacity());
      ++g_reject_count;
      return XAIOS_ERR_IO;
    }
  }
  return blk_flush();
}

static xaios_status_t clear_journal(void) {
  uint8_t sector[MFS_SECTOR_SIZE];
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

static xaios_status_t read_journal(xaios_mfs_journal_t *journal) {
  if (blk_read(active_journal_header_sector(), journal,
                               sizeof(*journal)) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

static xaios_status_t write_journal(xaios_mfs_journal_t *journal) {
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
                                     uint16_t blocks[MFS_FILE_MAX_BLOCKS]) {
  if (count > g_active_file_max_blocks) {
    return XAIOS_ERR_INVALID;
  }
  if (count == 0) {
    return XAIOS_OK;
  }
  uint16_t found = 0;
  for (uint16_t i = 0; i < g_active_data_sectors && found < count; ++i) {
    if (g_mfs.block_bitmap[i] == 0) {
      g_mfs.block_bitmap[i] = 1;
      blocks[found++] = i;
      ++g_allocation_count;
    }
  }
  if (found != count) {
    for (uint16_t i = 0; i < found; ++i) {
      g_mfs.block_bitmap[blocks[i]] = 0;
      ++g_free_count;
    }
    ++g_reject_count;
    return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

static void free_blocks(uint16_t count,
                        const uint16_t blocks[MFS_FILE_MAX_BLOCKS]) {
  for (uint16_t i = 0; i < count; ++i) {
    if (blocks[i] < g_active_data_sectors && g_mfs.block_bitmap[blocks[i]] != 0) {
      g_mfs.block_bitmap[blocks[i]] = 0;
      ++g_free_count;
    }
  }
}

static xaios_status_t validate_disk(uint64_t expected_checksum) {
  if (!bytes_eq(g_mfs.magic, MFS_MAGIC, MFS_MAGIC_LEN) ||
      g_mfs.version != g_active_version ||
      g_mfs.sector_size != MFS_SECTOR_SIZE ||
      g_mfs.metadata_sectors != g_active_metadata_sectors ||
      g_mfs.max_nodes != g_active_max_nodes ||
      g_mfs.start_sector != MFS_START_SECTOR ||
      g_mfs.journal_header_sector != active_journal_header_sector() ||
      g_mfs.journal_data_sector != active_journal_data_sector() ||
      g_mfs.data_start_sector != active_data_start_sector() ||
      g_mfs.data_sectors != g_active_data_sectors) {
    return XAIOS_ERR_INVALID;
  }
  if (g_mfs.checksum != expected_checksum) {
    ++g_checksum_error_count;
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_mfs_node_t *node = &g_mfs.nodes[i];
    if ((node->active != 0 || node->snapshot_active != 0) &&
        validate_path(node->path) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (node->active != 0 &&
        node->type != MFS_NODE_DIR && node->type != MFS_NODE_FILE) {
      return XAIOS_ERR_INVALID;
    }
    if (node->snapshot_active != 0 &&
        node->snapshot_type != MFS_NODE_DIR &&
        node->snapshot_type != MFS_NODE_FILE) {
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
  bytes_zero(&g_mfs, sizeof(g_mfs));
  bytes_copy(g_mfs.magic, MFS_MAGIC, MFS_MAGIC_LEN);
  g_mfs.version = g_active_version;
  g_mfs.sector_size = (uint32_t)MFS_SECTOR_SIZE;
  g_mfs.metadata_sectors = g_active_metadata_sectors;
  g_mfs.max_nodes = g_active_max_nodes;
  g_mfs.start_sector = MFS_START_SECTOR;
  g_mfs.journal_header_sector = active_journal_header_sector();
  g_mfs.journal_data_sector = active_journal_data_sector();
  g_mfs.data_start_sector = active_data_start_sector();
  g_mfs.data_sectors = g_active_data_sectors;
  g_mfs.generation = 1;
  g_mfs.committed_generation = 0;
  ++g_format_count;
  if (clear_journal() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  return write_metadata();
}

static xaios_status_t write_file(const char *path, const void *data,
                                uint64_t size);
static xaios_status_t create_dir(const char *path);

static xaios_status_t replay_journal(void) {
  xaios_mfs_journal_t journal;
  if (read_journal(&journal) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  if (!bytes_eq(journal.magic, MFS_JOURNAL_MAGIC, MFS_MAGIC_LEN) ||
      journal.state == MFS_JOURNAL_EMPTY) {
    return XAIOS_OK;
  }
  uint64_t expected = journal.checksum;
  if (journal.version != MFS_JOURNAL_VERSION ||
      journal.state != MFS_JOURNAL_PENDING ||
      journal.op != MFS_JOURNAL_OP_WRITE_FILE ||
      journal.size == 0 || journal.size > MFS_SECTOR_SIZE ||
      journal_checksum(&journal) != expected ||
      validate_path(journal.path) != XAIOS_OK) {
    ++g_checksum_error_count;
    ++g_reject_count;
    return clear_journal();
  }

  uint8_t sector[MFS_SECTOR_SIZE];
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
  klog("mutable-fs: journal replay path=%s size=%lu\n",
       journal.path, journal.size);
  return XAIOS_OK;
}

static xaios_status_t mount_volume(uint32_t mount_flags) {
  set_active_v2();
  if (blk_capacity() < active_data_start_sector() + g_active_data_sectors) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }

  g_mount_flags = mount_flags;
  if (read_metadata() != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  uint64_t saved_checksum = g_mfs.checksum;
  if (validate_disk(g_metadata_verified_checksum) == XAIOS_OK &&
      saved_checksum == g_metadata_verified_checksum) {
    ++g_boot_load_count;
    klog("mutable-fs: existing state loaded files=%lu directories=%lu blocks=%lu generation=%lu committed=%lu\n",
         node_count_by_type(MFS_NODE_FILE), node_count_by_type(MFS_NODE_DIR),
         block_count_used(), g_mfs.generation, g_mfs.committed_generation);
  } else {
    klog("mutable-fs: no valid filesystem at sector=%lu; formatting\n",
         MFS_START_SECTOR);
    if (format_volume() != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }

  g_mounted = 1;
  ++g_mount_count;
  if (replay_journal() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }

  if ((g_mount_flags & MFS_MOUNT_READ_WRITE) != 0U) {
    xaios_mfs_node_t *root = find_node("/", 1);
    if (root == 0) {
      if (create_dir("/") != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    } else if (root->active == 0) {
      if (restore_snapshot_node(root) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    } else if (root->type != MFS_NODE_DIR) {
      ++g_reject_count;
      return XAIOS_ERR_INVALID;
    }
  }

  klog("mutable-fs: mounted start=%lu metadata=%lu journal=%lu data=%lu sectors=%u nodes=%u policy=%s\n",
       MFS_START_SECTOR, (uint64_t)g_active_metadata_sectors, MFS_JOURNAL_SECTORS,
       active_data_start_sector(), g_active_data_sectors, g_active_max_nodes,
       (g_mount_flags & MFS_MOUNT_READ_WRITE) != 0 ? "rw" : "ro");
  return XAIOS_OK;
}

static int parent_exists_for(const char *path) {
  char parent[MFS_PATH_MAX];
  parent_path_of(path, parent);
  if (str_eq(parent, "/")) {
    return 1;
  }
  xaios_mfs_node_t *node = find_node(parent, 0);
  return node != 0 && node->active != 0 && node->type == MFS_NODE_DIR;
}

static xaios_status_t create_dir(const char *path) {
  if (g_mounted == 0 || (g_mount_flags & MFS_MOUNT_READ_WRITE) == 0 ||
      validate_path(path) != XAIOS_OK || !parent_exists_for(path)) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_mfs_node_t *node = find_node(path, 1);
  if (node != 0 && node->active != 0) {
    return node->type == MFS_NODE_DIR ? XAIOS_OK : XAIOS_ERR_INVALID;
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
  node->type = MFS_NODE_DIR;
  node->size = 0;
  node->content_hash = 0;
  node->generation = g_mfs.generation++;
  node->block_count = 0;
  bytes_zero(node->blocks, sizeof(node->blocks));
  copy_path(node->path, path);
  ++g_directory_count;
  klog("mutable-fs: mkdir path=%s generation=%lu\n",
       node->path, node->generation);
  return write_metadata();
}

static xaios_status_t ensure_base_directories(void) {
  static const char *const paths[] = {
      "/", "/etc", "/bin", "/state", "/state/services",
      "/state/workspaces", "/state/updates", "/config", "/logs",
      "/workspaces", "/models",
  };
  for (uint32_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
    if (create_dir(paths[i]) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  return XAIOS_OK;
}

static uint16_t block_count_for_size(uint64_t size) {
  return (uint16_t)((size + MFS_SECTOR_SIZE - 1U) / MFS_SECTOR_SIZE);
}

static xaios_status_t write_blocks(const uint16_t blocks[MFS_FILE_MAX_BLOCKS],
                                  uint16_t block_count, const void *data,
                                  uint64_t size) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint8_t sector[MFS_SECTOR_SIZE];
  for (uint16_t i = 0; i < block_count; ++i) {
    bytes_zero(sector, sizeof(sector));
    uint64_t offset = (uint64_t)i * MFS_SECTOR_SIZE;
    uint64_t remaining = size - offset;
    uint64_t copy = remaining < MFS_SECTOR_SIZE ? remaining : MFS_SECTOR_SIZE;
    bytes_copy(sector, bytes + offset, copy);
    if (blk_write(absolute_data_sector(blocks[i]), sector,
                                  sizeof(sector)) != XAIOS_OK) {
      ++g_reject_count;
      return XAIOS_ERR_IO;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t read_blocks(const uint16_t blocks[MFS_FILE_MAX_BLOCKS],
                                 uint16_t block_count, void *buffer,
                                 uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  uint8_t sector[MFS_SECTOR_SIZE];
  for (uint16_t i = 0; i < block_count; ++i) {
    uint64_t offset = (uint64_t)i * MFS_SECTOR_SIZE;
    uint64_t remaining = size - offset;
    uint64_t copy = remaining < MFS_SECTOR_SIZE ? remaining : MFS_SECTOR_SIZE;
    if (blk_read(absolute_data_sector(blocks[i]), sector,
                                 sizeof(sector)) != XAIOS_OK) {
      ++g_reject_count;
      return XAIOS_ERR_IO;
    }
    bytes_copy(bytes + offset, sector, copy);
  }
  return XAIOS_OK;
}

static xaios_status_t write_file(const char *path, const void *data,
                                uint64_t size) {
  if (g_mounted == 0 || (g_mount_flags & MFS_MOUNT_READ_WRITE) == 0 ||
      validate_path(path) != XAIOS_OK || !parent_exists_for(path) ||
      (data == 0 && size != 0) || size > g_active_max_file_bytes) {
    klog("mutable-fs: write rejected path=%s mounted=%u flags=0x%x parent=%u size=%lu\n",
         path == 0 ? "<null>" : path, g_mounted, g_mount_flags,
         path == 0 ? 0U : (uint32_t)parent_exists_for(path), size);
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }

  uint16_t new_count = block_count_for_size(size);
  uint16_t new_blocks[MFS_FILE_MAX_BLOCKS];
  bytes_zero(new_blocks, sizeof(new_blocks));
  if (allocate_blocks(new_count, new_blocks) != XAIOS_OK) {
    klog("mutable-fs: write allocation failed path=%s blocks=%u used=%lu\n",
         path, new_count, block_count_used());
    return XAIOS_ERR_NO_MEMORY;
  }
  if (write_blocks(new_blocks, new_count, data, size) != XAIOS_OK) {
    klog("mutable-fs: write block IO failed path=%s blocks=%u\n",
         path, new_count);
    free_blocks(new_count, new_blocks);
    return XAIOS_ERR_IO;
  }

  xaios_mfs_node_t *node = find_node(path, 1);
  if (node != 0 && node->active != 0 && node->type != MFS_NODE_FILE) {
    klog("mutable-fs: write rejected existing non-file path=%s type=%u\n",
         path, node->type);
    free_blocks(new_count, new_blocks);
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  if (node == 0) {
    node = find_free_node();
  }
  if (node == 0) {
    klog("mutable-fs: write no free node path=%s files=%lu directories=%lu\n",
         path, node_count_by_type(MFS_NODE_FILE),
         node_count_by_type(MFS_NODE_DIR));
    free_blocks(new_count, new_blocks);
    ++g_reject_count;
    return XAIOS_ERR_NO_MEMORY;
  }

  if (node->active != 0 && node->type == MFS_NODE_FILE) {
    free_blocks(node->block_count, node->blocks);
  }
  node->active = 1;
  node->type = MFS_NODE_FILE;
  node->size = size;
  node->content_hash = fnv1a64(data, size);
  node->generation = g_mfs.generation++;
  node->block_count = new_count;
  copy_path(node->path, path);
  bytes_zero(node->blocks, sizeof(node->blocks));
  bytes_copy(node->blocks, new_blocks, sizeof(new_blocks));
  if (new_count > 1U) {
    ++g_multi_sector_file_count;
  }
  ++g_write_count;
  klog("mutable-fs: write path=%s size=%lu blocks=%u generation=%lu\n",
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
  xaios_mfs_node_t *node = find_node(path, 0);
  if (node == 0 || node->active == 0 || node->type != MFS_NODE_FILE ||
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
  klog("mutable-fs: read path=%s size=%lu blocks=%u generation=%lu\n",
       node->path, node->size, node->block_count, node->generation);
  return XAIOS_OK;
}

static int has_active_children(const char *path) {
  uint64_t parent_len = cstr_len(path);
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_mfs_node_t *node = &g_mfs.nodes[i];
    if (node->active == 0 || str_eq(node->path, path)) {
      continue;
    }
    if (bytes_eq(node->path, path, parent_len) && node->path[parent_len] == '/') {
      return 1;
    }
  }
  return 0;
}

static xaios_status_t delete_node(const char *path) {
  if (g_mounted == 0 || (g_mount_flags & MFS_MOUNT_READ_WRITE) == 0 ||
      validate_path(path) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_mfs_node_t *node = find_node(path, 0);
  if (node == 0 || node->active == 0) {
    ++g_reject_count;
    return XAIOS_ERR_NOT_FOUND;
  }
  if (node->type == MFS_NODE_DIR && has_active_children(path)) {
    ++g_reject_count;
    return XAIOS_ERR_BUSY;
  }
  if (node->type == MFS_NODE_FILE) {
    free_blocks(node->block_count, node->blocks);
    node->block_count = 0;
  }
  node->active = 0;
  node->generation = g_mfs.generation++;
  ++g_delete_count;
  klog("mutable-fs: delete path=%s generation=%lu\n",
       node->path, node->generation);
  return write_metadata();
}

static xaios_status_t rename_node(const char *old_path, const char *new_path) {
  char normalized_old[MFS_PATH_MAX];
  char normalized_new[MFS_PATH_MAX];
  if (g_mounted == 0 || (g_mount_flags & MFS_MOUNT_READ_WRITE) == 0 ||
      normalize_path(old_path, normalized_old) != XAIOS_OK ||
      normalize_path(new_path, normalized_new) != XAIOS_OK ||
      !parent_exists_for(normalized_new)) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_mfs_node_t *node = find_node(normalized_old, 0);
  if (node == 0 || node->active == 0) {
    ++g_reject_count;
    return XAIOS_ERR_NOT_FOUND;
  }
  if (find_node(normalized_new, 0) != 0) {
    ++g_reject_count;
    return XAIOS_ERR_BUSY;
  }
  if (node->type == MFS_NODE_DIR && has_active_children(normalized_old)) {
    ++g_reject_count;
    return XAIOS_ERR_BUSY;
  }
  copy_path(node->path, normalized_new);
  node->generation = g_mfs.generation++;
  ++g_rename_count;
  klog("mutable-fs: rename old=%s new=%s generation=%lu\n",
       normalized_old, normalized_new, node->generation);
  return write_metadata();
}

static xaios_status_t stat_node(const char *path, xaios_mfs_stat_t *stat) {
  char normalized[MFS_PATH_MAX];
  if (stat == 0 || normalize_path(path, normalized) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  xaios_mfs_node_t *node = find_node(normalized, 1);
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
  klog("mutable-fs: stat path=%s type=%u size=%lu generation=%lu\n",
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
  char normalized[MFS_PATH_MAX];
  uint64_t offset = 0;
  xaios_status_t append_status = XAIOS_OK;
  if (buffer == 0 || out_size == 0 || buffer_size == 0 ||
      normalize_path(path, normalized) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }

  xaios_mfs_node_t *dir = find_node(normalized, 1);
  if (!node_is_visible(dir) || dir->type != MFS_NODE_DIR) {
    if (!str_eq(normalized, "/")) {
      ++g_reject_count;
      return XAIOS_ERR_NOT_FOUND;
    }
  }

  buffer[0] = '\0';
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_mfs_node_t *node = &g_mfs.nodes[i];
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
  klog("mutable-fs: list path=%s bytes=%lu\n", normalized, offset);
  return XAIOS_OK;
}

static xaios_status_t commit_snapshot(const char *label) {
  (void)label;
  if (g_mounted == 0 || (g_mount_flags & MFS_MOUNT_READ_WRITE) == 0) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint8_t buffer[MFS_MAX_FILE_BYTES];
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_mfs_node_t *node = &g_mfs.nodes[i];
    if (node->snapshot_active != 0 && node->snapshot_type == MFS_NODE_FILE) {
      free_blocks(node->snapshot_block_count, node->snapshot_blocks);
    }
    node->snapshot_active = 0;
    node->snapshot_type = MFS_NODE_FREE;
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
    if (node->type == MFS_NODE_FILE) {
      if (read_blocks(node->blocks, node->block_count, buffer, node->size) !=
          XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      uint16_t snapshot_blocks[MFS_FILE_MAX_BLOCKS];
      bytes_zero(snapshot_blocks, sizeof(snapshot_blocks));
      if (allocate_blocks(node->block_count, snapshot_blocks) != XAIOS_OK) {
        return XAIOS_ERR_NO_MEMORY;
      }
      if (write_blocks(snapshot_blocks, node->block_count, buffer,
                       node->size) != XAIOS_OK) {
        free_blocks(node->block_count, snapshot_blocks);
        return XAIOS_ERR_IO;
      }
      node->snapshot_block_count = node->block_count;
      bytes_copy(node->snapshot_blocks, snapshot_blocks,
                 sizeof(snapshot_blocks));
    }
  }
  g_mfs.committed_generation = g_mfs.generation;
  ++g_commit_count;
  klog("mutable-fs: snapshot committed generation=%lu files=%lu directories=%lu blocks=%lu\n",
       g_mfs.committed_generation, node_count_by_type(MFS_NODE_FILE),
       node_count_by_type(MFS_NODE_DIR), block_count_used());
  return write_metadata();
}

static xaios_status_t restore_snapshot_node(xaios_mfs_node_t *node) {
  uint8_t buffer[MFS_MAX_FILE_BYTES];
  if (node->snapshot_active == 0) {
    return XAIOS_OK;
  }
  if (node->active != 0 && node->type == MFS_NODE_FILE) {
    free_blocks(node->block_count, node->blocks);
  }
  node->active = 1;
  node->type = node->snapshot_type;
  node->size = node->snapshot_size;
  node->content_hash = node->snapshot_hash;
  node->generation = node->snapshot_generation;
  node->block_count = 0;
  bytes_zero(node->blocks, sizeof(node->blocks));
  if (node->snapshot_type == MFS_NODE_FILE) {
    if (read_blocks(node->snapshot_blocks, node->snapshot_block_count, buffer,
                    node->snapshot_size) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    uint16_t restored_blocks[MFS_FILE_MAX_BLOCKS];
    bytes_zero(restored_blocks, sizeof(restored_blocks));
    if (allocate_blocks(node->snapshot_block_count, restored_blocks) !=
        XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (write_blocks(restored_blocks, node->snapshot_block_count, buffer,
                     node->snapshot_size) != XAIOS_OK) {
      free_blocks(node->snapshot_block_count, restored_blocks);
      return XAIOS_ERR_IO;
    }
    node->block_count = node->snapshot_block_count;
    bytes_copy(node->blocks, restored_blocks, sizeof(restored_blocks));
  }
  return XAIOS_OK;
}

static xaios_status_t rollback_snapshot(void) {
  if (g_mounted == 0 || (g_mount_flags & MFS_MOUNT_READ_WRITE) == 0) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
    xaios_mfs_node_t *node = &g_mfs.nodes[i];
    if (node->snapshot_active == 0 && node->active != 0 &&
        node->generation >= g_mfs.committed_generation) {
      if (node->type == MFS_NODE_FILE) {
        free_blocks(node->block_count, node->blocks);
      }
      node->active = 0;
      node->block_count = 0;
      bytes_zero(node->blocks, sizeof(node->blocks));
    }
  }
  for (uint32_t pass = 0; pass < 2U; ++pass) {
    for (uint32_t i = 0; i < g_active_max_nodes; ++i) {
      xaios_mfs_node_t *node = &g_mfs.nodes[i];
      if (node->snapshot_active == 0) {
        continue;
      }
      if ((pass == 0 && node->snapshot_type == MFS_NODE_DIR) ||
          (pass == 1 && node->snapshot_type == MFS_NODE_FILE)) {
        if (restore_snapshot_node(node) != XAIOS_OK) {
          return XAIOS_ERR_IO;
        }
      }
    }
  }
  ++g_mfs.generation;
  ++g_rollback_count;
  klog("mutable-fs: snapshot rollback committed=%lu files=%lu directories=%lu blocks=%lu\n",
       g_mfs.committed_generation, node_count_by_type(MFS_NODE_FILE),
       node_count_by_type(MFS_NODE_DIR), block_count_used());
  return write_metadata();
}

static xaios_status_t write_pending_journal_file(const char *path,
                                                const void *data,
                                                uint64_t size) {
  if (validate_path(path) != XAIOS_OK || data == 0 || size == 0 ||
      size > MFS_SECTOR_SIZE) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  uint8_t sector[MFS_SECTOR_SIZE];
  bytes_zero(sector, sizeof(sector));
  bytes_copy(sector, data, size);
  if (blk_write(active_journal_data_sector(), sector,
                                sizeof(sector)) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  xaios_mfs_journal_t journal;
  bytes_zero(&journal, sizeof(journal));
  bytes_copy(journal.magic, MFS_JOURNAL_MAGIC, MFS_MAGIC_LEN);
  journal.version = MFS_JOURNAL_VERSION;
  journal.state = MFS_JOURNAL_PENDING;
  journal.op = MFS_JOURNAL_OP_WRITE_FILE;
  journal.size = size;
  journal.content_hash = fnv1a64(data, size);
  copy_path(journal.path, path);
  klog("mutable-fs: journal pending path=%s size=%lu\n", path, size);
  return write_journal(&journal);
}

xaios_status_t mutable_fs_record_service_state(const char *name,
                                              const char *state) {
  char path[MFS_PATH_MAX];
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

xaios_status_t mutable_fs_record_workspace_state(uint32_t workspace_id,
                                                const char *revision) {
  char path[MFS_PATH_MAX];
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

xaios_status_t mutable_fs_record_update_state(const char *policy) {
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

xaios_status_t mutable_fs_record_update_transaction(uint32_t generation,
                                                   const char *state,
                                                   const char *target,
                                                   const char *rollback_label) {
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

xaios_status_t mutable_fs_record_admin_status(const char *service,
                                             const char *state,
                                             uint32_t starts,
                                             uint32_t restarts,
                                             uint32_t logs) {
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

xaios_status_t mutable_fs_commit(const char *label) {
  return commit_snapshot(label);
}

xaios_status_t mutable_fs_rollback(void) {
  return rollback_snapshot();
}

xaios_status_t mutable_fs_mkdir(const char *path) {
  return create_dir(path);
}

xaios_status_t mutable_fs_write(const char *path, const void *data,
                               uint64_t size) {
  return write_file(path, data, size);
}

xaios_status_t mutable_fs_read(const char *path, void *buffer,
                              uint64_t buffer_size, uint64_t *out_size) {
  return read_file(path, buffer, buffer_size, out_size);
}

xaios_status_t mutable_fs_delete(const char *path) {
  return delete_node(path);
}

xaios_status_t mutable_fs_rename(const char *old_path, const char *new_path) {
  return rename_node(old_path, new_path);
}

xaios_status_t mutable_fs_stat(const char *path, xaios_mfs_stat_t *stat) {
  return stat_node(path, stat);
}

xaios_status_t mutable_fs_list(const char *path, char *buffer,
                              uint64_t buffer_size, uint64_t *out_size) {
  return list_dir(path, buffer, buffer_size, out_size);
}

static xaios_mfs_file_handle_t *handle_for_fd(uint32_t fd) {
  if (fd == 0 || fd > MFS_MAX_OPEN_FILES) {
    return 0;
  }
  xaios_mfs_file_handle_t *handle = &g_open_files[fd - 1U];
  return handle->in_use != 0 ? handle : 0;
}

int64_t mutable_fs_open(const char *path, uint32_t flags) {
  char normalized[MFS_PATH_MAX];
  if (normalize_path(path, normalized) != XAIOS_OK ||
      (flags & (XAIOS_MFS_OPEN_READ | XAIOS_MFS_OPEN_WRITE)) == 0 ||
      (flags & ~(XAIOS_MFS_OPEN_READ | XAIOS_MFS_OPEN_WRITE |
                 XAIOS_MFS_OPEN_CREATE | XAIOS_MFS_OPEN_TRUNCATE)) != 0) {
    ++g_reject_count;
    return (int64_t)XAIOS_ERR_INVALID;
  }

  xaios_mfs_node_t *node = find_node(normalized, 0);
  if (node == 0 || node->active == 0) {
    if ((flags & XAIOS_MFS_OPEN_CREATE) == 0) {
      ++g_reject_count;
      return (int64_t)XAIOS_ERR_NOT_FOUND;
    }
    if ((flags & XAIOS_MFS_OPEN_WRITE) == 0 || !parent_exists_for(normalized)) {
      ++g_reject_count;
      return (int64_t)XAIOS_ERR_INVALID;
    }
  } else if (node->type != MFS_NODE_FILE) {
    ++g_reject_count;
    return (int64_t)XAIOS_ERR_INVALID;
  }

  if ((flags & XAIOS_MFS_OPEN_CREATE) != 0 && node == 0) {
    if (write_file(normalized, 0, 0) != XAIOS_OK) {
      return (int64_t)XAIOS_ERR_IO;
    }
    node = find_node(normalized, 0);
  }
  if ((flags & XAIOS_MFS_OPEN_TRUNCATE) != 0 && node != 0 &&
      node->active != 0) {
    if (write_file(normalized, 0, 0) != XAIOS_OK) {
      return (int64_t)XAIOS_ERR_IO;
    }
    node = find_node(normalized, 0);
  }

  for (uint32_t i = 0; i < MFS_MAX_OPEN_FILES; ++i) {
    if (g_open_files[i].in_use == 0) {
      g_open_files[i].in_use = 1;
      g_open_files[i].flags = flags;
      g_open_files[i].cursor = 0;
      copy_path(g_open_files[i].path, normalized);
      ++g_open_count;
      klog("mutable-fs: open fd=%u path=%s flags=0x%x\n", i + 1U,
           normalized, flags);
      return (int64_t)(i + 1U);
    }
  }

  ++g_reject_count;
  return (int64_t)XAIOS_ERR_NO_MEMORY;
}

int64_t mutable_fs_read_fd(uint32_t fd, void *buffer, uint64_t size) {
  xaios_mfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0 || buffer == 0 || size == 0 ||
      (handle->flags & XAIOS_MFS_OPEN_READ) == 0) {
    ++g_reject_count;
    return (int64_t)XAIOS_ERR_INVALID;
  }
  uint8_t file_buffer[MFS_MAX_FILE_BYTES];
  uint64_t file_size = 0;
  xaios_status_t read_status =
      read_file(handle->path, file_buffer, sizeof(file_buffer), &file_size);
  if (read_status != XAIOS_OK) {
    klog("mutable-fs: read-fd failed fd=%u path=%s status=%d\n", fd,
         handle->path, (int)read_status);
    return (int64_t)XAIOS_ERR_IO;
  }
  if (handle->cursor >= file_size) {
    return 0;
  }
  uint64_t available = file_size - handle->cursor;
  uint64_t copy = available < size ? available : size;
  bytes_copy(buffer, file_buffer + handle->cursor, copy);
  handle->cursor += copy;
  klog("mutable-fs: read-fd fd=%u bytes=%lu cursor=%lu\n", fd, copy,
       handle->cursor);
  return (int64_t)copy;
}

int64_t mutable_fs_write_fd(uint32_t fd, const void *buffer, uint64_t size) {
  xaios_mfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0 || buffer == 0 || size == 0 ||
      (handle->flags & XAIOS_MFS_OPEN_WRITE) == 0 ||
      handle->cursor > g_active_max_file_bytes ||
      size > g_active_max_file_bytes - handle->cursor) {
    ++g_reject_count;
    return (int64_t)XAIOS_ERR_INVALID;
  }

  uint8_t file_buffer[MFS_MAX_FILE_BYTES];
  uint64_t file_size = 0;
  bytes_zero(file_buffer, sizeof(file_buffer));
  if (find_node(handle->path, 0) != 0) {
    if (read_file(handle->path, file_buffer, sizeof(file_buffer), &file_size) !=
        XAIOS_OK) {
      return (int64_t)XAIOS_ERR_IO;
    }
  }
  uint64_t new_size = handle->cursor + size;
  if (new_size < file_size) {
    new_size = file_size;
  }
  bytes_copy(file_buffer + handle->cursor, buffer, size);
  if (write_file(handle->path, file_buffer, new_size) != XAIOS_OK) {
    return (int64_t)XAIOS_ERR_IO;
  }
  handle->cursor += size;
  klog("mutable-fs: write-fd fd=%u bytes=%lu cursor=%lu\n", fd, size,
       handle->cursor);
  return (int64_t)size;
}

xaios_status_t mutable_fs_seek(uint32_t fd, uint64_t offset) {
  xaios_mfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0 || offset > g_active_max_file_bytes) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  handle->cursor = offset;
  return XAIOS_OK;
}

xaios_status_t mutable_fs_close(uint32_t fd) {
  xaios_mfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }
  klog("mutable-fs: close fd=%u path=%s\n", fd, handle->path);
  handle->in_use = 0;
  handle->flags = 0;
  handle->cursor = 0;
  handle->path[0] = '\0';
  ++g_close_count;
  return XAIOS_OK;
}

uint64_t mutable_fs_mount_count(void) { return g_mount_count; }
uint64_t mutable_fs_format_count(void) { return g_format_count; }
uint64_t mutable_fs_boot_load_count(void) { return g_boot_load_count; }
uint64_t mutable_fs_file_count(void) { return node_count_by_type(MFS_NODE_FILE); }
uint64_t mutable_fs_directory_count(void) { return node_count_by_type(MFS_NODE_DIR); }
uint64_t mutable_fs_write_count(void) { return g_write_count; }
uint64_t mutable_fs_read_count(void) { return g_read_count; }
uint64_t mutable_fs_delete_count(void) { return g_delete_count; }
uint64_t mutable_fs_commit_count(void) { return g_commit_count; }
uint64_t mutable_fs_rollback_count(void) { return g_rollback_count; }
uint64_t mutable_fs_reject_count(void) { return g_reject_count; }
uint64_t mutable_fs_checksum_error_count(void) { return g_checksum_error_count; }
uint64_t mutable_fs_allocation_count(void) { return g_allocation_count; }
uint64_t mutable_fs_free_count(void) { return g_free_count; }
uint64_t mutable_fs_replay_count(void) { return g_replay_count; }
uint64_t mutable_fs_journal_write_count(void) { return g_journal_write_count; }
uint64_t mutable_fs_multi_sector_file_count(void) { return g_multi_sector_file_count; }
uint64_t mutable_fs_state_record_count(void) { return g_state_record_count; }
uint64_t mutable_fs_rename_count(void) { return g_rename_count; }
uint64_t mutable_fs_list_count(void) { return g_list_count; }
uint64_t mutable_fs_stat_count(void) { return g_stat_count; }
uint64_t mutable_fs_open_count(void) { return g_open_count; }
uint64_t mutable_fs_close_count(void) { return g_close_count; }
uint64_t mutable_fs_persistent_mount_count(void) { return g_persistent_mount_count; }

xaios_status_t mutable_fs_mount_persistent(uint32_t slot) {
  virtio_block_handle_t *handle = 0;
  xaios_status_t status = virtio_block_open_slot(slot, &handle);
  if (status != XAIOS_OK) {
    klog("mutable-fs: persistent block device not found at slot=%u\n", slot);
    return status;
  }
  set_active_v3();
  if (virtio_block_capacity_sectors_h(handle) <
      active_data_start_sector() + MFS_V3_DATA_SECTORS) {
    klog("mutable-fs: persistent disk too small capacity=%lu needed=%lu\n",
         virtio_block_capacity_sectors_h(handle),
         active_data_start_sector() + MFS_V3_DATA_SECTORS);
    set_active_v2();
    virtio_block_close(handle);
    return XAIOS_ERR_IO;
  }
  g_persistent_handle = handle;
  g_mounted = 0;
  g_mount_flags = 0;
  if (read_metadata() != XAIOS_OK) {
    g_persistent_handle = 0;
    set_active_v2();
    virtio_block_close(handle);
    return XAIOS_ERR_IO;
  }
  uint64_t saved_checksum = g_mfs.checksum;
  if (validate_disk(g_metadata_verified_checksum) == XAIOS_OK &&
      saved_checksum == g_metadata_verified_checksum) {
    ++g_boot_load_count;
    klog("mutable-fs: persistent loaded files=%lu dirs=%lu blocks=%lu gen=%lu\n",
         node_count_by_type(MFS_NODE_FILE), node_count_by_type(MFS_NODE_DIR),
         block_count_used(), g_mfs.generation);
  } else {
    klog("mutable-fs: persistent disk no valid fs; formatting v3\n");
    if (format_volume() != XAIOS_OK) {
      g_persistent_handle = 0;
      set_active_v2();
      virtio_block_close(handle);
      return XAIOS_ERR_IO;
    }
  }
  g_mounted = 1;
  g_mount_flags = MFS_MOUNT_READ_WRITE;
  ++g_mount_count;
  ++g_persistent_mount_count;
  if (replay_journal() != XAIOS_OK) {
    g_persistent_handle = 0;
    set_active_v2();
    virtio_block_close(handle);
    return XAIOS_ERR_IO;
  }
  xaios_mfs_node_t *root = find_node("/", 1);
  if (root == 0) {
    if (create_dir("/") != XAIOS_OK) {
      g_persistent_handle = 0;
      set_active_v2();
      virtio_block_close(handle);
      return XAIOS_ERR_IO;
    }
  }
  if (ensure_base_directories() != XAIOS_OK) {
    g_persistent_handle = 0;
    set_active_v2();
    virtio_block_close(handle);
    return XAIOS_ERR_IO;
  }
  klog("mutable-fs: persistent mounted v3 nodes=%u sectors=%u\n",
       g_active_max_nodes, g_active_data_sectors);
  return XAIOS_OK;
}

static void fsck_count_file_blocks(
    uint16_t block_count, const uint16_t blocks[MFS_FILE_MAX_BLOCKS],
    uint8_t references[MFS_V3_DATA_SECTORS],
    xaios_mfs_fsck_result_t *result) {
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

xaios_mfs_fsck_result_t mutable_fs_fsck(void) {
  xaios_mfs_fsck_result_t result;
  uint8_t references[MFS_V3_DATA_SECTORS];
  bytes_zero(&result, sizeof(result));
  bytes_zero(references, sizeof(references));
  result.version = g_active_version;
  result.files = node_count_by_type(MFS_NODE_FILE);
  result.directories = node_count_by_type(MFS_NODE_DIR);
  result.blocks_used = block_count_used();
  result.errors = 0;

  for (uint32_t n = 0; n < g_active_max_nodes; ++n) {
    xaios_mfs_node_t *node = &g_mfs.nodes[n];
    if (node->active != 0 && node->type == MFS_NODE_FILE) {
      fsck_count_file_blocks(node->block_count, node->blocks, references,
                             &result);
    }
    if (node->snapshot_active != 0 &&
        node->snapshot_type == MFS_NODE_FILE) {
      fsck_count_file_blocks(node->snapshot_block_count,
                             node->snapshot_blocks, references, &result);
    }
  }

  for (uint32_t i = 0; i < g_active_data_sectors; ++i) {
    int in_use = g_mfs.block_bitmap[i] != 0;
    int referenced = references[i] != 0U;
    if (in_use != referenced) {
      ++result.errors;
    }
  }
  result.valid = (result.errors == 0) ? 1U : 0U;
  klog("mutable-fs: fsck v%u files=%lu dirs=%lu blocks=%lu errors=%lu valid=%u\n",
       result.version, result.files, result.directories,
       result.blocks_used, result.errors, result.valid);
  return result;
}

void mutable_fs_self_test(void) {
  kassert(sizeof(xaios_mfs_journal_t) == MFS_SECTOR_SIZE);
  kassert(sizeof(xaios_mfs_disk_t) <= MFS_METADATA_SECTORS * MFS_SECTOR_SIZE);
  g_mounted = 0;
  g_mount_flags = 0;
  g_persistent_handle = 0;
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

  kassert(mount_volume(MFS_MOUNT_READ_WRITE) == XAIOS_OK);
  kassert(format_volume() == XAIOS_OK);
  kassert(ensure_base_directories() == XAIOS_OK);

  kassert(mutable_fs_record_service_state("/svc/source-index", "running") ==
          XAIOS_OK);
  kassert(mutable_fs_record_workspace_state(0, "boot") == XAIOS_OK);
  kassert(mutable_fs_record_update_state("signed-update-required") == XAIOS_OK);
  kassert(mutable_fs_record_admin_status("/svc/source-index", "running", 1, 0,
                                         0) == XAIOS_OK);
  kassert(write_file("/config/xaios.conf", k_config_v1,
                     sizeof(k_config_v1)) == XAIOS_OK);

  uint8_t large[MFS_SECTOR_SIZE * 3U];
  for (uint64_t i = 0; i < sizeof(large); ++i) {
    large[i] = (uint8_t)('A' + (i % 23U));
  }
  kassert(write_file("/state/services/large.state", large, sizeof(large)) ==
          XAIOS_OK);

  uint8_t buffer[MFS_MAX_FILE_BYTES];
  uint64_t size = 0;
  kassert(read_file("/state/services/large.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(large));
  kassert(bytes_eq(buffer, large, sizeof(large)) != 0);

  char listing[XAIOS_MFS_MAX_LIST_BYTES];
  xaios_mfs_stat_t stat;
  kassert(list_dir("/state", listing, sizeof(listing), &size) == XAIOS_OK);
  kassert(size > 0);
  kassert(stat_node("/state/services/large.state", &stat) == XAIOS_OK);
  kassert(stat.type == MFS_NODE_FILE);
  kassert(stat.size == sizeof(large));
  kassert(rename_node("/config/xaios.conf", "/config/xaios-renamed.conf") ==
          XAIOS_OK);
  kassert(stat_node("/config/xaios-renamed.conf", &stat) == XAIOS_OK);
  kassert(read_file("/config/xaios.conf", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);

  static const char k_fd_payload[] = "fd-api=ok\n";
  int64_t fd = mutable_fs_open("/logs/fd-api.log",
                               XAIOS_MFS_OPEN_READ | XAIOS_MFS_OPEN_WRITE |
                                   XAIOS_MFS_OPEN_CREATE);
  kassert(fd > 0);
  kassert(mutable_fs_write_fd((uint32_t)fd, k_fd_payload,
                              sizeof(k_fd_payload)) ==
          (int64_t)sizeof(k_fd_payload));
  kassert(mutable_fs_seek((uint32_t)fd, 3U) == XAIOS_OK);
  kassert(handle_for_fd((uint32_t)fd)->cursor == 3U);
  kassert(mutable_fs_seek((uint32_t)fd, 0U) == XAIOS_OK);
  kassert(mutable_fs_close((uint32_t)fd) == XAIOS_OK);
  fd = mutable_fs_open("/logs/fd-api.log", XAIOS_MFS_OPEN_READ);
  kassert(fd > 0);
  kassert(mutable_fs_read_fd((uint32_t)fd, buffer, sizeof(k_fd_payload)) ==
          (int64_t)sizeof(k_fd_payload));
  kassert(bytes_eq(buffer, k_fd_payload, sizeof(k_fd_payload)) != 0);
  kassert(mutable_fs_close((uint32_t)fd) == XAIOS_OK);
  fd = mutable_fs_open("/logs/fd-api.log",
                       XAIOS_MFS_OPEN_READ | XAIOS_MFS_OPEN_WRITE |
                           XAIOS_MFS_OPEN_TRUNCATE);
  kassert(fd > 0);
  kassert(stat_node("/logs/fd-api.log", &stat) == XAIOS_OK);
  kassert(stat.size == 0);
  kassert(mutable_fs_close((uint32_t)fd) == XAIOS_OK);
  kassert(mutable_fs_open("/missing/nope", XAIOS_MFS_OPEN_READ) ==
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
  kassert(mount_volume(MFS_MOUNT_READ_WRITE) == XAIOS_OK);
  kassert(read_file("/state/services/replayed.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(k_replayed_state));
  kassert(bytes_eq(buffer, k_replayed_state, sizeof(k_replayed_state)) != 0);
  xaios_mfs_fsck_result_t snapshot_fsck = mutable_fs_fsck();
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
  uint8_t too_large[MFS_MAX_FILE_BYTES + 1U];
  kassert(write_file("/state/services/too-large", too_large,
                     sizeof(too_large)) == XAIOS_ERR_INVALID);
  kassert(read_file("/state/missing.state", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);

  kassert(mutable_fs_mount_count() == 2);
  kassert(mutable_fs_format_count() >= 1);
  kassert(mutable_fs_format_count() <= 2);
  kassert(mutable_fs_file_count() >= 6);
  kassert(mutable_fs_directory_count() >= 11);
  kassert(mutable_fs_write_count() >= 12);
  kassert(mutable_fs_read_count() >= 5);
  kassert(mutable_fs_delete_count() == 1);
  kassert(mutable_fs_commit_count() == 1);
  kassert(mutable_fs_rollback_count() == 1);
  kassert(mutable_fs_replay_count() == 1);
  kassert(mutable_fs_journal_write_count() == 1);
  kassert(mutable_fs_multi_sector_file_count() >= 1);
  kassert(mutable_fs_state_record_count() == 4);
  kassert(mutable_fs_reject_count() >= 7);
  kassert(mutable_fs_checksum_error_count() == 0);
  kassert(mutable_fs_rename_count() == 1);
  kassert(mutable_fs_list_count() == 1);
  kassert(mutable_fs_stat_count() == 3);
  kassert(mutable_fs_open_count() == 3);
  kassert(mutable_fs_close_count() == 3);
  klog("mutable-fs: allocator self-test passed allocations=%lu frees=%lu blocks=%lu\n",
       mutable_fs_allocation_count(), mutable_fs_free_count(),
       block_count_used());
  klog("mutable-fs: directory tree self-test passed directories=%lu\n",
       mutable_fs_directory_count());
  klog("mutable-fs: multi-sector file self-test passed files=%lu multi_sector=%lu\n",
       mutable_fs_file_count(), mutable_fs_multi_sector_file_count());
  klog("mutable-fs: journal replay self-test passed replays=%lu journal_writes=%lu\n",
       mutable_fs_replay_count(), mutable_fs_journal_write_count());
  klog("mutable-fs: public API self-test passed list=%lu stat=%lu rename=%lu open=%lu close=%lu\n",
       mutable_fs_list_count(), mutable_fs_stat_count(),
       mutable_fs_rename_count(), mutable_fs_open_count(),
       mutable_fs_close_count());
  klog("mutable-fs: subsystem records self-test passed records=%lu\n",
       mutable_fs_state_record_count());
  klog("mutable-fs: self-test passed files=%lu directories=%lu writes=%lu reads=%lu deletes=%lu commits=%lu rollbacks=%lu replays=%lu rejects=%lu checksum_errors=%lu\n",
       mutable_fs_file_count(), mutable_fs_directory_count(),
       mutable_fs_write_count(), mutable_fs_read_count(),
       mutable_fs_delete_count(), mutable_fs_commit_count(),
       mutable_fs_rollback_count(), mutable_fs_replay_count(),
       mutable_fs_reject_count(), mutable_fs_checksum_error_count());
}
