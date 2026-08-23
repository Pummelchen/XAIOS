#include <xaios/assert.h>
#include <xaios/initramfs.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/virtio_blk.h>

#define INITFS_SECTOR UINT64_C(1)
#define INITFS_MAGIC "XAIOSROFS2"
#define INITFS_MAGIC_LEN 9U
#define INITFS_MAX_FILES 64U
#define INITFS_PATH_MAX 64U
#define INITFS_MODE_MAX 32U
#define SECTOR_SIZE UINT64_C(512)
#define INITFS_HEADER_BYTES 8192U
#define INITFS_DATA_OFFSET UINT64_C(4096)
#define INITFS_VERSION 2U
#define INITFS_FLAG_READ_ONLY 1U
#define INITFS_ENTRY_FLAG_EXECUTABLE 1U
#define INITFS_ENTRY_FLAG_MANIFEST 2U
#define INITFS_ENTRY_TYPE_FILE 1U
#define FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define FNV1A64_PRIME UINT64_C(1099511628211)

typedef struct initfs_disk_entry {
  char path[INITFS_PATH_MAX];
  uint64_t offset;
  uint64_t size;
  uint32_t flags;
  uint32_t type;
  uint64_t content_hash;
} initfs_disk_entry_t;

typedef struct initfs_disk_header {
  char magic[16];
  uint32_t version;
  uint32_t header_bytes;
  uint32_t block_size;
  uint32_t entry_count;
  uint32_t manifest_index;
  uint32_t flags;
  uint64_t data_offset;
  uint64_t image_size;
  initfs_disk_entry_t entries[INITFS_MAX_FILES];
} initfs_disk_header_t;

static xaios_initramfs_file_t g_files[INITFS_MAX_FILES];
static char g_file_paths[INITFS_MAX_FILES][INITFS_PATH_MAX];
static char g_config_service_path[INITFS_PATH_MAX];
static char g_config_service_manager_path[INITFS_PATH_MAX];
static char g_config_service_descriptor_path[INITFS_PATH_MAX];
static char g_config_mode[INITFS_MODE_MAX];
static char g_config_child_service_path[INITFS_PATH_MAX];
static char g_config_child_service_parent[INITFS_PATH_MAX];
static char g_config_child_service_restart[INITFS_MODE_MAX];
static xaios_initramfs_config_t g_config;
static uint32_t g_file_count;

static uint32_t str_len(const char *value) {
  uint32_t length = 0U;
  while (value[length] != '\0') ++length;
  return length;
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

static int bytes_eq(const char *a, const char *b, uint64_t count) {
  for (uint64_t i = 0; i < count; ++i) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

static int magic_ok(const char *magic) {
  for (uint32_t i = 0; i < INITFS_MAGIC_LEN; ++i) {
    if (magic[i] != INITFS_MAGIC[i]) {
      return 0;
    }
  }
  return 1;
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
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

static void copy_path(char *dst, const char *src) {
  for (uint32_t i = 0; i < INITFS_PATH_MAX; ++i) {
    dst[i] = src[i];
    if (src[i] == '\0') {
      return;
    }
  }
  dst[INITFS_PATH_MAX - 1U] = '\0';
}

static xaios_status_t copy_config_value(char *dst, uint32_t capacity,
                                       const char *src, uint64_t size) {
  if (capacity == 0 || size == 0 || size >= capacity) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; i < size; ++i) {
    char c = src[i];
    if (c == '\r' || c == '\n' || c == '\0') {
      return XAIOS_ERR_INVALID;
    }
    dst[i] = c;
  }
  dst[size] = '\0';
  return XAIOS_OK;
}

static xaios_status_t parse_config_line(const char *line, uint64_t len) {
  if (len == 0 || line[0] == '#') {
    return XAIOS_OK;
  }
  if (len > 8 && bytes_eq(line, "service=", 8)) {
    return copy_config_value(g_config_service_path, INITFS_PATH_MAX, line + 8,
                             len - 8);
  }
  if (len > 16 && bytes_eq(line, "service_manager=", 16)) {
    return copy_config_value(g_config_service_manager_path, INITFS_PATH_MAX,
                             line + 16, len - 16);
  }
  if (len > 19 && bytes_eq(line, "service_descriptor=", 19)) {
    return copy_config_value(g_config_service_descriptor_path, INITFS_PATH_MAX,
                             line + 19, len - 19);
  }
  if (len > 5 && bytes_eq(line, "mode=", 5)) {
    return copy_config_value(g_config_mode, INITFS_MODE_MAX, line + 5,
                             len - 5);
  }
  if (len > 14 && bytes_eq(line, "child_service=", 14)) {
    return copy_config_value(g_config_child_service_path, INITFS_PATH_MAX,
                             line + 14, len - 14);
  }
  if (len > 13 && bytes_eq(line, "child_parent=", 13)) {
    return copy_config_value(g_config_child_service_parent, INITFS_PATH_MAX,
                             line + 13, len - 13);
  }
  if (len > 14 && bytes_eq(line, "child_restart=", 14)) {
    return copy_config_value(g_config_child_service_restart, INITFS_MODE_MAX,
                             line + 14, len - 14);
  }
  klog("initramfs: rejected config line len=%lu\n", len);
  return XAIOS_ERR_INVALID;
}

static xaios_status_t parse_config_manifest(const xaios_initramfs_file_t *file) {
  if (file == 0 || file->base == 0 || file->size == 0 ||
      file->manifest == 0) {
    return XAIOS_ERR_INVALID;
  }

  g_config_service_path[0] = '\0';
  g_config_service_manager_path[0] = '\0';
  g_config_service_descriptor_path[0] = '\0';
  g_config_mode[0] = '\0';
  g_config_child_service_path[0] = '\0';
  g_config_child_service_parent[0] = '\0';
  g_config_child_service_restart[0] = '\0';
  const char *bytes = (const char *)file->base;
  uint64_t line_start = 0;
  for (uint64_t i = 0; i <= file->size; ++i) {
    if (i == file->size || bytes[i] == '\n') {
      uint64_t line_len = i - line_start;
      if (line_len != 0 && bytes[line_start + line_len - 1U] == '\r') {
        --line_len;
      }
      if (parse_config_line(bytes + line_start, line_len) != XAIOS_OK) {
        return XAIOS_ERR_INVALID;
      }
      line_start = i + 1U;
    }
  }

  if (g_config_service_path[0] == '\0' ||
      g_config_service_manager_path[0] == '\0' ||
      g_config_service_descriptor_path[0] == '\0' ||
      g_config_mode[0] == '\0' ||
      g_config_child_service_path[0] == '\0' ||
      g_config_child_service_parent[0] == '\0' ||
      g_config_child_service_restart[0] == '\0') {
    klog("initramfs: config missing required service/mode/child descriptor\n");
    return XAIOS_ERR_INVALID;
  }

  g_config.service_path = g_config_service_path;
  g_config.service_manager_path = g_config_service_manager_path;
  g_config.service_descriptor_path = g_config_service_descriptor_path;
  g_config.mode = g_config_mode;
  g_config.child_service_path = g_config_child_service_path;
  g_config.child_service_parent = g_config_child_service_parent;
  g_config.child_service_restart = g_config_child_service_restart;
  g_config.valid = 1;
  klog("initramfs: config service=%s mode=%s\n",
       g_config.service_path, g_config.mode);
  klog("initramfs: service-manager path=%s descriptor=%s\n",
       g_config.service_manager_path, g_config.service_descriptor_path);
  klog("initramfs: child service=%s parent=%s restart=%s\n",
       g_config.child_service_path, g_config.child_service_parent,
       g_config.child_service_restart);
  return XAIOS_OK;
}

static xaios_status_t validate_executable_target(const char *path) {
  for (uint32_t i = 0; i < g_file_count; ++i) {
    if (str_eq(g_files[i].path, path)) {
      if (g_files[i].executable == 0) {
        klog("initramfs: config service target is not executable path=%s\n",
             path);
        return XAIOS_ERR_INVALID;
      }
      return XAIOS_OK;
    }
  }
  klog("initramfs: config service target missing path=%s\n",
       path);
  return XAIOS_ERR_NOT_FOUND;
}

static xaios_status_t validate_descriptor_target(void) {
  for (uint32_t i = 0; i < g_file_count; ++i) {
    if (str_eq(g_files[i].path, g_config.service_descriptor_path)) {
      if (g_files[i].executable != 0 || g_files[i].manifest != 0) {
        klog("initramfs: descriptor has invalid flags path=%s\n",
             g_config.service_descriptor_path);
        return XAIOS_ERR_INVALID;
      }
      return XAIOS_OK;
    }
  }
  klog("initramfs: descriptor target missing path=%s\n",
       g_config.service_descriptor_path);
  return XAIOS_ERR_NOT_FOUND;
}

/* Bounded retry for boot-time block reads.

   A single transient sector read used to end the boot in a panic, with no
   second attempt anywhere on the path. Retrying cannot smuggle in corruption:
   the header is structurally validated and every file is checked against its
   recorded hash below, so a bad read still fails. A retry that was actually
   needed is logged, so a marginal device stays visible rather than silently
   absorbed. */
#define INITFS_READ_ATTEMPTS 3U

static xaios_status_t read_sector_retrying(uint64_t sector, void *buffer) {
  for (uint32_t attempt = 0U; attempt < INITFS_READ_ATTEMPTS; ++attempt) {
    if (virtio_block_read_sector(sector, buffer, SECTOR_SIZE) == XAIOS_OK) {
      if (attempt != 0U) {
        klog("initramfs: sector=%lu read recovered on attempt %u\n", sector,
             (unsigned)(attempt + 1U));
      }
      return XAIOS_OK;
    }
  }
  klog("initramfs: sector=%lu unreadable after %u attempts\n", sector,
       (unsigned)INITFS_READ_ATTEMPTS);
  return XAIOS_ERR_IO;
}

static xaios_status_t read_file_bytes(uint64_t offset, uint64_t size,
                                     void *buffer) {
  uint8_t sector[SECTOR_SIZE];
  uint8_t *out = (uint8_t *)buffer;
  uint64_t copied = 0;

  while (copied < size) {
    uint64_t absolute = offset + copied;
    uint64_t sector_index = absolute / SECTOR_SIZE;
    uint64_t sector_offset = absolute % SECTOR_SIZE;
    uint64_t chunk = SECTOR_SIZE - sector_offset;
    if (chunk > size - copied) {
      chunk = size - copied;
    }
    if (read_sector_retrying(sector_index, sector) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    bytes_copy(out + copied, sector + sector_offset, chunk);
    copied += chunk;
  }

  return XAIOS_OK;
}

static xaios_status_t validate_header(const initfs_disk_header_t *header) {
  if (!magic_ok(header->magic) || header->version != INITFS_VERSION ||
      header->header_bytes != INITFS_HEADER_BYTES ||
      header->block_size != SECTOR_SIZE ||
      header->entry_count == 0 || header->entry_count > INITFS_MAX_FILES ||
      header->manifest_index >= header->entry_count ||
      (header->flags & INITFS_FLAG_READ_ONLY) == 0 ||
      header->data_offset < INITFS_DATA_OFFSET ||
      header->image_size < header->data_offset ||
      header->image_size > virtio_block_capacity_sectors() * SECTOR_SIZE) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

static xaios_status_t validate_entry(const initfs_disk_header_t *header,
                                    const initfs_disk_entry_t *entry,
                                    uint32_t index) {
  if (entry->path[0] != '/' || entry->size == 0 ||
      entry->type != INITFS_ENTRY_TYPE_FILE ||
      entry->offset < header->data_offset ||
      entry->offset + entry->size < entry->offset ||
      entry->offset + entry->size > header->image_size ||
      (entry->offset % header->block_size) != 0 ||
      entry->content_hash == 0) {
    klog("initramfs: bad entry index=%u path0=0x%x offset=%lu size=%lu type=%u\n",
         index, (unsigned)entry->path[0], entry->offset, entry->size,
         entry->type);
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < INITFS_PATH_MAX; ++i) {
    if (entry->path[i] == '\0') {
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_INVALID;
}

xaios_status_t initramfs_init(void) {
  uint8_t header_bytes[INITFS_HEADER_BYTES];
  for (uint64_t i = 0; i < INITFS_HEADER_BYTES / SECTOR_SIZE; ++i) {
    if (read_sector_retrying(INITFS_SECTOR + i,
                             header_bytes + (i * SECTOR_SIZE)) != XAIOS_OK) {
      klog("initramfs: failed to read header sector=%lu\n",
           INITFS_SECTOR + i);
      return XAIOS_ERR_IO;
    }
  }

  const initfs_disk_header_t *header =
      (const initfs_disk_header_t *)(const void *)header_bytes;
  if (validate_header(header) != XAIOS_OK) {
    klog("initramfs: bad rofs header magic='%c%c%c%c' version=%u entries=%u header_bytes=%u block=%u\n",
         header->magic[0], header->magic[1], header->magic[2],
         header->magic[3], header->version, header->entry_count,
         header->header_bytes, header->block_size);
    return XAIOS_ERR_INVALID;
  }

  g_file_count = 0;
  g_config.valid = 0;
  for (uint32_t i = 0; i < header->entry_count; ++i) {
    const initfs_disk_entry_t *entry = &header->entries[i];
    if (validate_entry(header, entry, i) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    for (uint32_t existing = 0; existing < g_file_count; ++existing) {
      if (str_eq(entry->path, g_files[existing].path)) {
        klog("initramfs: duplicate path=%s\n", entry->path);
        return XAIOS_ERR_INVALID;
      }
    }

    void *content = kheap_alloc(entry->size, 16);
    if (content == 0) {
      klog("initramfs: allocation failed path=%s size=%lu\n",
           entry->path, entry->size);
      return XAIOS_ERR_NO_MEMORY;
    }
    if (read_file_bytes(entry->offset, entry->size, content) != XAIOS_OK) {
      klog("initramfs: failed to read path=%s offset=%lu size=%lu\n",
           entry->path, entry->offset, entry->size);
      return XAIOS_ERR_IO;
    }
    uint64_t hash = fnv1a64(content, entry->size);
    if (hash != entry->content_hash) {
      klog("initramfs: hash mismatch path=%s expected=0x%lx actual=0x%lx\n",
           entry->path, entry->content_hash, hash);
      return XAIOS_ERR_INVALID;
    }

    copy_path(g_file_paths[g_file_count], entry->path);
    g_files[g_file_count].path = g_file_paths[g_file_count];
    g_files[g_file_count].base = content;
    g_files[g_file_count].size = entry->size;
    g_files[g_file_count].executable =
        (entry->flags & INITFS_ENTRY_FLAG_EXECUTABLE) != 0;
    g_files[g_file_count].manifest =
        (entry->flags & INITFS_ENTRY_FLAG_MANIFEST) != 0;
    g_files[g_file_count].content_hash = entry->content_hash;
    ++g_file_count;
  }

  if ((header->entries[header->manifest_index].flags &
       INITFS_ENTRY_FLAG_MANIFEST) == 0 ||
      parse_config_manifest(&g_files[header->manifest_index]) != XAIOS_OK ||
      validate_executable_target(g_config.service_path) != XAIOS_OK ||
      validate_executable_target(g_config.service_manager_path) != XAIOS_OK ||
      validate_descriptor_target() != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  klog("initramfs: mounted rofs version=%u files=%u manifest=%s source=virtio-blk\n",
       header->version, g_file_count, g_files[header->manifest_index].path);
  return XAIOS_OK;
}

xaios_status_t initramfs_lookup(const char *path,
                               const xaios_initramfs_file_t **file) {
  if (path == 0 || file == 0) {
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < g_file_count; ++i) {
    if (str_eq(path, g_files[i].path)) {
      *file = &g_files[i];
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

uint32_t initramfs_file_count(void) { return g_file_count; }

const xaios_initramfs_file_t *initramfs_file_at(uint32_t index) {
  return index < g_file_count ? &g_files[index] : 0;
}

/* The image stores flat absolute paths and no directory records, so
   directory shape is derived: a directory exists when any file path extends
   it, and its children are the first path components under it. */
int initramfs_child_at(const char *directory, uint32_t index, char *name,
                       uint64_t name_capacity, int *is_directory) {
  const xaios_initramfs_file_t *file = initramfs_file_at(index);
  uint32_t dir_length = 0U;
  if (directory == 0 || name == 0 || is_directory == 0 || file == 0 ||
      file->path == 0 || directory[0] != '/') {
    return 0;
  }
  dir_length = str_len(directory);
  if (dir_length > 1U) {
    uint32_t i = 0U;
    while (i < dir_length && file->path[i] == directory[i]) ++i;
    if (i != dir_length || file->path[i] != '/') return 0;
  }
  const char *remainder =
      file->path + (dir_length == 1U ? 1U : dir_length + 1U);
  uint64_t component = 0U;
  while (remainder[component] != '\0' && remainder[component] != '/')
    ++component;
  if (component == 0U || component + 1U > name_capacity) return 0;
  for (uint64_t i = 0U; i < component; ++i) name[i] = remainder[i];
  name[component] = '\0';
  *is_directory = remainder[component] == '/';
  return 1;
}

int initramfs_directory_exists(const char *directory) {
  char name[64];
  int is_directory = 0;
  if (directory == 0 || directory[0] != '/') return 0;
  if (directory[1] == '\0') return 1;
  for (uint32_t i = 0U; i < g_file_count; ++i) {
    if (initramfs_child_at(directory, i, name, sizeof(name), &is_directory))
      return 1;
  }
  return 0;
}

const xaios_initramfs_config_t *initramfs_config(void) {
  return g_config.valid != 0 ? &g_config : 0;
}

void initramfs_self_test(void) {
  kassert(initramfs_init() == XAIOS_OK);
  const xaios_initramfs_file_t *init = 0;
  const xaios_initramfs_file_t *config = 0;
  kassert(initramfs_lookup("/init", &init) == XAIOS_OK);
  kassert(init != 0);
  kassert(init->base != 0);
  kassert(init->size != 0);
  kassert(init->executable != 0);
  kassert(initramfs_lookup("/etc/xaios-init.conf", &config) == XAIOS_OK);
  kassert(config != 0);
  kassert(config->base != 0);
  kassert(config->size != 0);
  kassert(config->manifest != 0);
  kassert(config->content_hash != 0);
  const xaios_initramfs_config_t *parsed = initramfs_config();
  kassert(parsed != 0);
  kassert(parsed->valid != 0);
  kassert(str_eq(parsed->service_path, "/init"));
  kassert(str_eq(parsed->service_manager_path, "/bin/service-manager"));
  kassert(str_eq(parsed->service_descriptor_path,
                 "/etc/services/source-index.svc"));
  kassert(str_eq(parsed->mode, "qemu-mvp"));
  kassert(str_eq(parsed->child_service_path, "/svc/source-index"));
  kassert(str_eq(parsed->child_service_parent, "/init"));
  kassert(str_eq(parsed->child_service_restart, "never"));
  kassert(initramfs_lookup("/bin/service-manager", &init) == XAIOS_OK);
  kassert(init != 0);
  kassert(init->executable != 0);
  kassert(initramfs_lookup("/bin/xaios-worker", &init) == XAIOS_OK);
  kassert(init != 0);
  kassert(init->executable != 0);
  kassert(initramfs_lookup("/etc/services/source-index.svc", &config) ==
          XAIOS_OK);
  kassert(config != 0);
  kassert(config->manifest == 0);
  kassert(config->executable == 0);
  kassert(initramfs_lookup("/models/cpu-ai-v1-fixture.xaiosmodel", &config) ==
          XAIOS_OK);
  kassert(config != 0);
  kassert(config->base != 0);
  kassert(config->size > 256U);
  kassert(config->manifest == 0);
  kassert(config->executable == 0);
  kassert(initramfs_lookup("/missing", &init) == XAIOS_ERR_NOT_FOUND);
  klog("initramfs: rofs metadata/config self-test passed\n");
}
