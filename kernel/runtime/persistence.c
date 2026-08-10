#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/persistence.h>
#include <xaios/virtio_blk.h>

#define MAX_SNAPSHOTS 8U
#define SNAPSHOT_LABEL_MAX 32U
#define PERSISTENCE_SECTOR UINT64_C(3000)
#define PERSISTENCE_SECTOR_SIZE UINT64_C(512)
#define PERSISTENCE_MAGIC "XAIOSPST1"
#define PERSISTENCE_MAGIC_LEN 8U
#define PERSISTENCE_VERSION 1U
#define FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define FNV1A64_PRIME UINT64_C(1099511628211)

typedef struct xaios_snapshot_record {
  uint8_t active;
  xaios_snapshot_kind_t kind;
  uint32_t owner_id;
  uint64_t generation;
  char label[SNAPSHOT_LABEL_MAX];
} xaios_snapshot_record_t;

typedef struct xaios_persistence_disk_record {
  uint32_t active;
  uint32_t kind;
  uint32_t owner_id;
  uint32_t reserved;
  uint64_t generation;
  char label[SNAPSHOT_LABEL_MAX];
} xaios_persistence_disk_record_t;

typedef struct xaios_persistence_disk_sector {
  char magic[8];
  uint32_t version;
  uint32_t sector_bytes;
  uint32_t record_count;
  uint32_t reserved;
  uint64_t next_generation;
  uint64_t checksum;
  xaios_persistence_disk_record_t records[MAX_SNAPSHOTS];
  uint8_t padding[24];
} xaios_persistence_disk_sector_t;

static xaios_snapshot_record_t g_snapshots[MAX_SNAPSHOTS];
static uint64_t g_snapshot_count;
static uint64_t g_rollback_count;
static uint64_t g_reject_count;
static uint64_t g_next_generation;
static uint64_t g_disk_write_count;
static uint64_t g_disk_load_count;
static uint64_t g_disk_boot_load_count;
static uint64_t g_checksum_error_count;

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

static int bytes_eq(const char *a, const char *b, uint64_t count) {
  for (uint64_t i = 0; i < count; ++i) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
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

static void clear_snapshot_table(void) {
  for (uint32_t i = 0; i < MAX_SNAPSHOTS; ++i) {
    g_snapshots[i].active = 0;
    g_snapshots[i].kind = XAIOS_SNAPSHOT_BOOT_CONFIG;
    g_snapshots[i].owner_id = 0;
    g_snapshots[i].generation = 0;
    g_snapshots[i].label[0] = '\0';
  }
  g_snapshot_count = 0;
  g_next_generation = 1;
}

static int label_valid(const char *label) {
  if (label == 0 || label[0] == '\0') {
    return 0;
  }
  for (uint32_t i = 0; label[i] != '\0'; ++i) {
    if (i + 1U >= SNAPSHOT_LABEL_MAX ||
        label[i] < ' ' || label[i] > '~') {
      return 0;
    }
  }
  return 1;
}

static int kind_valid(xaios_snapshot_kind_t kind) {
  return kind == XAIOS_SNAPSHOT_BOOT_CONFIG ||
         kind == XAIOS_SNAPSHOT_SERVICE ||
         kind == XAIOS_SNAPSHOT_WORKSPACE ||
         kind == XAIOS_SNAPSHOT_SANDBOX ||
         kind == XAIOS_SNAPSHOT_UPDATE;
}

static void copy_label(char dst[SNAPSHOT_LABEL_MAX], const char *src) {
  uint32_t i = 0;
  while (i + 1U < SNAPSHOT_LABEL_MAX && src[i] != '\0') {
    dst[i] = src[i];
    ++i;
  }
  dst[i] = '\0';
}

static xaios_snapshot_record_t *find_snapshot(xaios_snapshot_kind_t kind,
                                             uint32_t owner_id) {
  xaios_snapshot_record_t *best = 0;
  for (uint32_t i = 0; i < MAX_SNAPSHOTS; ++i) {
    if (g_snapshots[i].active != 0 &&
        g_snapshots[i].kind == kind &&
        g_snapshots[i].owner_id == owner_id &&
        (best == 0 || g_snapshots[i].generation > best->generation)) {
      best = &g_snapshots[i];
    }
  }
  return best;
}

void persistence_runtime_init(void) {
  clear_snapshot_table();
  g_rollback_count = 0;
  g_reject_count = 0;
  g_disk_write_count = 0;
  g_disk_load_count = 0;
  g_disk_boot_load_count = 0;
  g_checksum_error_count = 0;
  klog("persistence: runtime initialized slots=%u\n", MAX_SNAPSHOTS);
}

static uint64_t persistence_sector_checksum(xaios_persistence_disk_sector_t *sector) {
  uint64_t saved = sector->checksum;
  sector->checksum = 0;
  uint64_t checksum = fnv1a64(sector, sizeof(*sector));
  sector->checksum = saved;
  return checksum;
}

static xaios_status_t persistence_flush_to_disk(void) {
  xaios_persistence_disk_sector_t sector;
  bytes_zero(&sector, sizeof(sector));
  bytes_copy(sector.magic, PERSISTENCE_MAGIC, PERSISTENCE_MAGIC_LEN);
  sector.version = PERSISTENCE_VERSION;
  sector.sector_bytes = PERSISTENCE_SECTOR_SIZE;
  sector.record_count = (uint32_t)g_snapshot_count;
  sector.next_generation = g_next_generation;

  uint32_t out = 0;
  for (uint32_t i = 0; i < MAX_SNAPSHOTS; ++i) {
    if (g_snapshots[i].active == 0) {
      continue;
    }
    kassert(out < MAX_SNAPSHOTS);
    sector.records[out].active = 1;
    sector.records[out].kind = (uint32_t)g_snapshots[i].kind;
    sector.records[out].owner_id = g_snapshots[i].owner_id;
    sector.records[out].generation = g_snapshots[i].generation;
    copy_label(sector.records[out].label, g_snapshots[i].label);
    ++out;
  }
  sector.record_count = out;
  sector.checksum = persistence_sector_checksum(&sector);

  if (virtio_block_write_sector(PERSISTENCE_SECTOR, &sector,
                                sizeof(sector)) != XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }
  ++g_disk_write_count;
  klog("persistence: disk write sector=%lu version=%u records=%u checksum=0x%lx\n",
       PERSISTENCE_SECTOR, sector.version, sector.record_count,
       sector.checksum);
  return XAIOS_OK;
}

static xaios_status_t persistence_load_from_disk(void) {
  xaios_persistence_disk_sector_t sector;
  bytes_zero(&sector, sizeof(sector));
  if (virtio_block_read_sector(PERSISTENCE_SECTOR, &sector, sizeof(sector)) !=
      XAIOS_OK) {
    ++g_reject_count;
    return XAIOS_ERR_IO;
  }

  if (!bytes_eq(sector.magic, PERSISTENCE_MAGIC, PERSISTENCE_MAGIC_LEN) ||
      sector.version != PERSISTENCE_VERSION ||
      sector.sector_bytes != PERSISTENCE_SECTOR_SIZE ||
      sector.record_count > MAX_SNAPSHOTS) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }

  uint64_t expected = sector.checksum;
  uint64_t actual = persistence_sector_checksum(&sector);
  if (actual != expected) {
    ++g_checksum_error_count;
    ++g_reject_count;
    klog("persistence: checksum mismatch expected=0x%lx actual=0x%lx\n",
         expected, actual);
    return XAIOS_ERR_INVALID;
  }

  for (uint32_t i = 0; i < sector.record_count; ++i) {
    if (sector.records[i].active == 0 ||
        !kind_valid((xaios_snapshot_kind_t)sector.records[i].kind) ||
        !label_valid(sector.records[i].label)) {
      ++g_reject_count;
      return XAIOS_ERR_INVALID;
    }
  }

  clear_snapshot_table();
  g_next_generation = sector.next_generation;
  for (uint32_t i = 0; i < sector.record_count; ++i) {
    g_snapshots[i].active = 1;
    g_snapshots[i].kind = (xaios_snapshot_kind_t)sector.records[i].kind;
    g_snapshots[i].owner_id = sector.records[i].owner_id;
    g_snapshots[i].generation = sector.records[i].generation;
    copy_label(g_snapshots[i].label, sector.records[i].label);
    ++g_snapshot_count;
  }

  ++g_disk_load_count;
  klog("persistence: disk loaded sector=%lu version=%u records=%lu next_generation=%lu\n",
       PERSISTENCE_SECTOR, sector.version, g_snapshot_count,
       g_next_generation);
  return XAIOS_OK;
}

static void persistence_probe_existing_disk_state(void) {
  xaios_persistence_disk_sector_t sector;
  bytes_zero(&sector, sizeof(sector));
  if (virtio_block_read_sector(PERSISTENCE_SECTOR, &sector, sizeof(sector)) !=
      XAIOS_OK) {
    return;
  }
  if (!bytes_eq(sector.magic, PERSISTENCE_MAGIC, PERSISTENCE_MAGIC_LEN) ||
      sector.version != PERSISTENCE_VERSION ||
      sector.sector_bytes != PERSISTENCE_SECTOR_SIZE ||
      sector.record_count > MAX_SNAPSHOTS) {
    klog("persistence: no existing disk state sector=%lu\n",
         PERSISTENCE_SECTOR);
    return;
  }

  uint64_t expected = sector.checksum;
  uint64_t actual = persistence_sector_checksum(&sector);
  if (actual != expected) {
    ++g_checksum_error_count;
    klog("persistence: existing disk checksum mismatch expected=0x%lx actual=0x%lx\n",
         expected, actual);
    return;
  }
  for (uint32_t i = 0; i < sector.record_count; ++i) {
    if (sector.records[i].active == 0 ||
        !kind_valid((xaios_snapshot_kind_t)sector.records[i].kind) ||
        !label_valid(sector.records[i].label)) {
      klog("persistence: existing disk state invalid record=%u sector=%lu\n",
           i, PERSISTENCE_SECTOR);
      return;
    }
  }

  ++g_disk_boot_load_count;
  klog("persistence: existing disk state loaded records=%u next_generation=%lu checksum=0x%lx\n",
       sector.record_count, sector.next_generation, sector.checksum);
}

xaios_status_t persistence_snapshot_create(xaios_snapshot_kind_t kind,
                                          uint32_t owner_id,
                                          const char *label) {
  if (!kind_valid(kind) || !label_valid(label)) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }

  for (uint32_t i = 0; i < MAX_SNAPSHOTS; ++i) {
    if (g_snapshots[i].active == 0) {
      g_snapshots[i].active = 1;
      g_snapshots[i].kind = kind;
      g_snapshots[i].owner_id = owner_id;
      g_snapshots[i].generation = g_next_generation;
      ++g_next_generation;
      copy_label(g_snapshots[i].label, label);
      ++g_snapshot_count;
      klog("persistence: snapshot kind=%u owner=%u generation=%lu label=%s\n",
           (unsigned)kind, owner_id, g_snapshots[i].generation,
           g_snapshots[i].label);
      return XAIOS_OK;
    }
  }

  ++g_reject_count;
  return XAIOS_ERR_NO_MEMORY;
}

xaios_status_t persistence_rollback(xaios_snapshot_kind_t kind,
                                   uint32_t owner_id) {
  if (!kind_valid(kind)) {
    ++g_reject_count;
    return XAIOS_ERR_INVALID;
  }

  xaios_snapshot_record_t *snapshot = find_snapshot(kind, owner_id);
  if (snapshot == 0) {
    ++g_reject_count;
    return XAIOS_ERR_NOT_FOUND;
  }

  ++g_rollback_count;
  klog("persistence: rollback kind=%u owner=%u generation=%lu label=%s\n",
       (unsigned)kind, owner_id, snapshot->generation, snapshot->label);
  snapshot->active = 0;
  snapshot->label[0] = '\0';
  return XAIOS_OK;
}

uint64_t persistence_snapshot_count(void) {
  return g_snapshot_count;
}

uint64_t persistence_rollback_count(void) {
  return g_rollback_count;
}

uint64_t persistence_reject_count(void) {
  return g_reject_count;
}

uint64_t persistence_disk_write_count(void) {
  return g_disk_write_count;
}

uint64_t persistence_disk_load_count(void) {
  return g_disk_load_count;
}

uint64_t persistence_disk_boot_load_count(void) {
  return g_disk_boot_load_count;
}

uint64_t persistence_checksum_error_count(void) {
  return g_checksum_error_count;
}

void persistence_self_test(void) {
  persistence_runtime_init();
  kassert(sizeof(xaios_persistence_disk_sector_t) <= PERSISTENCE_SECTOR_SIZE);
  kassert(PERSISTENCE_SECTOR < virtio_block_capacity_sectors());
  klog("persistence: self-test scratch sector=%lu sectors=1 initramfs_payload_start=4096\n",
       PERSISTENCE_SECTOR);
  persistence_probe_existing_disk_state();

  kassert(persistence_snapshot_create(XAIOS_SNAPSHOT_BOOT_CONFIG, 0,
                                      "boot-config-v1") == XAIOS_OK);
  kassert(persistence_snapshot_create(XAIOS_SNAPSHOT_SERVICE, 1,
                                      "init-service") == XAIOS_OK);
  kassert(persistence_snapshot_create(XAIOS_SNAPSHOT_WORKSPACE, 1,
                                      "workspace-r4") == XAIOS_OK);
  kassert(persistence_snapshot_create(XAIOS_SNAPSHOT_SANDBOX, 0,
                                      "sandbox-rev-good") == XAIOS_OK);
  kassert(persistence_snapshot_create(XAIOS_SNAPSHOT_UPDATE, 0,
                                      "update-policy-v1") == XAIOS_OK);
  kassert(persistence_flush_to_disk() == XAIOS_OK);
  clear_snapshot_table();
  kassert(g_snapshot_count == 0);
  kassert(persistence_load_from_disk() == XAIOS_OK);
  kassert(g_snapshot_count == 5);

  kassert(persistence_rollback(XAIOS_SNAPSHOT_BOOT_CONFIG, 0) == XAIOS_OK);
  kassert(persistence_rollback(XAIOS_SNAPSHOT_SERVICE, 1) == XAIOS_OK);
  kassert(persistence_rollback(XAIOS_SNAPSHOT_WORKSPACE, 1) == XAIOS_OK);
  kassert(persistence_rollback(XAIOS_SNAPSHOT_SANDBOX, 0) == XAIOS_OK);
  kassert(persistence_rollback(XAIOS_SNAPSHOT_UPDATE, 0) == XAIOS_OK);
  kassert(persistence_rollback(XAIOS_SNAPSHOT_WORKSPACE, 99) ==
          XAIOS_ERR_NOT_FOUND);
  kassert(persistence_snapshot_create((xaios_snapshot_kind_t)99, 0,
                                      "bad") == XAIOS_ERR_INVALID);

  kassert(g_snapshot_count == 5);
  kassert(g_rollback_count == 5);
  kassert(g_reject_count == 2);
  kassert(g_disk_write_count == 1);
  kassert(g_disk_load_count == 1);
  kassert(g_checksum_error_count == 0);
  klog("persistence: disk reload/rollback self-test passed snapshots=%lu rollbacks=%lu rejects=%lu disk_writes=%lu disk_loads=%lu checksum_errors=%lu\n",
       g_snapshot_count, g_rollback_count, g_reject_count,
       g_disk_write_count, g_disk_load_count, g_checksum_error_count);
}
