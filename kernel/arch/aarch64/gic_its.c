#include <xaios/gic.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/vmm.h>

/* Where QEMU's virt machine puts the translation service. Firmware that
   describes its own is believed instead; this is only the fallback for a
   platform that provides no description at all. */
#define ITS_DEFAULT_BASE UINT64_C(0x08080000)
#define ITS_SIZE UINT64_C(0x20000)
#define GITS_CTLR 0x0000U
#define GITS_TYPER 0x0008U
#define GITS_CBASER 0x0080U
#define GITS_CWRITER 0x0088U
#define GITS_CREADR 0x0090U
#define GITS_BASER 0x0100U
#define GITS_TRANSLATER 0x10040U
#define GITS_CTLR_ENABLE UINT32_C(1)
#define GITS_CTLR_QUIESCENT (UINT32_C(1) << 31U)
#define GITS_BASER_VALID (UINT64_C(1) << 63U)
#define GITS_BASER_TYPE_SHIFT 56U
#define GITS_BASER_ENTRY_SIZE_SHIFT 48U
#define GITS_BASER_PAGE_SIZE_64K (UINT64_C(2) << 8U)
#define GITS_BASER_INNER_SHAREABLE (UINT64_C(2) << 10U)
#define GITS_BASER_RAWAWB (UINT64_C(7) << 59U)
#define GITS_CBASER_VALID (UINT64_C(1) << 63U)
#define GITS_CBASER_INNER_SHAREABLE (UINT64_C(2) << 10U)
#define GITS_CBASER_RAWAWB (UINT64_C(7) << 59U)
#define GITS_BASER_TYPE_DEVICE 1U
#define GITS_BASER_TYPE_COLLECTION 4U
#define GITS_CMD_MAPD UINT64_C(0x08)
#define GITS_CMD_MAPC UINT64_C(0x09)
#define GITS_CMD_MAPTI UINT64_C(0x0a)
#define GITS_CMD_SYNC UINT64_C(0x05)
#define GICR_CTLR 0x0000U
#define GICR_CTLR_ENABLE_LPIS UINT32_C(1)
#define GICR_CTLR_RWP (UINT32_C(1) << 3U)
#define GICR_PROPBASER 0x0070U
#define GICR_PENDBASER 0x0078U
#define GICR_PROPBASER_INNER_SHAREABLE (UINT64_C(2) << 10U)
#define GICR_PROPBASER_RAWAWB (UINT64_C(7) << 7U)
#define GICR_PENDBASER_INNER_SHAREABLE (UINT64_C(2) << 10U)
#define GICR_PENDBASER_RAWAWB (UINT64_C(7) << 7U)
#define GICR_PENDBASER_PTZ (UINT64_C(1) << 62U)
#define GICR_BASE UINT64_C(0x080A0000)
#define GICR_HIGH_BASE UINT64_C(0x4000000000)
#define GICR_LOW_FRAMES 123U
#define GICR_STRIDE UINT64_C(0x20000)
#define ITS_TABLE_SIZE UINT64_C(0x10000)
#define ITS_COMMAND_SIZE UINT64_C(32)
#define ITS_COMMAND_COUNT (ITS_TABLE_SIZE / ITS_COMMAND_SIZE)
#define ITS_LPI_BASE 8192U
#define ITS_LPI_LIMIT 16384U

typedef struct its_command {
  uint64_t words[4];
} its_command_t;

/* One interrupt translation table per device. The driver used to keep a single
   one, so the first device to ask for a vector took the translation service and
   every other was refused: a machine with both NVMe and virtio on PCI could
   give message-signalled interrupts to exactly one of them. */
#define ITS_MAX_DEVICES 16U

typedef struct its_device {
  uint32_t device_id;
  uint32_t used;
  void *itt;
} its_device_t;

typedef struct its_state {
  uint32_t initialized;
  uint32_t device_capacity;
  uint32_t collection_capacity;
  uint64_t typer;
  its_command_t *commands;
  uint64_t command_write;
  uint8_t *properties;
  its_device_t devices[ITS_MAX_DEVICES];
  void **pending;
  uint8_t *collection_ready;
  uint32_t cpu_capacity;
  uint64_t base;
  uint32_t unavailable;
} its_state_t;

static its_state_t g_its = {.base = ITS_DEFAULT_BASE};

void gic_its_set_base(uint64_t base) {
  if (g_its.initialized != 0U || base == 0U) return;
  g_its.base = base;
  g_its.unavailable = 0U;
}

static uint32_t read32(uint64_t address) {
  return *(volatile uint32_t *)(uintptr_t)address;
}

static uint64_t read64(uint64_t address) {
  return *(volatile uint64_t *)(uintptr_t)address;
}

static void write32(uint64_t address, uint32_t value) {
  *(volatile uint32_t *)(uintptr_t)address = value;
}

static void write64(uint64_t address, uint64_t value) {
  *(volatile uint64_t *)(uintptr_t)address = value;
}

static uint64_t physical_address(const void *pointer) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  if (pointer == 0 ||
      vmm_translate((uint64_t)(uintptr_t)pointer, &physical, &flags) !=
          XAIOS_OK ||
      (flags & XAIOS_VMM_PRESENT) == 0U) {
    return 0U;
  }
  return physical;
}

static uint64_t redistributor_base(uint32_t cpu_id) {
  if (cpu_id < GICR_LOW_FRAMES) {
    return GICR_BASE + (uint64_t)cpu_id * GICR_STRIDE;
  }
  return GICR_HIGH_BASE +
         (uint64_t)(cpu_id - GICR_LOW_FRAMES) * GICR_STRIDE;
}

static xaios_status_t map_device_range(uint64_t start, uint64_t length) {
  for (uint64_t offset = 0U; offset < length; offset += UINT64_C(0x1000)) {
    uint64_t physical = 0U;
    uint32_t flags = 0U;
    uint64_t address = start + offset;
    if (vmm_translate(address, &physical, &flags) == XAIOS_OK &&
        physical == address && (flags & XAIOS_VMM_DEVICE) != 0U) {
      continue;
    }
    xaios_status_t status =
        vmm_map_page(address, address,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE);
    if (status != XAIOS_OK) return status;
  }
  return XAIOS_OK;
}

static int wait_clear32(uint64_t address, uint32_t mask) {
  for (uint32_t attempt = 0U; attempt < UINT32_C(10000000); ++attempt) {
    if ((read32(address) & mask) == 0U) return 1;
    xaios_cpu_relax();
  }
  return 0;
}

static int wait_set32(uint64_t address, uint32_t mask) {
  for (uint32_t spin = 0U; spin < UINT32_C(10000000); ++spin) {
    if ((read32(address) & mask) == mask) {
      return 1;
    }
    __asm__ volatile("yield" ::: "memory");
  }
  return 0;
}

static int wait_command(uint64_t writer) {
  for (uint32_t attempt = 0U; attempt < UINT32_C(10000000); ++attempt) {
    if ((read64(g_its.base + GITS_CREADR) & ~UINT64_C(0x1f)) == writer) {
      return 1;
    }
    xaios_cpu_relax();
  }
  return 0;
}

static xaios_status_t send_command(const its_command_t *command) {
  if (command == 0 || g_its.commands == 0) return XAIOS_ERR_INVALID;
  uint64_t index = g_its.command_write / ITS_COMMAND_SIZE;
  if (index >= ITS_COMMAND_COUNT) return XAIOS_ERR_IO;
  g_its.commands[index] = *command;
  __asm__ volatile("dsb ishst" ::: "memory");
  g_its.command_write += ITS_COMMAND_SIZE;
  if (g_its.command_write == ITS_TABLE_SIZE) g_its.command_write = 0U;
  write64(g_its.base + GITS_CWRITER, g_its.command_write);
  return wait_command(g_its.command_write) ? XAIOS_OK : XAIOS_ERR_IO;
}

static xaios_status_t program_baser(uint32_t wanted_type,
                                    uint32_t *capacity) {
  for (uint32_t index = 0U; index < 8U; ++index) {
    uint64_t address = g_its.base + GITS_BASER + (uint64_t)index * 8U;
    uint64_t original = read64(address);
    uint32_t type = (uint32_t)((original >> GITS_BASER_TYPE_SHIFT) & 7U);
    if (type != wanted_type) continue;
    uint32_t entry_size =
        (uint32_t)((original >> GITS_BASER_ENTRY_SIZE_SHIFT) & 0x1fU) + 1U;
    if (entry_size == 0U || entry_size > 256U) return XAIOS_ERR_UNSUPPORTED;
    void *table = kheap_calloc(ITS_TABLE_SIZE, ITS_TABLE_SIZE);
    if (table == 0) return XAIOS_ERR_NO_MEMORY;
    uint64_t table_physical = physical_address(table);
    if (table_physical == 0U) return XAIOS_ERR_IO;
    uint64_t value = (table_physical &
                      UINT64_C(0x0000ffffffff0000)) |
                     ((uint64_t)type << GITS_BASER_TYPE_SHIFT) |
                     ((uint64_t)(entry_size - 1U)
                      << GITS_BASER_ENTRY_SIZE_SHIFT) |
                     GITS_BASER_RAWAWB | GITS_BASER_INNER_SHAREABLE |
                     GITS_BASER_PAGE_SIZE_64K | GITS_BASER_VALID;
    write64(address, value);
    __asm__ volatile("dsb sy" ::: "memory");
    if ((read64(address) & GITS_BASER_VALID) == 0U) return XAIOS_ERR_IO;
    *capacity = (uint32_t)(ITS_TABLE_SIZE / entry_size);
    return XAIOS_OK;
  }
  return XAIOS_ERR_UNSUPPORTED;
}

static xaios_status_t initialize_its(void) {
  if (g_its.initialized != 0U) return XAIOS_OK;
  /* A machine that has no translation service will not grow one, and every
     queue setup would otherwise probe an address nothing answers at. */
  if (g_its.unavailable != 0U) return XAIOS_ERR_UNSUPPORTED;
  if (map_device_range(g_its.base, ITS_SIZE) != XAIOS_OK) {
    g_its.unavailable = 1U;
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint64_t typer = read64(g_its.base + GITS_TYPER);
  uint32_t ctlr = read32(g_its.base + GITS_CTLR);
  klog("gic-its: probe base=0x%lx typer=0x%lx ctlr=0x%x\n", g_its.base,
       typer, ctlr);
  if (typer == UINT64_MAX || ctlr == UINT32_MAX) {
    klog("gic-its: nothing responds at 0x%lx; interrupts stay polled\n",
         g_its.base);
    g_its.unavailable = 1U;
    return XAIOS_ERR_UNSUPPORTED;
  }
  write32(g_its.base + GITS_CTLR, ctlr & ~GITS_CTLR_ENABLE);
  if (!wait_set32(g_its.base + GITS_CTLR, GITS_CTLR_QUIESCENT)) {
    return XAIOS_ERR_IO;
  }
  g_its.commands =
      (its_command_t *)kheap_calloc(ITS_TABLE_SIZE, ITS_TABLE_SIZE);
  g_its.properties = (uint8_t *)kheap_calloc(ITS_TABLE_SIZE, ITS_TABLE_SIZE);
  if (g_its.commands == 0 || g_its.properties == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  xaios_status_t device_status =
      program_baser(GITS_BASER_TYPE_DEVICE, &g_its.device_capacity);
  xaios_status_t collection_status = program_baser(
      GITS_BASER_TYPE_COLLECTION, &g_its.collection_capacity);
  if (device_status != XAIOS_OK || collection_status != XAIOS_OK) {
    klog("gic-its: table setup failed device=%d collection=%d\n",
         (int)device_status, (int)collection_status);
    return XAIOS_ERR_UNSUPPORTED;
  }
  g_its.cpu_capacity = smp_capacity();
  if (g_its.cpu_capacity == 0U ||
      g_its.cpu_capacity > g_its.collection_capacity) {
    klog("gic-its: CPU capacity %u exceeds collection capacity %u\n",
         g_its.cpu_capacity, g_its.collection_capacity);
    return XAIOS_ERR_UNSUPPORTED;
  }
  g_its.pending = (void **)kheap_calloc(
      (uint64_t)g_its.cpu_capacity * sizeof(*g_its.pending), 16U);
  g_its.collection_ready = (uint8_t *)kheap_calloc(
      g_its.cpu_capacity, 16U);
  if (g_its.pending == 0 || g_its.collection_ready == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  uint64_t commands_physical = physical_address(g_its.commands);
  if (commands_physical == 0U) return XAIOS_ERR_IO;
  uint64_t cbaser = (commands_physical &
                     UINT64_C(0x0000fffffffff000)) |
                    GITS_CBASER_RAWAWB | GITS_CBASER_INNER_SHAREABLE |
                    UINT64_C(15) | GITS_CBASER_VALID;
  write64(g_its.base + GITS_CBASER, cbaser);
  write64(g_its.base + GITS_CWRITER, 0U);
  g_its.command_write = 0U;
  write32(g_its.base + GITS_CTLR, GITS_CTLR_ENABLE);
  __asm__ volatile("dsb sy\n\tisb" ::: "memory");
  if ((read32(g_its.base + GITS_CTLR) & GITS_CTLR_ENABLE) == 0U) {
    return XAIOS_ERR_IO;
  }
  g_its.typer = typer;
  g_its.initialized = 1U;
  klog("gic-its: initialized base=0x%lx typer=0x%lx devices=%u collections=%u\n",
       g_its.base, typer, g_its.device_capacity, g_its.collection_capacity);
  return XAIOS_OK;
}

static xaios_status_t enable_lpis(uint32_t cpu_id) {
  if (cpu_id >= g_its.cpu_capacity || smp_cpu_state(cpu_id) == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (g_its.pending[cpu_id] != 0) return XAIOS_OK;
  void *pending = kheap_calloc(ITS_TABLE_SIZE, ITS_TABLE_SIZE);
  if (pending == 0) return XAIOS_ERR_NO_MEMORY;
  uint64_t properties_physical = physical_address(g_its.properties);
  uint64_t pending_physical = physical_address(pending);
  if (properties_physical == 0U || pending_physical == 0U) {
    return XAIOS_ERR_IO;
  }
  uint64_t base = redistributor_base(cpu_id);
  if (map_device_range(base, UINT64_C(0x10000)) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint64_t propbaser =
      (properties_physical & UINT64_C(0x000ffffffffff000)) |
      GICR_PROPBASER_INNER_SHAREABLE | GICR_PROPBASER_RAWAWB | UINT64_C(15);
  uint64_t pendbaser =
      (pending_physical & UINT64_C(0x000fffffffff0000)) |
      GICR_PENDBASER_INNER_SHAREABLE | GICR_PENDBASER_RAWAWB |
      GICR_PENDBASER_PTZ;
  write64(base + GICR_PROPBASER, propbaser);
  write64(base + GICR_PENDBASER, pendbaser);
  write32(base + GICR_CTLR,
          read32(base + GICR_CTLR) | GICR_CTLR_ENABLE_LPIS);
  if (!wait_clear32(base + GICR_CTLR, GICR_CTLR_RWP) ||
      (read32(base + GICR_CTLR) & GICR_CTLR_ENABLE_LPIS) == 0U) {
    return XAIOS_ERR_IO;
  }
  g_its.pending[cpu_id] = pending;
  return XAIOS_OK;
}

static uint64_t collection_target(uint32_t cpu_id) {
  return (g_its.typer & (UINT64_C(1) << 19U)) != 0U
             ? redistributor_base(cpu_id)
             : cpu_id;
}

static xaios_status_t map_collection(uint32_t cpu_id) {
  if (cpu_id >= g_its.cpu_capacity || cpu_id >= g_its.collection_capacity) {
    return XAIOS_ERR_INVALID;
  }
  if (g_its.collection_ready[cpu_id] != 0U) return XAIOS_OK;
  its_command_t mapc = {{GITS_CMD_MAPC, 0U,
                         (collection_target(cpu_id) &
                          UINT64_C(0x0000ffffffff0000)) |
                             cpu_id | (UINT64_C(1) << 63U),
                         0U}};
  xaios_status_t status = send_command(&mapc);
  if (status != XAIOS_OK) return status;
  its_command_t sync = {{GITS_CMD_SYNC, 0U,
                         collection_target(cpu_id) &
                             UINT64_C(0x0000ffffffff0000),
                         0U}};
  status = send_command(&sync);
  if (status == XAIOS_OK) g_its.collection_ready[cpu_id] = 1U;
  return status;
}

xaios_status_t gic_its_configure_msi(uint32_t device_id, uint32_t event_id,
                                     uint32_t intid, uint32_t cpu_id,
                                     uint64_t *message_address,
                                     uint32_t *message_data) {
  if (message_address == 0 || message_data == 0 || intid < ITS_LPI_BASE ||
      intid >= ITS_LPI_LIMIT || event_id >= 32U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = initialize_its();
  if (status != XAIOS_OK) return status;
  if (device_id >= g_its.device_capacity) return XAIOS_ERR_UNSUPPORTED;
  /* Populate the property before enabling LPIs so the redistributor cannot
   * cache the descriptor's disabled state. */
  g_its.properties[intid - ITS_LPI_BASE] = UINT8_C(0xa3);
  __asm__ volatile("dsb ishst" ::: "memory");
  status = enable_lpis(cpu_id);
  if (status != XAIOS_OK) return status;
  status = map_collection(cpu_id);
  if (status != XAIOS_OK) return status;

  its_device_t *entry = 0;
  for (uint32_t index = 0U; index < ITS_MAX_DEVICES; ++index) {
    if (g_its.devices[index].used != 0U &&
        g_its.devices[index].device_id == device_id) {
      entry = &g_its.devices[index];
      break;
    }
  }
  if (entry == 0) {
    for (uint32_t index = 0U; index < ITS_MAX_DEVICES; ++index) {
      if (g_its.devices[index].used == 0U) {
        entry = &g_its.devices[index];
        break;
      }
    }
    if (entry == 0) return XAIOS_ERR_NO_MEMORY;
    void *itt = kheap_calloc(UINT64_C(0x2000), UINT64_C(0x100));
    if (itt == 0) return XAIOS_ERR_NO_MEMORY;
    uint64_t itt_physical = physical_address(itt);
    if (itt_physical == 0U) return XAIOS_ERR_IO;
    its_command_t mapd = {
        {GITS_CMD_MAPD | ((uint64_t)device_id << 32U), UINT64_C(4),
         (itt_physical & UINT64_C(0x0000ffffffffff00)) |
             (UINT64_C(1) << 63U),
         0U}};
    status = send_command(&mapd);
    if (status != XAIOS_OK) return status;
    entry->itt = itt;
    entry->device_id = device_id;
    entry->used = 1U;
  }
  its_command_t mapti = {
      {GITS_CMD_MAPTI | ((uint64_t)device_id << 32U),
       event_id | ((uint64_t)intid << 32U), cpu_id, 0U}};
  status = send_command(&mapti);
  if (status != XAIOS_OK) return status;
  its_command_t sync = {{GITS_CMD_SYNC, 0U,
                         collection_target(cpu_id) &
                             UINT64_C(0x0000ffffffff0000),
                         0U}};
  status = send_command(&sync);
  if (status != XAIOS_OK) return status;
  *message_address = g_its.base + GITS_TRANSLATER;
  *message_data = event_id;
  return XAIOS_OK;
}

int gic_its_available(void) { return g_its.initialized != 0U; }
