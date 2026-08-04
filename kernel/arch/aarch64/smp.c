#include <xaios/assert.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/thread.h>
#include <xaios/vmm.h>

#define PSCI_0_2_FN64_CPU_ON UINT64_C(0xc4000003)
#define SECONDARY_STACK_SIZE 4096U
#define SECONDARY_BOOT_BASE_TIMEOUT_MS UINT64_C(5000)

/* QEMU virt GICv3 redistributor region used for early CPU discovery. */
#define QEMU_VIRT_GICR_BASE UINT64_C(0x080A0000)
#define GICR_STRIDE UINT64_C(0x20000)
#define GICR_TYPER 0x0008U
#define GICR_TYPER_LAST (UINT64_C(1) << 4U)
#define QEMU_VIRT_GICR_END UINT64_C(0x09000000)
#define QEMU_VIRT_GICR_HIGH_BASE UINT64_C(0x4000000000)
#define QEMU_VIRT_GICR_HIGH_FRAMES UINT32_C(512)
#define PAGE_SIZE UINT64_C(4096)
#define EARLY_IDENTITY_LIMIT UINT64_C(0x100000000)

extern char aarch64_secondary_entry[];

uint8_t *g_secondary_stacks;
static xaios_cpu_state_t *g_cpu_states;
static uint32_t g_cpu_capacity;
static uint64_t g_bootstrap_start;
static uint64_t g_bootstrap_end;
static xaios_spinlock_t g_smp_lock = XAIOS_SPINLOCK_INIT;

static uint64_t read_mpidr_el1(void) {
  uint64_t value = 0;
  __asm__ volatile("mrs %[value], mpidr_el1" : [value] "=r"(value));
  return value;
}

static uint64_t mmio_read64(uint64_t base, uint32_t offset) {
  volatile uint64_t *reg = (volatile uint64_t *)(uintptr_t)(base + offset);
  return *reg;
}

static uint64_t psci_cpu_on(uint64_t mpidr, uint64_t entry, uint64_t context) {
  register uint64_t x0 __asm__("x0") = PSCI_0_2_FN64_CPU_ON;
  register uint64_t x1 __asm__("x1") = mpidr;
  register uint64_t x2 __asm__("x2") = entry;
  register uint64_t x3 __asm__("x3") = context;

  __asm__ volatile("hvc #0"
                   : "+r"(x0)
                   : "r"(x1), "r"(x2), "r"(x3)
                   : "memory");
  return x0;
}

static uint32_t g_online_count; /* cached for O(1) reads */
static uint32_t g_secondary_scheduler_release;

static uint32_t count_online(void) {
  return g_online_count;
}

static void bump_online(void) {
  __sync_fetch_and_add(&g_online_count, 1);
  __asm__ volatile("sev" ::: "memory");
}

/* QEMU virt exposes one contiguous GICv3 redistributor frame per vCPU. */
static uint32_t detect_cpu_count(void) {
  uint64_t frames = (QEMU_VIRT_GICR_END - QEMU_VIRT_GICR_BASE) / GICR_STRIDE;
  for (uint32_t cpu = 0; cpu < frames; ++cpu) {
    uint64_t base = QEMU_VIRT_GICR_BASE + (uint64_t)cpu * GICR_STRIDE;
    if ((mmio_read64(base, GICR_TYPER) & GICR_TYPER_LAST) != 0) {
      if ((uint64_t)cpu + 1U < frames) return cpu + 1U;
      /* UEFI does not map QEMU's high redistributor window. Admit the
       * architectural window here and let PSCI determine populated CPUs. */
      return (uint32_t)frames + QEMU_VIRT_GICR_HIGH_FRAMES;
    }
  }
  return 1U;
}

static uint64_t mpidr_for_ordinal(uint32_t ordinal) {
  return (uint64_t)(ordinal % 16U) |
         ((uint64_t)((ordinal / 16U) % 256U) << 8U) |
         ((uint64_t)(ordinal / 4096U) << 16U);
}

uint32_t smp_cpu_id(void) {
  uint64_t mpidr = read_mpidr_el1() & UINT64_C(0x00ffffff);
  for (uint32_t cpu = 0U; cpu < g_cpu_capacity; ++cpu) {
    if (g_cpu_states[cpu].online != 0U &&
        (g_cpu_states[cpu].mpidr & UINT64_C(0x00ffffff)) == mpidr) {
      return cpu;
    }
  }
  return UINT32_MAX;
}

static uint64_t align_up(uint64_t value, uint64_t alignment) {
  return (value + alignment - 1U) & ~(alignment - 1U);
}

static int overlaps(uint64_t start, uint64_t end, uint64_t used_start,
                    uint64_t used_end) {
  return start < used_end && used_start < end;
}

static uint64_t allocate_bootstrap(const xaios_boot_info_t *boot,
                                   uint64_t bytes) {
  for (uint64_t offset = 0U;
       offset + sizeof(xaios_memory_descriptor_t) <= boot->memory_map_size;
       offset += boot->memory_descriptor_size) {
    const xaios_memory_descriptor_t *descriptor =
        (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map +
                                                       offset);
    if (descriptor->type != XAIOS_MEMORY_TYPE_CONVENTIONAL ||
        descriptor->number_of_pages > UINT64_MAX / PAGE_SIZE) {
      continue;
    }
    uint64_t start = align_up(descriptor->physical_start, PAGE_SIZE);
    uint64_t region_bytes = descriptor->number_of_pages * PAGE_SIZE;
    if (descriptor->physical_start > UINT64_MAX - region_bytes) continue;
    uint64_t end = descriptor->physical_start + region_bytes;
    if (end > EARLY_IDENTITY_LIMIT) end = EARLY_IDENTITY_LIMIT;
    uint64_t candidate = start;
    for (uint32_t retry = 0U; retry < 3U && candidate < end; ++retry) {
      uint64_t candidate_end = candidate + bytes;
      if (candidate_end < candidate || candidate_end > end) break;
      if (overlaps(candidate, candidate_end, boot->kernel_phys_base,
                   boot->kernel_phys_end)) {
        candidate = align_up(boot->kernel_phys_end, PAGE_SIZE);
        continue;
      }
      uint64_t map_end = boot->memory_map + boot->memory_map_size;
      if (overlaps(candidate, candidate_end, boot->memory_map, map_end)) {
        candidate = align_up(map_end, PAGE_SIZE);
        continue;
      }
      return candidate;
    }
  }
  return 0U;
}

static void bytes_zero(void *buffer, uint64_t bytes) {
  uint8_t *output = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < bytes; ++index) output[index] = 0U;
}

void smp_secondary_main(uint64_t cpu_id) {
  if (cpu_id < g_cpu_capacity) {
    g_cpu_states[cpu_id].cpu_id = (uint32_t)cpu_id;
    g_cpu_states[cpu_id].mpidr = read_mpidr_el1();
    g_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_SCHEDULING;
    g_cpu_states[cpu_id].lease_owner_id = 0;
    g_cpu_states[cpu_id].irq_routed_away = 0;
    g_cpu_states[cpu_id].tick_suppressed = 0;
    g_cpu_states[cpu_id].online = 1;
    g_cpu_states[cpu_id].scheduling_enabled = 0;
    g_cpu_states[cpu_id].steal_count = 0;
    bump_online();
  }

  while (g_secondary_scheduler_release == 0) {
    __asm__ volatile("wfe");
  }

  /* Secondary CPUs start on the firmware/bootstrap translation tables. */
  vmm_activate_kernel();

  /* Initialize this CPU's GIC redistributor and CPU interface */
  gic_secondary_init((uint32_t)cpu_id);

  /* Enable per-CPU timer for preemptive scheduling */
  timer_enable_periodic(XAIOS_SCHEDULER_DEFAULT_TICK_HZ);

  if (cpu_id < g_cpu_capacity) {
    g_cpu_states[cpu_id].scheduling_enabled = 1;
  }

  __asm__ volatile("msr daifclr, #2" ::: "memory");

  /* Run assigned kernel work, otherwise wait for an IRQ or a new job. */
  for (;;) {
    if (xaios_thread_run_pending((uint32_t)cpu_id) == 0U) {
      __asm__ volatile("wfe");
    }
  }
}

void smp_init_qemu_virt(const xaios_boot_info_t *boot) {
  uint32_t candidate_capacity = detect_cpu_count();
  uint64_t state_bytes = align_up(
      (uint64_t)candidate_capacity * sizeof(xaios_cpu_state_t), PAGE_SIZE);
  uint64_t stack_bytes =
      (uint64_t)candidate_capacity * SECONDARY_STACK_SIZE;
  uint64_t bootstrap_bytes = state_bytes + stack_bytes;
  g_bootstrap_start = allocate_bootstrap(boot, bootstrap_bytes);
  kassert(g_bootstrap_start != 0U);
  g_bootstrap_end = g_bootstrap_start + bootstrap_bytes;
  g_cpu_states = (xaios_cpu_state_t *)(uintptr_t)g_bootstrap_start;
  g_secondary_stacks = (uint8_t *)(uintptr_t)(g_bootstrap_start + state_bytes);
  g_cpu_capacity = candidate_capacity;
  bytes_zero((void *)(uintptr_t)g_bootstrap_start, bootstrap_bytes);
  for (uint32_t i = 0; i < g_cpu_capacity; ++i) {
    g_cpu_states[i].cpu_id = i;
    g_cpu_states[i].online = 0;
    g_cpu_states[i].mpidr = i;
    g_cpu_states[i].role = XAIOS_CPU_ROLE_OFFLINE;
    g_cpu_states[i].lease_owner_id = 0;
    g_cpu_states[i].irq_routed_away = 0;
    g_cpu_states[i].tick_suppressed = 0;
    g_cpu_states[i].migration_count = 0;
    g_cpu_states[i].involuntary_context_switch_count = 0;
    g_cpu_states[i].scheduling_enabled = 0;
    g_cpu_states[i].steal_count = 0;
  }
  xaios_spin_init(&g_smp_lock);
  g_online_count = 0;
  g_secondary_scheduler_release = 0;

  g_cpu_states[0].online = 1;
  g_cpu_states[0].mpidr = read_mpidr_el1();
  g_cpu_states[0].role = XAIOS_CPU_ROLE_HOUSEKEEPING;
  g_cpu_states[0].irq_routed_away = 0;
  g_cpu_states[0].tick_suppressed = 0;
  bump_online();

  klog("smp: boot cpu mpidr=0x%lx role=housekeeping\n",
       g_cpu_states[0].mpidr);

  klog("smp: probing candidate_capacity=%u dynamic_registry_bytes=%lu stack_bytes=%lu\n",
       candidate_capacity, state_bytes, stack_bytes);

  /* Wake secondary CPUs via PSCI */
  uint32_t admitted_count = 1U;
  uint32_t rejected_count = 0U;
  for (uint32_t cpu = 1; cpu < candidate_capacity; ++cpu) {
    uint64_t mpidr = mpidr_for_ordinal(cpu);
    uint64_t status =
        psci_cpu_on(mpidr, (uint64_t)(uintptr_t)aarch64_secondary_entry, cpu);
    if (status == 0U) ++admitted_count;
    else ++rejected_count;
  }
  klog("smp: PSCI admitted=%u rejected=%u\n", admitted_count,
       rejected_count);

  /* Wait for secondaries to come online with timeout */
  uint64_t start_time = timer_counter();
  uint64_t timeout_ms = SECONDARY_BOOT_BASE_TIMEOUT_MS +
                        (uint64_t)admitted_count * UINT64_C(250);
  uint64_t timeout = timer_frequency_hz() * timeout_ms / 1000U;
  while (count_online() < admitted_count) {
    if (timer_counter() - start_time > timeout) {
      klog("smp: boot timeout — %u/%u CPUs online\n",
           count_online(), admitted_count);
      break;
    }
    __asm__ volatile("wfe");
  }

  g_cpu_capacity = admitted_count;
  klog("smp: online cpus=%u/%u dynamic_capacity=%u\n",
       count_online(), admitted_count, g_cpu_capacity);
  for (uint32_t cpu = 0; cpu < g_cpu_capacity; ++cpu) {
    if (g_cpu_states[cpu].online != 0) {
      klog("smp: cpu%u online=%u mpidr=0x%lx role=%u\n",
           cpu, g_cpu_states[cpu].online, g_cpu_states[cpu].mpidr,
           (unsigned)g_cpu_states[cpu].role);
    }
  }
}

void smp_release_secondary_schedulers(void) {
  __atomic_store_n(&g_secondary_scheduler_release, 1U, __ATOMIC_RELEASE);
  __asm__ volatile("sev" ::: "memory");
}

const xaios_cpu_state_t *smp_cpu_state(uint32_t cpu_id) {
  if (cpu_id >= g_cpu_capacity) {
    return 0;
  }
  return &g_cpu_states[cpu_id];
}

xaios_status_t smp_set_scheduling_enabled(uint32_t cpu_id, uint32_t enabled) {
  if (cpu_id >= g_cpu_capacity || enabled > 1U) {
    return XAIOS_ERR_INVALID;
  }

  xaios_spin_lock(&g_smp_lock);
  if (g_cpu_states[cpu_id].online == 0 ||
      (g_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_HOUSEKEEPING &&
       g_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_SCHEDULING)) {
    xaios_spin_unlock(&g_smp_lock);
    return XAIOS_ERR_INVALID;
  }
  g_cpu_states[cpu_id].scheduling_enabled = enabled;
  xaios_spin_unlock(&g_smp_lock);
  return XAIOS_OK;
}

xaios_status_t smp_mark_core_leased(uint32_t cpu_id, uint32_t owner_id) {
  xaios_spin_lock(&g_smp_lock);

  if (cpu_id == 0 || cpu_id >= g_cpu_capacity || owner_id == UINT32_MAX ||
      g_cpu_states[cpu_id].online == 0 ||
      g_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_SCHEDULING) {
    xaios_spin_unlock(&g_smp_lock);
    return XAIOS_ERR_INVALID;
  }

  if (g_cpu_states[cpu_id].lease_owner_id != 0 &&
      g_cpu_states[cpu_id].lease_owner_id != owner_id + 1U) {
    ++g_cpu_states[cpu_id].migration_count;
    xaios_spin_unlock(&g_smp_lock);
    return XAIOS_ERR_BUSY;
  }

  g_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_AI_HOT;
  g_cpu_states[cpu_id].lease_owner_id = owner_id + 1U;
  g_cpu_states[cpu_id].irq_routed_away = 1;
  g_cpu_states[cpu_id].tick_suppressed = 1;
  g_cpu_states[cpu_id].scheduling_enabled = 0;

  xaios_spin_unlock(&g_smp_lock);
  klog("smp: cpu%u leased owner=%u role=ai-hot\n", cpu_id, owner_id);
  return XAIOS_OK;
}

xaios_status_t smp_release_core_lease(uint32_t cpu_id, uint32_t owner_id) {
  xaios_spin_lock(&g_smp_lock);

  if (cpu_id == 0 || cpu_id >= g_cpu_capacity ||
      g_cpu_states[cpu_id].online == 0 ||
      g_cpu_states[cpu_id].role != XAIOS_CPU_ROLE_AI_HOT ||
      g_cpu_states[cpu_id].lease_owner_id != owner_id + 1U) {
    xaios_spin_unlock(&g_smp_lock);
    return XAIOS_ERR_INVALID;
  }

  g_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_SCHEDULING;
  g_cpu_states[cpu_id].lease_owner_id = 0;
  g_cpu_states[cpu_id].irq_routed_away = 0;
  g_cpu_states[cpu_id].tick_suppressed = 0;
  g_cpu_states[cpu_id].scheduling_enabled = g_secondary_scheduler_release;

  xaios_spin_unlock(&g_smp_lock);
  klog("smp: cpu%u released owner=%u role=scheduling\n", cpu_id, owner_id);
  return XAIOS_OK;
}

uint32_t smp_hot_core_mask(void) {
  uint32_t mask = 0;
  /* uint32_t mask only covers CPUs 0-31 */
  uint32_t limit = g_cpu_capacity < 32U ? g_cpu_capacity : 32U;
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    if (g_cpu_states[cpu].role == XAIOS_CPU_ROLE_AI_HOT) {
      mask |= UINT32_C(1) << cpu;
    }
  }
  return mask;
}

uint32_t smp_irq_isolated_mask(void) {
  uint32_t mask = 0;
  /* uint32_t mask only covers CPUs 0-31 */
  uint32_t limit = g_cpu_capacity < 32U ? g_cpu_capacity : 32U;
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    if (g_cpu_states[cpu].irq_routed_away != 0) {
      mask |= UINT32_C(1) << cpu;
    }
  }
  return mask;
}

uint64_t smp_total_migration_count(void) {
  uint64_t total = 0;
  uint32_t limit = count_online();
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    total += g_cpu_states[cpu].migration_count;
  }
  return total;
}

uint64_t smp_total_involuntary_context_switch_count(void) {
  uint64_t total = 0;
  uint32_t limit = count_online();
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    total += g_cpu_states[cpu].involuntary_context_switch_count;
  }
  return total;
}

uint32_t smp_online_count(void) {
  return count_online();
}

uint32_t smp_capacity(void) { return g_cpu_capacity; }

xaios_status_t smp_bootstrap_reserved_range(uint64_t *start, uint64_t *end) {
  if (start == 0 || end == 0 || g_bootstrap_start == 0U ||
      g_bootstrap_start >= g_bootstrap_end) {
    return XAIOS_ERR_INVALID;
  }
  *start = g_bootstrap_start;
  *end = g_bootstrap_end;
  return XAIOS_OK;
}

xaios_status_t smp_cpu_id_at(uint32_t ordinal, uint32_t *cpu_id) {
  if (cpu_id == 0 || ordinal >= count_online()) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t found = 0;
  for (uint32_t cpu = 0; cpu < g_cpu_capacity; ++cpu) {
    if (g_cpu_states[cpu].online == 0) {
      continue;
    }
    if (found == ordinal) {
      *cpu_id = cpu;
      return XAIOS_OK;
    }
    ++found;
  }
  return XAIOS_ERR_INVALID;
}

xaios_status_t smp_run_user_task_set(uint64_t requested_workers,
                                    uint64_t iterations,
                                    uint64_t *ran_workers,
                                    uint64_t *checksum) {
  if (ran_workers == 0 || checksum == 0 || requested_workers == 0 ||
      iterations == 0) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t online = count_online();
  if (online == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t workers = requested_workers;
  if (workers > online) {
    workers = online;
  }
  if (iterations > UINT64_C(100000)) {
    iterations = UINT64_C(100000);
  }

  uint64_t total = 0;
  uint64_t assigned = 0;
  uint32_t limit = count_online();
  for (uint32_t cpu = 0; cpu < limit && assigned < workers; ++cpu) {
    if (g_cpu_states[cpu].online == 0) {
      continue;
    }
    uint64_t local = ((uint64_t)cpu + 1U) * UINT64_C(0x9e3779b185ebca87);
    for (uint64_t i = 0; i < iterations; ++i) {
      local ^= (i + 1U) * (assigned + 3U);
      local = (local << 7U) | (local >> 57U);
    }
    total ^= local + (iterations << (assigned & 7U));
    ++assigned;
  }

  *ran_workers = assigned;
  *checksum = total;
  klog("smp: app task set workers=%lu iterations=%lu checksum=0x%lx\n",
       assigned, iterations, total);
  return assigned == 0 ? XAIOS_ERR_INVALID : XAIOS_OK;
}

xaios_status_t smp_run_user_thread_group(uint64_t requested_threads,
                                        uint64_t iterations,
                                        uint64_t *ran_threads,
                                        uint64_t *checksum) {
  return xaios_thread_run_group(requested_threads, iterations, ran_threads,
                                checksum);
}

void smp_self_test(void) {
  kassert(g_cpu_states[0].online != 0);
  kassert(g_cpu_states[0].role == XAIOS_CPU_ROLE_HOUSEKEEPING);
  kassert(g_cpu_states[0].tick_suppressed == 0);
  kassert(smp_online_count() >= 1);
  klog("smp: per-core registry self-test passed online=%u\n",
       smp_online_count());
}
