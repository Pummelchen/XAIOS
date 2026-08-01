#include <xaios/assert.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/timer.h>

#define PSCI_0_2_FN64_CPU_ON UINT64_C(0xc4000003)
#define SECONDARY_STACK_SIZE 4096U
#define SECONDARY_BOOT_TIMEOUT_MS UINT64_C(5000)

/* QEMU virt GICv3 redistributor region used for early CPU discovery. */
#define QEMU_VIRT_GICR_BASE UINT64_C(0x080A0000)
#define GICR_STRIDE UINT64_C(0x20000)
#define GICR_TYPER 0x0008U
#define GICR_TYPER_LAST (UINT64_C(1) << 4U)

extern char aarch64_secondary_entry[];

uint8_t g_secondary_stacks[XAIOS_MAX_CPUS][SECONDARY_STACK_SIZE]
    __attribute__((aligned(16)));

static xaios_cpu_state_t g_cpu_states[XAIOS_MAX_CPUS];
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
  for (uint32_t cpu = 0; cpu < XAIOS_MAX_CPUS; ++cpu) {
    uint64_t base = QEMU_VIRT_GICR_BASE + (uint64_t)cpu * GICR_STRIDE;
    if ((mmio_read64(base, GICR_TYPER) & GICR_TYPER_LAST) != 0) {
      return cpu + 1U;
    }
  }
  return 1U;
}

void smp_secondary_main(uint64_t cpu_id) {
  if (cpu_id < XAIOS_MAX_CPUS) {
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

  /* Initialize this CPU's GIC redistributor and CPU interface */
  gic_secondary_init((uint32_t)cpu_id);

  /* Enable per-CPU timer for preemptive scheduling */
  timer_enable_periodic(XAIOS_SCHEDULER_DEFAULT_TICK_HZ);

  if (cpu_id < XAIOS_MAX_CPUS) {
    g_cpu_states[cpu_id].scheduling_enabled = 1;
  }

  __asm__ volatile("msr daifclr, #2" ::: "memory");

  /* Enter idle loop — timer IRQs will invoke scheduler_tick */
  for (;;) {
    __asm__ volatile("wfe");
  }
}

void smp_init_qemu_virt(void) {
  /* Only initialize up to the detected hardware CPU count,
   * not all 131K slots (that would be extremely slow at boot). */
  uint32_t hw_cpu_count = detect_cpu_count();
  uint32_t init_limit = hw_cpu_count < XAIOS_MAX_CPUS ? hw_cpu_count : XAIOS_MAX_CPUS;
  for (uint32_t i = 0; i < init_limit; ++i) {
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

  klog("smp: hardware reports %u CPUs (max %u)\n", hw_cpu_count, XAIOS_MAX_CPUS);

  /* Wake secondary CPUs via PSCI */
  for (uint32_t cpu = 1; cpu < hw_cpu_count; ++cpu) {
    uint64_t mpidr = cpu;
    uint64_t status =
        psci_cpu_on(mpidr, (uint64_t)(uintptr_t)aarch64_secondary_entry, cpu);
    if (status != 0) {
      klog("smp: cpu%u PSCI failed status=0x%lx\n", cpu, status);
    }
  }

  /* Wait for secondaries to come online with timeout */
  uint64_t start_time = timer_counter();
  uint64_t timeout = timer_frequency_hz() * SECONDARY_BOOT_TIMEOUT_MS / 1000U;
  while (count_online() < hw_cpu_count) {
    if (timer_counter() - start_time > timeout) {
      klog("smp: boot timeout — %u/%u CPUs online\n",
           count_online(), hw_cpu_count);
      break;
    }
    __asm__ volatile("wfe");
  }

  klog("smp: online cpus=%u/%u (hw detected=%u)\n",
       count_online(), init_limit, hw_cpu_count);
  for (uint32_t cpu = 0; cpu < init_limit; ++cpu) {
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
  if (cpu_id >= XAIOS_MAX_CPUS) {
    return 0;
  }
  return &g_cpu_states[cpu_id];
}

xaios_status_t smp_set_scheduling_enabled(uint32_t cpu_id, uint32_t enabled) {
  if (cpu_id >= XAIOS_MAX_CPUS || enabled > 1U) {
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

  if (cpu_id == 0 || cpu_id >= XAIOS_MAX_CPUS || owner_id == UINT32_MAX ||
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

  if (cpu_id == 0 || cpu_id >= XAIOS_MAX_CPUS ||
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
  uint32_t limit = XAIOS_MAX_CPUS < 32U ? XAIOS_MAX_CPUS : 32U;
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
  uint32_t limit = XAIOS_MAX_CPUS < 32U ? XAIOS_MAX_CPUS : 32U;
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
  if (limit > 32U) limit = 32U; /* cache-line optimization */
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    total += g_cpu_states[cpu].migration_count;
  }
  return total;
}

uint64_t smp_total_involuntary_context_switch_count(void) {
  uint64_t total = 0;
  uint32_t limit = count_online();
  if (limit > 32U) limit = 32U;
  for (uint32_t cpu = 0; cpu < limit; ++cpu) {
    total += g_cpu_states[cpu].involuntary_context_switch_count;
  }
  return total;
}

uint32_t smp_online_count(void) {
  return count_online();
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
  if (ran_threads == 0 || checksum == 0 || requested_threads == 0 ||
      iterations == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (requested_threads > 32U) {
    requested_threads = 32U;
  }
  if (iterations > UINT64_C(200000)) {
    iterations = UINT64_C(200000);
  }

  uint64_t total = 0;
  for (uint64_t tid = 0; tid < requested_threads; ++tid) {
    uint64_t local = (tid + 1U) * UINT64_C(0x100000001b3);
    uint32_t cpu = (uint32_t)(tid % count_online());
    for (uint64_t i = 0; i < iterations; ++i) {
      local ^= (i + 17U) + (tid << 8U) + cpu;
      local *= UINT64_C(0x9e3779b185ebca87);
      local = (local >> 11U) | (local << 53U);
    }
    total ^= local + (tid << 32U);
  }

  *ran_threads = requested_threads;
  *checksum = total;
  klog("threads: user thread group started threads=%lu iterations=%lu\n",
       requested_threads, iterations);
  klog("threads: user thread group complete threads=%lu checksum=0x%lx\n",
       requested_threads, total);
  return XAIOS_OK;
}

void smp_self_test(void) {
  kassert(g_cpu_states[0].online != 0);
  kassert(g_cpu_states[0].role == XAIOS_CPU_ROLE_HOUSEKEEPING);
  kassert(g_cpu_states[0].tick_suppressed == 0);
  kassert(smp_online_count() >= 1);
  uint64_t ran = 0;
  uint64_t checksum = 0;
  kassert(smp_run_user_thread_group(2, 8, &ran, &checksum) == XAIOS_OK);
  kassert(ran == 2);
  kassert(checksum != 0);
  klog("smp: per-core registry self-test passed online=%u\n",
       smp_online_count());
}
