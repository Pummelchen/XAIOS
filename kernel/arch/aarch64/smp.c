#include <xaios/assert.h>
#include <xaios/aarch64_acpi.h>
#include <xaios/aarch64_sve.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/thread.h>
#include <xaios/vmm.h>

#include "platform.h"

#define PSCI_0_2_FN64_CPU_ON UINT64_C(0xc4000003)
#define WORKER_SGI_INTID UINT64_C(1)
#define SECONDARY_STACK_SIZE 16384U
#define SECONDARY_BOOT_BASE_TIMEOUT_MS UINT64_C(5000)
#define SECONDARY_WORKER_READY_TIMEOUT_MS UINT64_C(30000)

/* QEMU virt GICv3 redistributor region used for early CPU discovery. */
/* The layout the ARM virtual-machine convention places a GICv3 at. It is a
   last resort, used only when firmware describes no interrupt controller, and
   the choice is reported: the boot line reads "built-in-fallback" rather than
   "ACPI" whenever these apply. They were named for the hypervisor they were
   taken from, which made one vendor's memory map look like the definition of
   normal -- the same habit that had the loader advertise a serial port to a
   machine with none, and cost this port a boot. See
   docs/PLATFORM-NEUTRALITY.md. */
#define GIC_ARM_VIRT_REDISTRIBUTOR_BASE UINT64_C(0x080A0000)
#define GICR_STRIDE UINT64_C(0x20000)
#define GICR_TYPER 0x0008U
#define GICR_TYPER_LAST (UINT64_C(1) << 4U)
#define GIC_ARM_VIRT_REDISTRIBUTOR_END UINT64_C(0x09000000)
#define GIC_ARM_VIRT_REDISTRIBUTOR_HIGH_BASE UINT64_C(0x4000000000)
#define GIC_ARM_VIRT_REDISTRIBUTOR_HIGH_FRAMES UINT32_C(512)
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

static uint64_t psci_cpu_on(uint64_t mpidr, uint64_t entry, uint64_t context,
                            uint32_t use_hvc) {
  register uint64_t x0 __asm__("x0") = PSCI_0_2_FN64_CPU_ON;
  register uint64_t x1 __asm__("x1") = mpidr;
  register uint64_t x2 __asm__("x2") = entry;
  register uint64_t x3 __asm__("x3") = context;

  if (use_hvc != 0U) {
    __asm__ volatile("hvc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
  } else {
    __asm__ volatile("smc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
  }
  return x0;
}

static uint32_t g_online_count; /* cached for O(1) reads */
static uint32_t g_secondary_scheduler_release;

/* Whether more than one CPU is running kernel code under the kernel's own
 * translation tables -- which is a different question from how many CPUs are
 * online, and it is the one a lock has to ask.
 *
 * A secondary publishes online=1 while its MMU is still off, and stays that
 * way until it is released below. During that window it is not in kernel code
 * and takes no locks: it spins on one plain acquire load. But it does view
 * every address as Device memory, because that is what translation being off
 * means, while the boot CPU views the same addresses as Normal cacheable. An
 * exclusive or atomic on a location that different PEs see under mismatched
 * attributes is not architecturally supported, and a platform is entitled to
 * refuse it -- VMware Fusion does, with DFSC 0b110101, which is what stopped
 * XAIOS running more than one vCPU there. QEMU and Apple's hypervisor permit
 * it, so the defect was invisible on both.
 *
 * Set before the release store, so the switch to real atomics happens while
 * the boot CPU is still the only one running: no CPU can be part-way through
 * the cheap path when another starts using the expensive one. */
static uint32_t g_smp_locking_active;

uint32_t smp_locking_active(void) {
  return __atomic_load_n(&g_smp_locking_active, __ATOMIC_ACQUIRE);
}

static uint32_t count_online(void) {
  return g_online_count;
}

static void bump_online(void) {
  __sync_fetch_and_add(&g_online_count, 1);
  __asm__ volatile("sev" ::: "memory");
}

/* PSCI starts a secondary at reset state, with translation off, while UEFI
 * handed the boot CPU an MMU that was already on and the kernel's own tables
 * do not exist until vmm_init() runs, long after this. So a secondary spends
 * its first instructions seeing every address as Device memory, and two things
 * follow that cost a boot each.
 *
 * Exclusives are architecturally unsupported on Device memory, so the atomic
 * increment these CPUs used to announce themselves with took a data abort --
 * ESR 0x96000035, DFSC 0b110101 -- before it could announce anything. QEMU's
 * TCG permits the access, which is why this survived every gate. A secondary
 * therefore publishes itself with plain stores, which Device memory does
 * allow, and the boot CPU does the counting.
 *
 * Those stores then go straight to memory and never enter the caches the boot
 * CPU is using -- and the boot CPU filled those lines itself when it zeroed
 * the array -- so it would read its own stale zeros and conclude that nothing
 * came up. So everything a secondary reads before it enables translation is
 * pushed out to memory before the first CPU_ON, and read back from memory
 * while waiting.
 *
 * That is more than the state array. The whole bootstrap region counts: this
 * CPU zeroed all of it with caches on, including the stacks the secondaries
 * are about to run on, so those lines sit here dirty over memory that is
 * about to become somebody else's live stack, and evicting one later would
 * write zeros across it. The pointers count too -- the assembly entry path
 * loads g_secondary_stacks with translation still off, and gets whatever
 * memory holds rather than what this CPU last wrote. */
static void bootstrap_to_memory(void) {
  if (g_bootstrap_start == 0U || g_bootstrap_end <= g_bootstrap_start) return;
  vmm_clean_to_memory((const void *)(uintptr_t)g_bootstrap_start,
                      g_bootstrap_end - g_bootstrap_start);
  vmm_clean_to_memory(&g_secondary_stacks, sizeof(g_secondary_stacks));
  vmm_clean_to_memory(&g_cpu_states, sizeof(g_cpu_states));
  vmm_clean_to_memory(&g_cpu_capacity, sizeof(g_cpu_capacity));
  /* A secondary reads this to decide whether to enable SVE on itself, while
   * the context switcher reads it later with translation on. Left stale, the
   * two would disagree and a CPU would save state it had trapped. */
  aarch64_sve_publish_to_memory();
}

static uint32_t observe_online(void) {
  if (g_cpu_states == 0 || g_cpu_capacity == 0U) return count_online();
  vmm_invalidate_from_memory(
      g_cpu_states, (uint64_t)g_cpu_capacity * sizeof(xaios_cpu_state_t));
  uint32_t online = 0U;
  for (uint32_t cpu = 0U; cpu < g_cpu_capacity; ++cpu) {
    if (g_cpu_states[cpu].online != 0U) ++online;
  }
  g_online_count = online;
  return online;
}

/* QEMU virt exposes one contiguous GICv3 redistributor frame per vCPU. */
static uint32_t detect_cpu_count(void) {
  uint64_t frames = (GIC_ARM_VIRT_REDISTRIBUTOR_END - GIC_ARM_VIRT_REDISTRIBUTOR_BASE) / GICR_STRIDE;
  for (uint32_t cpu = 0; cpu < frames; ++cpu) {
    uint64_t base = GIC_ARM_VIRT_REDISTRIBUTOR_BASE + (uint64_t)cpu * GICR_STRIDE;
    if ((mmio_read64(base, GICR_TYPER) & GICR_TYPER_LAST) != 0) {
      if ((uint64_t)cpu + 1U < frames) return cpu + 1U;
      /* UEFI does not map QEMU's high redistributor window. Admit the
       * architectural window here and let PSCI determine populated CPUs. */
      return (uint32_t)frames + GIC_ARM_VIRT_REDISTRIBUTOR_HIGH_FRAMES;
    }
  }
  return 1U;
}

static uint64_t mpidr_for_ordinal(uint32_t ordinal) {
  return (uint64_t)(ordinal % 16U) |
         ((uint64_t)((ordinal / 16U) % 256U) << 8U) |
         ((uint64_t)(ordinal / 4096U) << 16U);
}

static int acpi_is_qemu_virt(const aarch64_acpi_info_t *info) {
  return info->gic_distributor_base == UINT64_C(0x08000000) &&
         info->gic_redistributor_base == UINT64_C(0x080A0000) &&
         info->pci_ecam_base == UINT64_C(0x4010000000);
}

/* PSCI_VERSION over HVC. Firmware that implements PSCI answers with a version;
   firmware that does not returns NOT_SUPPORTED. HVC is the conduit this tree
   already uses for SYSTEM_OFF on every AArch64 target. */
static uint32_t psci_probe_version(void) {
  register uint64_t x0 __asm__("x0") = UINT64_C(0x84000000);
  __asm__ volatile("hvc #0" : "+r"(x0) : : "x1", "x2", "x3", "memory");
  return (uint32_t)x0;
}

static uint32_t platform_cpu_capacity(const xaios_boot_info_t *boot,
                                      aarch64_acpi_info_t *acpi_info) {
  if (aarch64_acpi_parse(boot->acpi_rsdp, acpi_info) != 0 &&
      acpi_info->enabled_cpus != 0U) {
    if (acpi_info->psci_compliant != 0U || acpi_is_qemu_virt(acpi_info)) {
      return acpi_info->enabled_cpus;
    }
    /* Firmware may implement PSCI and still leave the FADT's boot-architecture
       flags clear; Virtualization.framework reports four enabled CPUs that way
       while answering PSCI perfectly well. Refusing every secondary on the
       strength of an unset flag costs the whole machine, so ask PSCI itself
       before giving up on it. */
    if (acpi_info->enabled_cpus > 1U) {
      uint32_t version = psci_probe_version();
      if (version != UINT32_MAX && (version >> 16U) <= 1U) {
        klog("smp: firmware answers PSCI %u.%u without advertising it\n",
             version >> 16U, version & UINT32_C(0xffff));
        acpi_info->psci_compliant = 1U;
        acpi_info->psci_use_hvc = 1U;
        return acpi_info->enabled_cpus;
      }
    }
    return 1U;
  }
  *acpi_info = (aarch64_acpi_info_t){0};
  return detect_cpu_count();
}

static uint64_t platform_mpidr(const aarch64_acpi_info_t *acpi_info,
                               uint64_t boot_mpidr, uint32_t ordinal) {
  if (acpi_info->madt == 0U) return mpidr_for_ordinal(ordinal);
  if (ordinal == 0U) return boot_mpidr;
  uint32_t selected = 1U;
  for (uint32_t index = 0U; index < acpi_info->enabled_cpus; ++index) {
    uint64_t candidate = 0U;
    if (aarch64_acpi_cpu_mpidr(acpi_info, index, &candidate) == 0) break;
    if ((candidate & UINT64_C(0x00ffffff)) ==
        (boot_mpidr & UINT64_C(0x00ffffff))) {
      continue;
    }
    if (selected++ == ordinal) return candidate;
  }
  return 0U;
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

void aarch64_platform_set_page_tables(uint32_t ordinal, uint64_t *root,
                                      uint64_t *user_directory) {
  if (ordinal >= g_cpu_capacity) return;
  g_cpu_states[ordinal].page_table_root = root;
  g_cpu_states[ordinal].user_page_directory = user_directory;
}

uint64_t *aarch64_platform_page_table_root(uint32_t ordinal) {
  return ordinal < g_cpu_capacity ? g_cpu_states[ordinal].page_table_root : 0;
}

uint64_t *aarch64_platform_user_page_directory(uint32_t ordinal) {
  return ordinal < g_cpu_capacity ? g_cpu_states[ordinal].user_page_directory
                                  : 0;
}

uint32_t aarch64_platform_current_ordinal(void) { return smp_cpu_id(); }

xaios_status_t smp_wake_cpu(uint32_t cpu_id) {
  if (cpu_id >= g_cpu_capacity || g_cpu_states[cpu_id].online == 0U ||
      __atomic_load_n(&g_cpu_states[cpu_id].scheduling_enabled,
                      __ATOMIC_ACQUIRE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t mpidr = g_cpu_states[cpu_id].mpidr;
  uint32_t aff0 = (uint32_t)(mpidr & UINT64_C(0xff));
  if (aff0 >= 16U) return XAIOS_ERR_UNSUPPORTED;
  uint64_t sgi = UINT64_C(1) << aff0;
  sgi |= ((mpidr >> 8U) & UINT64_C(0xff)) << 16U;
  sgi |= WORKER_SGI_INTID << 24U;
  sgi |= ((mpidr >> 16U) & UINT64_C(0xff)) << 32U;
  sgi |= ((mpidr >> 32U) & UINT64_C(0xff)) << 48U;
  __asm__ volatile("dsb ishst\n\tmsr S3_0_C12_C11_5, %[sgi]\n\tisb"
                   :
                   : [sgi] "r"(sgi)
                   : "memory");
  return XAIOS_OK;
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
  /* Everything up to the rendezvous below runs with translation off: no
   * exclusives, and nothing published here is visible to the boot CPU until it
   * reads past its caches. See cpu_states_to_memory() for why. */
  if (aarch64_sve_enabled() != 0U) {
    uint64_t cpacr = 0U;
    __asm__ volatile("mrs %0, cpacr_el1" : "=r"(cpacr));
    cpacr = (cpacr & ~(UINT64_C(3) << 16U)) | (UINT64_C(3) << 16U);
    __asm__ volatile("msr cpacr_el1, %0\n"
                     "msr S3_0_C1_C2_0, %1\n"
                     "isb\n"
                     :
                     : "r"(cpacr), "r"(UINT64_C(0xf))
                     : "memory");
  }
  if (cpu_id < g_cpu_capacity) {
    g_cpu_states[cpu_id].cpu_id = (uint32_t)cpu_id;
    g_cpu_states[cpu_id].mpidr = read_mpidr_el1();
    g_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_SCHEDULING;
    g_cpu_states[cpu_id].lease_owner_id = 0;
    g_cpu_states[cpu_id].irq_routed_away = 0;
    g_cpu_states[cpu_id].tick_suppressed = 0;
    g_cpu_states[cpu_id].scheduling_enabled = 0;
    g_cpu_states[cpu_id].steal_count = 0;
    /* Online last, and only once everything it describes has landed: it is
     * what the boot CPU waits on, and an entry seen half-written is worse
     * than one not seen at all. */
    __asm__ volatile("dsb sy" : : : "memory");
    g_cpu_states[cpu_id].online = 1;
    __asm__ volatile("dsb sy\nsev" : : : "memory");
  }

  while (__atomic_load_n(&g_secondary_scheduler_release, __ATOMIC_ACQUIRE) ==
         0U) {
    /* QEMU 8.2 can lose a long-lived pre-GIC WFE event. This startup-only
     * rendezvous must observe release without depending on an event latch. */
    __asm__ volatile("yield" ::: "memory");
  }

  /* Re-activate now that this CPU is online and findable by MPIDR, so any
   * kernel mapping published while it waited at the rendezvous takes effect. */
  vmm_activate_kernel();

  /* Initialize this CPU's GIC redistributor and CPU interface */
  gic_secondary_init((uint32_t)cpu_id);

  /* Kernel workers are event-driven. Keep the local scheduler timer masked
   * until this CPU owns a preemptible userspace run queue. */
  timer_mask_local();

  if (cpu_id < g_cpu_capacity) {
    __atomic_store_n(&g_cpu_states[cpu_id].scheduling_enabled, 1U,
                     __ATOMIC_RELEASE);
  }

  __asm__ volatile("msr daifclr, #2" ::: "memory");

  /* Run assigned kernel work, otherwise wait for an IRQ or a new job. */
  for (;;) {
    if (xaios_thread_run_pending((uint32_t)cpu_id) == 0U) {
      __asm__ volatile("wfe");
    }
  }
}

void smp_init_platform(const xaios_boot_info_t *boot) {
  aarch64_acpi_info_t acpi_info;
  uint32_t candidate_capacity = platform_cpu_capacity(boot, &acpi_info);
  uint32_t qemu_virt = acpi_info.madt != 0U && acpi_is_qemu_virt(&acpi_info);
  uint32_t psci_use_hvc =
      acpi_info.madt != 0U ? (qemu_virt != 0U ? 1U : acpi_info.psci_use_hvc)
                          : 1U;
  uint64_t boot_mpidr = read_mpidr_el1();
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
    g_cpu_states[i].mpidr = platform_mpidr(&acpi_info, boot_mpidr, i);
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
  g_smp_locking_active = 0U;

  g_cpu_states[0].online = 1;
  g_cpu_states[0].mpidr = boot_mpidr;
  g_cpu_states[0].role = XAIOS_CPU_ROLE_HOUSEKEEPING;
  g_cpu_states[0].irq_routed_away = 0;
  g_cpu_states[0].tick_suppressed = 0;
  bump_online();

  klog("smp: boot cpu mpidr=0x%lx role=housekeeping\n",
       g_cpu_states[0].mpidr);

  klog("smp: source=%s candidate_capacity=%u psci=%s dynamic_registry_bytes=%lu stack_bytes=%lu\n",
       acpi_info.madt != 0U ? (acpi_info.psci_compliant != 0U ? "ACPI-PSCI" :
                               (qemu_virt != 0U ? "ACPI-PSCI-inferred" : "ACPI-bootstrap-only")) : "built-in-fallback", candidate_capacity,
       candidate_capacity > 1U ? (psci_use_hvc != 0U ? "hvc" : "smc") : "unavailable",
       state_bytes, stack_bytes);

  bootstrap_to_memory();

  /* Wake secondary CPUs via PSCI */
  uint32_t admitted_count = 1U;
  uint32_t rejected_count = 0U;
  for (uint32_t cpu = 1; cpu < candidate_capacity; ++cpu) {
    uint64_t mpidr = g_cpu_states[cpu].mpidr;
    if (mpidr == 0U) {
      ++rejected_count;
      continue;
    }
    uint64_t status = psci_cpu_on(mpidr,
                                  (uint64_t)(uintptr_t)aarch64_secondary_entry,
                                  cpu, psci_use_hvc);
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
  while (observe_online() < admitted_count) {
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

xaios_status_t smp_release_secondary_schedulers(void) {
  /* Locks become real atomics from here, before anything else can run: past
   * this point every CPU that reaches kernel code activates the kernel's
   * translation first, so all of them agree the memory is Normal cacheable. */
  __atomic_store_n(&g_smp_locking_active, 1U, __ATOMIC_RELEASE);
  __atomic_store_n(&g_secondary_scheduler_release, 1U, __ATOMIC_RELEASE);
  /* The secondaries waiting on this still have translation off, so they read
   * it from memory and never from the caches this store lands in. They spin
   * rather than sleep, so a late arrival costs nothing, but nothing else would
   * ever push this out -- and the caller asserts on the barrier it gates. */
  vmm_clean_to_memory(&g_secondary_scheduler_release,
                  sizeof(g_secondary_scheduler_release));
  __asm__ volatile("sev" ::: "memory");
  uint64_t started = timer_counter();
  uint64_t timeout = timer_frequency_hz() *
                     SECONDARY_WORKER_READY_TIMEOUT_MS / UINT64_C(1000);
  for (;;) {
    uint32_t ready = 1U;
    for (uint32_t cpu = 1U; cpu < g_cpu_capacity; ++cpu) {
      if (g_cpu_states[cpu].online != 0U &&
          __atomic_load_n(&g_cpu_states[cpu].scheduling_enabled,
                          __ATOMIC_ACQUIRE) != 0U) {
        ++ready;
      }
    }
    if (ready == count_online()) {
      klog("smp: secondary worker barrier passed ready=%u\n", ready);
      return XAIOS_OK;
    }
    __asm__ volatile("sev\n\tyield" ::: "memory");
    if (timer_counter() - started >= timeout) {
      klog("smp: secondary worker barrier timed out ready=%u online=%u\n",
           ready, count_online());
      return XAIOS_ERR_BUSY;
    }
  }
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
