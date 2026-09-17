#include <xaios/assert.h>
#include <xaios/aarch64_acpi.h>
#include <xaios/aarch64_sve.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/network_stack.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/thread.h>
#include <xaios/vmm.h>

#include "platform.h"
#include "smp_internal.h"

#define WORKER_SGI_INTID UINT64_C(1)
#define SECONDARY_STACK_SIZE 16384U
#define SECONDARY_BOOT_BASE_TIMEOUT_MS UINT64_C(5000)
#define SECONDARY_WORKER_READY_TIMEOUT_MS UINT64_C(30000)

#define PAGE_SIZE UINT64_C(4096)
#define EARLY_IDENTITY_LIMIT UINT64_C(0x100000000)

extern char aarch64_secondary_entry[];

uint8_t *g_secondary_stacks;
xaios_cpu_state_t *a64smp_cpu_states;
uint32_t a64smp_cpu_capacity;
uint64_t a64smp_bootstrap_start;
uint64_t a64smp_bootstrap_end;
xaios_spinlock_t a64smp_lock = XAIOS_SPINLOCK_INIT;

static uint32_t g_online_count; /* cached for O(1) reads */
uint32_t a64smp_secondary_release;

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
static uint32_t a64smp_locking_active;

uint32_t smp_locking_active(void) {
  return __atomic_load_n(&a64smp_locking_active, __ATOMIC_ACQUIRE);
}

uint32_t a64smp_count_online(void) {
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
  if (a64smp_bootstrap_start == 0U || a64smp_bootstrap_end <= a64smp_bootstrap_start) return;
  vmm_clean_to_memory((const void *)(uintptr_t)a64smp_bootstrap_start,
                      a64smp_bootstrap_end - a64smp_bootstrap_start);
  vmm_clean_to_memory(&g_secondary_stacks, sizeof(g_secondary_stacks));
  vmm_clean_to_memory(&a64smp_cpu_states, sizeof(a64smp_cpu_states));
  vmm_clean_to_memory(&a64smp_cpu_capacity, sizeof(a64smp_cpu_capacity));
  /* A secondary reads this to decide whether to enable SVE on itself, while
   * the context switcher reads it later with translation on. Left stale, the
   * two would disagree and a CPU would save state it had trapped. */
  aarch64_sve_publish_to_memory();
}

static uint32_t observe_online(void) {
  if (a64smp_cpu_states == 0 || a64smp_cpu_capacity == 0U) return a64smp_count_online();
  vmm_invalidate_from_memory(
      a64smp_cpu_states, (uint64_t)a64smp_cpu_capacity * sizeof(xaios_cpu_state_t));
  uint32_t online = 0U;
  for (uint32_t cpu = 0U; cpu < a64smp_cpu_capacity; ++cpu) {
    if (a64smp_cpu_states[cpu].online != 0U) ++online;
  }
  g_online_count = online;
  return online;
}

/* What this CPU is waiting for, published for another CPU to read. AArch64
 * has no TLB shootdown that waits for an acknowledgement -- `tlbi vaae1is` is
 * broadcast by the hardware -- so nothing reports this yet; it is recorded
 * anyway, because a report from a CPU that is waiting is the only way to say
 * what it was waiting for, and the field belongs to the CPU rather than to the
 * mechanism that reads it (B-123). */
void xaios_cpu_note_wait(const char *reason) {
  uint32_t cpu = smp_cpu_id();
  if (cpu < a64smp_cpu_capacity) {
    a64smp_cpu_states[cpu].waiting_for = reason;
  }
}

uint32_t smp_cpu_id(void) {
  uint64_t mpidr = a64smp_read_mpidr_el1() & UINT64_C(0x00ffffff);
  for (uint32_t cpu = 0U; cpu < a64smp_cpu_capacity; ++cpu) {
    if (a64smp_cpu_states[cpu].online != 0U &&
        (a64smp_cpu_states[cpu].mpidr & UINT64_C(0x00ffffff)) == mpidr) {
      return cpu;
    }
  }
  return UINT32_MAX;
}

void aarch64_platform_set_page_tables(uint32_t ordinal, uint64_t *root,
                                      uint64_t *user_directory) {
  if (ordinal >= a64smp_cpu_capacity) return;
  a64smp_cpu_states[ordinal].page_table_root = root;
  a64smp_cpu_states[ordinal].user_page_directory = user_directory;
}

uint64_t *aarch64_platform_page_table_root(uint32_t ordinal) {
  return ordinal < a64smp_cpu_capacity ? a64smp_cpu_states[ordinal].page_table_root : 0;
}

uint64_t *aarch64_platform_user_page_directory(uint32_t ordinal) {
  return ordinal < a64smp_cpu_capacity ? a64smp_cpu_states[ordinal].user_page_directory
                                  : 0;
}

uint32_t aarch64_platform_current_ordinal(void) { return smp_cpu_id(); }

xaios_status_t smp_wake_cpu(uint32_t cpu_id) {
  if (cpu_id >= a64smp_cpu_capacity || a64smp_cpu_states[cpu_id].online == 0U ||
      __atomic_load_n(&a64smp_cpu_states[cpu_id].scheduling_enabled,
                      __ATOMIC_ACQUIRE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t mpidr = a64smp_cpu_states[cpu_id].mpidr;
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
  if (cpu_id < a64smp_cpu_capacity) {
    a64smp_cpu_states[cpu_id].cpu_id = (uint32_t)cpu_id;
    a64smp_cpu_states[cpu_id].mpidr = a64smp_read_mpidr_el1();
    a64smp_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_SCHEDULING;
    a64smp_cpu_states[cpu_id].lease_owner_id = 0;
    a64smp_cpu_states[cpu_id].irq_routed_away = 0;
    a64smp_cpu_states[cpu_id].tick_suppressed = 0;
    a64smp_cpu_states[cpu_id].scheduling_enabled = 0;
    a64smp_cpu_states[cpu_id].steal_count = 0;
    /* Online last, and only once everything it describes has landed: it is
     * what the boot CPU waits on, and an entry seen half-written is worse
     * than one not seen at all. */
    __asm__ volatile("dsb sy" : : : "memory");
    a64smp_cpu_states[cpu_id].online = 1;
    __asm__ volatile("dsb sy\nsev" : : : "memory");
  }

  while (__atomic_load_n(&a64smp_secondary_release, __ATOMIC_ACQUIRE) ==
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

  if (cpu_id < a64smp_cpu_capacity) {
    __atomic_store_n(&a64smp_cpu_states[cpu_id].scheduling_enabled, 1U,
                     __ATOMIC_RELEASE);
  }

  __asm__ volatile("msr daifclr, #2" ::: "memory");

  /* Run assigned kernel work, otherwise wait for an IRQ or a new job.
   *
   * `msr daifclr, #2` every turn, and not only the one before this loop, is
   * load-bearing twice over. `vector_entry` masks DAIF on every trap, and this
   * CPU was measured spinning here with I *set* while a pending timer sat
   * visible in its CPU interface (`hppir1=27`, `DAIF=0x3c0`) -- so it never
   * took another interrupt, and nothing re-enabled them. And with a pending
   * interrupt the wait-for-event latch is set, so `wfe` returns immediately
   * instead of sleeping: the same run spun 134 million times. A secondary that
   * cannot take an interrupt cannot be woken by one either, which is how the
   * scheduler moves work between CPUs. */
  for (;;) {
    __asm__ volatile("msr daifclr, #2" ::: "memory");
    if (xaios_thread_run_pending((uint32_t)cpu_id) == 0U) {
      /* Idle, so this CPU can carry the network tick: claim it once, repair a
       * tick this CPU lost while running a task, and poll the stack while
       * there is nothing else to do. The tick is what makes this come round at
       * the tick rate instead of only when something else wakes the CPU, and
       * the poll is here rather than in the handler because no port has to be
       * more interrupt-safe than it already is for this to work. */
      if (timer_arm_network_tick() != 0U) {
        network_poll_tick_from_carrier();
      }
      __asm__ volatile("wfe");
    }
  }
}

void smp_init_platform(const xaios_boot_info_t *boot) {
  aarch64_acpi_info_t acpi_info;
  uint32_t candidate_capacity = a64smp_platform_cpu_capacity(boot, &acpi_info);
  uint32_t qemu_virt = acpi_info.madt != 0U && a64smp_acpi_is_qemu_virt(&acpi_info);
  uint32_t psci_use_hvc =
      acpi_info.madt != 0U ? (qemu_virt != 0U ? 1U : acpi_info.psci_use_hvc)
                          : 1U;
  uint64_t boot_mpidr = a64smp_read_mpidr_el1();
  uint64_t state_bytes = align_up(
      (uint64_t)candidate_capacity * sizeof(xaios_cpu_state_t), PAGE_SIZE);
  uint64_t stack_bytes =
      (uint64_t)candidate_capacity * SECONDARY_STACK_SIZE;
  uint64_t bootstrap_bytes = state_bytes + stack_bytes;
  a64smp_bootstrap_start = allocate_bootstrap(boot, bootstrap_bytes);
  kassert(a64smp_bootstrap_start != 0U);
  a64smp_bootstrap_end = a64smp_bootstrap_start + bootstrap_bytes;
  a64smp_cpu_states = (xaios_cpu_state_t *)(uintptr_t)a64smp_bootstrap_start;
  g_secondary_stacks = (uint8_t *)(uintptr_t)(a64smp_bootstrap_start + state_bytes);
  a64smp_cpu_capacity = candidate_capacity;
  bytes_zero((void *)(uintptr_t)a64smp_bootstrap_start, bootstrap_bytes);
  for (uint32_t i = 0; i < a64smp_cpu_capacity; ++i) {
    a64smp_cpu_states[i].cpu_id = i;
    a64smp_cpu_states[i].online = 0;
    a64smp_cpu_states[i].mpidr = a64smp_platform_mpidr(&acpi_info, boot_mpidr, i);
    a64smp_cpu_states[i].role = XAIOS_CPU_ROLE_OFFLINE;
    a64smp_cpu_states[i].lease_owner_id = 0;
    a64smp_cpu_states[i].irq_routed_away = 0;
    a64smp_cpu_states[i].tick_suppressed = 0;
    a64smp_cpu_states[i].migration_count = 0;
    a64smp_cpu_states[i].involuntary_context_switch_count = 0;
    a64smp_cpu_states[i].scheduling_enabled = 0;
    a64smp_cpu_states[i].steal_count = 0;
  }
  xaios_spin_init(&a64smp_lock);
  g_online_count = 0;
  a64smp_secondary_release = 0;
  a64smp_locking_active = 0U;

  a64smp_cpu_states[0].online = 1;
  a64smp_cpu_states[0].mpidr = boot_mpidr;
  a64smp_cpu_states[0].role = XAIOS_CPU_ROLE_HOUSEKEEPING;
  a64smp_cpu_states[0].irq_routed_away = 0;
  a64smp_cpu_states[0].tick_suppressed = 0;
  bump_online();

  klog("smp: boot cpu mpidr=0x%lx role=housekeeping\n",
       a64smp_cpu_states[0].mpidr);

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
    uint64_t mpidr = a64smp_cpu_states[cpu].mpidr;
    if (mpidr == 0U) {
      ++rejected_count;
      continue;
    }
    uint64_t status = a64smp_psci_cpu_on(mpidr,
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
           a64smp_count_online(), admitted_count);
      break;
    }
    __asm__ volatile("wfe");
  }

  a64smp_cpu_capacity = admitted_count;
  klog("smp: online cpus=%u/%u dynamic_capacity=%u\n",
       a64smp_count_online(), admitted_count, a64smp_cpu_capacity);
  for (uint32_t cpu = 0; cpu < a64smp_cpu_capacity; ++cpu) {
    if (a64smp_cpu_states[cpu].online != 0) {
      klog("smp: cpu%u online=%u mpidr=0x%lx role=%u\n",
           cpu, a64smp_cpu_states[cpu].online, a64smp_cpu_states[cpu].mpidr,
           (unsigned)a64smp_cpu_states[cpu].role);
    }
  }
}

xaios_status_t smp_bring_secondaries_online(void) {
  /* Already online: this platform starts its secondaries in
     smp_init_platform, where firmware hands them over with an address space
     they can run in. Nothing to do, and saying so is the point -- the caller
     should not have to know which platforms need it. */
  return XAIOS_OK;
}

xaios_status_t smp_release_secondary_schedulers(void) {
  /* Locks become real atomics from here, before anything else can run: past
   * this point every CPU that reaches kernel code activates the kernel's
   * translation first, so all of them agree the memory is Normal cacheable. */
  __atomic_store_n(&a64smp_locking_active, 1U, __ATOMIC_RELEASE);
  __atomic_store_n(&a64smp_secondary_release, 1U, __ATOMIC_RELEASE);
  /* The secondaries waiting on this still have translation off, so they read
   * it from memory and never from the caches this store lands in. They spin
   * rather than sleep, so a late arrival costs nothing, but nothing else would
   * ever push this out -- and the caller asserts on the barrier it gates. */
  vmm_clean_to_memory(&a64smp_secondary_release,
                  sizeof(a64smp_secondary_release));
  __asm__ volatile("sev" ::: "memory");
  uint64_t started = timer_counter();
  uint64_t timeout = timer_frequency_hz() *
                     SECONDARY_WORKER_READY_TIMEOUT_MS / UINT64_C(1000);
  for (;;) {
    uint32_t ready = 1U;
    for (uint32_t cpu = 1U; cpu < a64smp_cpu_capacity; ++cpu) {
      if (a64smp_cpu_states[cpu].online != 0U &&
          __atomic_load_n(&a64smp_cpu_states[cpu].scheduling_enabled,
                          __ATOMIC_ACQUIRE) != 0U) {
        ++ready;
      }
    }
    if (ready == a64smp_count_online()) {
      klog("smp: secondary worker barrier passed ready=%u\n", ready);
      return XAIOS_OK;
    }
    __asm__ volatile("sev\n\tyield" ::: "memory");
    if (timer_counter() - started >= timeout) {
      klog("smp: secondary worker barrier timed out ready=%u online=%u\n",
           ready, a64smp_count_online());
      return XAIOS_ERR_BUSY;
    }
  }
}
