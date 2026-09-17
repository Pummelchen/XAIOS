/* x86_64 CPU topology and core-placement reporting.
 *
 * Extracted verbatim from kernel/arch/x86_64/early.c. This is the early CPU
 * work that reads the CPU's topology leaves, turns them into the placement
 * policy the scheduler is told about, and prints that policy. The per-CPU
 * record table itself stays in early.c: the TLB shootdown reads it through
 * early_module.h, and this report needs none of it.
 *
 * early_module.h is the shared seam. It declares the early.c primitives this
 * file must not own; they are aliased below so the moved body is unchanged. */

#include "early_module.h"

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

#if XAIOS_X86_COMMON_RUNTIME
#define X86_BRINGUP_ONLY __attribute__((unused))
#else
#define X86_BRINGUP_ONLY
#endif

/* early.c's primitives, under the names early_module.h declares. */
#define cpuid xaios_x86_early_cpuid
#define serial_puts xaios_x86_early_serial_puts
#define serial_hex64 xaios_x86_early_serial_hex64
#define serial_dec xaios_x86_early_serial_dec

typedef enum x86_64_core_role {
  X86_64_CORE_HOUSEKEEPING = 1,
  X86_64_CORE_AI_HOT = 2,
  X86_64_CORE_BACKGROUND = 3,
} x86_64_core_role_t;

typedef struct x86_64_placement_state {
  uint32_t logical_cpus;
  uint32_t housekeeping_cpus;
  uint32_t ai_hot_cpus;
  uint32_t background_cpus;
  uint32_t smt_disabled_by_default;
  uint32_t p_core_policy_ready;
  uint32_t e_core_policy_ready;
  uint32_t threads_per_core;
  uint32_t topology_leaf;
  uint64_t migration_total;
  uint64_t context_switch_total;
} x86_64_placement_state_t;

static x86_64_placement_state_t g_placement;

void X86_BRINGUP_ONLY x86_64_early_cpu_build_placement_policy(uint16_t serial_base) {
  uint32_t eax = 0;
  uint32_t ebx = 0;
  uint32_t ecx = 0;
  uint32_t edx = 0;
  cpuid(0, 0, &eax, &ebx, &ecx, &edx);
  uint32_t max_leaf = eax;
  uint32_t topology_leaf = max_leaf >= 0x1fU ? 0x1fU :
                           (max_leaf >= 0x0bU ? 0x0bU : 0U);
  uint32_t logical_cpus = 0U;
  uint32_t threads_per_core = 1U;
  if (topology_leaf != 0U) {
    for (uint32_t level = 0U; level < 32U; ++level) {
      cpuid(topology_leaf, level, &eax, &ebx, &ecx, &edx);
      uint32_t level_type = (ecx >> 8U) & 0xffU;
      uint32_t count = ebx & UINT32_C(0xffff);
      if (count == 0U || level_type == 0U) break;
      if (level_type == 1U) threads_per_core = count;
      if (count > logical_cpus) logical_cpus = count;
    }
  }
  if (logical_cpus == 0U) {
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    logical_cpus = (ebx >> 16) & 0xffU;
    if (logical_cpus == 0U) logical_cpus = 1U;
  }

  g_placement = (x86_64_placement_state_t){0};
  g_placement.logical_cpus = logical_cpus;
  g_placement.housekeeping_cpus = 1U;
  if (logical_cpus >= 4U) {
    g_placement.ai_hot_cpus = 2U;
    g_placement.background_cpus = logical_cpus - 3U;
  } else if (logical_cpus >= 2U) {
    g_placement.ai_hot_cpus = 1U;
    g_placement.background_cpus = logical_cpus - 2U;
  } else {
    g_placement.ai_hot_cpus = 0U;
    g_placement.background_cpus = 0U;
  }
  g_placement.smt_disabled_by_default = 1U;
  g_placement.p_core_policy_ready = max_leaf >= 0x1aU ? 1U : 0U;
  g_placement.e_core_policy_ready = max_leaf >= 0x1aU ? 1U : 0U;
  g_placement.threads_per_core = threads_per_core;
  g_placement.topology_leaf = topology_leaf;
  g_placement.migration_total = 0;
  g_placement.context_switch_total = 0;

  serial_puts(serial_base, "x86_64: placement policy logical_cpus=");
  serial_dec(serial_base, g_placement.logical_cpus);
  serial_puts(serial_base, " housekeeping=");
  serial_dec(serial_base, g_placement.housekeeping_cpus);
  serial_puts(serial_base, " ai_hot=");
  serial_dec(serial_base, g_placement.ai_hot_cpus);
  serial_puts(serial_base, " background=");
  serial_dec(serial_base, g_placement.background_cpus);
  serial_puts(serial_base, " threads_per_core=");
  serial_dec(serial_base, g_placement.threads_per_core);
  serial_puts(serial_base, " topology_leaf=");
  serial_hex64(serial_base, g_placement.topology_leaf);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: SMT policy disabled_by_default=");
  serial_dec(serial_base, g_placement.smt_disabled_by_default);
  serial_puts(serial_base, " p_core_policy=");
  serial_dec(serial_base, g_placement.p_core_policy_ready);
  serial_puts(serial_base, " e_core_policy=");
  serial_dec(serial_base, g_placement.e_core_policy_ready);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: hot-core telemetry migration_total=");
  serial_dec(serial_base, g_placement.migration_total);
  serial_puts(serial_base, " context_switch_total=");
  serial_dec(serial_base, g_placement.context_switch_total);
  serial_puts(serial_base, "\n");
}
