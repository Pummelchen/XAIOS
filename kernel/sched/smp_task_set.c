/* Work spread across the online CPUs, once rather than three times.
 *
 * This lived in kernel/arch/aarch64/smp.c, kernel/arch/x86_64/smp.c and
 * kernel/arch/riscv64/smp.c as three copies of the same arithmetic, and the
 * copies had already started to drift: two of them keyed the per-worker seed
 * on the CPU's identifier and one on its ordinal, which agree on every machine
 * whose CPUs are numbered from zero without gaps and disagree on any machine
 * that is not. Nothing pins the checksum, so the difference had gone
 * unnoticed -- which is the usual way a copy stops being a copy.
 *
 * There is nothing architecture-specific in it. It asks how many CPUs are
 * online through the shared interface and does integer work; the answer is
 * the same everywhere. Keeping it under an architecture's name was the same
 * identity-versus-capability mistake this codebase has a rule about, applied
 * to a directory rather than to firmware.
 */
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/status.h>

/* Golden-ratio odd constant: a cheap way to give each worker a distinct
   starting value without a table. */
#define TASK_SET_SEED UINT64_C(0x9e3779b185ebca87)
#define TASK_SET_MAX_ITERATIONS UINT64_C(100000)

xaios_status_t smp_run_user_task_set(uint64_t requested_workers,
                                     uint64_t iterations,
                                     uint64_t *ran_workers,
                                     uint64_t *checksum) {
  if (ran_workers == 0 || checksum == 0 || requested_workers == 0U ||
      iterations == 0U) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t online = smp_online_count();
  if (online == 0U) return XAIOS_ERR_INVALID;

  /* Capped at what the machine actually has. A caller measuring parallel
     speedup against a worker count it did not get would be measuring
     nothing, so the number assigned is reported rather than the number
     asked for. */
  uint64_t workers = requested_workers > online ? online : requested_workers;
  if (iterations > TASK_SET_MAX_ITERATIONS) {
    iterations = TASK_SET_MAX_ITERATIONS;
  }

  /* Keyed on the worker's ordinal, not on any CPU's identifier: the result
     then describes how much work was asked for and not how the firmware
     happened to number its processors. */
  uint64_t total = 0U;
  for (uint64_t worker = 0U; worker < workers; ++worker) {
    uint64_t value = (worker + 1U) * TASK_SET_SEED;
    for (uint64_t index = 0U; index < iterations; ++index) {
      value ^= (index + 1U) * (worker + 3U);
      value = (value << 7U) | (value >> 57U);
    }
    total ^= value + (iterations << (worker & 7U));
  }

  *ran_workers = workers;
  *checksum = total;
  klog("smp: app task set workers=%lu iterations=%lu checksum=%lx\n", workers,
       iterations, total);
  return XAIOS_OK;
}
