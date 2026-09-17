/* Remote TLB shootdown, and the address-space fences that ask for it.
 *
 * This is the middle of mmu.c, moved here whole: the shootdown counters, the
 * hart-mask construction that never assumes dense firmware hart ids, the SBI
 * RFENCE call, and the four address-space fences the page-table code calls.
 * The test that proves a fence reaches another hart's TLB is mmu_shootdown.c,
 * and the declarations the two share are in mmu_shootdown.h, which
 * mmu_internal.h includes.
 *
 * Nothing here reads the page tables or any state mmu.c owns. The inputs are
 * the online-hart list from smp.c and the RFENCE extension from firmware, so
 * the move needed no shim and no accessor.
 *
 * The fence ordering did not change and must not: riscv64_mmu_flush_one fences
 * this hart before it asks firmware for the others, and riscv64_mmu_flush_leaf
 * keeps its global fence for any leaf above 4 KiB.
 */
#include "mmu_internal.h"

#include <xaios/riscv64_sbi.h>
#include <xaios/smp.h>

/* ---------------------------------------------------------------------------
 * Remote TLB shootdown.
 *
 * `sfence.vma` fences the hart that executes it and no other. That is not a
 * QEMU detail or a cautious reading -- it is the definition of the
 * instruction, and there is no supervisor-mode instruction that fences a hart
 * this one is not running on. So until this existed, every fence in this file
 * was a fence of one TLB: the kernel cleared a page table entry, fenced
 * itself, freed the page, and the other harts went on translating through the
 * entry that had been cleared. A write through such a stale translation lands
 * in whatever the allocator handed out next. It is silent, it is late, and
 * when it surfaces it does not look like a paging bug.
 *
 * The other two architectures already close this. x86-64 sends an
 * inter-processor interrupt and waits for each CPU to acknowledge a
 * generation (x86_64_platform_invalidate_page_all). AArch64 does not have the
 * problem at all: `tlbi vaae1is` is broadcast by the hardware across the inner
 * shareable domain. RISC-V's answer is neither -- it is firmware's, through
 * the RFENCE extension, which is the same shape as HSM for starting a hart
 * and IPI for waking one, and for the same reason: the work is machine-mode
 * work and supervisor mode asks for it. That is also why there is no
 * acknowledgement counter here to match x86-64's. The ecall does not return
 * until firmware says every named hart has fenced; the wait is the call.
 *
 * The hart mask is the part worth being careful about. SBI takes a bitmap and
 * a base, and bit N means hart (base + N) -- not hart N. Hart ids are
 * firmware's to choose and this project has already been bitten by assuming
 * they are dense: booting through EDK2 leaves one hart already started, so the
 * machine comes up with ids 0, 2, 3, and code that indexed by id was wrong. A
 * shootdown that gets the base wrong fences some other hart and reports
 * success, which is the worst failure available -- the kernel would believe it
 * had done the thing it had not done. So the mask is built from the hart ids
 * of the online CPUs, grouped into 64-hart windows around the lowest id in
 * each group, and never assumed to start at zero.
 * ------------------------------------------------------------------------ */

/* Completed shootdown operations: fences that reached at least one other
   hart. Not the number of ecalls -- a machine whose hart ids are spread wider
   than 64 takes several ecalls for one logical shootdown -- and not the
   number attempted, because a fence firmware refused proves nothing. */
static uint64_t g_tlb_shootdown_count;
/* Remote harts fenced, summed over every shootdown. The pair is what makes
   the self-test's assertion mean anything: a count of operations alone cannot
   tell "fenced three harts twice" from "fenced nobody twice". */
static uint64_t g_tlb_remote_hart_fences;
/* Firmware refusals, counted rather than ignored. Without this a kernel whose
   every remote fence was rejected would report exactly the same shootdown
   count as one where they all worked. */
static uint64_t g_tlb_remote_fence_errors;
/* The negative control, and nothing but the self-test writes it.
 *
 * "The remote hart no longer translates the address" is a claim about
 * hardware that could be true for reasons having nothing to do with this
 * code: an implementation is free to drop a translation whenever it likes, so
 * an assertion that only ever sees the fixed kernel cannot tell a working
 * shootdown from a machine that never held the entry. The self-test therefore
 * withdraws a mapping twice -- once with this set, which is exactly the kernel
 * that existed before this change, and once without -- and compares. If the
 * suppressed withdrawal already stops the remote hart translating, the machine
 * cannot demonstrate the bug and the test says so rather than claiming a proof
 * it does not have. */
static uint32_t g_tlb_shootdown_suppressed;

uint64_t riscv64_platform_tlb_shootdown_count(void) {
  return __atomic_load_n(&g_tlb_shootdown_count, __ATOMIC_ACQUIRE);
}

uint64_t riscv64_platform_tlb_remote_hart_fences(void) {
  return __atomic_load_n(&g_tlb_remote_hart_fences, __ATOMIC_ACQUIRE);
}

uint64_t riscv64_platform_tlb_remote_fence_errors(void) {
  return __atomic_load_n(&g_tlb_remote_fence_errors, __ATOMIC_ACQUIRE);
}

/* Said once, not once per fence: firmware without RFENCE cannot be worked
   around from supervisor mode, and a line per unmap would bury the boot. */
static uint32_t g_rfence_warned;

/* The mask and base of the last window fenced, kept so the self-test can
   print what was actually sent rather than what the reader assumes. A
   shootdown that names the wrong harts succeeds silently -- firmware has no
   way to know the caller meant somebody else -- so the numbers that decide
   whether the gap handling is right are worth having in the boot log. */
static uint64_t g_tlb_last_mask;
static uint64_t g_tlb_last_base;
static uint32_t g_tlb_last_windows;

uint64_t riscv64_platform_tlb_last_mask(void) { return g_tlb_last_mask; }
uint64_t riscv64_platform_tlb_last_base(void) { return g_tlb_last_base; }
uint32_t riscv64_platform_tlb_last_windows(void) { return g_tlb_last_windows; }

/* The fence itself. A `size` of zero means the whole address space, which is
 * how the specification spells it and what the global callers want.
 *
 * Returns the number of remote harts named, which is zero on a machine that
 * is still single-hart. That early exit is not an optimisation for its own
 * sake: vmm_init maps thousands of pages before any secondary exists, and an
 * ecall each to reach nobody would be a real cost for no correctness. */
static uint32_t tlb_remote_fence(uint64_t start, uint64_t size) {
  if (g_tlb_shootdown_suppressed != 0U) return 0U;
  if (smp_online_count() <= 1U) return 0U;
  if (sbi_rfence_available() == 0) {
    if (__atomic_exchange_n(&g_rfence_warned, 1U, __ATOMIC_ACQ_REL) == 0U) {
      klog("vmm: WARNING firmware offers no SBI RFENCE extension; a kernel "
           "mapping withdrawn on one hart stays live in every other hart's "
           "TLB and supervisor mode cannot fix that\n");
    }
    return 0U;
  }

  uint64_t harts[VMM_MAX_HARTS];
  uint32_t pending[VMM_MAX_HARTS];
  uint32_t count = 0U;
  uint32_t self = smp_cpu_id();
  uint32_t capacity = smp_capacity();
  if (capacity > VMM_MAX_HARTS) capacity = VMM_MAX_HARTS;
  for (uint32_t cpu = 0U; cpu < capacity && count < VMM_MAX_HARTS; ++cpu) {
    if (cpu == self) continue;
    /* Online CPUs only. A hart that was never started, or that refused to,
       is not one firmware will accept in a mask: SBI answers
       SBI_ERR_INVALID_PARAM for the whole call, so a single absent hart would
       cancel the fence for every present one. */
    if (smp_cpu_state(cpu) == 0) continue;
    harts[count] = (uint64_t)riscv64_hart_of_cpu(cpu);
    pending[count] = 1U;
    ++count;
  }
  if (count == 0U) return 0U;

  /* Grouped into windows rather than assuming one call covers everything.
     Sixty-four harts fit in a mask; ids 0 and 200 do not, however few harts
     there are. Each pass takes the lowest id still unfenced as the base and
     sweeps up everything within 63 of it. */
  uint32_t remaining = count;
  uint32_t fenced = 0U;
  uint32_t windows = 0U;
  while (remaining != 0U) {
    uint64_t base = UINT64_C(0xFFFFFFFFFFFFFFFF);
    for (uint32_t i = 0U; i < count; ++i) {
      if (pending[i] != 0U && harts[i] < base) base = harts[i];
    }
    uint64_t mask = 0U;
    uint32_t in_window = 0U;
    for (uint32_t i = 0U; i < count; ++i) {
      if (pending[i] == 0U) continue;
      uint64_t offset = harts[i] - base;
      if (offset >= 64U) continue;
      mask |= UINT64_C(1) << offset;
      pending[i] = 0U;
      ++in_window;
    }
    /* The lowest pending id is always in its own window, so this is never
       zero; the guard is here so a future change that breaks that invariant
       hangs a boot loudly rather than spinning forever in the unmap path. */
    if (in_window == 0U) break;
    remaining -= in_window;
    ++windows;
    g_tlb_last_mask = mask;
    g_tlb_last_base = base;
    int64_t error = sbi_remote_sfence_vma(mask, base, start, size);
    if (error != 0) {
      __atomic_add_fetch(&g_tlb_remote_fence_errors, 1U, __ATOMIC_RELAXED);
      klog("vmm: SBI remote fence refused mask=0x%lx base=%lu error=0x%lx\n",
           mask, base, (uint64_t)error);
      continue;
    }
    __atomic_add_fetch(&g_tlb_remote_hart_fences, (uint64_t)in_window,
                       __ATOMIC_RELAXED);
    fenced += in_window;
  }
  /* Counted only when firmware actually fenced somebody. A shootdown that
     every window refused is not a shootdown, and counting it would let the
     self-test's assertion pass on a machine where nothing happened. */
  if (fenced != 0U) {
    __atomic_add_fetch(&g_tlb_shootdown_count, 1U, __ATOMIC_RELAXED);
  }
  g_tlb_last_windows = windows;
  return fenced;
}

/* The names the shootdown self-test in mmu_shootdown.c calls, so the header
   that declares them did not have to change when the state they read moved
   here. */
uint32_t riscv64_mmu_remote_fence(uint64_t start, uint64_t size) {
  return tlb_remote_fence(start, size);
}

void riscv64_mmu_set_remote_fence_suppressed(uint32_t suppressed) {
  __atomic_store_n(&g_tlb_shootdown_suppressed, suppressed, __ATOMIC_RELEASE);
}

void riscv64_mmu_flush_all(void) {
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");
}

/* The global fence, on every hart. Kept apart from riscv64_mmu_flush_all
   because not every caller of riscv64_mmu_flush_all wants it: switching this
   hart's user directory changes only this hart's translations, and
   broadcasting that would be an ecall per context switch to fence harts whose
   directories were untouched. */
void riscv64_mmu_flush_all_everywhere(void) {
  riscv64_mmu_flush_all();
  (void)tlb_remote_fence(0U, 0U);
}

void riscv64_mmu_flush_one(uint64_t virtual_address) {
  __asm__ volatile("sfence.vma %0, zero" : : "r"(virtual_address) : "memory");
  /* Every caller of this edits a table some other hart walks: kernel leaves
     live in the shared hierarchy that is mirrored into each hart's root, and
     a process's leaf tables are reached from every hart's own user directory
     by pointer. So the address is withdrawn from this hart and then from the
     others, in that order -- the local fence first because it cannot fail and
     costs nothing, the remote one second because it is an ecall that blocks
     until firmware says every named hart has fenced. */
  (void)tlb_remote_fence(virtual_address, PAGE_SIZE);
}

/* The fence that covers a leaf of the given level, which for anything above
   4 KiB is the global one.
 *
 * `sfence.vma` with an address names one virtual page. The specification is
 * explicit that this is not enough for a superpage: an implementation is
 * permitted to keep translations for the other pages the superpage covers,
 * and is permitted to cache the *absence* of a translation, so both making a
 * 2 MiB leaf valid and taking one away can leave stale entries behind for
 * every address in it except the one named. QEMU flushes generously and never
 * showed this; real hardware is under no such obligation, and the failure it
 * would produce -- a store landing in the memory a mapping used to describe
 * -- is silent and arrives late.
 *
 * The cost is a global fence on operations that are rare by construction:
 * the boot map, which runs before anything can have a stale entry, and the
 * large-page interface, which nothing calls in a loop. 4 KiB mappings, which
 * are the ones on the process-loading path, keep the narrow fence. */
void riscv64_mmu_flush_leaf(uint64_t virtual_address, uint32_t level) {
  if (level == 0U) {
    riscv64_mmu_flush_one(virtual_address);
    return;
  }
  /* Global, and on every hart. The paragraph above argues the global part;
     the remote part is the same argument one level out -- a superpage the
     kernel has withdrawn is withdrawn from one TLB unless firmware is asked
     to fence the rest, and a stale gibibyte is a worse stale than a stale
     page. */
  riscv64_mmu_flush_all_everywhere();
}
