/* Proving a remote hart stopped translating: the TLB shootdown self-test.
 *
 * Split out of mmu.c, which had grown well past two thousand lines. This is
 * the diagnostic half of remote shootdown. The fence itself, the counters it
 * adds to and the flag the negative control sets stay in mmu.c behind the
 * named entry points in mmu_shootdown.h; nothing else crosses between the two
 * files. The section below is the one that was at the bottom of mmu.c, moved
 * verbatim.
 *
 * The two entry points the rest of the kernel calls keep the names they had,
 * because smp.c calls them: riscv64_tlb_probe_service, from the polling loop a
 * secondary hart waits in before the scheduler rendezvous, and
 * riscv64_tlb_shootdown_self_test, once a second hart exists to be asked.
 */
#include "mmu_shootdown.h"

#include <xaios/pmm.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>

/* ---------------------------------------------------------------------------
 * Proving a remote hart stopped translating.
 *
 * Counting shootdowns is the easy half, and on its own it is close to
 * worthless: "the function ran N times" is satisfied by a function that sends
 * a mask of zero to the wrong base and is told everything is fine. What has
 * to be shown is the thing the bug was about -- a hart that is not this one
 * losing a translation it demonstrably had.
 *
 * That needs a second hart to execute a load at a moment of this hart's
 * choosing, which is what the little request block below is for. A secondary
 * sitting at the pre-scheduler gate polls it (riscv64_tlb_probe_service),
 * dereferences the address it is given with the page-fault probe armed, and
 * reports back either the value it read or the fact that it faulted. The boot
 * hart then has the one measurement that matters, taken on the other hart's
 * own MMU.
 *
 * Three states are read out of the same remote hart, in one boot, on the same
 * address:
 *
 *   1. mapped                    -> the remote hart reads the signature.
 *      (This is also what loads the translation into its TLB. Without it the
 *      test would prove nothing later: an address that was never translated
 *      cannot go stale.)
 *   2. unmapped, local fence only -> what the kernel did before this change.
 *   3. remote fence issued        -> the remote hart must fault.
 *
 * Steps 2 and 3 differ by exactly one thing: the SBI call. So if step 2 shows
 * the remote hart still reading through a cleared page table entry and step 3
 * shows it faulting, the fence is what removed the translation, and that is a
 * genuine remote TLB effect rather than a counter going up. If step 2 shows
 * the remote hart already faulting, this machine has dropped the entry on its
 * own -- permitted, and it means the negative control could not be
 * demonstrated here. The test says which of the two happened rather than
 * quietly claiming the stronger one.
 *
 * Step 4 is the control in the other direction, and the test would be
 * vacuous without it: a probe mechanism that reported "faulted" no matter
 * what would satisfy step 3 while proving nothing at all. So the page is
 * mapped again, with a different signature, and the remote hart has to read
 * the new value back.
 * ------------------------------------------------------------------------ */

/* One slot per CPU. Written by the boot hart, read and answered by the hart
   it names; volatile because the two are genuinely concurrent and the
   compiler has no way to know it. */
typedef struct tlb_probe_slot {
  volatile uint64_t address;
  volatile uint32_t request;  /* bumped by the asker */
  volatile uint32_t done;     /* set to `request` by the answerer */
  volatile uint32_t faulted;
  volatile uint64_t observed;
} tlb_probe_slot_t;

static tlb_probe_slot_t g_tlb_probe[VMM_MAX_HARTS];

/* Called by a secondary hart from the loop it waits in before the scheduler
   rendezvous. Costs one load and one CSR write per pass when there is nothing
   to do.
 *
 * The software-interrupt pending bit is cleared *first*, before the request
 * is read, and the order is the whole correctness of the handshake. Clearing
 * it afterwards loses a wake-up: the asker writes the request and raises the
 * interrupt in the window between this hart reading a stale request and
 * clearing the bit, and this hart then goes back to wfi with a request
 * pending and nothing left to wake it. Clearing first means any request
 * visible after the clear is still seen by the read below, and any request
 * that arrives after the read has left the bit set, so the wfi returns
 * immediately. */
void riscv64_tlb_probe_service(uint32_t cpu_id) {
  __asm__ volatile("csrc sip, %0" : : "r"(UINT64_C(1) << 1) : "memory");
  if (cpu_id >= VMM_MAX_HARTS) return;
  tlb_probe_slot_t *slot = &g_tlb_probe[cpu_id];
  uint32_t sequence = __atomic_load_n(&slot->request, __ATOMIC_ACQUIRE);
  if (sequence == slot->done) return;

  volatile uint64_t *pointer = (volatile uint64_t *)(uintptr_t)slot->address;
  uint64_t value = 0U;
  exception_page_probe_begin();
  value = *pointer;
  exception_page_probe_end();
  uint32_t faulted = exception_page_probe_faulted() != 0 ? 1U : 0U;
  /* The recovery steps over the faulting load, which leaves its destination
     register holding whatever was there before -- so a faulted probe has no
     value to report and must not pretend otherwise. */
  slot->observed = faulted != 0U ? 0U : value;
  slot->faulted = faulted;
  __atomic_store_n(&slot->done, sequence, __ATOMIC_RELEASE);
}

/* Ask `cpu` to dereference `address`. Returns zero if it did not answer in
   time, which is a failure of the test harness rather than of the kernel and
   is reported as such. */
static int tlb_probe_remote(uint32_t cpu, uint64_t address, uint32_t *faulted,
                            uint64_t *observed) {
  if (cpu >= VMM_MAX_HARTS) return 0;
  tlb_probe_slot_t *slot = &g_tlb_probe[cpu];
  uint32_t sequence = slot->request + 1U;
  slot->address = address;
  __atomic_store_n(&slot->request, sequence, __ATOMIC_RELEASE);
  /* The flag is what it checks; the interrupt is what ends its sleep. Same
     pairing smp_release_secondary_schedulers uses, and for the same reason. */
  (void)sbi_send_ipi(UINT64_C(1), (uint64_t)riscv64_hart_of_cpu(cpu));

  uint64_t frequency = timer_frequency_hz();
  uint64_t deadline =
      timer_counter() + (frequency == 0U ? UINT64_C(0) : frequency * 2U);
  while (__atomic_load_n(&slot->done, __ATOMIC_ACQUIRE) != sequence) {
    if (frequency != 0U && timer_counter() >= deadline) return 0;
  }
  *faulted = slot->faulted;
  *observed = slot->observed;
  return 1;
}

/* A gibibyte-aligned window one past the three the large-page self-test uses,
   picked under the same four constraints that comment sets out: below 256 GiB
   so Sv39 can represent it, clear of the userspace window, clear of the
   identity map, and a gibibyte away from its neighbours so it cannot share a
   level-2 table with them. Checked for emptiness before use rather than
   assumed, because "no machine has 196 GiB of RAM" is an assumption with a
   date on it. */
#define SELF_TEST_SHOOTDOWN_VA UINT64_C(0x30C0000000) /* 195 GiB */
#define SELF_TEST_SHOOTDOWN_SIGNATURE UINT64_C(0x5849414f53544c42)  /* XAIOSTLB */
#define SELF_TEST_SHOOTDOWN_SIGNATURE2 UINT64_C(0x5849414f53464e43) /* XAIOSFNC */

/* Ask one hart to dereference the test address and hold it to an expectation.
 *
 * Every online hart other than this one is asked, not just the first: a hart
 * mask built against the wrong base still reaches *somebody*, and a test that
 * questioned one hart would pass while the others kept translating. Which
 * harts get fenced is the part of this that is easy to get quietly wrong, so
 * every one of them is the witness. */
static void tlb_probe_expect(uint32_t cpu, uint64_t address, int expect_fault,
                             uint64_t expect_value, const char *step) {
  uint32_t faulted = 0U;
  uint64_t observed = 0U;
  if (tlb_probe_remote(cpu, address, &faulted, &observed) == 0) {
    vmm_panic("hart cpu%u did not answer a TLB probe within two seconds "
              "during the %s step", (uint64_t)cpu, step);
  }
  if (expect_fault != 0) {
    if (faulted == 0U) {
      vmm_panic("%s: hart cpu%u still translated %lx and read %lx -- the "
                "translation was not withdrawn from that hart's TLB",
                step, (uint64_t)cpu, address, observed);
    }
    return;
  }
  if (faulted != 0U) {
    vmm_panic("%s: hart cpu%u faulted on %lx, which is mapped", step,
              (uint64_t)cpu, address);
  }
  if (observed != expect_value) {
    vmm_panic("%s: hart cpu%u read %lx through %lx, expected %lx", step,
              (uint64_t)cpu, observed, address, expect_value);
  }
}

void riscv64_tlb_shootdown_self_test(void) {
  const char *mode = (riscv64_mmu_root_level() == 2U) ? "sv39" : "sv48";

  if (smp_online_count() <= 1U) {
    klog("vmm: tlb shootdown self-test skipped mode=%s -- one hart online, so "
         "there is no remote TLB to observe; nothing about remote fencing is "
         "checked on this machine\n", mode);
    return;
  }
  if (sbi_rfence_available() == 0) {
    klog("vmm: tlb shootdown self-test skipped mode=%s -- firmware offers no "
         "RFENCE extension, so this kernel CANNOT withdraw a mapping from "
         "another hart's TLB and no assertion below would be honest\n", mode);
    return;
  }

  /* Every online hart that is not this one, named rather than assumed to be
     1..n: the boot hart is whichever one firmware handed over on, and a
     machine that failed to start one secondary still has the others. */
  uint32_t self = smp_cpu_id();
  uint32_t remotes[VMM_MAX_HARTS];
  uint32_t remote_count = 0U;
  uint32_t capacity = smp_capacity();
  if (capacity > VMM_MAX_HARTS) capacity = VMM_MAX_HARTS;
  for (uint32_t cpu = 0U; cpu < capacity; ++cpu) {
    if (cpu == self || smp_cpu_state(cpu) == 0) continue;
    remotes[remote_count++] = cpu;
  }
  if (remote_count == 0U) {
    klog("vmm: tlb shootdown self-test skipped mode=%s -- no online hart "
         "other than this one\n", mode);
    return;
  }

  if (vmm_translate(SELF_TEST_SHOOTDOWN_VA, 0, 0) == XAIOS_OK) {
    vmm_panic("tlb shootdown self-test window %lx is already mapped; this "
              "machine is too large for the address the test picked",
              SELF_TEST_SHOOTDOWN_VA);
  }

  /* The kernel's CPU numbers next to firmware's hart ids, printed because
     they are the input to the hart mask and the place this can silently go
     wrong. On QEMU with an SBI boot they are the same sequence; under EDK2
     they are not, and a reader who wants to know whether this machine
     exercised the gap case can only find out from a line like this. */
  for (uint32_t cpu = 0U; cpu < capacity; ++cpu) {
    if (smp_cpu_state(cpu) == 0) continue;
    klog("vmm: tlb shootdown cpu%u -> hart%u%s\n", cpu,
         riscv64_hart_of_cpu(cpu), cpu == self ? " (self, not fenced)" : "");
  }

  void *page = pmm_alloc_page();
  if (page == 0) vmm_panic("tlb shootdown self-test has no page to alias");
  uint64_t physical = (uint64_t)(uintptr_t)page;
  volatile uint64_t *identity = (volatile uint64_t *)(uintptr_t)physical;
  *identity = SELF_TEST_SHOOTDOWN_SIGNATURE;

  uint64_t shootdowns_before = riscv64_platform_tlb_shootdown_count();
  uint64_t hart_fences_before = riscv64_platform_tlb_remote_hart_fences();

  if (vmm_map_page(SELF_TEST_SHOOTDOWN_VA, physical,
                   XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) != XAIOS_OK) {
    vmm_panic("tlb shootdown self-test could not map %lx",
              SELF_TEST_SHOOTDOWN_VA);
  }

  /* --- 1. every remote hart reads it, which is what puts it in its TLB ---
     A failure here is not a shootdown failure: it would mean a kernel mapping
     the boot hart made is not reaching another hart's root at all, which is
     the mirroring bug sync_kernel_hierarchy exists to prevent. It is also the
     step that makes everything after it mean something -- an address a hart
     never translated cannot go stale. */
  for (uint32_t i = 0U; i < remote_count; ++i) {
    tlb_probe_expect(remotes[i], SELF_TEST_SHOOTDOWN_VA, 0,
                     SELF_TEST_SHOOTDOWN_SIGNATURE, "mapped");
  }

  /* --- 2. withdraw it with a hart-local fence only: the negative control --- */
  riscv64_mmu_set_remote_fence_suppressed(1U);
  xaios_status_t unmapped = vmm_unmap_page(SELF_TEST_SHOOTDOWN_VA);
  riscv64_mmu_set_remote_fence_suppressed(0U);
  if (unmapped != XAIOS_OK) {
    vmm_panic("tlb shootdown self-test could not unmap %lx",
              SELF_TEST_SHOOTDOWN_VA);
  }
  /* The entry really is gone from the tables -- otherwise step 3 would be
     asserting that a live mapping is live. */
  if (vmm_translate(SELF_TEST_SHOOTDOWN_VA, 0, 0) == XAIOS_OK) {
    vmm_panic("tlb shootdown self-test unmapped %lx and it still translates",
              SELF_TEST_SHOOTDOWN_VA);
  }
  /* Nothing is asserted here. Whether a hart still holds the translation is
     the machine's business -- an implementation may drop it whenever it
     likes -- and the point of asking is to find out whether this machine can
     demonstrate the bug at all. */
  uint32_t stale_harts = 0U;
  for (uint32_t i = 0U; i < remote_count; ++i) {
    uint32_t faulted = 0U;
    uint64_t observed = 0U;
    if (tlb_probe_remote(remotes[i], SELF_TEST_SHOOTDOWN_VA, &faulted,
                         &observed) == 0) {
      vmm_panic("hart cpu%u did not answer the negative-control probe",
                (uint64_t)remotes[i]);
    }
    if (faulted == 0U && observed == SELF_TEST_SHOOTDOWN_SIGNATURE) {
      ++stale_harts;
    }
  }

  /* --- 3. the remote fence, on its own, with the entry already cleared ---
     Steps 2 and 3 differ by exactly one thing: this call. */
  uint32_t reached = riscv64_mmu_remote_fence(SELF_TEST_SHOOTDOWN_VA, PAGE_SIZE);
  if (reached != remote_count) {
    vmm_panic("the remote fence reached %u harts, but %u are online besides "
              "this one -- the hart mask does not name them all",
              (uint64_t)reached, (uint64_t)remote_count);
  }
  for (uint32_t i = 0U; i < remote_count; ++i) {
    tlb_probe_expect(remotes[i], SELF_TEST_SHOOTDOWN_VA, 1, 0U,
                     "after an explicit remote fence");
  }

  /* --- 4. map it again: the control against a probe that always faults ---
     Without this the test would be vacuous. A probe mechanism that reported
     "faulted" whatever happened would satisfy step 3 and prove nothing. */
  *identity = SELF_TEST_SHOOTDOWN_SIGNATURE2;
  if (vmm_map_page(SELF_TEST_SHOOTDOWN_VA, physical,
                   XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) != XAIOS_OK) {
    vmm_panic("tlb shootdown self-test could not remap %lx",
              SELF_TEST_SHOOTDOWN_VA);
  }
  for (uint32_t i = 0U; i < remote_count; ++i) {
    tlb_probe_expect(remotes[i], SELF_TEST_SHOOTDOWN_VA, 0,
                     SELF_TEST_SHOOTDOWN_SIGNATURE2, "mapped again");
  }

  /* --- 5. the production path end to end: the ordinary unmap, unaided ---
     Step 3 proved the fence works when this test calls it by hand. This
     proves vmm_unmap_page actually calls it. */
  if (vmm_unmap_page(SELF_TEST_SHOOTDOWN_VA) != XAIOS_OK) {
    vmm_panic("tlb shootdown self-test could not unmap %lx the second time",
              SELF_TEST_SHOOTDOWN_VA);
  }
  for (uint32_t i = 0U; i < remote_count; ++i) {
    tlb_probe_expect(remotes[i], SELF_TEST_SHOOTDOWN_VA, 1, 0U,
                     "after the ordinary unmap path");
  }

  uint64_t shootdowns = riscv64_platform_tlb_shootdown_count();
  uint64_t hart_fences = riscv64_platform_tlb_remote_hart_fences();
  /* The same shape of assertion x86-64 makes, kept because it catches a
     different failure from the ones above: a fence that worked by accident
     while never being issued for most of what this test did. Two because the
     test performs a map, an explicit fence, a remap and an unmap, and every
     one of them must have fenced. */
  if (shootdowns - shootdowns_before < 2U) {
    vmm_panic("tlb shootdown self-test recorded %lu shootdowns, expected at "
              "least 2", shootdowns - shootdowns_before);
  }
  if (hart_fences - hart_fences_before <
      (shootdowns - shootdowns_before) * (uint64_t)remote_count) {
    vmm_panic("tlb shootdown self-test recorded %lu shootdowns over %u remote "
              "harts but only %lu hart fences: some shootdowns did not reach "
              "every hart", shootdowns - shootdowns_before,
              (uint64_t)remote_count, hart_fences - hart_fences_before);
  }
  if (riscv64_platform_tlb_remote_fence_errors() != 0U) {
    vmm_panic("firmware refused %lu remote fences",
              riscv64_platform_tlb_remote_fence_errors());
  }

  pmm_free_page(page);

  klog("vmm: tlb shootdown self-test passed mode=%s remote_harts=%u "
       "shootdowns=%lu hart_fences=%lu last_mask=0x%lx last_base=%lu "
       "windows=%u\n", mode, remote_count, shootdowns - shootdowns_before,
       hart_fences - hart_fences_before, riscv64_platform_tlb_last_mask(),
       riscv64_platform_tlb_last_base(), riscv64_platform_tlb_last_windows());
  if (stale_harts != 0U) {
    klog("vmm: tlb shootdown negative control held: after a hart-local fence "
         "%u of %u remote harts still read 0x%lx through the cleared entry, "
         "and stopped only once the SBI remote fence was issued -- so what "
         "was measured is REMOTE harts losing a translation, not a counter\n",
         stale_harts, remote_count, SELF_TEST_SHOOTDOWN_SIGNATURE);
  } else {
    klog("vmm: tlb shootdown negative control NOT demonstrable on this "
         "machine: all %u remote harts had already dropped the translation "
         "after a hart-local fence, which the architecture permits. The "
         "assertions above then only show that a remote hart does not "
         "translate a withdrawn page -- not that the remote fence is why\n",
         remote_count);
  }
}
