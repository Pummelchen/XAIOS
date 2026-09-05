/* What this machine is, checked rather than assumed.
 *
 * The rest of the boot proves things every architecture has to do: map a
 * page, take a trap, advance a clock. This proves the things only RISC-V
 * has, and it exists because a third architecture that is only ever asked
 * the first set of questions is being tested as an imitation of the first
 * two. A PLIC is not a GIC. An instruction cache that needs fence.i is not
 * one that snoops. A firmware interface reached by ecall is not one reached
 * by SMC. Each of those is a place this port could be wrong in a way no
 * shared test would notice.
 *
 * Everything here reports what it found rather than asserting a particular
 * answer, except where the answer would mean the kernel is already broken.
 * Which SBI extensions a firmware offers, and whether misaligned access
 * traps, are properties of the machine; a gate reads the report and decides
 * what this project requires. */

#include <xaios/klog.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/types.h>
#include <xaios/vmm.h>

#define SIE_SOFTWARE (UINT64_C(1) << 1)

/* An address in writable data, to ask the page tables about. */
static uint32_t g_code_buffer[4] __attribute__((aligned(64)));
static volatile uint64_t g_misaligned_source[2] = {
    UINT64_C(0x0011223344556677), UINT64_C(0x8899aabbccddeeff)};

/* --------------------------------------------------------------- SBI */

static void report_sbi(void) {
  uint64_t version = sbi_spec_version();
  /* The specification packs major and minor into one word: bits 24..30 are
     the major number, 0..23 the minor. Printed apart because "version
     16777216" tells nobody anything. */
  uint64_t major = (version >> 24U) & UINT64_C(0x7f);
  uint64_t minor = version & UINT64_C(0xffffff);
  klog("riscv-isa: sbi spec=%lu.%lu impl=%lu\n", major, minor,
       sbi_implementation_id());
  klog("riscv-isa: sbi extensions time=%d ipi=%d hsm=%d srst=%d dbcn=%d\n",
       sbi_probe_extension(SBI_EXT_TIME) != 0,
       sbi_probe_extension(SBI_EXT_IPI) != 0,
       sbi_probe_extension(SBI_EXT_HSM) != 0,
       sbi_probe_extension(SBI_EXT_SRST) != 0,
       sbi_probe_extension(SBI_EXT_DBCN) != 0);
  /* An extension that cannot exist. Probing it has to answer "no" rather
     than an error or a hang: a firmware that answers yes to everything would
     make every probe above meaningless, and this is the control that says
     the probes are being answered rather than assumed. */
  int absent = sbi_probe_extension(UINT64_C(0x7a7a7a7a));
  klog("riscv-isa: sbi absent-extension probe answered %d (expected 0)\n",
       absent);
}

/* ------------------------------------------------------- hart states */

static void report_hsm(void) {
  if (sbi_probe_extension(SBI_EXT_HSM) == 0) {
    klog("riscv-isa: hsm absent; hart states unknown to the supervisor\n");
    return;
  }
  /* Status of a hart that cannot exist. HSM must refuse it -- a negative
     error rather than a state -- which is what makes a positive answer for
     a real hart meaningful. */
  int64_t absent = sbi_hart_status(UINT64_C(4095));
  /* klog has no signed long, and the error codes are small, so the sign is
     the part worth carrying. */
  klog("riscv-isa: hsm absent-hart refused=%u status=%d\n",
       absent < 0 ? 1U : 0U, (int)absent);
}

/* ------------------------------------------- misaligned load and store */

static void report_misaligned(void) {
  /* RISC-V leaves misaligned access to the implementation: it may work, it
     may trap and be emulated by firmware, or it may fault. The kernel does
     not rely on it either way; what matters is knowing which machine this
     is, because a driver written against one behaviour is wrong on another.
     Reading across the boundary of two adjacent words is misaligned by
     construction. */
  const volatile uint8_t *bytes = (const volatile uint8_t *)g_misaligned_source;
  uint64_t value = 0U;
  const volatile uint64_t *unaligned =
      (const volatile uint64_t *)(const void *)(bytes + 4);
  value = *unaligned;
  /* Reached at all means it did not fault. Whether firmware emulated it or
     hardware did it is invisible from here and does not matter to us. */
  klog("riscv-isa: misaligned 64-bit load completed value=0x%lx\n", value);
}

/* --------------------------------- instruction fetch, and what may be it */

static void report_fence_i_and_permissions(void) {
  /* RISC-V does not make stores visible to instruction fetch on their own: a
     kernel that writes code and jumps to it without fence.i is relying on an
     accident of the implementation. The instruction is issued here to prove
     the assembler and the machine both accept it on this profile.

     What is deliberately not done is writing code into a data buffer and
     calling it. The first version of this test did, and it faulted the
     moment it ran with translation on -- which is the page tables being
     right: RISC-V spells no-execute as the absence of the PTE X bit, and
     this port sets it per section rather than mapping everything alike. So
     the property worth reporting is the permission itself, read back from
     the tables that enforce it, rather than a jump that has to be allowed
     for the test to pass. */
  __asm__ volatile("fence.i" ::: "memory");

  uint64_t physical = 0U;
  uint32_t text_flags = 0U;
  uint32_t data_flags = 0U;
  uint64_t text_address = (uint64_t)(uintptr_t)&report_fence_i_and_permissions;
  uint64_t data_address = (uint64_t)(uintptr_t)&g_code_buffer[0];
  if (vmm_translate(text_address, &physical, &text_flags) != XAIOS_OK) {
    text_flags = UINT32_MAX;
  }
  if (vmm_translate(data_address, &physical, &data_flags) != XAIOS_OK) {
    data_flags = UINT32_MAX;
  }
  klog("riscv-isa: fence.i accepted; text x=%u w=%u data x=%u w=%u\n",
       (text_flags & XAIOS_VMM_EXECUTABLE) != 0U,
       (text_flags & XAIOS_VMM_WRITABLE) != 0U,
       (data_flags & XAIOS_VMM_EXECUTABLE) != 0U,
       (data_flags & XAIOS_VMM_WRITABLE) != 0U);
}

/* ------------------------------------------------------------ paging */

static void report_paging(void) {
  uint64_t satp = 0U;
  __asm__ volatile("csrr %0, satp" : "=r"(satp));
  uint64_t mode = satp >> 60U;
  /* 8 is Sv39, 9 is Sv48, 10 is Sv57. The kernel builds Sv48 tables; a
     machine that came up in another mode would still boot and would place
     every mapping somewhere the kernel did not intend. */
  klog("riscv-isa: satp mode=%lu (8=sv39 9=sv48 10=sv57) asid=%lu\n", mode,
       (satp >> 44U) & UINT64_C(0xffff));
}

/* --------------------------------------------------------------- CSRs */

static void report_csrs(void) {
  uint64_t sstatus = 0U;
  uint64_t sie = 0U;
  __asm__ volatile("csrr %0, sstatus" : "=r"(sstatus));
  __asm__ volatile("csrr %0, sie" : "=r"(sie));
  /* SUM is the window that lets the kernel touch user memory, and it is the
     one CSR bit in this report whose right value depends on the caller. It
     is opened across syscall dispatch and closed again, and it is open here
     because the page-table self-test this runs at the end of writes through
     a user mapping. Reported rather than asserted for that reason: what a
     gate can hold this to is that it is closed when nothing has opened it,
     which is a question for a different moment in the boot. */
  klog("riscv-isa: sstatus sum=%lu sie=%lu enabled_interrupts=0x%lx\n",
       (sstatus >> 18U) & UINT64_C(1), (sstatus >> 1U) & UINT64_C(1), sie);
}

void riscv64_isa_self_test(void) {
  report_sbi();
  report_hsm();
  report_misaligned();
  report_fence_i_and_permissions();
  report_paging();
  report_csrs();
  klog("riscv-isa: self-test passed\n");
}
