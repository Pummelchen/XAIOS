/* The Supervisor Binary Interface, which is how this port talks to anything.
 *
 * On AArch64 and x86-64 the kernel drives a UART itself, because it can: the
 * hardware is at a known address and nothing else owns it. RISC-V puts a
 * layer underneath -- OpenSBI runs in M-mode and the kernel asks it for the
 * console, the timer and power. That is not a limitation being worked
 * around, it is the architecture's own boot contract, and using it is what
 * platform neutrality means on this machine: the capability is supplied by
 * firmware, and the kernel asks for it rather than assuming where it lives.
 */
#include <xaios/riscv64_sbi.h>

/* An SBI call is an ecall with the extension in a7, the function in a6, and
   arguments from a0. It returns an error in a0 and a value in a1.
 *
 * Five argument registers rather than three, which is not generality for its
 * own sake: RFENCE.REMOTE_SFENCE_VMA takes four (hart mask, mask base, start
 * address, size) and REMOTE_SFENCE_VMA_ASID takes five, and this file could
 * not express either. A three-argument helper does not fail visibly when it
 * is handed a four-argument call -- it leaves a3 holding whatever the
 * compiler last put there, and firmware reads that as a size. So the plumbing
 * grew rather than gaining a second copy beside it, and the three-argument
 * spelling below is a wrapper so every existing call site still reads as what
 * it is.
 *
 * a3 and a4 are zero for the calls that do not use them. The specification
 * says unused argument registers are ignored, and the legacy v0.1 calls read
 * only a0, so passing zero is both harmless and better than passing whatever
 * was there -- a future extension that starts reading a3 would otherwise
 * inherit a value nobody chose. */
static sbi_result_t sbi_call5(uint64_t extension, uint64_t function,
                              uint64_t arg0, uint64_t arg1, uint64_t arg2,
                              uint64_t arg3, uint64_t arg4) {
  register uint64_t a0 __asm__("a0") = arg0;
  register uint64_t a1 __asm__("a1") = arg1;
  register uint64_t a2 __asm__("a2") = arg2;
  register uint64_t a3 __asm__("a3") = arg3;
  register uint64_t a4 __asm__("a4") = arg4;
  register uint64_t a6 __asm__("a6") = function;
  register uint64_t a7 __asm__("a7") = extension;
  __asm__ volatile("ecall"
                   : "+r"(a0), "+r"(a1)
                   : "r"(a2), "r"(a3), "r"(a4), "r"(a6), "r"(a7)
                   : "memory");
  sbi_result_t result;
  result.error = (int64_t)a0;
  result.value = a1;
  return result;
}

static sbi_result_t sbi_call(uint64_t extension, uint64_t function,
                             uint64_t arg0, uint64_t arg1, uint64_t arg2) {
  return sbi_call5(extension, function, arg0, arg1, arg2, 0U, 0U);
}

/* Whether a given extension is present.
 *
 * Asked rather than assumed. The debug console extension is the modern way
 * to print and the legacy putchar is the one every implementation has; which
 * exists depends on the firmware, not on the architecture, so the kernel has
 * to find out at run time exactly as it does for every other capability. */
int sbi_probe_extension(uint64_t extension) {
  sbi_result_t result = sbi_call(SBI_EXT_BASE, SBI_BASE_PROBE_EXTENSION,
                                 extension, 0U, 0U);
  return result.error == 0 && result.value != 0U;
}

uint64_t sbi_spec_version(void) {
  sbi_result_t result =
      sbi_call(SBI_EXT_BASE, SBI_BASE_GET_SPEC_VERSION, 0U, 0U, 0U);
  return result.error == 0 ? result.value : 0U;
}

uint64_t sbi_implementation_id(void) {
  sbi_result_t result =
      sbi_call(SBI_EXT_BASE, SBI_BASE_GET_IMPL_ID, 0U, 0U, 0U);
  return result.error == 0 ? result.value : 0U;
}

static int g_debug_console_available;
static int g_console_probed;

void sbi_putchar(char value) {
  if (g_console_probed == 0) {
    g_debug_console_available = sbi_probe_extension(SBI_EXT_DBCN);
    g_console_probed = 1;
  }
  if (g_debug_console_available != 0) {
    /* One byte at a time. The extension can take a buffer, and a buffer is
       what a real console driver would use; a byte keeps this call the same
       shape as the legacy one it falls back to, and the bring-up prints
       little enough that the difference is not measurable. */
    char byte = value;
    (void)sbi_call(SBI_EXT_DBCN, SBI_DBCN_WRITE, 1U,
                   (uint64_t)(uintptr_t)&byte, 0U);
    return;
  }
  (void)sbi_call(SBI_EXT_LEGACY_PUTCHAR, 0U, (uint64_t)(unsigned char)value,
                 0U, 0U);
}

void sbi_puts(const char *text) {
  if (text == 0) return;
  for (const char *p = text; *p != '\0'; ++p) {
    if (*p == '\n') sbi_putchar('\r');
    sbi_putchar(*p);
  }
}

void sbi_put_u64_hex(uint64_t value) {
  static const char digits[] = "0123456789abcdef";
  char buffer[17];
  unsigned index = 0U;
  sbi_puts("0x");
  for (int shift = 60; shift >= 0; shift -= 4) {
    unsigned nibble = (unsigned)((value >> shift) & 0xFU);
    if (nibble != 0U || index != 0U || shift == 0) {
      buffer[index++] = digits[nibble];
    }
  }
  buffer[index] = '\0';
  sbi_puts(buffer);
}

void sbi_put_u64(uint64_t value) {
  char buffer[21];
  unsigned index = 0U;
  if (value == 0U) {
    sbi_puts("0");
    return;
  }
  while (value != 0U && index < sizeof(buffer) - 1U) {
    buffer[index++] = (char)('0' + (char)(value % 10U));
    value /= 10U;
  }
  while (index != 0U) {
    sbi_putchar(buffer[--index]);
  }
}

void sbi_shutdown(void) {
  /* The system-reset extension is the current way; the legacy shutdown is
     what older firmware has. Neither is guaranteed, so if both decline the
     caller is left to park rather than being told the machine stopped. */
  if (sbi_probe_extension(SBI_EXT_SRST) != 0) {
    (void)sbi_call(SBI_EXT_SRST, SBI_SRST_SYSTEM_RESET, 0U, 0U, 0U);
  }
  (void)sbi_call(SBI_EXT_LEGACY_SHUTDOWN, 0U, 0U, 0U, 0U);
}

/* Starting another hart.
 *
 * A supervisor-mode kernel cannot take a hart out of reset itself -- that is
 * machine-mode work -- so the HSM extension is the supported route and not a
 * workaround. The hart arrives at the given physical address with translation
 * off and its own id in a0, which is why the entry point has to be reachable
 * without a page table.
 */
int64_t sbi_hart_start(uint64_t hart_id, uint64_t start_address,
                       uint64_t opaque) {
  sbi_result_t result =
      sbi_call(SBI_EXT_HSM, SBI_HSM_HART_START, hart_id, start_address, opaque);
  return result.error;
}

int64_t sbi_hart_status(uint64_t hart_id) {
  sbi_result_t result =
      sbi_call(SBI_EXT_HSM, SBI_HSM_HART_STATUS, hart_id, 0U, 0U);
  return result.error == 0 ? (int64_t)result.value : result.error;
}

/* Waking another hart.
 *
 * A supervisor software interrupt is the only thing that brings a hart out of
 * wfi when nothing else is pending, and supervisor mode cannot raise one on
 * another hart itself -- that write lives in machine mode. This is what the
 * IPI extension is for.
 */
int64_t sbi_send_ipi(uint64_t hart_mask, uint64_t hart_mask_base) {
  sbi_result_t result =
      sbi_call(SBI_EXT_IPI, SBI_IPI_SEND, hart_mask, hart_mask_base, 0U);
  return result.error;
}

/* Fencing the harts this one is not running on.
 *
 * The only thing in this file that changes another hart's state rather than
 * asking it a question, and what the port needed it for is a correctness gap
 * rather than a missing feature: `sfence.vma` fences the hart that executes
 * it. A kernel that clears a page table entry and fences locally has
 * withdrawn the mapping from exactly one TLB. Every other online hart may go
 * on translating through the entry the kernel just cleared -- reading, and
 * worse writing, memory the allocator has already handed to somebody else.
 * Nothing catches that; it is silent, late, and looks like corruption
 * somewhere unrelated.
 *
 * Probed rather than assumed, and cached rather than probed each time: the
 * unmap path calls this, and an ecall to ask whether an ecall is possible
 * would double the cost of every fence. The state is written once by
 * whichever hart gets here first; two harts racing both compute the same
 * answer from the same firmware, so the race is benign and costs at most one
 * redundant probe. */
static int g_rfence_available = -1;

int sbi_rfence_available(void) {
  int known = __atomic_load_n(&g_rfence_available, __ATOMIC_ACQUIRE);
  if (known >= 0) return known;
  int probed = sbi_probe_extension(SBI_EXT_RFENCE);
  __atomic_store_n(&g_rfence_available, probed, __ATOMIC_RELEASE);
  return probed;
}

int64_t sbi_remote_sfence_vma(uint64_t hart_mask, uint64_t hart_mask_base,
                              uint64_t start_address, uint64_t size) {
  sbi_result_t result =
      sbi_call5(SBI_EXT_RFENCE, SBI_RFENCE_REMOTE_SFENCE_VMA, hart_mask,
                hart_mask_base, start_address, size, 0U);
  return result.error;
}

/* The ASID-qualified form, which this kernel does not use yet and carries
   anyway because leaving it out would be the more misleading choice: the
   fence above is the all-address-spaces one, and a reader who found only that
   could reasonably conclude the extension has no narrower form. Every mapping
   this port makes runs with satp.ASID zero -- one address space number for
   the whole machine -- so an ASID-qualified fence would name the only ASID
   there is and buy nothing. When per-process ASIDs arrive, this is the call
   that stops a process teardown from fencing every other process's
   translations off every hart. */
int64_t sbi_remote_sfence_vma_asid(uint64_t hart_mask, uint64_t hart_mask_base,
                                   uint64_t start_address, uint64_t size,
                                   uint64_t asid) {
  sbi_result_t result =
      sbi_call5(SBI_EXT_RFENCE, SBI_RFENCE_REMOTE_SFENCE_VMA_ASID, hart_mask,
                hart_mask_base, start_address, size, asid);
  return result.error;
}
