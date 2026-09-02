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
   arguments from a0. It returns an error in a0 and a value in a1. */
static sbi_result_t sbi_call(uint64_t extension, uint64_t function,
                             uint64_t arg0, uint64_t arg1, uint64_t arg2) {
  register uint64_t a0 __asm__("a0") = arg0;
  register uint64_t a1 __asm__("a1") = arg1;
  register uint64_t a2 __asm__("a2") = arg2;
  register uint64_t a6 __asm__("a6") = function;
  register uint64_t a7 __asm__("a7") = extension;
  __asm__ volatile("ecall"
                   : "+r"(a0), "+r"(a1)
                   : "r"(a2), "r"(a6), "r"(a7)
                   : "memory");
  sbi_result_t result;
  result.error = (int64_t)a0;
  result.value = a1;
  return result;
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
