/* klog and panic for RISC-V, on top of SBI.
 *
 * These two functions are the entire reason shared kernel code can run here
 * unmodified. `kernel/runtime/sha256.c` calls `klog` and `kassert` and
 * nothing else architectural; provide those against the console this machine
 * actually has and the same source file that runs on AArch64 and x86-64
 * compiles and runs on RISC-V with no edit. That is the platform-neutrality
 * rule stated as a test rather than as a claim -- and it is worth noting
 * which direction the test runs: it does not prove the rule holds
 * everywhere, only that a third architecture failed to contradict it.
 *
 * The formatter is deliberately smaller than the real klog. It carries the
 * specifiers the shared code being exercised actually uses, and an unknown
 * one prints itself rather than being silently dropped, so a caller that
 * needs more finds out by reading the output instead of by wondering where
 * its argument went.
 */
#include <stdarg.h>
#include <stdint.h>

#include <xaios/riscv64_sbi.h>

void klog(const char *fmt, ...);
void panic_at(const char *file, int line, const char *fmt, ...)
    __attribute__((noreturn));

static void emit(const char *fmt, va_list args) {
  if (fmt == 0) return;
  for (const char *p = fmt; *p != '\0'; ++p) {
    if (*p != '%') {
      if (*p == '\n') sbi_putchar('\r');
      sbi_putchar(*p);
      continue;
    }
    ++p;
    if (*p == '\0') {
      sbi_putchar('%');
      break;
    }
    if (*p == 's') {
      const char *value = va_arg(args, const char *);
      sbi_puts(value != 0 ? value : "(null)");
    } else if (*p == 'u') {
      sbi_put_u64((uint64_t)va_arg(args, unsigned int));
    } else if (*p == 'd') {
      int value = va_arg(args, int);
      if (value < 0) {
        sbi_putchar('-');
        sbi_put_u64((uint64_t)(-(int64_t)value));
      } else {
        sbi_put_u64((uint64_t)value);
      }
    } else if (*p == 'x') {
      sbi_put_u64_hex((uint64_t)va_arg(args, unsigned int));
    } else if (*p == 'l' && p[1] == 'u') {
      ++p;
      sbi_put_u64(va_arg(args, uint64_t));
    } else if (*p == 'l' && p[1] == 'x') {
      ++p;
      sbi_put_u64_hex(va_arg(args, uint64_t));
    } else if (*p == 'p') {
      sbi_put_u64_hex((uint64_t)(uintptr_t)va_arg(args, void *));
    } else if (*p == '%') {
      sbi_putchar('%');
    } else {
      /* Unrecognised. Printed rather than eaten, because a specifier this
         formatter does not know is a caller expecting something it will not
         get, and silence is the worst way to report that. */
      sbi_putchar('%');
      sbi_putchar(*p);
    }
  }
}

void klog(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  emit(fmt, args);
  va_end(args);
}

void panic_at(const char *file, int line, const char *fmt, ...) {
  sbi_puts("\n*** XAIOS panic (riscv64) ***\n  at ");
  sbi_puts(file != 0 ? file : "(unknown)");
  sbi_puts(":");
  sbi_put_u64((uint64_t)(line < 0 ? 0 : line));
  sbi_puts("\n  ");
  va_list args;
  va_start(args, fmt);
  emit(fmt, args);
  va_end(args);
  sbi_puts("\n  System halted.\n");
  /* Powered off rather than spun, so a gate waiting on this guest sees it
     stop instead of timing out and reporting a hang for a panic. */
  sbi_shutdown();
  for (;;) {
    __asm__ volatile("wfi");
  }
}
