/* The panic screen for RISC-V, on top of SBI.
 *
 * klog used to live here as well. It does not any more: kernel/core/klog.c
 * drives a memory-mapped 16550 directly, which is exactly the console this
 * board has, and the only thing keeping it from being used was a guard
 * naming AArch64 where it meant "reaches its UART through memory". Using the
 * shared logger brings the log ring with it, which is what a panic replays.
 *
 * The panic path stays here, and stays on SBI, for a reason worth stating: a
 * panic has to print when the machine is already broken. Reaching for a lock
 * or a ring buffer at that moment is how a panic becomes a hang, and an
 * ecall to firmware needs neither.
 */
#include <stdarg.h>
#include <stdint.h>

#include <xaios/riscv64_sbi.h>

void panic_at(const char *file, int line, const char *fmt, ...)
    __attribute__((noreturn));

/* Deliberately smaller than the real formatter: it carries the specifiers the
   panic path uses, and an unknown one prints itself rather than being
   silently dropped, so a caller that needs more finds out by reading the
   output instead of wondering where its argument went. */
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
      sbi_putchar('%');
      sbi_putchar(*p);
    }
  }
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
