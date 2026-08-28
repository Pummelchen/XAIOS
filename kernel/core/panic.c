#include <stdarg.h>
#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/arch_cpu.h>
#include <xaios/panic.h>
#include <xaios/pmm.h>
#include <xaios/smp.h>

/*
 * Cyan Screen of Death — XAI OS kernel panic display.
 *
 * Uses ANSI escape codes for cyan background + white text over UART.
 * Dumps all GP/system registers and a stack backtrace, then halts
 * permanently (no auto-reboot) so the operator can read diagnostics.
 */

#define XAIOS_PANIC_MAX_STACK 16U

#if defined(__aarch64__)
/* System register encodings for AArch64 mrs (S<op0>_<op1>_<Cn>_<Cm>_<op2>) */
#define SYS_CurrentEL "s3_0_c4_c0_0"
#define SYS_ELR_EL1   "s3_0_c4_c0_1"
#define SYS_ESR_EL1   "s3_0_c5_c2_0"
#define SYS_FAR_EL1   "s3_0_c6_c0_0"
#define SYS_SPSR_EL1  "s3_0_c4_c0_0"
#define SYS_SP_EL0    "s3_0_c4_c1_0"
#endif

/* ---- helpers ---- */

static void panic_putc(char c) {
  klog_write(&c, 1);
}

static void panic_puts(const char *s) {
  klog_puts(s);
}

/* Direct hex/decimal output bypassing klog spinlock (safe in panic) */
static void panic_u64_hex_direct(uint64_t v) {
  const char *hex = "0123456789abcdef";
  char buf[17];
  unsigned idx = 0;
  for (int i = 60; i >= 0; i -= 4) {
    uint8_t digit = (uint8_t)((v >> i) & 0xF);
    if (digit != 0 || idx > 0 || i == 0) {
      buf[idx++] = hex[digit];
    }
  }
  if (idx == 0) buf[idx++] = '0';
  buf[idx] = '\0';
  panic_puts("0x");
  panic_puts(buf);
}

static void panic_u32_direct(unsigned v) {
  char buf[11];
  unsigned idx = 0;
  if (v == 0) {
    panic_putc('0');
    return;
  }
  while (v > 0 && idx < sizeof(buf) - 1) {
    buf[idx++] = '0' + (v % 10);
    v /= 10;
  }
  while (idx > 0) {
    panic_putc(buf[--idx]);
  }
}

static void panic_u64_direct(uint64_t v) {
  char buf[21];
  unsigned idx = 0;
  if (v == 0) {
    panic_putc('0');
    return;
  }
  while (v > 0 && idx < sizeof(buf) - 1) {
    buf[idx++] = '0' + (v % 10);
    v /= 10;
  }
  while (idx > 0) {
    panic_putc(buf[--idx]);
  }
}

static void panic_u64_hex(uint64_t v) {
  panic_u64_hex_direct(v);
}

static void panic_u32(unsigned v) {
  panic_u32_direct(v);
}

static int panic_valid_addr(uint64_t addr) {
#if defined(__x86_64__)
  return addr >= UINT64_C(0x1000) && (addr & 7U) == 0U;
#else
  /* Must be above typical peripheral space and page-aligned-ish */
  return addr >= UINT64_C(0x40000000) && (addr & 3U) == 0;
#endif
}

/* ---- register capture ---- */

static void capture_gp_regs(uint64_t *r) {
#if defined(__aarch64__)
  /* r[0..30] = x0..x30, r[31] = SP */
  __asm__ volatile(
    "stp x0,  x1,  [%[b], #0]\n"
    "stp x2,  x3,  [%[b], #16]\n"
    "stp x4,  x5,  [%[b], #32]\n"
    "stp x6,  x7,  [%[b], #48]\n"
    "stp x8,  x9,  [%[b], #64]\n"
    "stp x10, x11, [%[b], #80]\n"
    "stp x12, x13, [%[b], #96]\n"
    "stp x14, x15, [%[b], #112]\n"
    "stp x16, x17, [%[b], #128]\n"
    "stp x18, x19, [%[b], #144]\n"
    "stp x20, x21, [%[b], #160]\n"
    "stp x22, x23, [%[b], #176]\n"
    "stp x24, x25, [%[b], #192]\n"
    "stp x26, x27, [%[b], #208]\n"
    "stp x28, x29, [%[b], #224]\n"
    "str x30,      [%[b], #240]\n"
    "mov x9, sp\n"
    "str x9,       [%[b], #248]\n"
    :
    : [b] "r"(r)
    : "x9", "memory");
#elif defined(__x86_64__)
  for (uint32_t i = 0U; i < 32U; ++i) r[i] = 0U;
  __asm__ volatile("mov %%rax, %0" : "=m"(r[0]));
  __asm__ volatile("mov %%rbx, %0" : "=m"(r[1]));
  __asm__ volatile("mov %%rcx, %0" : "=m"(r[2]));
  __asm__ volatile("mov %%rdx, %0" : "=m"(r[3]));
  __asm__ volatile("mov %%rsi, %0" : "=m"(r[4]));
  __asm__ volatile("mov %%rdi, %0" : "=m"(r[5]));
  __asm__ volatile("mov %%rbp, %0" : "=m"(r[6]));
  __asm__ volatile("mov %%r8, %0" : "=m"(r[7]));
  __asm__ volatile("mov %%r9, %0" : "=m"(r[8]));
  __asm__ volatile("mov %%r10, %0" : "=m"(r[9]));
  __asm__ volatile("mov %%r11, %0" : "=m"(r[10]));
  __asm__ volatile("mov %%r12, %0" : "=m"(r[11]));
  __asm__ volatile("mov %%r13, %0" : "=m"(r[12]));
  __asm__ volatile("mov %%r14, %0" : "=m"(r[13]));
  __asm__ volatile("mov %%r15, %0" : "=m"(r[14]));
  __asm__ volatile("mov %%rsp, %0" : "=m"(r[31]));
#else
#error "Unsupported XAIOS panic architecture"
#endif
}

static void capture_sys_regs(uint64_t *elr, uint64_t *esr, uint64_t *far,
                              uint64_t *spsr, uint64_t *sp_el0,
                              uint64_t *current_el) {
#if defined(__aarch64__)
  __asm__ volatile(
    "mrs %[elr], " SYS_ELR_EL1 "\n"
    "mrs %[esr], " SYS_ESR_EL1 "\n"
    "mrs %[far], " SYS_FAR_EL1 "\n"
    "mrs %[spsr], " SYS_SPSR_EL1 "\n"
    "mrs %[sp0], " SYS_SP_EL0 "\n"
    "mrs %[cel], " SYS_CurrentEL "\n"
    : [elr] "=r"(*elr), [esr] "=r"(*esr), [far] "=r"(*far),
      [spsr] "=r"(*spsr), [sp0] "=r"(*sp_el0), [cel] "=r"(*current_el));
#elif defined(__x86_64__)
  *elr = (uint64_t)(uintptr_t)__builtin_return_address(0);
  *esr = 0U;
  __asm__ volatile("mov %%cr2, %0" : "=r"(*far));
  __asm__ volatile("pushfq; popq %0" : "=r"(*spsr));
  __asm__ volatile("mov %%rsp, %0" : "=r"(*sp_el0));
  *current_el = 0U;
#else
#error "Unsupported XAIOS panic architecture"
#endif
}

/* ---- stack backtrace via frame pointer ---- */

static uint32_t capture_backtrace(uint64_t *trace, uint32_t max_depth) {
  volatile uint64_t *fp =
      (volatile uint64_t *)__builtin_frame_address(0);
  uint32_t depth = 0;

  while (depth < max_depth) {
    uint64_t fp_val = (uint64_t)(uintptr_t)fp;
    if (!panic_valid_addr(fp_val)) {
      break;
    }
    /* fp[0] = previous FP, fp[1] = return address (LR) */
    uint64_t ret_addr = fp[1];
    if (ret_addr == 0) {
      break;
    }
    trace[depth++] = ret_addr;
    uint64_t prev_fp = fp[0];
    if (!panic_valid_addr(prev_fp) || prev_fp <= fp_val) {
      break; /* chain ended or going backwards */
    }
    fp = (volatile uint64_t *)(uintptr_t)prev_fp;
  }
  return depth;
}

/* ---- cyan screen rendering ---- */

static void render_banner(void) {
  /* ANSI: clear screen, cyan bg, white bold fg */
  panic_puts("\033[2J\033[H\033[37;46;1m");
  panic_puts("\r\n");
  panic_puts("  =====================================================\r\n");
  panic_puts("  =                                                  =\r\n");
  panic_puts("  =        XAI OS - CYAN SCREEN OF DEATH            =\r\n");
  panic_puts("  =                                                  =\r\n");
  panic_puts("  =====================================================\r\n");
  panic_puts("\r\n");
}

static void render_message(const char *file, int line, const char *fmt,
                            va_list args) {
  panic_puts("  ERROR: ");
  /* Inline format: %s, %u, %lu, %lx, %x only — direct output, no klog lock */
  for (const char *p = fmt; *p != '\0'; ++p) {
    if (*p == '%' && p[1] == 's') {
      ++p;
      const char *s = va_arg(args, const char *);
      panic_puts(s ? s : "(null)");
    } else if (*p == '%' && p[1] == 'u') {
      ++p;
      panic_u32(va_arg(args, unsigned));
    } else if (*p == '%' && p[1] == 'l' && p[2] == 'u') {
      p += 2;
      panic_u64_direct(va_arg(args, uint64_t));
    } else if (*p == '%' && p[1] == 'l' && p[2] == 'x') {
      p += 2;
      panic_u64_hex(va_arg(args, uint64_t));
    } else if (*p == '%' && p[1] == 'x') {
      ++p;
      panic_u64_hex(va_arg(args, unsigned));
    } else {
      panic_putc(*p);
    }
  }
  panic_puts("\r\n");
  panic_puts("  File:  ");
  panic_puts(file);
  panic_puts("\r\n  Line:  ");
  panic_u32((unsigned)line);
  panic_puts("\r\n\r\n");
}

static void render_cpu_info(void) {
  panic_puts("  --- CPU ---\r\n");
  panic_puts("  CPU ID:    ");
  panic_u32(smp_cpu_id());
  panic_puts("\r\n  Online:    ");
  panic_u32(smp_online_count());
  panic_puts(" cores\r\n");
  panic_puts("  Free RAM:  ");
  panic_u64_direct(pmm_free_pages() * UINT64_C(4096));
  panic_puts(" bytes\r\n");
  panic_puts("  Total RAM: ");
  panic_u64_direct(pmm_total_pages() * UINT64_C(4096));
  panic_puts(" bytes\r\n\r\n");
}

static void render_gp_regs(const uint64_t *r) {
  panic_puts("  --- General Purpose Registers ---\r\n");
#if defined(__x86_64__)
  static const char *names[] = {"RAX", "RBX", "RCX", "RDX", "RSI",
                                "RDI", "RBP", "R8 ", "R9 ", "R10",
                                "R11", "R12", "R13", "R14", "R15"};
  for (uint32_t i = 0U; i < 15U; ++i) {
    panic_puts("  ");
    panic_puts(names[i]);
    panic_puts(" = ");
    panic_u64_hex(r[i]);
    panic_puts("\r\n");
  }
#else
  for (uint32_t i = 0; i < 31; i += 2) {
    panic_puts("  x");
    panic_u32(i);
    if (i < 10) {
      panic_putc(' ');
    }
    panic_puts(" = ");
    panic_u64_hex(r[i]);
    panic_puts("  x");
    panic_u32(i + 1);
    if (i + 1 < 10) {
      panic_putc(' ');
    }
    panic_puts(" = ");
    panic_u64_hex(r[i + 1]);
    panic_puts("\r\n");
  }
#endif
  panic_puts("  SP   = ");
  panic_u64_hex(r[31]);
  panic_puts("\r\n\r\n");
}

static void render_sys_regs(uint64_t elr, uint64_t esr, uint64_t far,
                              uint64_t spsr, uint64_t sp_el0,
                              uint64_t current_el) {
  panic_puts("  --- System Registers ---\r\n");
#if defined(__x86_64__)
  (void)esr;
  (void)current_el;
  panic_puts("  RIP      = ");
  panic_u64_hex(elr);
  panic_puts("\r\n  CR2      = ");
  panic_u64_hex(far);
  panic_puts("\r\n  RFLAGS   = ");
  panic_u64_hex(spsr);
  panic_puts("\r\n  RSP      = ");
  panic_u64_hex(sp_el0);
  panic_puts("\r\n\r\n");
#else
  panic_puts("  ELR_EL1  = ");
  panic_u64_hex(elr);
  panic_puts("\r\n  ESR_EL1  = ");
  panic_u64_hex(esr);
  panic_puts("\r\n  FAR_EL1  = ");
  panic_u64_hex(far);
  panic_puts("\r\n  SPSR_EL1 = ");
  panic_u64_hex(spsr);
  panic_puts("\r\n  SP_EL0   = ");
  panic_u64_hex(sp_el0);
  panic_puts("\r\n  CurrentEL= ");
  panic_u64_hex(current_el >> 2U);
  panic_puts(" (EL");
  panic_u32((unsigned)(current_el >> 2U));
  panic_puts(")\r\n\r\n");
#endif
}

extern char __kernel_start[];

static void render_backtrace(const uint64_t *trace, uint32_t depth) {
  panic_puts("  --- Stack Backtrace ---\r\n");
  /* Where this kernel was loaded, printed with the addresses rather than left
     to be found elsewhere. The kernel is position-independent and the loader
     places it wherever the machine has room, so the same build lands at a
     different address every boot and a bare address means nothing without
     this. An intermittent fault on VMware Fusion was recorded exactly once,
     as fifteen addresses and no base, and could not be turned back into
     function names at all. Subtract this from an address and give the result
     to llvm-symbolizer against kernel.elf. */
  panic_puts("  load base ");
  panic_u64_hex((uint64_t)(uintptr_t)__kernel_start);
  panic_puts("  (subtract from the addresses below)\r\n");
  for (uint32_t i = 0; i < depth; ++i) {
    panic_puts("  #");
    panic_u32(i);
    panic_puts("  ");
    panic_u64_hex(trace[i]);
    panic_puts("\r\n");
  }
  panic_puts("\r\n");
}

/* The last thing the kernel said before it died.

   Subsystems log why they fail, but a normal boot redraws the progress
   display over the serial console, so on a non-verbose boot that explanation
   is cleared off the screen a moment before the panic replaces it. Registers
   and a backtrace then describe where the assertion fired without ever
   saying what it found. Replaying the ring here keeps the reason attached to
   the failure, which is what makes a rare boot panic diagnosable at all. */
#define XAIOS_PANIC_LOG_BYTES 1536U

static void render_recent_log(void) {
  static char tail[XAIOS_PANIC_LOG_BYTES];
  uint32_t used = klog_ring_panic_tail(tail, sizeof(tail));
  uint32_t start = 0U;
  if (used == 0U) return;
  panic_puts("\r\n  --- Recent Kernel Log ---\r\n");
  /* The first line is usually cut mid-way by the tail boundary; drop it so
     the replay starts on a real line. */
  while (start < used && tail[start] != '\n') ++start;
  if (start < used) ++start;
  if (start >= used) start = 0U;
  panic_puts("  ");
  for (uint32_t i = start; i < used; ++i) {
    char c = tail[i];
    if (c == '\n') {
      panic_puts("\r\n  ");
    } else if (c == '\r') {
      continue;
    } else if (c >= 0x20 && c < 0x7f) {
      panic_putc(c);
    }
  }
  panic_puts("\r\n");
}

static void render_halt(void) {
  panic_puts("  System halted. Manual reset required.\r\n");
  panic_puts("  =====================================================\r\n");
  /* Reset ANSI colors */
  panic_puts("\033[0m\r\n");
}

/* ---- main panic entry ---- */

void panic_at(const char *file, int line, const char *fmt, ...) {
  /* Disable all interrupts immediately */
#if defined(__aarch64__)
  __asm__ volatile("msr daifset, #0xf" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("cli" ::: "memory");
#endif

  /* Boot progress intentionally suppresses ordinary logs. Fatal diagnostics
   * must always reach the console, including before userspace is available. */
  klog_console_set_log_output(1U);

  /* Capture GP registers */
  uint64_t gp_regs[32];
  capture_gp_regs(gp_regs);

  /* Capture system registers */
  uint64_t elr = 0, esr = 0, far = 0, spsr = 0, sp_el0 = 0, current_el = 0;
  capture_sys_regs(&elr, &esr, &far, &spsr, &sp_el0, &current_el);

  /* Capture stack backtrace */
  uint64_t stack_trace[XAIOS_PANIC_MAX_STACK];
  uint32_t trace_depth = capture_backtrace(stack_trace, XAIOS_PANIC_MAX_STACK);

  /* Render cyan screen */
  render_banner();

  va_list args;
  va_start(args, fmt);
  render_message(file, line, fmt, args);
  va_end(args);

  render_cpu_info();
  render_gp_regs(gp_regs);
  render_sys_regs(elr, esr, far, spsr, sp_el0, current_el);
  render_backtrace(stack_trace, trace_depth);
  render_recent_log();
  render_halt();

  /* Halt forever — no auto-reboot so the operator can read diagnostics */
  for (;;) xaios_cpu_wait();
}
