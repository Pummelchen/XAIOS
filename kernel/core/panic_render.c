/*
 * Cyan Screen of Death — XAI OS panic rendering.
 *
 * The output half of the panic handler: the banner, the formatted message,
 * the CPU, general-purpose-register, system-register, backtrace, recent-log
 * and halt reports, together with the direct hex/decimal writers that bypass
 * the log spinlock because a panic may hold it.
 *
 * Every field and its order is moved here verbatim from panic.c. The panic
 * output is parsed by tests/scripts/resolve-panic.py and matched by the fault
 * gates, so the rendering must not change: only the entry points gain the
 * `panic_render_' prefix, and the writers stay static because nothing outside
 * this file calls them.
 */
#include <stdarg.h>
#include <stdint.h>

#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/pmm.h>
#include <xaios/smp.h>

#include "panic_internal.h"

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

/* ---- cyan screen rendering ---- */

void panic_render_banner(void) {
  /* ANSI: cyan bg and white bold fg first, then clear.
   *
   * The order is the point. Erase-in-display fills with whatever background
   * is selected at the time, so clearing before choosing cyan paints the
   * screen in the old colour and leaves cyan behind the characters only --
   * which is what a terminal shows when it honours background codes at all.
   * Selecting first makes the whole screen cyan, on a framebuffer console and
   * over a serial line alike. */
  panic_puts("\033[37;46;1m\033[2J\033[H");
  panic_puts("\r\n");
  panic_puts("  =====================================================\r\n");
  panic_puts("  =                                                  =\r\n");
  panic_puts("  =        XAI OS - CYAN SCREEN OF DEATH            =\r\n");
  panic_puts("  =                                                  =\r\n");
  panic_puts("  =====================================================\r\n");
  panic_puts("\r\n");
}

void panic_render_message(const char *file, int line, const char *fmt,
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

void panic_render_cpu_info(void) {
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

void panic_render_gp_regs(const uint64_t *r) {
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
  /* This port's capture stores rsp in r[31] after zeroing the rest, so the
     line is real here. It used to be printed after the `#endif`, which made it
     look shared while only some of the branches filled the slot. */
  panic_puts("  RSP  = ");
  panic_u64_hex(r[31]);
  panic_puts("\r\n\r\n");
#elif defined(__riscv)
  /* By ABI name, in the order the capture stores them.
   *
   * This used to fall through to the AArch64 branch below, which prints
   * r[0..30] as "x0".."x30" and r[31] as "SP". The two captures do not agree:
   * AArch64 stores x0..x30 then SP, while this port stores ra, sp, gp, tp and
   * on in ABI order -- so on RISC-V every label named a different register than
   * the value printed under it, ten of the lines were never written at all,
   * and the "SP" line printed whatever happened to be on the stack. A fault
   * report that misnames its registers is worse than one that prints fewer:
   * the `sp` a reader needs is in here, and this defect is why a session's
   * worth of diagnosis went after "a stack pointer of zero" that was in fact
   * the `gp` register (B-111). */
  static const char *names[] = {"ra ", "sp ", "gp ", "tp ", "t0 ", "t1 ",
                                "t2 ", "s0 ", "s1 ", "a0 ", "a1 ", "a2 ",
                                "a3 ", "a4 ", "a5 ", "a6 ", "a7 ", "s2 ",
                                "s3 ", "s4 ", "s5 ", "s6 ", "s7 ", "s8 ",
                                "s9 ", "s10", "s11", "t3 ", "t4 ", "t5 ",
                                "t6 "};
  for (uint32_t i = 0U; i < 31U; ++i) {
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
  /* AArch64 puts the stack pointer in r[31]; RISC-V prints it in the list above,
     as `sp`, which is what a reader of that port looks for, and x86-64 prints
     `RSP` in its own branch. A shared line after the `#endif` was what let two
     of the three branches print a slot they never filled. */
  panic_puts("  SP   = ");
  panic_u64_hex(r[31]);
  panic_puts("\r\n\r\n");
#endif
}

void panic_render_sys_regs(uint64_t elr, uint64_t esr, uint64_t far,
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
#elif defined(__aarch64__)
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
#else
  /* RISC-V, under its own names.
   *
   * `capture_sys_regs` fills these same six slots from sepc, scause, stval and
   * sstatus, which are what carry the same four facts here. This branch used to
   * be the `#else` of the x86_64 test, so a RISC-V panic printed the AArch64
   * names -- and that is not a cosmetic complaint, because
   * `tests/scripts/resolve-panic.py` reads those labels to work out which
   * machine produced a panic. It therefore identified a RISC-V panic as
   * AArch64: it refused to resolve against the RISC-V kernel that had actually
   * produced it, and would have accepted an AArch64 kernel and printed
   * confident nonsense from the wrong symbol table.
   *
   * The privilege line is deliberately absent rather than translated.
   * `CurrentEL` above is AArch64's encoding, where the mode sits in bits [3:2]
   * of the register; this port passed the constant 1 for "supervisor", which
   * the same renderer shifted right by two and printed as `(EL0)` on every
   * RISC-V panic ever taken in the kernel. A wrong privilege level in a fault
   * report is worse than no line, so `sstatus` is printed and left to be read:
   * its SPP bit says which mode a trap came from, and it says nothing at all
   * about a panic that was not reached through a trap. */
  (void)current_el;
  panic_puts("  sepc     = ");
  panic_u64_hex(elr);
  panic_puts("\r\n  scause   = ");
  panic_u64_hex(esr);
  panic_puts("\r\n  stval    = ");
  panic_u64_hex(far);
  panic_puts("\r\n  sstatus  = ");
  panic_u64_hex(spsr);
  panic_puts("\r\n  sp       = ");
  panic_u64_hex(sp_el0);
  panic_puts("\r\n\r\n");
#endif
}

extern char __kernel_start[];
extern char __kernel_end[];

void panic_render_backtrace(const uint64_t *trace, uint32_t depth) {
  panic_puts("  --- Stack Backtrace ---\r\n");
  /* Where this kernel was loaded, printed with the addresses rather than left
     to be found elsewhere. The kernel is position-independent and the loader
     places it wherever the machine has room, so the same build lands at a
     different address every boot and a bare address means nothing without
     this. An intermittent fault on VMware Fusion was recorded exactly once,
     as fifteen addresses and no base, and could not be turned back into
     function names at all.

     This used to say "subtract from the addresses below" and to name
     llvm-symbolizer, and both halves were wrong -- which was found by
     causing a panic and following the instruction, not by reading it.
     Subtracting alone gives an offset from the start of the image, while
     kernel.elf is linked at 0x90000000, so the result lands nowhere. And
     the kernel is built without DWARF, so llvm-symbolizer answers "??" even
     when handed the right address. The one operation that works is
     runtime - load_base + link_base, resolved against the ELF symbol table.
     Rather than ask an operator to know that, the line below names the
     script that does it. */
  panic_puts("  load base ");
  panic_u64_hex((uint64_t)(uintptr_t)__kernel_start);
  panic_puts("\r\n  resolve with: tests/scripts/resolve-panic.py "
             "(paste this panic on stdin)\r\n");
  /* Stop at the first frame that is not in this kernel.
     A frame-pointer walk that leaves the kernel stack does not find the
     caller, it finds whatever words are lying there. On Fusion that is
     firmware memory, and a deliberate assertion in kmain produced sixteen
     frames of which two were real and fourteen were residue -- printed with
     the same formatting and the same authority as the two that meant
     something. The one recorded occurrence of B-15 was fifteen addresses,
     which is what that looks like when nobody can tell which is which.
     The count of what was dropped is printed, because silently showing two
     frames where sixteen were captured would be its own kind of lie. */
  uint64_t low = (uint64_t)(uintptr_t)__kernel_start;
  uint64_t high = (uint64_t)(uintptr_t)__kernel_end;
  uint32_t shown = 0;
  for (uint32_t i = 0; i < depth; ++i) {
    if (trace[i] < low || trace[i] >= high) break;
    panic_puts("  #");
    panic_u32(i);
    panic_puts("  ");
    panic_u64_hex(trace[i]);
    panic_puts("\r\n");
    ++shown;
  }
  if (shown < depth) {
    panic_puts("  (");
    panic_u32(depth - shown);
    panic_puts(" further frames captured, outside this kernel: stack residue "
               "past the end of the call chain, not callers)\r\n");
  }
  if (shown == 0) {
    panic_puts("  (no frame was inside this kernel: the frame pointer was "
               "not usable here)\r\n");
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

void panic_render_recent_log(void) {
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

void panic_render_halt(void) {
  /* Said rather than left out: the dump above is complete, but the machine's
     other harts were told to stop printing while it ran, and a reader comparing
     this console against one from a healthy boot needs to know that. */
  uint64_t dropped = klog_console_panic_dropped();
  if (dropped != 0U) {
    panic_puts("  console claimed: ");
    panic_u32((unsigned)dropped);
    panic_puts(" log writes from other harts suppressed\r\n");
  }
  uint64_t other = klog_console_panic_other();
  if (other != 0U) {
    panic_puts("  console claimed: ");
    panic_u32((unsigned)other);
    panic_puts(" further harts panicked while this dump ran and were not "
               "printed\r\n");
  }
  panic_puts("  System halted. Manual reset required.\r\n");
  panic_puts("  =====================================================\r\n");
  /* Reset ANSI colors */
  panic_puts("\033[0m\r\n");
}
