#include <stdarg.h>
#include <xaios/klog.h>
#include <xaios/arch_cpu.h>
#include <xaios/panic.h>

#include "panic_internal.h"

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
#elif defined(__riscv)
  /* Every general-purpose register with an ABI name, in the order the renderer
     prints them -- ra, sp, gp, tp, t0-t2, s0-s1, a0-a7, s2-s11, t3-t6.
     RISC-V has no instruction that spills them as a block, so each is stored
     individually, and all thirty-one are stored because a fault report that
     leaves some out invites a reader to believe a value it does not have.
     (`x0` is not stored: it is hardwired zero and nothing can change that.) */
  __asm__ volatile("sd ra,   0(%0)\n\t"
                   "sd sp,   8(%0)\n\t"
                   "sd gp,  16(%0)\n\t"
                   "sd tp,  24(%0)\n\t"
                   "sd t0,  32(%0)\n\t"
                   "sd t1,  40(%0)\n\t"
                   "sd t2,  48(%0)\n\t"
                   "sd s0,  56(%0)\n\t"
                   "sd s1,  64(%0)\n\t"
                   "sd a0,  72(%0)\n\t"
                   "sd a1,  80(%0)\n\t"
                   "sd a2,  88(%0)\n\t"
                   "sd a3,  96(%0)\n\t"
                   "sd a4, 104(%0)\n\t"
                   "sd a5, 112(%0)\n\t"
                   "sd a6, 120(%0)\n\t"
                   "sd a7, 128(%0)\n\t"
                   "sd s2, 136(%0)\n\t"
                   "sd s3, 144(%0)\n\t"
                   "sd s4, 152(%0)\n\t"
                   "sd s5, 160(%0)\n\t"
                   "sd s6, 168(%0)\n\t"
                   "sd s7, 176(%0)\n\t"
                   "sd s8, 184(%0)\n\t"
                   "sd s9, 192(%0)\n\t"
                   "sd s10, 200(%0)\n\t"
                   "sd s11, 208(%0)\n\t"
                   "sd t3, 216(%0)\n\t"
                   "sd t4, 224(%0)\n\t"
                   "sd t5, 232(%0)\n\t"
                   "sd t6, 240(%0)"
                   :
                   : "r"(r)
                   : "memory");
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
#elif defined(__riscv)
  /* The supervisor CSRs that carry the same meaning under different names:
     sepc is where the fault happened, scause why, stval the address or value
     it faulted on, and sstatus the mode it happened in. Mapped onto the
     AArch64 names the renderer already prints, because inventing a fourth
     vocabulary for the same four facts would help nobody reading a panic. */
  __asm__ volatile("csrr %0, sepc" : "=r"(*elr));
  __asm__ volatile("csrr %0, scause" : "=r"(*esr));
  __asm__ volatile("csrr %0, stval" : "=r"(*far));
  __asm__ volatile("csrr %0, sstatus" : "=r"(*spsr));
  __asm__ volatile("mv %0, sp" : "=r"(*sp_el0));
  /* Supervisor mode, which is the only mode this kernel runs in. */
  *current_el = 1U;
#else
#error "Unsupported XAIOS panic architecture"
#endif
}

/* ---- stack backtrace via frame pointer ---- */

/* A frame chain is followed only while it stays on the stack it started on.
   A kernel stack is small, so anything more than this far above the first
   frame is not a frame: a trap frame's saved register was written by a user
   program, and following it into user memory took a second fault inside the
   panic handler, which replaced the message about the first fault with one
   about the handler. The address-range test below cannot tell the two apart
   on its own, because user stacks sit at addresses the kernel also uses. */
#define PANIC_BACKTRACE_STACK_SPAN UINT64_C(0x100000)

static uint32_t capture_backtrace(uint64_t *trace, uint32_t max_depth) {
  volatile uint64_t *fp =
      (volatile uint64_t *)__builtin_frame_address(0);
  uint64_t stack_base = (uint64_t)(uintptr_t)fp;
  uint32_t depth = 0;

  while (depth < max_depth) {
    uint64_t fp_val = (uint64_t)(uintptr_t)fp;
    if (!panic_valid_addr(fp_val) || fp_val < stack_base ||
        fp_val - stack_base > PANIC_BACKTRACE_STACK_SPAN) {
      break;
    }
    /* Where the two words are depends on the architecture, and getting it
       wrong is not a wrong backtrace -- it is a second fault inside the panic
       handler, which replaces the message that was about to be printed with
       one about the handler. That is the worst possible time to lose a
       diagnostic, and it is exactly what happened here.

       AArch64 and x86-64 point the frame pointer at the saved pair, so the
       previous frame is at [0] and the return address at [1]. RISC-V points
       it just above the frame instead: the return address is at [-1] and the
       previous frame pointer at [-2]. */
#if defined(__riscv)
    if (!panic_valid_addr(fp_val - 16U)) {
      break;
    }
    uint64_t ret_addr = fp[-1];
    uint64_t prev_fp = fp[-2];
#else
    uint64_t ret_addr = fp[1];
    uint64_t prev_fp = fp[0];
#endif
    if (ret_addr == 0) {
      break;
    }
    trace[depth++] = ret_addr;
    if (!panic_valid_addr(prev_fp) || prev_fp <= fp_val) {
      break; /* chain ended or going backwards */
    }
    fp = (volatile uint64_t *)(uintptr_t)prev_fp;
  }
  return depth;
}

/* ---- main panic entry ---- */

void panic_at(const char *file, int line, const char *fmt, ...) {
  /* Disable all interrupts immediately */
#if defined(__aarch64__)
  __asm__ volatile("msr daifset, #0xf" ::: "memory");
#elif defined(__x86_64__)
  __asm__ volatile("cli" ::: "memory");
#elif defined(__riscv)
  /* This branch was missing, so a RISC-V panic kept taking interrupts while it
     dumped -- every other port stops them here. Clearing SIE covers the timer,
     an IPI and an external interrupt at once. */
  __asm__ volatile("csrci sstatus, 2" ::: "memory");
#endif

  /* Claim the console before the first character goes out.
   *
   * The dump below writes around the log lock on purpose, and every other hart
   * writes through it, so without this the two streams interleave a byte at a
   * time and the dump arrives unreadable -- which is what happened to the first
   * RISC-V panic taken from a running system, where `System halted` came out
   * inside a `user: rejected syscall=11` line. Output the other harts ask for
   * is dropped from here on, and the dump says how much. */
  /* One dump per console. A hart that panics while another dump is already
     running does not print: two dumps on one console interleave a character at
     a time and neither can be read, which is what happened on the first
     RISC-V boot failure where two CPUs took a controlled page fault together
     (B-110). Its death is counted and the running dump reports it, so it is
     deferred rather than hidden. */
  if (klog_console_panic_claim() == 0) {
    for (;;) xaios_cpu_wait();
  }

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
  panic_render_banner();

  va_list args;
  va_start(args, fmt);
  panic_render_message(file, line, fmt, args);
  va_end(args);

  panic_render_cpu_info();
  panic_render_gp_regs(gp_regs);
  panic_render_sys_regs(elr, esr, far, spsr, sp_el0, current_el);
  panic_render_backtrace(stack_trace, trace_depth);
  panic_render_recent_log();
  panic_render_halt();

  /* Halt forever — no auto-reboot so the operator can read diagnostics */
  for (;;) xaios_cpu_wait();
}
