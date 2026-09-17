/* Private interface shared by exception.c, exception_frame.c and
 * exception_selftest.c.
 *
 * exception.c keeps the vector: the trap handler, the interrupt-controller
 * discovery and dispatch, and the boot self-test. The trap frame's decoding
 * side -- the cause names, the two deliberate-fault probes, the instruction
 * width and the mapping between this port's frame and the shared
 * xaios_context_frame_t -- moved into exception_frame.c, and the preemption
 * self-test that measures that mapping into exception_selftest.c. The split is
 * a size split only: the frame layout, the register order entry.S stores in
 * and the trap decoding are unchanged, so the panic register output the boot
 * and fault gates read is unchanged too.
 *
 * Everything the three files share is declared here once and defined once.
 * State stays behind functions -- no accessor hands out a pointer into another
 * file's mutable file-scope data -- and every name crossing a translation unit
 * carries the riscv64_ prefix.
 */
#ifndef XAIOS_ARCH_RISCV64_EXCEPTION_INTERNAL_H
#define XAIOS_ARCH_RISCV64_EXCEPTION_INTERNAL_H

#include <xaios/types.h>

/* Declared here rather than taken from xaios/klog.h, which carries a printf
   format attribute: this is the declaration exception.c has always used, moved
   so that the split files share one copy of it. */
void klog(const char *fmt, ...);

/* The register frame the trap stub builds, in the order it stores them. */
typedef struct riscv64_trap_frame {
  uint64_t ra, sp, gp, tp;
  uint64_t t0, t1, t2;
  uint64_t s0, s1;
  uint64_t a0, a1, a2, a3, a4, a5, a6, a7;
  uint64_t s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;
  uint64_t t3, t4, t5, t6;
  uint64_t sepc, scause, stval, sstatus;
  /* The kernel stack this context's next trap from user mode lands on, which
     the stub writes at entry and the trap return re-arms `sscratch` from. A
     field rather than arithmetic, because it is the one value a context switch
     has to carry for the incoming task (`B-132`). */
  uint64_t kernel_sp;
  /* The floating-point registers and control/status word, saved by the stub on
     every trap and restored on the way out. They travel with the context
     because a switched-to task has to resume with its own -- two preempted
     processes sharing one set is a wrong answer with no symptom until the
     numbers matter. The stub reserves 560 bytes, so the eight bytes of padding
     after `fcsr` are its own. */
  uint64_t fp[32];
  uint64_t fcsr;
} riscv64_trap_frame_t;

#define SSTATUS_SPP (UINT64_C(1) << 8)
/* Supervisor previous interrupt enable: what SIE becomes after `sret`, and
   the only way a frame can say "resume in the kernel with interrupts on". */
#define SSTATUS_SPIE (UINT64_C(1) << 5)
/* `sstatus.FS` bits 13:14: value 1 is Initial, which is "this context may
   use the floating-point unit". */
#define SSTATUS_FS_INITIAL (UINT64_C(1) << 13)
#define SSTATUS_SUM (UINT64_C(1) << 18)

#define CAUSE_ECALL_FROM_USER 8U
#define CAUSE_BREAKPOINT 3U
#define CAUSE_ILLEGAL_INSTRUCTION 2U
#define CAUSE_LOAD_ACCESS_FAULT 5U
#define CAUSE_STORE_ACCESS_FAULT 7U
#define CAUSE_INSTRUCTION_PAGE_FAULT 12U
#define CAUSE_LOAD_PAGE_FAULT 13U
#define CAUSE_STORE_PAGE_FAULT 15U

/* The scheduler tick the trap handler applies to an interrupted frame. It and
   the frame-mapping self-test live in exception_frame.c. */
void riscv64_scheduler_tick(riscv64_trap_frame_t *frame);

/* The supervisor user-page window. begin/end are the production pair the
   syscall path opens; suspend/resume are what the trap handler uses around a
   fault taken from user mode, so that no pointer to the per-hart depth escapes
   exception_frame.c. */
void xaios_user_access_begin(void);
void xaios_user_access_end(void);
void riscv64_user_access_suspend(void);
void riscv64_user_access_resume(void);

/* The two deliberate-fault probes, which the trap handler asks before it
   decides a synchronous exception is fatal. Their flags live in
   exception_frame.c; these read and set them on the caller's behalf, in the
   order the handler used to touch them. The exception_page_probe_* entry
   points are declared in mmu_shootdown.h, where their caller looks. */
int riscv64_mmio_probe_in_progress(void);
void riscv64_mmio_probe_note_fault(void);
int riscv64_page_probe_handle_fault(uint32_t cpu);

/* Trap decoding helpers, now in exception_frame.c. */
uint64_t riscv64_instruction_width(uint64_t pc);
const char *riscv64_trap_cause_name(uint64_t cause);

#endif /* XAIOS_ARCH_RISCV64_EXCEPTION_INTERNAL_H */
