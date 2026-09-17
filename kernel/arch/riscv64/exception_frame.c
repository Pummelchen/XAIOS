/* The trap frame's decoding side: what a trap was, the probes that fault on
 * purpose, and the mapping between this port's frame and the scheduler's.
 *
 * This was the middle of exception.c, moved here whole to keep that file
 * inside the repository's 500-line limit; exception.c keeps the vector, the
 * interrupt controller and the trap handler itself. Nothing about the frame
 * changed: the layout entry.S stores into, the order of the registers and
 * every decoded value are exactly as they were, because the panic register
 * output the boot and fault gates read comes from them. The names that now
 * cross a translation unit carry the riscv64_ prefix, and the user-page window
 * exposes suspend/resume calls rather than a depth pointer, which is the only
 * structural change.
 *
 * The shared declarations are in exception_internal.h; the page probe's entry
 * points are declared in mmu_shootdown.h, where the TLB shootdown test that
 * calls them already looks, and the MMIO probe's in xaios/exception.h.
 */
#include "exception_internal.h"

#include <xaios/assert.h>
#include <xaios/exception.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/timer.h>

#include "mmu_shootdown.h"

/* Supervisor access to user pages, opened only where it is meant to be used.
 *
 * SUM was set once at startup and left on for the whole life of the kernel,
 * which made a stray dereference of a user pointer anywhere in the kernel a
 * silent success. AArch64 does the opposite with PAN: privileged access to
 * user memory is refused by default and opened explicitly around the places
 * that copy, with a depth counter so nested opens close correctly.
 *
 * The same shape here, in the place that matters most. Kernel-initiated
 * access -- loading an ELF, setting up a process -- runs with SUM set,
 * because the kernel is acting for itself and knows the address is one it
 * just mapped. Kernel code running *on behalf of a user*, which is where an
 * unvalidated pointer would be dereferenced, runs with SUM clear and has to
 * open a window to touch anything. That is the case PAN exists for.
 *
 * The frame's sstatus is restored on the way out, so the kernel's own default
 * comes back without anyone having to put it back.
 *
 * The depth is per hart, because sstatus is per hart. It was one counter
 * shared by every hart, and four harts running syscalls interleaved their
 * increments and decrements on it: a hart's inner `end` could find the count
 * at zero because another hart had just decremented, and clear its own SUM
 * while its outer syscall was still inside a user buffer. That only bites
 * when one hart nests -- a syscall that runs a transient child, whose exit
 * ecall is the nested window -- which is why every ordinary syscall worked
 * and the first on-demand application launched over SSH faulted the kernel
 * on the first byte it wrote back to the caller. */
#define USER_ACCESS_MAX_HARTS 64U
static uint32_t g_user_access_depth[USER_ACCESS_MAX_HARTS];

static uint32_t *user_access_depth(void) {
  uint32_t cpu = smp_cpu_id();
  if (cpu >= USER_ACCESS_MAX_HARTS) cpu = USER_ACCESS_MAX_HARTS - 1U;
  return &g_user_access_depth[cpu];
}

void xaios_user_access_begin(void) {
  uint32_t *depth = user_access_depth();
  if (*depth == UINT32_MAX) return;
  ++*depth;
  __asm__ volatile("csrs sstatus, %0" : : "r"(SSTATUS_SUM) : "memory");
}

void xaios_user_access_end(void) {
  uint32_t *depth = user_access_depth();
  if (*depth == 0U) return;
  if (--*depth == 0U) {
    __asm__ volatile("csrc sstatus, %0" : : "r"(SSTATUS_SUM) : "memory");
  }
}

/* Close the user-page window for the duration of handling a fault taken from
 * user mode, and reopen it only if the per-hart depth counter says the
 * enclosing syscall had it open.
 *
 * exception.c's trap handler used to take the depth pointer and touch the live
 * CSR itself. The depth is per hart and lives here, so the pair is a call each
 * and no pointer to this file's state escapes. The order is unchanged: the
 * window closes before the fault is logged and reopens after the process has
 * been noted, with the counter read at exactly the point the handler used to
 * dereference it.
 */
void riscv64_user_access_suspend(void) {
  __asm__ volatile("csrc sstatus, %0" : : "r"(SSTATUS_SUM) : "memory");
}

void riscv64_user_access_resume(void) {
  if (*user_access_depth() != 0U) {
    __asm__ volatile("csrs sstatus, %0" : : "r"(SSTATUS_SUM) : "memory");
  }
}

/* What a trap was, in words.
 *
 * The number alone is not enough for a gate to hold this architecture to
 * anything: "the kernel panicked" is true of a machine that faulted the way
 * it was asked to and of one that fell over for an unrelated reason. AArch64
 * prints an exception class name for exactly this, and the fault matrix
 * asserts it. These are the names for the same purpose -- a store to
 * read-only memory has to report a store page fault and not a load one, or
 * the page tables are not doing what the boot said they were. */
const char *riscv64_trap_cause_name(uint64_t cause) {
  switch (cause) {
    case 0U: return "instruction-address-misaligned";
    case 1U: return "instruction-access-fault";
    case CAUSE_ILLEGAL_INSTRUCTION: return "illegal-instruction";
    case CAUSE_BREAKPOINT: return "breakpoint";
    case 4U: return "load-address-misaligned";
    case CAUSE_LOAD_ACCESS_FAULT: return "load-access-fault";
    case 6U: return "store-address-misaligned";
    case CAUSE_STORE_ACCESS_FAULT: return "store-access-fault";
    case CAUSE_ECALL_FROM_USER: return "ecall-from-user";
    case 9U: return "ecall-from-supervisor";
    case CAUSE_INSTRUCTION_PAGE_FAULT: return "instruction-page-fault";
    case CAUSE_LOAD_PAGE_FAULT: return "load-page-fault";
    case CAUSE_STORE_PAGE_FAULT: return "store-page-fault";
    default: return "unknown";
  }
}

/* A read of an address nothing is mapped at, on purpose.
 *
 * The counterpart of AArch64's exception_trigger_page_fault_for_test: the
 * fault matrix builds a kernel that ends its boot by faulting in a stated
 * way, and requires the machine to report that way rather than any other.
 * The address is above everything this port maps and below the top of Sv48's
 * user half, so it is a translation failure rather than a malformed address
 * -- which would be a different trap and would prove something else. */
void exception_trigger_page_fault_for_test(void) {
  volatile uint64_t *unmapped = (volatile uint64_t *)UINT64_C(0x1000000000);
  klog("exceptions: triggering controlled page fault at 0x%lx\n",
       (uint64_t)(uintptr_t)unmapped);
  (void)*unmapped;
}

/* Probing for a device that may not be there.
 *
 * Reading configuration space at an address nothing answers is a fault on
 * this architecture, not a read of all-ones, so the shared "did that come
 * back as 0xffffffff" test cannot tell an absent host bridge from a present
 * one. AArch64 solved the same problem the same way for its IOMMU probe.
 * Between begin and end, an access fault sets the flag and steps over the
 * instruction instead of killing the machine.
 *
 * Illegal instruction counts too, because the same question gets asked about
 * optional CSRs: reading one the hardware does not implement traps exactly
 * like this, and asking is the only way to find out. */
static volatile int g_mmio_probe_active;
static volatile int g_mmio_probe_faulted;

void exception_mmio_probe_begin(void) {
  g_mmio_probe_faulted = 0;
  g_mmio_probe_active = 1;
}

void exception_mmio_probe_end(void) { g_mmio_probe_active = 0; }

int exception_mmio_probe_faulted(void) { return g_mmio_probe_faulted; }

/* The trap handler asks whether a probe is in progress before it decides a
   synchronous exception is fatal, and records the fault through a second call
   rather than reading the flags across translation units: the order the
   handler has always used -- active flag first, then the cause -- is kept. */
int riscv64_mmio_probe_in_progress(void) { return g_mmio_probe_active != 0; }

void riscv64_mmio_probe_note_fault(void) { g_mmio_probe_faulted = 1; }

/* A page fault the kernel went looking for, on whichever hart went looking.
 *
 * The MMIO probe above is one global pair of flags, which is right for what
 * it does: bus probing happens once, on the boot hart, before anything else
 * is running. This is not that. The TLB shootdown self-test asks a *different*
 * hart to dereference an address the boot hart has just unmapped, and the
 * whole point is that two harts are doing different things at the same time.
 * One global flag would let the boot hart's own faults and a secondary's
 * answer each other, so the state is per hart -- indexed by the kernel's CPU
 * number, which is what tp holds and what every other per-CPU array here is
 * indexed by.
 *
 * Page faults, not access faults: the MMIO probe recovers from
 * load/store-access-fault, which is what an unbacked physical address
 * produces. An address with no valid page table entry produces
 * load/store-page-fault instead, a different cause entirely, and the probe
 * above would have let it through to the panic. Both are accepted here
 * because a machine that reports the withdrawn mapping as an access fault
 * rather than a page fault has still stopped translating it, which is the
 * question being asked.
 *
 * This recovers by stepping over the faulting instruction, which leaves the
 * load's destination register untouched -- so a caller must never believe the
 * value it read back without first asking whether the probe faulted. */
/* Sized to match smp.c's RISCV64_MAX_HARTS, which this file cannot see: that
   constant is static to the SMP implementation, and exporting it so two files
   could share one number would put a bound on hart identifiers into a header
   that nothing else needs. A hart above the bound simply cannot arm a probe --
   exception_page_probe_begin does nothing and the caller's dereference stays
   fatal, which is the safe direction to fail in. */
#define PAGE_PROBE_MAX_CPUS 8U
static volatile uint32_t g_page_probe_armed[PAGE_PROBE_MAX_CPUS];
static volatile uint32_t g_page_probe_faulted[PAGE_PROBE_MAX_CPUS];

void exception_page_probe_begin(void) {
  uint32_t cpu = smp_cpu_id();
  if (cpu >= PAGE_PROBE_MAX_CPUS) return;
  g_page_probe_faulted[cpu] = 0U;
  /* Armed last and with a release, because the trap handler reads the two in
     the other order: a hart that took a fault between the two stores would
     otherwise clear the flag it had just set. */
  __atomic_store_n(&g_page_probe_armed[cpu], 1U, __ATOMIC_RELEASE);
}

void exception_page_probe_end(void) {
  uint32_t cpu = smp_cpu_id();
  if (cpu >= PAGE_PROBE_MAX_CPUS) return;
  __atomic_store_n(&g_page_probe_armed[cpu], 0U, __ATOMIC_RELEASE);
}

int exception_page_probe_faulted(void) {
  uint32_t cpu = smp_cpu_id();
  if (cpu >= PAGE_PROBE_MAX_CPUS) return 0;
  return g_page_probe_faulted[cpu] != 0U ? 1 : 0;
}

/* One call for the handler's whole check: the bounds guard, the acquire load
   of the armed flag and the store of the faulted flag, in that order. Non-zero
   means this hart had armed a probe, which is the signal to step over the
   faulting instruction rather than treat the fault as fatal. */
int riscv64_page_probe_handle_fault(uint32_t cpu) {
  if (cpu >= PAGE_PROBE_MAX_CPUS) return 0;
  if (__atomic_load_n(&g_page_probe_armed[cpu], __ATOMIC_ACQUIRE) == 0U) {
    return 0;
  }
  g_page_probe_faulted[cpu] = 1U;
  return 1;
}

/* An instruction's length, from its own first two bits.
 *
 * The compressed extension makes this a question rather than a constant: a
 * c.ebreak is two bytes and a full ebreak is four, and advancing by four
 * either way resumes in the middle of the next instruction. */
uint64_t riscv64_instruction_width(uint64_t pc) {
  const uint16_t *halfword = (const uint16_t *)(uintptr_t)pc;
  return ((*halfword & 0x3U) == 0x3U) ? 4U : 2U;
}

/* Preemption: the trap frame and the scheduler's context frame, mapped.
 *
 * The shared scheduler does the whole of a preemption in one call: it saves the
 * interrupted task's context into that task's own `xaios_context_frame_t`,
 * picks the next runnable one, and writes *its* frame back through the pointer
 * it was given -- and whoever called it then resumes through that frame. That
 * is why the AArch64 port works: its IRQ handler takes the context frame
 * directly, so its trap frame *is* the scheduler's frame. This port's frame is
 * its own shape, so the two are mapped here, in both directions, once.
 *
 * The 31 general-purpose registers the stub saves -- ra, sp, gp, tp, t0-t2,
 * s0-s1, a0-a7, s2-s11, t3-t6 -- are exactly `xaios_context_frame_t.regs[31]`
 * in that order, which is why this is a copy rather than a table. `sepc` is the
 * program counter and `sstatus` the processor state. The stack is the one field
 * that needs a rule: `user.c` builds a task's *first* frame as `elr_el1` =
 * entry, `sp_el0` = stack, `spsr_el1` = 0, with every register zero, while a
 * task that has been interrupted has its stack in `regs[1]` because that is
 * where the stub saves it. A zero `regs[1]` therefore means "never ran, use
 * `sp_el0`", and anything else means "resume on the stack the trap saved".
 *
 * A local rather than a static: a trap on another hart may be running this at
 * the same time, and the scheduler keeps no pointer to it. */
static void riscv64_frame_to_context(const riscv64_trap_frame_t *frame,
                                     xaios_context_frame_t *context) {
  const uint64_t *saved = &frame->ra;
  for (uint32_t index = 0U; index < 31U; ++index) {
    context->regs[index] = saved[index];
  }
  context->elr_el1 = frame->sepc;
  context->spsr_el1 = frame->sstatus;
  context->sp_el0 = frame->sp;
  /* The kernel stack this task's next trap lands on, not the user stack: a
     trap from user mode swaps `sscratch` for it, and the trap return has to put
     the *incoming* task's value back, which is what makes a switch survive the
     next syscall (B-132). */
  context->sp_el1 = frame->kernel_sp;
  context->padding = 0U;
  /* The shared frame's SIMD area is 512 bytes for AArch64's 32 x 128-bit
     registers; this port's are 64-bit each for the D extension, so the first
     thirty-two slots carry them exactly and the rest are not this port's to
     use. `fpcr` is the control/status word here and `fpsr` has no RISC-V
     counterpart, so it is zero rather than a copy of the same value. */
  for (uint32_t index = 0U; index < 32U; ++index) {
    context->simd[index] = frame->fp[index];
  }
  for (uint32_t index = 32U; index < 64U; ++index) context->simd[index] = 0U;
  context->fpcr = frame->fcsr;
  context->fpsr = 0U;
}

static void riscv64_context_to_frame(const xaios_context_frame_t *context,
                                     riscv64_trap_frame_t *frame) {
  uint64_t *saved = &frame->ra;
  for (uint32_t index = 0U; index < 31U; ++index) {
    saved[index] = context->regs[index];
  }
  frame->sepc = context->elr_el1;
  frame->sstatus = context->spsr_el1;
  /* `regs[1]` is the stack a trap saved. A task that has never run has every
     register zero -- `user.c` builds such a frame with only elr_el1, sp_el0 and
     spsr_el1 set -- and gets its stack from `sp_el0` instead. */
  frame->sp = context->regs[1] != 0U ? context->regs[1] : context->sp_el0;
  /* A task that has never been given a kernel stack keeps the one this trap is
     already on, which is the caller's -- exactly the behaviour before a switch
     could carry one, so a frame that cannot name a stack cannot change one. */
  if (context->sp_el1 != 0U) frame->kernel_sp = context->sp_el1;
  for (uint32_t index = 0U; index < 32U; ++index) {
    frame->fp[index] = context->simd[index];
  }
  frame->fcsr = context->fpcr;
}

/* Build a frame that starts a task in kernel mode on a stack of its own.
 *
 * This is the piece a user-process dispatch needs and a kernel-context switch
 * cannot do without: the frame says where the task's first instruction is and
 * *which stack it runs on*, so a trap return that switches to it lands on that
 * task's stack instead of the one the CPU was already using. RISC-V can express
 * it because its trap return loads `sp` from the frame (`regs[1]`) and its
 * `sret` takes the privilege from `sstatus.SPP`, so a supervisor frame with a
 * stack in it is exactly "resume this task in kernel mode, on this stack, with
 * interrupts on". */
int xaios_context_frame_kernel_entry(xaios_context_frame_t *frame,
                                     void (*entry)(void),
                                     uint64_t stack_top) {
  if (frame == 0 || entry == 0 || stack_top == 0U) return 0;
  uint8_t *bytes = (uint8_t *)frame;
  for (uint64_t index = 0U; index < sizeof(*frame); ++index) bytes[index] = 0U;
  frame->regs[1] = stack_top;
  frame->sp_el1 = stack_top;
  frame->elr_el1 = (uint64_t)(uintptr_t)entry;
  /* FS = Initial as well, because a task whose `sstatus` says the unit is Off
     takes an illegal instruction on its first floating-point register access --
     and the kernel task this builds is arbitrary C code, which may have one. */
  frame->spsr_el1 = SSTATUS_SPP | SSTATUS_SPIE | SSTATUS_FS_INITIAL;
  return 1;
}

/* What the tick has actually done, counted rather than reasoned about.
 *
 * A timer trap that ticks the scheduler and a timer trap that preempts a user
 * context are two claims, and only the second is the capability this port is
 * said to lack. `sstatus.SPP` says which mode the trap interrupted, and the
 * scheduler's own idea of the current task says whether the frame this returns
 * belongs to another one -- so the two counters together are the measurement,
 * taken on the machine rather than argued from the code. */
static uint64_t g_tick_count;
static uint64_t g_tick_user_count;
static uint64_t g_tick_user_switches;

void riscv64_scheduler_tick(riscv64_trap_frame_t *frame) {
  if (timer_local_tick_is_network_only() != 0U) {
    /* The CPU carrying the network tick polls the stack in its idle loop; its
       timer interrupt exists to wake it and does not tick the scheduler, which
       is the same division the other two ports make. */
    return;
  }
  uint32_t before = scheduler_current_pid();
  int from_user = (frame->sstatus & SSTATUS_SPP) == 0U;
  xaios_context_frame_t context;
  riscv64_frame_to_context(frame, &context);
  scheduler_tick(&context, 0);
  riscv64_context_to_frame(&context, frame);

  ++g_tick_count;
  if (g_tick_count == 1U) {
    klog("sched-tick: riscv64 first timer tick from=%s pid=%u\n",
         from_user != 0 ? "user" : "kernel", (unsigned)before);
  }
  if (from_user == 0) return;
  ++g_tick_user_count;
  if (g_tick_user_count <= 8U) {
    /* Named one by one at first, because the interesting fact is whether a
       tick from a user context arrives at all, and whether the scheduler then
       has another task to hand back. */
    klog("sched-tick: riscv64 user-context tick pid=%u -> pid=%u "
         "ticks=%lu user_ticks=%lu switches=%lu\n",
         (unsigned)before, (unsigned)scheduler_current_pid(),
         (unsigned long)g_tick_count, (unsigned long)g_tick_user_count,
         (unsigned long)g_tick_user_switches);
  }
  if (scheduler_current_pid() == before) return;
  ++g_tick_user_switches;
  if ((g_tick_user_switches % 256U) == 0U) {
    klog("sched-tick: riscv64 user-context switches=%lu ticks=%lu "
         "user_ticks=%lu\n",
         (unsigned long)g_tick_user_switches, (unsigned long)g_tick_count,
         (unsigned long)g_tick_user_count);
  }
}

static void riscv64_zero(void *destination, uint64_t size) {
  uint8_t *bytes = (uint8_t *)destination;
  for (uint64_t index = 0U; index < size; ++index) bytes[index] = 0U;
}

void platform_scheduler_tick_self_test(void) {
  riscv64_trap_frame_t frame;
  riscv64_zero(&frame, sizeof(frame));
  frame.ra = UINT64_C(0x11);
  frame.sp = UINT64_C(0xbbbb);
  frame.a0 = UINT64_C(0x22);
  frame.sepc = UINT64_C(0xaaaa);
  frame.sstatus = UINT64_C(0x33);
  frame.kernel_sp = UINT64_C(0xcc);
  frame.fp[0] = UINT64_C(0xf0f0f0f0f0f0f0f0);
  frame.fp[31] = UINT64_C(0x0f0f0f0f0f0f0f0f);
  frame.fcsr = UINT64_C(0x7f);

  xaios_context_frame_t context;
  riscv64_frame_to_context(&frame, &context);
  int saved = context.regs[0] == UINT64_C(0x11) &&
              context.regs[1] == UINT64_C(0xbbbb) &&
              context.regs[9] == UINT64_C(0x22) &&
              context.elr_el1 == UINT64_C(0xaaaa) &&
              context.spsr_el1 == UINT64_C(0x33) &&
              context.sp_el0 == UINT64_C(0xbbbb) &&
              context.sp_el1 == UINT64_C(0xcc) &&
              context.simd[0] == UINT64_C(0xf0f0f0f0f0f0f0f0) &&
              context.simd[31] == UINT64_C(0x0f0f0f0f0f0f0f0f) &&
              context.fpcr == UINT64_C(0x7f) &&
              context.simd[32] == 0U;

  /* What the scheduler hands back for a task that has already run carries the
     stack its own trap saved; what it hands back for one that never has carries
     the user stack `user.c` put in sp_el0. Both must land in the trap frame's
     sp, because that is what the trap return resumes on. */
  context.regs[0] = UINT64_C(0x44);
  context.regs[1] = UINT64_C(0x9999);
  context.elr_el1 = UINT64_C(0x1234);
  context.sp_el0 = UINT64_C(0x5678);
  context.spsr_el1 = 0U;
  context.sp_el1 = UINT64_C(0xdd);
  context.simd[1] = UINT64_C(0xa5a5a5a5a5a5a5a5);
  context.fpcr = UINT64_C(0x1f);
  riscv64_context_to_frame(&context, &frame);
  int interrupted = frame.ra == UINT64_C(0x44) && frame.sepc == UINT64_C(0x1234) &&
                    frame.sp == UINT64_C(0x9999) &&
                    frame.kernel_sp == UINT64_C(0xdd) &&
                    frame.fp[1] == UINT64_C(0xa5a5a5a5a5a5a5a5) &&
                    frame.fcsr == UINT64_C(0x1f);

  context.regs[1] = 0U;
  riscv64_context_to_frame(&context, &frame);
  int never_ran = frame.sp == UINT64_C(0x5678);

  /* A frame that names no kernel stack leaves the one this trap is on alone --
     the whole point of the field being conditional, because a task that cannot
     name a stack must not be able to move one. */
  context.sp_el1 = 0U;
  riscv64_context_to_frame(&context, &frame);
  int stack_kept = frame.kernel_sp == UINT64_C(0xdd);

  klog("sched-tick: riscv64 trap-frame mapping self-test saved=%d "
       "interrupted=%d never_ran=%d stack_kept=%d\n",
       saved, interrupted, never_ran, stack_kept);
  kassert(saved != 0);
  kassert(interrupted != 0);
  kassert(never_ran != 0);
  kassert(stack_kept != 0);
  klog("sched-tick: riscv64 trap-frame mapping self-test passed\n");
}
