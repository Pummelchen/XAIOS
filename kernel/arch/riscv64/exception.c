/* Traps, interrupts, and the PLIC.
 *
 * RISC-V routes everything through one vector: exceptions and interrupts
 * arrive at stvec and are told apart by the top bit of scause. That is
 * simpler than AArch64's sixteen-entry table and x86-64's IDT, and it moves
 * the work into software -- the dispatch below is the part those
 * architectures get from hardware.
 *
 * External devices arrive through the Platform-Level Interrupt Controller,
 * which is found in the device tree rather than assumed: its address is
 * board-specific and hardcoding QEMU's would be the identity-versus-
 * capability mistake again.
 */
#include <xaios/riscv64_fdt.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/timer.h>

void klog(const char *fmt, ...);
uint32_t riscv64_hart_of_cpu(uint32_t cpu_id);
void panic_at(const char *file, int line, const char *fmt, ...)
    __attribute__((noreturn));
#define exception_panic(...) panic_at(__FILE__, __LINE__, __VA_ARGS__)

extern void riscv64_trap_entry(void);

#define SCAUSE_INTERRUPT (UINT64_C(1) << 63)
#define SIE_SOFTWARE (UINT64_C(1) << 1)
#define SIE_TIMER (UINT64_C(1) << 5)
#define SIE_EXTERNAL (UINT64_C(1) << 9)
#define SSTATUS_SIE (UINT64_C(1) << 1)

#define IRQ_SOFTWARE 1U
#define IRQ_TIMER 5U
#define IRQ_EXTERNAL 9U

/* PLIC register layout, from the specification. Priorities start at zero,
   the enable bitmap is per context, and claim/complete is a single register
   read to take an interrupt and written to release it. */
#define PLIC_PRIORITY_BASE UINT64_C(0x000000)
#define PLIC_ENABLE_BASE UINT64_C(0x002000)
#define PLIC_CONTEXT_BASE UINT64_C(0x200000)
#define PLIC_CONTEXT_STRIDE UINT64_C(0x1000)
#define PLIC_ENABLE_STRIDE UINT64_C(0x80)
#define PLIC_MAX_SOURCES 1024U

static uint64_t g_plic_base;
static const void *g_device_tree;
static uint64_t g_trap_counts[16];
static uint64_t g_external_count;

typedef struct riscv64_irq_handler {
  void (*handler)(uint32_t source, void *context);
  void *context;
} riscv64_irq_handler_t;

static riscv64_irq_handler_t g_handlers[PLIC_MAX_SOURCES];

void riscv64_exception_set_device_tree(const void *blob) {
  g_device_tree = blob;
}

static volatile uint32_t *plic_register(uint64_t offset) {
  return (volatile uint32_t *)(uintptr_t)(g_plic_base + offset);
}

/* Supervisor context for hart 0. QEMU's virt board gives each hart a machine
   context and a supervisor context, interleaved, so supervisor is the odd
   one. Hardcoded to hart 0 for as long as this port runs one hart; when
   secondaries arrive this becomes a function of the hart id. */
static uint64_t supervisor_context(void) {
  /* QEMU's virt board gives every hart a machine context and a supervisor
     context, interleaved, so hart N's supervisor context is 2N+1. This
     returned 1 unconditionally, which is right only for hart 0 -- and
     firmware does not always boot on hart 0, so on the runs where it did not
     the kernel set the threshold on another hart's context and enabled
     interrupts on a context that was not its own. Indexed by hart, because
     that is what the controller is indexed by; the kernel's own CPU number is
     a different thing. */
  return 2U * (uint64_t)riscv64_hart_of_cpu(smp_cpu_id()) + 1U;
}

void riscv64_plic_enable(uint32_t source, uint32_t priority) {
  if (g_plic_base == 0U || source == 0U || source >= PLIC_MAX_SOURCES) return;
  /* Priority zero means "never interrupt", so a source enabled at zero is
     enabled and silent -- which looks exactly like a device that is not
     working. */
  *plic_register(PLIC_PRIORITY_BASE + source * 4U) =
      priority == 0U ? 1U : priority;
  uint64_t context = supervisor_context();
  volatile uint32_t *enable = plic_register(
      PLIC_ENABLE_BASE + context * PLIC_ENABLE_STRIDE + (source / 32U) * 4U);
  *enable |= UINT32_C(1) << (source % 32U);
}

xaios_status_t riscv64_irq_register(uint32_t source,
                                    void (*handler)(uint32_t, void *),
                                    void *context) {
  if (source == 0U || source >= PLIC_MAX_SOURCES || handler == 0) {
    return XAIOS_ERR_INVALID;
  }
  g_handlers[source].handler = handler;
  g_handlers[source].context = context;
  riscv64_plic_enable(source, 1U);
  return XAIOS_OK;
}

static void handle_external(void) {
  if (g_plic_base == 0U) return;
  uint64_t context = supervisor_context();
  volatile uint32_t *claim =
      plic_register(PLIC_CONTEXT_BASE + context * PLIC_CONTEXT_STRIDE + 4U);
  for (;;) {
    uint32_t source = *claim;
    if (source == 0U) break;
    ++g_external_count;
    if (source < PLIC_MAX_SOURCES && g_handlers[source].handler != 0) {
      g_handlers[source].handler(source, g_handlers[source].context);
    }
    /* Completed even when nothing handled it. An unclaimed source stays
       pending forever and the controller stops delivering anything else --
       one unhandled device would silence every other. */
    *claim = source;
  }
}

/* The register frame the trap stub builds, in the order it stores them. */
typedef struct riscv64_trap_frame {
  uint64_t ra, sp, gp, tp;
  uint64_t t0, t1, t2;
  uint64_t s0, s1;
  uint64_t a0, a1, a2, a3, a4, a5, a6, a7;
  uint64_t s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;
  uint64_t t3, t4, t5, t6;
  uint64_t sepc, scause, stval, sstatus;
} riscv64_trap_frame_t;

#define SSTATUS_SPP (UINT64_C(1) << 8)

#define CAUSE_ECALL_FROM_USER 8U
#define CAUSE_BREAKPOINT 3U
#define CAUSE_LOAD_ACCESS_FAULT 5U
#define CAUSE_STORE_ACCESS_FAULT 7U

/* Probing for a device that may not be there.
 *
 * Reading configuration space at an address nothing answers is a fault on
 * this architecture, not a read of all-ones, so the shared "did that come
 * back as 0xffffffff" test cannot tell an absent host bridge from a present
 * one. AArch64 solved the same problem the same way for its IOMMU probe.
 * Between begin and end, an access fault sets the flag and steps over the
 * instruction instead of killing the machine. */
static volatile int g_mmio_probe_active;
static volatile int g_mmio_probe_faulted;

void exception_mmio_probe_begin(void) {
  g_mmio_probe_faulted = 0;
  g_mmio_probe_active = 1;
}

void exception_mmio_probe_end(void) { g_mmio_probe_active = 0; }

int exception_mmio_probe_faulted(void) { return g_mmio_probe_faulted; }

uint64_t syscall_dispatch(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                          uint64_t arg2);
uint64_t user_process_note_fault(void);

/* An instruction's length, from its own first two bits.
 *
 * The compressed extension makes this a question rather than a constant: a
 * c.ebreak is two bytes and a full ebreak is four, and advancing by four
 * either way resumes in the middle of the next instruction. */
static uint64_t instruction_width(uint64_t pc) {
  const uint16_t *halfword = (const uint16_t *)(uintptr_t)pc;
  return ((*halfword & 0x3U) == 0x3U) ? 4U : 2U;
}

/* Returns zero to resume the interrupted context, or the encoded result of a
   process that has just exited -- which the stub uses to leave user mode for
   good rather than returning into a process that is finished. AArch64 makes
   the same decision in its vector, comparing the top half of the syscall
   result against the same marker. Without it the exit syscall returns to a
   program that has already said goodbye, which then spins in the idle loop
   after its own exit and never yields: the kernel logs the process as exited
   and then waits forever for it to leave. */
#define USER_EXIT_MARKER UINT64_C(0x4f534149)

uint64_t riscv64_trap_handler(riscv64_trap_frame_t *frame) {
  uint64_t cause = frame->scause;
  if ((cause & SCAUSE_INTERRUPT) != 0U) {
    uint64_t which = cause & ~SCAUSE_INTERRUPT;
    if (which < 16U) ++g_trap_counts[which];
    if (which == IRQ_TIMER) {
      timer_rearm();
    } else if (which == IRQ_EXTERNAL) {
      handle_external();
    }
    /* An interrupt resumes the instruction it interrupted, which has not
       run, so sepc is left exactly as it arrived. */
    return 0U;
  }

  /* A system call. The number is in a7 and the arguments in a0 upwards,
     which is the calling convention userspace assembly already uses, and the
     result goes back in a0 where the caller will read it. */
  if (cause == CAUSE_ECALL_FROM_USER) {
    uint64_t result =
        syscall_dispatch(frame->a7, frame->a0, frame->a1, frame->a2);
    frame->a0 = result;
    /* ecall is never compressed, so four is right here and only here --
       past the instruction, or the syscall is made again forever. */
    frame->sepc += 4U;
    return (result >> 32U) == USER_EXIT_MARKER ? result : 0U;
  }

  /* An access fault the kernel went looking for. Recovered rather than
     fatal, and only while a probe is in progress. */
  if (g_mmio_probe_active != 0 && (cause == CAUSE_LOAD_ACCESS_FAULT ||
                                   cause == CAUSE_STORE_ACCESS_FAULT)) {
    g_mmio_probe_faulted = 1;
    frame->sepc += instruction_width(frame->sepc);
    return 0U;
  }

  /* A breakpoint the kernel placed deliberately -- the SIMD-across-a-trap
     check executes one to provoke a trap it can survive. Stepping past it is
     the whole point, and the width has to be read from the instruction
     because the compressed c.ebreak is two bytes where ebreak is four:
     advancing by four either way resumes in the middle of the next
     instruction. */
  if (cause == CAUSE_BREAKPOINT) {
    frame->sepc += instruction_width(frame->sepc);
    return 0U;
  }

  /* A fault in user mode is the process's problem, not the machine's. Killing
     the process and continuing is what the other architectures do; panicking
     would let any user program halt the system. */
  if ((frame->sstatus & SSTATUS_SPP) == 0U) {
    klog("user exception: cause=%lu sepc=0x%lx stval=0x%lx\n", cause,
         frame->sepc, frame->stval);
    uint64_t note = user_process_note_fault();
    frame->a0 = note;
    frame->sepc += instruction_width(frame->sepc);
    return (note >> 32U) == USER_EXIT_MARKER ? note : 0U;
  }

  /* A synchronous exception in the kernel is fatal, and saying which one is
     the whole value of getting here. */
  exception_panic("unhandled trap cause=%lu epc=%lx stval=%lx", cause,
                  frame->sepc, frame->stval);
}

void exception_init(void) {
  /* Zeroed before the vector is armed, because the trap stub reads it to
     decide which stack to land on and reset leaves it undefined. A boot that
     takes its first trap with garbage here switches to an address nothing
     chose, which presents as a fault whose reported cause is itself
     nonsense -- the frame was written to a stack that does not exist. */
  __asm__ volatile("csrw sscratch, zero" ::: "memory");
  __asm__ volatile("csrw stvec, %0"
                   :
                   : "r"((uint64_t)(uintptr_t)riscv64_trap_entry)
                   : "memory");

  uint64_t plic = 0U;
  /* By compatible string, not by node name: this controller is called
     `interrupt-controller@c000000` here, and `interrupt-controller` alone is
     the hart's local one under /cpus. Looking for "plic" found neither. */
  if (g_device_tree != 0 &&
      (fdt_find_compatible(g_device_tree, "riscv,plic0", &plic) ||
       fdt_find_compatible(g_device_tree, "sifive,plic-1.0.0", &plic))) {
    g_plic_base = plic;
    uint64_t context = supervisor_context();
    /* Threshold zero: take everything whose priority is above it. A non-zero
       threshold here is how a controller ends up enabled and delivering
       nothing. */
    *plic_register(PLIC_CONTEXT_BASE + context * PLIC_CONTEXT_STRIDE) = 0U;
    klog("exception: plic at %lx context=%lu threshold=0\n", g_plic_base,
         context);
  } else {
    klog("exception: no plic in the device tree; external interrupts will "
         "not be delivered\n");
  }

  /* Timer and external enabled; software interrupts stay masked until there
     is a second hart to send one. */
  __asm__ volatile("csrs sie, %0" : : "r"(SIE_TIMER | SIE_EXTERNAL));
  __asm__ volatile("csrs sstatus, %0" : : "r"(SSTATUS_SIE));
  klog("exception: stvec armed, timer and external interrupts enabled\n");
}

void exception_self_test(void) {
  /* A trap provoked, taken, identified and returned from. ebreak rather than
     an illegal instruction because its width is knowable and its cause is
     unambiguous -- an illegal instruction on a machine with optional
     extensions could mean several things. */
  uint64_t before = g_trap_counts[IRQ_TIMER];
  (void)before;

  /* Interrupts are already on, so this also proves the vector handles a
     synchronous exception while asynchronous ones are enabled -- the case
     where a wrong sscratch or a clobbered register shows up. */
  uint64_t timer_before = timer_now_ns();
  uint64_t deadline = timer_before + UINT64_C(20000000);
  timer_enable_periodic(100U);
  while (timer_now_ns() < deadline) {
    __asm__ volatile("wfi" ::: "memory");
  }
  if (g_trap_counts[IRQ_TIMER] == 0U) {
    exception_panic("no timer interrupt arrived in 20 ms with the timer "
                    "armed at 100 Hz");
  }
  klog("exception: self-test passed timer_interrupts=%lu external=%lu\n",
       g_trap_counts[IRQ_TIMER], g_external_count);
}
