/* Harts: finding them, starting them, and letting them run.
 *
 * The shared kernel asks four things before it can run at all: which CPU am
 * I, how many are there, is locking live, and how many could there be. It
 * then expects to be able to release secondary schedulers and have them
 * arrive. This answers all of that for real harts rather than for one.
 *
 * A supervisor-mode kernel cannot take a hart out of reset itself; that is
 * machine-mode work. SBI's Hart State Management extension exists for exactly
 * this, so asking firmware is the supported route and not a workaround. The
 * hart arrives with translation off, which is why its entry point is in the
 * identity-mapped kernel image and why the stack and satp it needs are handed
 * over as a plain record at a physical address.
 *
 * `smp_locking_active` deserves the note it always did. It reports whether
 * more than one hart can be executing kernel code, and the shared spinlock
 * uses it to decide whether an atomic is needed. Returning 1 on a single-hart
 * system would be merely wasteful; returning 0 once secondaries exist would
 * be a silent data race. It is derived from the online count, so bringing
 * harts up changes the answer without anyone having to remember this file.
 */
#include <xaios/boot_info.h>
#include <xaios/riscv64_fdt.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/network_stack.h>
#include <xaios/timer.h>

#include "smp_internal.h"

void gic_secondary_init(uint32_t cpu_id);
void timer_mask_local(void);
uint32_t xaios_thread_run_pending(uint32_t cpu_id);
uint32_t xaios_thread_pending_on_cpu(uint32_t cpu_id);
xaios_status_t xaios_thread_run_group(uint64_t requested_threads,
                                      uint64_t iterations,
                                      uint64_t *ran_threads,
                                      uint64_t *checksum);
uint64_t riscv64_kernel_satp(void);
/* The remote half of the TLB shootdown self-test.
 *
 * The kernel can count its own shootdowns without anybody's help, and a count
 * proves almost nothing -- the question is whether a hart that is *not* the
 * one doing the unmapping loses the translation. Answering it needs a second
 * hart to perform a load when the first one says so, and the only place a
 * secondary can be asked to do that before the scheduler exists is the loop
 * it waits in below. So the wait loop polls, and mmu.c owns the protocol and
 * the assertions. The service call costs one load and one CSR write per pass
 * when there is nothing to answer. */
void riscv64_tlb_probe_service(uint32_t cpu_id);

/* The same size the boot stack was raised to, for the same reason.
 *
 * The boot hart's stack is 256 KiB with a guard page under it, and
 * kernel/arch/riscv64/linker.ld says why: sixty-four was not enough, because
 * the deepest chain this kernel takes is storage -- an installer walking a FAT
 * directory from inside a syscall from inside osctl -- and an overflow there
 * did not fault, it quietly overwrote the per-CPU current-process table.
 *
 * These were 16 KiB, a quarter of the size already proven too small, and with
 * nothing below them at all. A thread that runs on a hart other than the boot
 * hart takes its whole syscall chain on this stack, so the same deep chain had
 * a quarter of the space and no way to say it had run out. */
#define SECONDARY_STACK_BYTES 262144U
#define SECONDARY_STACK_GUARD_BYTES 4096U

/* Logical CPU number to hart id. Index 0 is the boot hart, whichever one
   firmware chose. Everything that talks to SBI goes through this; everything
   that indexes a per-CPU structure uses the logical number. */
uint32_t riscv64_smp_hart_of_cpu[RISCV64_MAX_HARTS];
uint32_t riscv64_smp_online = 1U;
/* Two different numbers that were one.
 *
 * riscv64_smp_capacity bounds the *identifier* space: smp_cpu_state and everything that
 * indexes by CPU id -- the core lease table among them -- treats it as "ids
 * below this". riscv64_smp_online_target is how many harts are expected to arrive, and
 * is what the rendezvous loops wait for.
 *
 * They were the same variable, set to a count. That is right only while ids
 * run 0,1,2,... with no gaps, and firmware does not promise that: booting
 * through UEFI can leave one hart already started, which this kernel cannot
 * take over, so the machine comes up with ids 0,2,3 and a capacity of 3 --
 * and every lease of CPU 3 was refused as out of range. Identity is the
 * firmware's to choose; counting is ours. */
uint32_t riscv64_smp_capacity = 1U;
uint32_t riscv64_smp_online_target = 1U;
uint32_t riscv64_smp_secondary_release;
uint32_t riscv64_smp_locking_active;
xaios_cpu_state_t riscv64_smp_cpu_states[RISCV64_MAX_HARTS];
/* Guard first, then the stack, so the page under each stack is the one that
   faults when a hart runs out of room. The two are one object rather than two
   arrays because the adjacency is the whole point of the guard, and separate
   arrays would leave the linker free to put them anywhere. */
typedef struct {
  uint8_t guard[SECONDARY_STACK_GUARD_BYTES];
  uint8_t stack[SECONDARY_STACK_BYTES];
} secondary_stack_t;

static secondary_stack_t g_secondary_stacks[RISCV64_MAX_HARTS]
    __attribute__((aligned(4096)));

/* Where a hart's stack may not reach, and the top it starts from. Read by
   vmm_init, which unmaps the guard pages once paging is on -- the same thing
   it does for the boot stack's guard. */
uint8_t *riscv64_secondary_stack_guard(uint32_t cpu) {
  return cpu < RISCV64_MAX_HARTS ? g_secondary_stacks[cpu].guard : (uint8_t *)0;
}

uint8_t *riscv64_secondary_stack_top(uint32_t cpu) {
  return cpu < RISCV64_MAX_HARTS
             ? &g_secondary_stacks[cpu].stack[SECONDARY_STACK_BYTES]
             : (uint8_t *)0;
}

/* How many of the above there are, so vmm_init does not have to be told the
   hart limit a second time and keep the two in step by hand. */
uint32_t riscv64_secondary_stack_count(void) { return RISCV64_MAX_HARTS; }

/* What this CPU is waiting for, published for another CPU to read. RISC-V's
 * remote fence is firmware's (`sbi_remote_sfence_vma`), and that call does not
 * return until firmware says every named hart has fenced, so no CPU waits on
 * this note yet; it is recorded because the field belongs to the CPU, not to
 * the mechanism that reads it (B-123). */
void xaios_cpu_note_wait(const char *reason) {
  uint32_t cpu = smp_cpu_id();
  if (cpu < RISCV64_MAX_HARTS) {
    riscv64_smp_cpu_states[cpu].waiting_for = reason;
  }
}

uint32_t smp_cpu_id(void) {
  /* tp holds this hart's logical CPU number, put there by the entry code.
     Read from a register rather than a CSR because mhartid is machine mode
     only -- a supervisor-mode kernel cannot ask the hardware who it is, and
     has to be told once and remember. */
  uint64_t cpu = 0U;
  __asm__ volatile("mv %0, tp" : "=r"(cpu));
  return (uint32_t)cpu;
}

uint32_t riscv64_hart_of_cpu(uint32_t cpu_id) {
  return cpu_id < RISCV64_MAX_HARTS ? riscv64_smp_hart_of_cpu[cpu_id] : 0U;
}

uint32_t smp_online_count(void) {
  return __atomic_load_n(&riscv64_smp_online, __ATOMIC_ACQUIRE);
}

uint32_t smp_locking_active(void) {
  return __atomic_load_n(&riscv64_smp_locking_active, __ATOMIC_ACQUIRE);
}

uint32_t smp_capacity(void) { return riscv64_smp_capacity; }

/* Where a secondary hart lands once SBI has started it. */
void smp_secondary_main(uint64_t cpu_id) {
  if (cpu_id < RISCV64_MAX_HARTS) {
    riscv64_smp_cpu_states[cpu_id].cpu_id = (uint32_t)cpu_id;
    riscv64_smp_cpu_states[cpu_id].mpidr = riscv64_smp_hart_of_cpu[cpu_id];
    riscv64_smp_cpu_states[cpu_id].role = XAIOS_CPU_ROLE_SCHEDULING;
    riscv64_smp_cpu_states[cpu_id].scheduling_enabled = 0U;
    /* Online last, and only once everything it describes has landed: it is
       what the boot hart waits on, and an entry seen half-written is worse
       than one not seen at all. */
    __atomic_store_n(&riscv64_smp_cpu_states[cpu_id].online, 1U, __ATOMIC_RELEASE);
    __atomic_add_fetch(&riscv64_smp_online, 1U, __ATOMIC_ACQ_REL);
  }

  /* Sleep rather than spin, and be woken by an IPI when the gate opens.
     This used to spin, which was harmless while the gate opened immediately
     after the harts were started. It stopped being harmless when they began
     coming online early enough to be leased: three harts spinning through
     everything between bring-up and the rendezvous starve the boot hart on
     any machine with fewer real cores than harts, and under emulation, where
     every hart is a thread on one host core, it turned a boot into a timeout.

     Enabling the software interrupt first is what makes wfi safe here: a
     hart whose sie has nothing enabled may wait for something that never
     comes. Woken spuriously it simply re-reads the flag. */
  __asm__ volatile("csrs sie, %0" : : "r"(UINT64_C(1) << 1) : "memory");
  while (__atomic_load_n(&riscv64_smp_secondary_release, __ATOMIC_ACQUIRE) == 0U) {
    /* Answers a TLB probe if one has been posted, and clears the pending
       software interrupt either way -- see riscv64_tlb_probe_service. */
    riscv64_tlb_probe_service((uint32_t)cpu_id);
    /* Re-read after that clear, and this ordering is not decoration. The
       service call consumes the pending bit, which may have been the release
       IPI itself; a hart that went straight to wfi from here would sleep with
       the gate already open and nothing left to wake it. Reading the flag
       after the clear closes that: the release store happens before its IPI,
       so a flag that still reads zero here means the IPI has not been sent
       yet, and when it is it will find the pending bit clear and the hart in
       wfi. */
    if (__atomic_load_n(&riscv64_smp_secondary_release, __ATOMIC_ACQUIRE) != 0U) break;
    __asm__ volatile("wfi" ::: "memory");
  }
  /* Whatever woke it has been consumed by the read above. */
  __asm__ volatile("csrc sip, %0" : : "r"(UINT64_C(1) << 1) : "memory");

  gic_secondary_init((uint32_t)cpu_id);

  /* Kernel workers are event-driven. The local timer stays masked until this
     hart owns a preemptible run queue. */
  timer_mask_local();

  if (cpu_id < RISCV64_MAX_HARTS) {
    __atomic_store_n(&riscv64_smp_cpu_states[cpu_id].scheduling_enabled, 1U,
                     __ATOMIC_RELEASE);
  }

  __asm__ volatile("csrs sstatus, %0" : : "r"(UINT64_C(2)) : "memory");

  /* Sleeping, not spinning.
   *
   * This spun, because the first version of smp_wake_cpu here reported that
   * there was no way to wake a hart -- so a hart that slept would have slept
   * through every job it was given. There is a way: the shared scheduler
   * already calls smp_wake_cpu whenever it queues work for a CPU other than
   * the one it is running on, and SBI's IPI extension raises the supervisor
   * software interrupt that brings a hart out of wfi. Spinning cost a core
   * doing nothing on every idle machine.
   *
   * The pending work is still checked before sleeping and after waking,
   * because a wake that arrives between the two would otherwise be missed. */
  for (;;) {
    /* The supervisor interrupt enable every turn, not only the one before this
       loop: a trap clears sstatus.SIE and the return path is what puts it back,
       so a hart that came back from one without it never takes another
       interrupt -- and a hart that cannot take an interrupt cannot be woken by
       one, which is how the scheduler moves work between harts. */
    __asm__ volatile("csrs sstatus, %0" : : "r"(UINT64_C(2)) : "memory");
    /* The timer is masked across `xaios_thread_run_pending`, and that is a
       property of this port rather than of the mechanism. Running a user
       thread here is nested inside the joiner's syscall (B-02), and this
       port's trap entry is deliberately minimal -- its own `entry.S` says "a
       full context switch belongs with the scheduler work this port has not
       done". A timer trap taken inside that window was measured corrupting a
       frame: `/bin/c99-thread-context` returned to program counter zero
       (`class=instruction-access-fault sepc=0x0`, `reason=thread-join-failed`)
       and the machine halted before the service phase.
       
       So the tick is permitted only where the trap context is this loop's own
       frame -- `timer_arm_network_tick()` enables it, so it is live for the
       poll and the sleep below -- and every hart, carrier or not, keeps its
       timer masked while it is running work. The other two ports take that
       trap anywhere; what is the same on all three is that one CPU polls the
       stack at the tick rate. */
    timer_mask_local();
    if (xaios_thread_run_pending((uint32_t)cpu_id) != 0U) continue;
    /* Idle, so this hart can carry the network tick: claim it once, repair a
     * tick this hart lost while running a task, and poll the stack while
     * there is nothing else to do. See network_poll_tick_from_carrier(). */
    if (timer_arm_network_tick() != 0U) {
      network_poll_tick_from_carrier();
      continue;
    }
    /* Ask the queue once more with interrupts masked, and wait while they stay
     * masked.
     *
     * `wfi` was reached with sstatus.SIE set, and an IPI that arrived between
     * the check above and the wait was taken by its handler -- after which the
     * hart slept with the thread that IPI announced still pending, and nothing
     * woke it again, because the network tick is armed on one hart (B-120).
     * RISC-V makes the fix cheaper than x86-64's `sti; hlt` pair: `wfi`
     * resumes for a locally enabled interrupt that is pending even with SIE
     * clear, so an IPI that arrives inside this window is left pending and
     * wakes the hart instead of being consumed. The loop's first instruction
     * re-enables interrupts, which is where the pending IPI is then taken. */
    __asm__ volatile("csrrc zero, sstatus, %0" ::"r"(UINT64_C(2)) : "memory");
    if (xaios_thread_pending_on_cpu((uint32_t)cpu_id) != 0U) continue;
    __asm__ volatile("wfi" ::: "memory");
  }
}

/* Whether this CPU is inside a trap handler.
 *
 * This port answers with the interrupt mask rather than a trap depth, which is
 * what every caller asked before the question was separated: it is
 * conservative, shortening the console lock's wait in a thread context that
 * happens to hold a spinlock. x86-64 answers exactly because the observed drop
 * was there (B-119). */
uint32_t xaios_cpu_in_interrupt(void) {
  return xaios_interrupts_enabled() != 0 ? 0U : 1U;
}

xaios_status_t smp_wake_cpu(uint32_t cpu_id) {
  if (cpu_id >= RISCV64_MAX_HARTS || riscv64_smp_cpu_states[cpu_id].online == 0U ||
      __atomic_load_n(&riscv64_smp_cpu_states[cpu_id].scheduling_enabled,
                      __ATOMIC_ACQUIRE) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  /* Addressed by hart, because that is what firmware knows about; the mask is
     one bit relative to that hart rather than a bitmap based at zero, so this
     says nothing about harts it was not asked to wake. */
  uint64_t hart = riscv64_smp_hart_of_cpu[cpu_id];
  return sbi_send_ipi(UINT64_C(1), hart) == 0 ? XAIOS_OK : XAIOS_ERR_IO;
}

/* Kernel threads, which the shared scheduler places itself. */
xaios_status_t smp_run_user_thread_group(uint64_t requested_threads,
                                         uint64_t iterations,
                                         uint64_t *ran_threads,
                                         uint64_t *checksum) {
  return xaios_thread_run_group(requested_threads, iterations, ran_threads,
                                checksum);
}
