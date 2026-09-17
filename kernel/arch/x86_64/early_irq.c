/* The C half of the x86-64 trap entry: dispatch by vector.
 *
 * Extracted verbatim from kernel/arch/x86_64/early.c. This is the body
 * entry.S's stubs call for every external interrupt, for the ring-3 syscall
 * gate and for the device-IRQ gates; it names the vector and runs the handler
 * class that vector belongs to. It has no boot position of its own: it first
 * runs only after the IDT is loaded and the first delivered vector arrives,
 * which is after the GDT, the page tables, the APIC and the LAPIC timer are
 * set up. Nothing here is called by, or calls into, the INIT-SIPI-SIPI
 * sequence in start_application_processors; an AP's first entry into this file
 * is an ordinary delivered vector, exactly as it was before the split.
 *
 * early.c still owns the CPU record table, the APIC-ready flag and the timer
 * interrupt counter; early_module.h is the shared seam and the aliases below
 * keep the moved body unchanged.
 *
 * Runs before this file: the loader, x86_64_kmain, install_gdt_tss, install_idt
 * and -- for an AP -- x86_64_ap_entry's lidt and SPURIOUS-vector programming.
 * Runs after this file returns: whatever the generic layers do with the
 * handler it dispatched, and, on the ring-3 exit paths, x86_64_ring3_resume in
 * entry.S. */

#include <xaios/arch_cpu.h>
#include <xaios/gic.h>
#include <xaios/syscall.h>
#include <xaios/types.h>
#include <xaios/user.h>

#include "early_module.h"
#include "early_serial.h"
#include "platform.h"

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

/* The moved body names these the way early.c did; each expands to the
 * primitive or constant early.c exports through early_module.h. */
#define X86_IRQ_COM1_PORT UINT16_C(0x3f8)
#define COM1_PORT X86_IRQ_COM1_PORT
#define APIC_EOI UINT32_C(0x0b0)
#define X86_USER_BASE UINT64_C(0x100000000)
#define X86_USER_WINDOW_SIZE UINT64_C(0x1000000)
#define X86_USER_LOG_MAX UINT64_C(4096)
#define current_ordinal_fast xaios_x86_early_current_ordinal_fast
#define lapic_id xaios_x86_early_lapic_id
#define lapic_write xaios_x86_early_lapic_write
#define panic_halt xaios_x86_early_panic_halt
#define serial_putc xaios_x86_early_serial_putc

#if XAIOS_X86_COMMON_RUNTIME
/* Moved here with the body it guards, under the same guard: the post-syscall
 * kernel/syscall stack canary check, compiled only when the common runtime
 * drives syscalls through this entry. */
static int kernel_stack_guard_valid(uint32_t ordinal) {
  x86_64_cpu_record_t *g_cpu_records = xaios_x86_early_cpu_records();
  uint32_t g_cpu_record_count = xaios_x86_early_cpu_record_count();
  if (ordinal >= g_cpu_record_count ||
      g_cpu_records[ordinal].kernel_stack_top < X86_KERNEL_STACK_SIZE ||
      g_cpu_records[ordinal].syscall_stack_top < X86_KERNEL_STACK_SIZE) {
    return 0;
  }
  const uint8_t *kernel_guard = (const uint8_t *)(uintptr_t)(
      g_cpu_records[ordinal].kernel_stack_top - X86_KERNEL_STACK_SIZE);
  const uint8_t *syscall_guard = (const uint8_t *)(uintptr_t)(
      g_cpu_records[ordinal].syscall_stack_top - X86_KERNEL_STACK_SIZE);
  for (uint32_t i = 0U; i < X86_KERNEL_STACK_GUARD_BYTES; ++i) {
    if (kernel_guard[i] != X86_KERNEL_STACK_GUARD_VALUE ||
        syscall_guard[i] != X86_KERNEL_STACK_GUARD_VALUE) {
      return 0;
    }
  }
  return 1;
}
#endif

/* The body of the trap entry, wrapped below so that the per-CPU trap depth is
 * maintained on every path out -- the function has a return per vector class
 * and the wrapper is the one place that can see them all. */
static uint64_t x86_64_interrupt_entry_body(x86_64_exception_frame_t *frame) {
  /* early.c's file-scope state, read once here the way the moved body read it:
   * the record table is filled before any vector can arrive, and the APIC is
   * ready no later than the LAPIC timer self-test, so none of the three
   * changes under this body. */
  x86_64_cpu_record_t *g_cpu_records = xaios_x86_early_cpu_records();
  uint32_t g_cpu_record_count = xaios_x86_early_cpu_record_count();
  uint32_t g_lapic_ready = xaios_x86_early_lapic_ready();
  /* Liveness and last-vector, per CPU: a TLB shootdown that times out prints
   * these for the CPU that did not answer, which is how "it never took the
   * interrupt" is told apart from "it took it and answered the wrong
   * generation" (B-123). The ring-3 syscall arrives through this same entry
   * and is not an interrupt, so it is not counted. */
  if (frame != 0 && g_cpu_records != 0 && frame->vector >= 32U &&
      frame->vector != 128U) {
    uint32_t ordinal = current_ordinal_fast();
    if (ordinal < g_cpu_record_count) {
      x86_64_cpu_record_t *record = &g_cpu_records[ordinal];
      __atomic_add_fetch(&record->interrupts_taken, 1U, __ATOMIC_RELAXED);
      __atomic_store_n(&record->last_vector, frame->vector, __ATOMIC_RELEASE);
    }
  }
  if (frame != 0 && frame->vector == 128U) {
    if ((frame->cs & 3U) != 3U) panic_halt(COM1_PORT, "ring3 syscall CPL");
    xaios_x86_mem_note_ring3_call();
#if XAIOS_X86_COMMON_RUNTIME
    uint64_t result = syscall_dispatch(frame->rax, frame->rdi, frame->rsi,
                                       frame->rdx);
    uint32_t ordinal = x86_64_platform_current_ordinal();
    if (!kernel_stack_guard_valid(ordinal)) {
      panic_halt(COM1_PORT, "kernel syscall stack overflow");
    }
    if ((result & XAIOS_USER_EXIT_RETURN_MASK) ==
        XAIOS_USER_EXIT_RETURN_MAGIC) {
      x86_64_platform_set_user_return(result);
      return (uint64_t)(uintptr_t)x86_64_ring3_resume;
    }
    frame->rax = result;
    return 0U;
#else
    if (frame->rax == 1U) {
      uint64_t address = frame->rdi;
      uint64_t length = frame->rsi;
      if (length == 0U || length > X86_USER_LOG_MAX ||
          address < X86_USER_BASE ||
          address > X86_USER_BASE + X86_USER_WINDOW_SIZE - length) {
        panic_halt(COM1_PORT, "ring3 log buffer");
      }
      const char *text = (const char *)(uintptr_t)address;
      for (uint64_t i = 0U; i < length; ++i) {
        if (text[i] == '\n') serial_putc(COM1_PORT, '\r');
        serial_putc(COM1_PORT, text[i]);
      }
      frame->rax = 0U;
      return 0U;
    }
    if (frame->rax == 2U) {
      xaios_x86_mem_set_ring3_exit(frame->rdi);
      return (uint64_t)(uintptr_t)x86_64_ring3_resume;
    }
    panic_halt(COM1_PORT, "ring3 syscall number");
#endif
  }
  if (frame != 0 && frame->vector == 33U && g_cpu_records != 0) {
#if XAIOS_X86_COMMON_RUNTIME
    x86_64_platform_eoi();
    return 0U;
#else
    uint32_t current_id = lapic_id();
    for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
      x86_64_cpu_record_t *record = &g_cpu_records[i];
      if (record->apic_id != current_id) continue;
      uint32_t generation = __atomic_load_n(
          &record->requested_generation, __ATOMIC_ACQUIRE);
      uint64_t value = UINT64_C(0xcbf29ce484222325) ^ current_id;
      for (uint32_t step = 0U; step < 4096U; ++step) {
        value ^= (uint64_t)step + ((uint64_t)i << 32U);
        value *= UINT64_C(0x100000001b3);
      }
      record->checksum = value;
      __atomic_store_n(&record->completed_generation, generation,
                       __ATOMIC_RELEASE);
      lapic_write(APIC_EOI, 0U);
      return 0U;
    }
    panic_halt(COM1_PORT, "AP worker identity");
#endif
  }
  if (frame != 0 && frame->vector == 34U && g_lapic_ready != 0U) {
    xaios_x86_pci_note_msix_interrupt();
    lapic_write(APIC_EOI, 0U);
    return 0U;
  }
  if (frame != 0 && frame->vector == 35U && g_lapic_ready != 0U) {
    /* The shootdown's own state lives in early_tlb.c now; this is the same
     * read the inline block did, in the same place in the dispatch order. */
    xaios_x86_early_tlb_note_interrupt();
    lapic_write(APIC_EOI, 0U);
    return 0U;
  }
  if (frame != 0 && frame->vector >= 64U && frame->vector < 128U &&
      g_lapic_ready != 0U) {
    (void)gic_dispatch_interrupt((uint32_t)frame->vector);
    lapic_write(APIC_EOI, 0U);
    return 0U;
  }
  if (frame != 0 && frame->vector == 32U && g_lapic_ready != 0U) {
    ++g_x86_lapic_timer_interrupts;
#if XAIOS_X86_COMMON_RUNTIME
    x86_64_platform_timer_irq();
#endif
    lapic_write(APIC_EOI, 0U);
    return 0U;
  }
  if (frame != 0 && frame->vector == 255U) return 0U;
  panic_halt(COM1_PORT, "unexpected external interrupt");
  return 0U;
}

uint64_t x86_64_interrupt_entry(x86_64_exception_frame_t *frame) {
  x86_64_cpu_record_t *g_cpu_records = xaios_x86_early_cpu_records();
  uint32_t g_cpu_record_count = xaios_x86_early_cpu_record_count();
  uint32_t ordinal = current_ordinal_fast();
  x86_64_cpu_record_t *record =
      g_cpu_records != 0 && ordinal < g_cpu_record_count ? &g_cpu_records[ordinal]
                                                         : 0;
  /* A ring-3 syscall arrives through this same entry and is *not* a handler for
   * this purpose: it runs on behalf of a thread, so a line it prints may wait
   * for the console lock the way a thread's may. Counting it as a handler
   * shortened that wait and the smoke showed the consequence immediately --
   * `klog: 1 log lines dropped, the console lock was held in_handler=1
   * masked=0`, which is a syscall context reported as a handler. Only a trap
   * that interrupted kernel work counts. */
  int is_trap = frame != 0 && frame->vector != 128U;
  if (record != 0 && is_trap) {
    __atomic_add_fetch(&record->state.interrupt_depth, 1U, __ATOMIC_ACQ_REL);
  }
  uint64_t result = x86_64_interrupt_entry_body(frame);
  if (record != 0 && is_trap) {
    __atomic_sub_fetch(&record->state.interrupt_depth, 1U, __ATOMIC_ACQ_REL);
  }
  return result;
}

/* Whether this CPU is inside a trap. Exact here, because the depth above is
 * maintained for every vector through the one entry. */
uint32_t xaios_cpu_in_interrupt(void) {
  x86_64_cpu_record_t *g_cpu_records = xaios_x86_early_cpu_records();
  uint32_t g_cpu_record_count = xaios_x86_early_cpu_record_count();
  if (g_cpu_records == 0) return 0U;
  uint32_t ordinal = current_ordinal_fast();
  if (ordinal >= g_cpu_record_count) return 0U;
  return __atomic_load_n(&g_cpu_records[ordinal].state.interrupt_depth,
                         __ATOMIC_ACQUIRE) != 0U
             ? 1U
             : 0U;
}
