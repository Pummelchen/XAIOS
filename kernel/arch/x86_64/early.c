#include <xaios/boot_info.h>
#include <xaios/ai_kernels.h>
#include <xaios/common_runtime.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/network_stack.h>
#include <xaios/security.h>
#include <xaios/smp.h>
#include <xaios/syscall.h>
#include <xaios/thread.h>
#include <xaios/timer.h>
#include <xaios/types.h>
#include <xaios/user.h>
#include <xaios/vmm.h>
#include <xaios_engine/packed.h>

#include "early_module.h"
#include "early_idt.h"
#include "early_lapic.h"
#include "early_serial.h"
#include "early_exception.h"
#include "early_contract.h"
#include "early_post_smp.h"
#include "early_fpu.h"
#include "platform.h"

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

/* The COM1 UART, the port-I/O primitives beneath it and the panic halt now
 * live in early_serial.c. These keep every call site in this file -- and the
 * panic_at() below -- spelling them the way they did. The port primitives
 * themselves come from early_serial.h, defined there once and inlined here. */
#define serial_init xaios_x86_early_serial_init
#define serial_putc xaios_x86_early_serial_putc
#define serial_puts xaios_x86_early_serial_puts
#define serial_hex64 xaios_x86_early_serial_hex64
#define serial_dec xaios_x86_early_serial_dec
#define panic_halt xaios_x86_early_panic_halt

/* The paging/PM half moved to early_mem.c and the PCI half to early_pci.c;
 * these aliases keep the call sites that remain in this file -- early_alloc,
 * parse_memory_map and install_page_tables -- spelling them the way they did.
 * The PCI probes and validate_ring3_syscall moved on with the milestone 48-51
 * stage to early_post_smp.c, which declares its own aliases. */
#define early_alloc xaios_x86_mem_alloc
#define parse_memory_map xaios_x86_mem_parse_map
#define install_page_tables xaios_x86_mem_install_page_tables

/* The GDT/TSS construction moved to early_gdt.c; these aliases keep its two
 * call sites -- x86_64_kmain and x86_64_ap_entry -- spelling it the way they
 * did. The BSP's rsp0 is reached through the scalar accessors the platform
 * hooks below call, never through a pointer into that file's state. */
#define install_gdt_tss xaios_x86_gdt_install
#define install_ap_gdt_tss xaios_x86_gdt_install_ap

/* The IDT and its gate builders moved to early_idt.c; these aliases keep the
 * one call site in x86_64_kmain and the table name x86_64_ap_entry's IDTR
 * reload uses spelling them the way they did. The module defines the object
 * early_idt.h declares as g_x86_idt; nothing else about either statement
 * changes. */
#define install_idt xaios_x86_idt_install
#define g_idt g_x86_idt

/* The exception entry and its controlled round-trip moved to early_exception.c;
 * this alias keeps the one call site in x86_64_kmain spelling it the way it
 * did. The entry itself keeps its name because entry.S calls it by that name. */
#define validate_exception_round_trip xaios_x86_early_exception_round_trip

/* The OS-contract and hardware-gate reports moved to early_contract.c, and
 * their two call sites moved on with the milestone 48-51 stage to
 * early_post_smp.c, which declares its own aliases. */

/* The LAPIC register accessors and the CPU-identity pair moved to
 * early_lapic.c; these aliases keep every call site in this file -- including
 * the LAPIC timer self-test and the AP startup sequence -- spelling them the
 * way it did. The raw MSR/CR/TSC/CPUID primitives are `static inline` in
 * early_lapic.h, so the call sites that inline them are unchanged. */
#define lapic_read xaios_x86_early_lapic_read
#define lapic_write xaios_x86_early_lapic_write
#define lapic_id xaios_x86_early_lapic_id
#define lapic_send xaios_x86_early_lapic_send
#define prepare_tsc_aux xaios_x86_early_prepare_tsc_aux

#define COM1_PORT UINT16_C(0x3f8)
#define PAGE_SIZE UINT64_C(4096)
#define X86_EFLAGS_ID UINT64_C(1 << 21)
/* The CR4/XCR0/XSAVE control bits and the primitives that program them now
 * live in early_fpu.h, which the extended-state block below and the AVX2 canary
 * in x86_64_kmain share with early_fpu.c. MSR_IA32_APIC_BASE moved to
 * early_module.h, because early_lapic.c's LAPIC accessors and the calibration
 * in early_timer_discover.c both read that one register. */
/* The local-APIC register map and MSR_IA32_TSC_AUX moved to early_lapic.h with
 * the accessors that spell them and with prepare_tsc_aux(). The LAPIC timer
 * self-test and the AP entry below still name the same constants, which now
 * come from that header. */
/* X86_USER_BASE, _WINDOW_SIZE and _LOG_MAX moved to early_irq.c with the
 * ring-3 syscall dispatch that was their only user. */
/* X86_KERNEL_STACK_SIZE, _GUARD_BYTES and _GUARD_VALUE moved to
 * early_module.h: early_gdt.c sizes the BSP syscall stack with them and this
 * file guards the kernel and syscall stacks with them. */
/* IDT_PRESENT, IDT_INTERRUPT_GATE, IDT_TRAP_GATE and the x86_64_idt_entry_t
 * gate layout moved to early_idt.h and early_idt.c with install_idt, their only
 * user; this file still reads that layout through the header, because
 * x86_64_ap_entry reloads the table the module built. */

/* x86_64_idtr_t moved to early_module.h, where early_gdt.c's builder and the
 * two loaders in this file both read it. */

/* x86_64_exception_frame_t moved to early_module.h: the exception entry below
 * and the interrupt dispatch in early_irq.c both name it, and its layout is
 * entry.S's. */

/* x86_64_contract_state_t and x86_64_hardware_gate_state_t moved to
 * early_contract.c with the two report functions that were their only users. */

/* The x86_64_isr_N, x86_64_irq_N and x86_64_device_irq_stubs declarations
 * moved to early_idt.c with install_idt, which was their only user. */
/* x86_64_load_gdt/x86_64_load_tss are declared in early_gdt.c now: the two
 * functions here that called them moved there with them. */
extern void x86_64_ring3_resume(void);
extern uint8_t x86_64_ap_trampoline_start[];
extern uint8_t x86_64_ap_trampoline_end[];
extern uint8_t x86_64_ap_trampoline_cr3[];
extern uint8_t x86_64_ap_trampoline_gdt_base[];
extern uint8_t x86_64_ap_trampoline_long_ip[];
extern uint8_t x86_64_ap_trampoline_stack[];
extern uint8_t x86_64_ap_trampoline_ordinal[];
extern uint8_t x86_64_ap_trampoline_entry[];
extern uint8_t x86_64_ap_trampoline_long_offset[];
extern uint8_t x86_64_ap_trampoline_gdt_offset[];

/* g_idt moved to early_idt.c as the exported g_x86_idt: this file reaches the
 * table through the alias above, for x86_64_ap_entry's IDTR reload. */
/* g_gdt, g_tss and g_syscall_stack moved to early_gdt.c with the builder that
 * fills them; this file reaches the BSP's rsp0 through the scalar accessors
 * xaios_x86_gdt_bsp_rsp0/_set_bsp_rsp0. A CPU record's own TSS is still here. */
/* g_contract and g_hardware_gate moved to early_contract.c with the two
 * report functions that were their only readers and writers. */
/* g_exception_vectors_installed and g_code_selector moved to early_idt.c with
 * install_idt: it was their only writer and their only reader. */
/* The APIC-ready flag stays file-scope with the LAPIC timer self-test below,
 * which is its only writer, and so does the accessor early_irq.c and
 * early_platform.c call: that accessor reads the flag here instead of the flag
 * crossing the seam. g_lapic_x2apic likewise has no reader outside that
 * self-test. */
static uint32_t g_lapic_ready;
static uint32_t g_lapic_x2apic;
volatile uint64_t g_x86_lapic_timer_interrupts;
volatile uint64_t g_ring3_return_value;
static xaios_boot_info_t g_boot_info_copy;
static x86_64_cpu_record_t *g_cpu_records;
static uint32_t g_cpu_record_count;
static uint32_t g_bsp_ordinal = UINT32_MAX;
static volatile uint32_t g_common_worker_release;
static uint64_t g_tsc_frequency;
static uint64_t g_lapic_frequency;
/* Whether IA32_TSC_AUX holds this CPU's ordinal, so the fast identity in
 * early_lapic.c may use RDTSCP. Set by whichever CPU prepares first; it is a
 * property of the CPU model, not of one CPU. It crosses the seam as the same
 * object, so it is no longer file-scope. */
uint32_t g_tsc_aux_ready;
/* The idle-wakeup self-test's probe pair moved to early_platform.c with its
 * setter and getter; the idle loop below still reads it through
 * xaios_x86_early_idle_probe_get. */

/* The common kernel's entry is reached from the post-SMP stage in
 * early_post_smp.c, which calls it under this same guard. */

/* The five forward declarations that stood here -- rdtsc, lapic_id,
 * current_ordinal_fast, lapic_send and lapic_write -- are gone: rdtsc is a
 * `static inline` in early_lapic.h, and the other four are declared there and
 * in early_module.h beside the accessors that define them. */

#if !XAIOS_X86_COMMON_RUNTIME
uint32_t smp_online_count(void) {
  if (g_cpu_records == 0 || g_cpu_record_count == 0U) return 1U;
  uint32_t online = 0U;
  for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
    if (__atomic_load_n(&g_cpu_records[i].online, __ATOMIC_ACQUIRE) != 0U) {
      ++online;
    }
  }
  return online == 0U ? 1U : online;
}

/* x86_64 has no equivalent of the window this guards on AArch64: long mode
 * requires paging, so a secondary is never running with translation off, and
 * every CPU that is online already agrees on the memory attributes. Online is
 * therefore the right question here, and this just answers it in the shape the
 * lock asks for. */
uint32_t smp_locking_active(void) { return smp_online_count() > 1U ? 1U : 0U; }

#endif

/* The seam early_tlb.c and early_platform.c reach through: the CPU table this
 * file owns. The per-CPU getters for it live in early_tlb.c with the rest of
 * the shootdown; this file keeps only the storage and these reads. */
x86_64_cpu_record_t *xaios_x86_early_cpu_records(void) { return g_cpu_records; }

uint32_t xaios_x86_early_cpu_record_count(void) { return g_cpu_record_count; }

/* The scalars early_platform.c's platform hooks read or write. Each is a
 * scalar read or write of this file's storage, never a pointer into it; the
 * storage stays here because the timer and AP bring-up paths own it. */
uint64_t xaios_x86_early_tsc_hz(void) { return g_tsc_frequency; }

void xaios_x86_early_set_tsc_hz(uint64_t frequency) {
  g_tsc_frequency = frequency;
}

uint64_t xaios_x86_early_lapic_hz(void) { return g_lapic_frequency; }

uint32_t xaios_x86_early_bsp_ordinal(void) { return g_bsp_ordinal; }

void xaios_x86_early_set_worker_release(uint32_t value) {
  __atomic_store_n(&g_common_worker_release, value, __ATOMIC_RELEASE);
}

/* The CR4/XCR0/XSAVE/FXSAVE primitives, the per-CPU IRQ-state area lookup and
 * the interrupt entry's state save/restore now live in early_fpu.h and
 * early_fpu.c. The primitives are `static inline` in that header, so this file
 * still inlines them at the AVX2 canary and in x86_64_ap_entry; the two
 * save/restore entry points keep their names because entry.S calls them. */

/* The MSR/CR/TSC/CPUID primitives that stood here now live, also `static
 * inline`, in early_lapic.h: this file still inlines read_cr3 while it stages
 * the AP trampoline, rdmsr/rdtsc in the LAPIC timer self-test and the AP
 * startup delays, and cpuid at the AVX2 canary, and early_lapic.c inlines the
 * same six primitives in the accessors it defines. */

static uint64_t memory_descriptor_count(const xaios_boot_info_t *boot) {
  if (boot == 0 || boot->memory_descriptor_size == 0) {
    return 0;
  }
  return boot->memory_map_size / boot->memory_descriptor_size;
}

static void bytes_copy(void *destination, const void *source, uint64_t bytes) {
  uint8_t *output = (uint8_t *)destination;
  const uint8_t *input = (const uint8_t *)source;
  for (uint64_t i = 0U; i < bytes; ++i) output[i] = input[i];
}

#if !XAIOS_X86_COMMON_RUNTIME
void panic_at(const char *file, int line, const char *fmt, ...) {
  (void)file;
  (void)line;
  panic_halt(COM1_PORT, fmt != 0 ? fmt : "kernel panic");
}
#endif

/* idt_set_gate and idt_set_user_gate moved to early_idt.c with install_idt,
 * which was their only caller. */

/* install_gdt_tss and install_ap_gdt_tss moved to early_gdt.c as
 * xaios_x86_gdt_install and xaios_x86_gdt_install_ap, together with g_gdt,
 * g_tss and g_syscall_stack. The aliases at the top of this file keep both
 * call sites -- x86_64_kmain and x86_64_ap_entry -- spelling them as before. */

/* kernel_stack_guard_valid moved to early_irq.c with the syscall dispatch that
 * calls it, under the same XAIOS_X86_COMMON_RUNTIME guard. Nothing else in
 * this file used it. */

/* install_idt moved to early_idt.c as xaios_x86_idt_install, called at this
 * same point in x86_64_kmain through the alias above; the gate builders, the
 * ISR declarations and the table moved with it. */

/* The LAPIC register accessors, the CPU-identity pair and the MSR/CR/TSC/CPUID
 * accessors that stood here -- lapic_read, lapic_write, lapic_id, lapic_send,
 * current_ordinal_fast, prepare_tsc_aux and the exported wrappers early_tlb.c,
 * early_irq.c, early_cpu.c, early_mem.c, early_pci.c and
 * early_timer_discover.c call -- now live in early_lapic.c. The aliases at the
 * top of this file keep every call site here -- the LAPIC timer self-test and
 * the AP startup sequence included -- spelling them the way it did, and the raw
 * primitives come from early_lapic.h, so the call sites that inline them are
 * unchanged. */

/* The one accessor of that group that stays: it reports this file's APIC-ready
 * flag, which its own LAPIC timer self-test sets a few dozen lines below, so
 * neither the flag nor this read crosses the seam. early_module.h declares it
 * and early_irq.c and early_platform.c call it, as before. */
uint32_t xaios_x86_early_lapic_ready(void) { return g_lapic_ready; }

static void tsc_delay(uint64_t cycles) {
  uint64_t deadline = rdtsc() + cycles;
  while ((int64_t)(rdtsc() - deadline) < 0) __asm__ volatile("pause");
}

void x86_64_ap_entry(uint32_t ordinal) {
  if (ordinal >= g_cpu_record_count) panic_halt(COM1_PORT, "AP ordinal");
  prepare_tsc_aux(ordinal);
  x86_64_idtr_t idtr = {
      .limit = (uint16_t)(sizeof(g_idt) - 1U),
      .base = (uint64_t)(uintptr_t)g_idt,
  };
  __asm__ volatile("lidt %0" : : "m"(idtr) : "memory");
  write_cr4(read_cr4() | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT);
  /* The mask early_fpu.c validated and programmed before any AP started; read
   * once here so this CPU programs the same XCR0. */
  uint64_t xsave_enabled = xaios_x86_fpu_enabled_mask();
  if (xsave_enabled != 0U) {
    write_cr4(read_cr4() | X86_CR4_OSXSAVE);
    write_xcr0(xsave_enabled);
  }
  lapic_write(APIC_SPURIOUS, UINT32_C(0x100) | UINT32_C(0xff));
  if (lapic_id() != g_cpu_records[ordinal].apic_id) {
    panic_halt(COM1_PORT, "AP APIC identity");
  }
  install_ap_gdt_tss(&g_cpu_records[ordinal]);
  __atomic_store_n(&g_cpu_records[ordinal].online, 1U, __ATOMIC_RELEASE);
  __asm__ volatile("sti" ::: "memory");
#if XAIOS_X86_COMMON_RUNTIME
  while (__atomic_load_n(&g_common_worker_release, __ATOMIC_ACQUIRE) == 0U) {
    __asm__ volatile("hlt");
  }
  vmm_activate_kernel();
  __atomic_store_n(&g_cpu_records[ordinal].worker_ready, 1U,
                   __ATOMIC_RELEASE);
  for (;;) {
    /* Ring-3 exit returns with IF clear. Re-enable worker wake IPIs before
     * checking the queue so every subsequent detached job can run -- and that
     * same `sti` is what lets this CPU take the network tick's interrupt at
     * all; on AArch64 the equivalent line was missing and the tick stopped
     * after a few dozen polls because of it. */
    __asm__ volatile("sti" ::: "memory");
    if (xaios_thread_run_pending(ordinal) != 0U) continue;
    /* Idle, so this CPU can carry the network tick: claim it once, repair a
     * tick this CPU lost while running a task, and poll the stack while
     * there is nothing else to do. See network_poll_tick_from_carrier(). */
    if (timer_arm_network_tick() != 0U) {
      network_poll_tick_from_carrier();
      continue;
    }
    /* Ask the queue one last time with interrupts masked, then halt and
     * enable them in one step.
     *
     * `hlt` used to follow the check after a gap, and an IPI that arrived in
     * that gap was taken by its handler -- after which the CPU slept with the
     * thread the IPI announced still pending. Nothing woke it again: the
     * network tick is armed on one CPU, and a secondary has no periodic
     * interrupt of its own, so the thread sat `PENDING` until the join that
     * was waiting for it gave up (B-120). AArch64 closes the same window with
     * `xaios_cpu_notify()`'s `sev`, which sets the event register the `wfe`
     * would otherwise wait on; x86-64 has no event register, so the answer is
     * the `sti; hlt` pair, whose interrupt shadow means the interrupt is
     * recognised after the halt rather than before it. */
    x86_64_idle_probe_state_t probe;
    xaios_x86_early_idle_probe_get(&probe);
    uint64_t probe_gap = probe.gap_cycles;
    if (probe_gap != 0U) {
      __atomic_add_fetch(&g_cpu_records[ordinal].idle_gap_rounds, 1U,
                         __ATOMIC_RELEASE);
      tsc_delay(probe_gap);
    }
    __asm__ volatile("cli" ::: "memory");
    /* Read again after `cli`, where this used to load the legacy flag: the two
     * loads keep the order they had before the split. */
    xaios_x86_early_idle_probe_get(&probe);
    if (probe.legacy == 0U &&
        xaios_thread_pending_on_cpu(ordinal) != 0U) {
      /* The window was real and this CPU was in it. Counted once per CPU, and
         then said out loud with interrupts restored: this is the measurement
         that the fix is catching something rather than the claim that it
         cannot happen. */
      uint32_t previous = __atomic_fetch_add(
          &g_cpu_records[ordinal].idle_wakeups_raced, 1U, __ATOMIC_ACQ_REL);
      __asm__ volatile("sti" ::: "memory");
      if (previous == 0U) {
        klog("x86_64: idle wakeup race avoided cpu=%u\n", ordinal);
      }
      continue;
    }
    __asm__ volatile("sti; hlt" ::: "memory");
  }
#else
  for (;;) __asm__ volatile("hlt");
#endif
}

/* XSAVE/XRSTOR validation and the per-CPU nested IRQ-state areas now live in
 * early_fpu.c as xaios_x86_fpu_validate and xaios_x86_fpu_prepare_irq_areas,
 * called at this same point in x86_64_kmain. */

/* How many APIC timer counts the rate is measured over. One million counts is
 * about ten milliseconds of the timer's own clock, which is long enough that
 * the TSC's resolution is irrelevant and short enough to disappear in a boot. */
#define LAPIC_MEASURE_COUNTS UINT32_C(1000000)

/* The TSC/PIT calibration (measure_tsc_with_pit, B-122) and the APIC capability
 * report that used to sit here now live in early_timer_discover.c as
 * xaios_x86_early_timer_discover; the call below is at the same point in the
 * sequence and the frequency is still this file's g_tsc_frequency, written and
 * read through the seam's accessors. The LAPIC timer interrupt itself -- the
 * EOI path, the periodic tick and the self-test below -- is unchanged. */

static void validate_lapic_timer_interrupt(uint16_t serial_base) {
  uint64_t apic_msr = rdmsr(MSR_IA32_APIC_BASE);
  if ((apic_msr & APIC_BASE_ENABLE) == 0U) {
    panic_halt(serial_base, "local APIC unavailable");
  }
  g_lapic_x2apic =
      (apic_msr & APIC_BASE_X2APIC) != 0U ? UINT32_C(1) : UINT32_C(0);
  g_lapic_ready = 1U;
  uint32_t apic_id = lapic_read(APIC_ID);
  if (g_lapic_x2apic == 0U) apic_id >>= 24U;
  uint32_t version = lapic_read(APIC_VERSION) & UINT32_C(0xff);
  lapic_write(APIC_SPURIOUS, UINT32_C(0x100) | UINT32_C(0xff));
  lapic_write(APIC_LVT_TIMER, 32U);
  lapic_write(APIC_TIMER_DIVIDE, UINT32_C(0x0b));
  g_x86_lapic_timer_interrupts = 0U;
  uint64_t started_tsc = rdtsc();
  lapic_write(APIC_TIMER_INITIAL, UINT32_C(100000));
  __asm__ volatile("sti; hlt; cli" ::: "memory");
  uint64_t elapsed_tsc = rdtsc() - started_tsc;
  lapic_write(APIC_LVT_TIMER, UINT32_C(1 << 16) | 32U);
  if (g_x86_lapic_timer_interrupts != 1U ||
      lapic_read(APIC_TIMER_CURRENT) != 0U) {
    panic_halt(serial_base, "local APIC timer interrupt failed");
  }
  /* The frequency, measured instead of inferred from the interrupt above.
   *
   * Deriving it from `elapsed_tsc` made the answer depend on how long the host
   * took to deliver one interrupt: this machine reported 22,031,284 Hz in one
   * boot and 55,216,540 Hz in another, and a CI job's three boots of the same
   * host reported 115,658,845, 169,648,168 and 164,735,927 Hz. The periodic
   * tick's interval is built from this number, so the machine booted with the
   * scheduler ticking at whatever rate the host happened to be running at.
   * The counter's own rate has nothing to do with interrupts, so it is read
   * directly: run it down over a known number of counts, time that with the
   * calibrated TSC, and the counts per second follow. The divisor is the one
   * the periodic tick uses, so the number is in the units `periodic_count`
   * divides by the tick rate. */
  lapic_write(APIC_LVT_TIMER, UINT32_C(1 << 16) | 32U); /* masked */
  lapic_write(APIC_TIMER_DIVIDE, UINT32_C(0x0b));
  lapic_write(APIC_TIMER_INITIAL, UINT32_C(0xffffffff));
  uint64_t count_started_tsc = rdtsc();
  uint64_t count_budget = g_tsc_frequency / 4U;
  uint32_t measured_counts = 0U;
  for (;;) {
    measured_counts = UINT32_C(0xffffffff) - lapic_read(APIC_TIMER_CURRENT);
    if (measured_counts >= LAPIC_MEASURE_COUNTS) break;
    if (rdtsc() - count_started_tsc > count_budget) break;
  }
  uint64_t count_elapsed_tsc = rdtsc() - count_started_tsc;
  lapic_write(APIC_TIMER_INITIAL, 0U);
  if (measured_counts != 0U && count_elapsed_tsc != 0U) {
    g_lapic_frequency =
        ((uint64_t)measured_counts * g_tsc_frequency) / count_elapsed_tsc;
  }
  if (g_lapic_frequency == 0U) g_lapic_frequency = UINT64_C(1000000);
  serial_puts(serial_base, "x86_64: local APIC timer interrupt passed id=");
  serial_dec(serial_base, apic_id);
  serial_puts(serial_base, " version=");
  serial_dec(serial_base, version);
  serial_puts(serial_base, " interrupts=");
  serial_dec(serial_base, g_x86_lapic_timer_interrupts);
  serial_puts(serial_base, " mode=");
  serial_puts(serial_base,
              g_lapic_x2apic != 0U ? "x2apic" : "xapic");
  serial_puts(serial_base, " interrupt_tsc=");
  serial_dec(serial_base, elapsed_tsc);
  serial_puts(serial_base, " counts=");
  serial_dec(serial_base, measured_counts);
  serial_puts(serial_base, " counts_tsc=");
  serial_dec(serial_base, count_elapsed_tsc);
  serial_puts(serial_base, " lapic_hz=");
  serial_dec(serial_base, g_lapic_frequency);
  serial_puts(serial_base, "\n");
}

static void write_u32(uint8_t *address, uint32_t value) {
  address[0] = (uint8_t)value;
  address[1] = (uint8_t)(value >> 8U);
  address[2] = (uint8_t)(value >> 16U);
  address[3] = (uint8_t)(value >> 24U);
}

static void write_u64(uint8_t *address, uint64_t value) {
  write_u32(address, (uint32_t)value);
  write_u32(address + 4U, (uint32_t)(value >> 32U));
}

static void patch_ap_trampoline(uint16_t serial_base, uint64_t base,
                                uint64_t stack, uint32_t ordinal) {
  uint64_t bytes = (uint64_t)(x86_64_ap_trampoline_end -
                              x86_64_ap_trampoline_start);
  if (base == 0U || base >= UINT64_C(0x100000) || bytes > PAGE_SIZE ||
      read_cr3() > UINT32_MAX) {
    panic_halt(serial_base, "AP trampoline contract");
  }
  uint8_t *destination = (uint8_t *)(uintptr_t)base;
  bytes_copy(destination, x86_64_ap_trampoline_start, bytes);
#define AP_PATCH(symbol) \
  (destination + ((uint64_t)(symbol) - \
                  (uint64_t)(uintptr_t)x86_64_ap_trampoline_start))
  write_u32(AP_PATCH(x86_64_ap_trampoline_cr3), (uint32_t)read_cr3());
  write_u32(AP_PATCH(x86_64_ap_trampoline_gdt_base),
            (uint32_t)(base +
                       (uint64_t)(uintptr_t)x86_64_ap_trampoline_gdt_offset));
  write_u32(AP_PATCH(x86_64_ap_trampoline_long_ip),
            (uint32_t)(base +
                       (uint64_t)(uintptr_t)x86_64_ap_trampoline_long_offset));
  write_u64(AP_PATCH(x86_64_ap_trampoline_stack), stack);
  write_u32(AP_PATCH(x86_64_ap_trampoline_ordinal), ordinal);
  write_u64(AP_PATCH(x86_64_ap_trampoline_entry),
            (uint64_t)(uintptr_t)x86_64_ap_entry);
#undef AP_PATCH
  __asm__ volatile("mfence" ::: "memory");
}

static void start_application_processors(uint16_t serial_base,
                                         const xaios_boot_info_t *boot) {
  if (boot->ap_trampoline == 0U || g_cpu_records == 0 ||
      g_cpu_record_count == 0U) {
    panic_halt(serial_base, "AP startup inputs");
  }
  uint32_t bsp_id = lapic_id();
  uint32_t bsp_found = 0U;
  for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
    if (g_cpu_records[i].apic_id == bsp_id) {
      g_cpu_records[i].online = 1U;
      g_cpu_records[i].kernel_stack_top = xaios_x86_gdt_bsp_rsp0();
      g_cpu_records[i].syscall_stack_top = xaios_x86_gdt_bsp_rsp0();
      g_bsp_ordinal = i;
      bsp_found = 1U;
    }
  }
  if (bsp_found == 0U) panic_halt(serial_base, "BSP absent from MADT");
  /* Before any secondary runs, so every CPU that asks has an answer, and
     before anything that can spin. */
  prepare_tsc_aux(g_bsp_ordinal);

  uint32_t online = 1U;
  for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
    x86_64_cpu_record_t *record = &g_cpu_records[i];
    if (record->apic_id == bsp_id) continue;
    uint8_t *stack =
        (uint8_t *)early_alloc(X86_KERNEL_STACK_SIZE, PAGE_SIZE);
    uint8_t *syscall_stack =
        (uint8_t *)early_alloc(X86_KERNEL_STACK_SIZE, PAGE_SIZE);
    if (stack == 0 || syscall_stack == 0) {
      panic_halt(serial_base, "AP stack allocation");
    }
    for (uint32_t guard = 0U; guard < X86_KERNEL_STACK_GUARD_BYTES; ++guard) {
      stack[guard] = X86_KERNEL_STACK_GUARD_VALUE;
      syscall_stack[guard] = X86_KERNEL_STACK_GUARD_VALUE;
    }
    record->kernel_stack_top =
        (uint64_t)(uintptr_t)(stack + X86_KERNEL_STACK_SIZE);
    record->syscall_stack_top =
        (uint64_t)(uintptr_t)(syscall_stack + X86_KERNEL_STACK_SIZE);
    patch_ap_trampoline(serial_base, boot->ap_trampoline,
                        record->kernel_stack_top, i);
    lapic_send(record->apic_id, UINT32_C(0x0000c500));
    tsc_delay(UINT64_C(10000000));
    lapic_send(record->apic_id, UINT32_C(0x00008500));
    tsc_delay(UINT64_C(10000000));
    uint32_t vector = (uint32_t)(boot->ap_trampoline >> 12U);
    lapic_send(record->apic_id, UINT32_C(0x00000600) | vector);
    tsc_delay(UINT64_C(1000000));
    lapic_send(record->apic_id, UINT32_C(0x00000600) | vector);
    uint64_t deadline = rdtsc() + UINT64_C(2000000000);
    while (__atomic_load_n(&record->online, __ATOMIC_ACQUIRE) == 0U &&
           (int64_t)(rdtsc() - deadline) < 0) {
      __asm__ volatile("pause");
    }
    if (record->online == 0U) panic_halt(serial_base, "AP startup timeout");
    ++online;
  }

  serial_puts(serial_base, "x86_64: SMP AP startup passed online=");
  serial_dec(serial_base, online);
  serial_puts(serial_base, " madt_cpus=");
  serial_dec(serial_base, g_cpu_record_count);
  serial_puts(serial_base, " dynamic_records=1\n");
  /* How a CPU names itself when it has no time to ask the APIC: `rdtscp` is a
     register read, `apic-id` is a host round trip. A machine that reports the
     second is still correct, and worth being able to see. */
  serial_puts(serial_base, "x86_64: per-CPU identity source=");
  serial_puts(serial_base, g_tsc_aux_ready != 0U ? "rdtscp" : "apic-id");
  serial_puts(serial_base, "\n");

#if !XAIOS_X86_COMMON_RUNTIME
  uint32_t workers = 0U;
  uint64_t combined = 0U;
  for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
    x86_64_cpu_record_t *record = &g_cpu_records[i];
    if (record->apic_id == bsp_id) continue;
    __atomic_store_n(&record->requested_generation, 1U, __ATOMIC_RELEASE);
    lapic_send(record->apic_id, 33U);
  }
  uint64_t work_deadline = rdtsc() + UINT64_C(2000000000);
  for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
    x86_64_cpu_record_t *record = &g_cpu_records[i];
    if (record->apic_id == bsp_id) continue;
    while (__atomic_load_n(&record->completed_generation, __ATOMIC_ACQUIRE) !=
               1U &&
           (int64_t)(rdtsc() - work_deadline) < 0) {
      __asm__ volatile("pause");
    }
    if (record->completed_generation != 1U || record->checksum == 0U) {
      panic_halt(serial_base, "AP worker timeout");
    }
    combined ^= record->checksum;
    ++workers;
  }
  serial_puts(serial_base, "x86_64: SMP IPI worker dispatch passed workers=");
  serial_dec(serial_base, workers);
  serial_puts(serial_base, " checksum=");
  serial_hex64(serial_base, combined);
  serial_puts(serial_base, "\n");
#endif
}

/* validate_x86_os_contract and validate_hardware_gate moved to
 * early_contract.c; the milestone 48-51 stage that called them, and the rest
 * of the post-AP platform bring-up around it, now lives in early_post_smp.c
 * and runs at the same point in the sequence. */

void x86_64_kmain(const xaios_boot_info_t *boot) {
  uint16_t serial_base = COM1_PORT;
  if (boot != 0 && boot->uart_base != 0 && boot->uart_base <= UINT16_MAX) {
    serial_base = (uint16_t)boot->uart_base;
  }
  serial_init(serial_base);

  serial_puts(serial_base, "XAIOS x86_64 kernel starting\n");
  if (boot == 0 || boot->magic != XAIOS_BOOT_INFO_MAGIC ||
      boot->version != XAIOS_BOOT_INFO_VERSION) {
    serial_puts(serial_base, "x86_64: boot info invalid\n");
    for (;;) {
      __asm__ volatile("hlt");
    }
  }
  g_boot_info_copy = *boot;
  boot = &g_boot_info_copy;

  serial_puts(serial_base, "x86_64: UEFI boot info valid\n");
  serial_puts(serial_base, "x86_64: memory descriptors=");
  serial_hex64(serial_base, memory_descriptor_count(boot));
  serial_puts(serial_base, " desc_size=");
  serial_hex64(serial_base, boot->memory_descriptor_size);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: kernel range ");
  serial_hex64(serial_base, boot->kernel_phys_base);
  serial_puts(serial_base, "-");
  serial_hex64(serial_base, boot->kernel_phys_end);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: COM1 serial online\n");
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 43 boot path passed\n");
  uint32_t avx_eax = 0U;
  uint32_t avx_ebx = 0U;
  uint32_t avx_ecx = 0U;
  uint32_t avx_edx = 0U;
  cpuid(1U, 0U, &avx_eax, &avx_ebx, &avx_ecx, &avx_edx);
  if ((avx_ecx & (UINT32_C(1) << 26U)) != 0U &&
      (avx_ecx & (UINT32_C(1) << 28U)) != 0U) {
    write_cr4(read_cr4() | X86_CR4_OSXSAVE);
    write_xcr0(UINT64_C(7));
  }
  if (xaios_packed_avx2_available()) {
    serial_puts(serial_base,
                "x86_64: AVX2 packed no-expand known-answer canary passed\n");
  } else {
    serial_puts(serial_base,
                "x86_64: AVX2 packed canary unsupported on selected CPU\n");
  }
  install_gdt_tss(serial_base);
  install_idt(serial_base);
  validate_exception_round_trip(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 44 early exceptions passed\n");
  parse_memory_map(serial_base, boot);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 45 memory map passed\n");
  xaios_x86_early_acpi_parse(serial_base, boot);
  xaios_x86_early_acpi_prepare_cpu_records(serial_base, &g_cpu_records,
                                           &g_cpu_record_count);
  serial_puts(serial_base, "x86_64: ACPI topology and NUMA tables validated\n");
  install_page_tables(serial_base);
  if (xaios_x86_mem_page_tables_loaded() == 0U) {
    panic_halt(serial_base, "page tables not loaded");
  }
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 46 page tables passed\n");
  xaios_x86_fpu_validate(serial_base);
  xaios_x86_fpu_prepare_irq_areas(serial_base);
  xaios_x86_early_timer_discover(serial_base);
  validate_lapic_timer_interrupt(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 47 timers APIC passed\n");
  start_application_processors(serial_base, boot);
  xaios_x86_early_post_smp_bringup(serial_base, boot);
}
