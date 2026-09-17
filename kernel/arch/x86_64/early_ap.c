/* x86-64 application-processor bring-up: the trampoline patch, the C entry the
 * trampoline jumps to, and the INIT-SIPI-SIPI sequence that starts every
 * secondary and then runs the legacy IPI-worker self-test.
 *
 * Split out of kernel/arch/x86_64/early.c. The whole cluster moved in one
 * piece -- bytes_copy(), tsc_delay(), x86_64_ap_entry(), write_u32(),
 * write_u64(), patch_ap_trampoline() and start_application_processors() -- so
 * every statement kept its place: the `sti; hlt` idle pair, the `mfence` after
 * the trampoline patch, the `cli`/`sti` pair, the delays between the INIT and
 * the two SIPIs, the `sti; hlt; cli` timer wait and every register write that
 * programs CR4/XCR0/CR3 and the LAPIC are the ones early.c executed at the
 * same points. Moving this code to another translation unit changes no
 * register write, no barrier, no delay and no order; the trampoline still
 * reaches its entry through the same absolute address
 * patch_ap_trampoline() installs, and x86_64_kmain still calls the sequence at
 * the one point it did, through the start_application_processors alias in
 * early_ap.h.
 *
 * The one thing that could not move is the storage the AP path reads and
 * writes: early.c owns the CPU record table and the scalars, and its own
 * xaios_x86_early_acpi_prepare_cpu_records() call passes their addresses, so
 * they stay defined there and are reached from here through the extern
 * declarations early_ap.h carries. Only the file-scope `static` was dropped;
 * every statement still spells them the way it did, through the aliases in
 * that header.
 *
 * The helpers keep their internal linkage: bytes_copy(), tsc_delay(),
 * write_u32() and write_u64() moved with their only callers and stay `static`.
 * start_application_processors is the one symbol that gains external linkage;
 * it is defined here as xaios_x86_ap_start_all and declared in early_ap.h. */

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

#include "early_ap.h"
#include "early_fpu.h"
#include "early_idt.h"
#include "early_lapic.h"
#include "early_module.h"

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

/* The primitives the moved code names the way early.c did; each expands to the
 * function defined once in the module beside this one, and the names
 * early_module.h already declares keep those exact spellings. The g_-prefixed
 * objects come from early_ap.h above. */
#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define serial_hex64 xaios_x86_early_serial_hex64
#define panic_halt xaios_x86_early_panic_halt
#define early_alloc xaios_x86_mem_alloc
#define install_ap_gdt_tss xaios_x86_gdt_install_ap
#define prepare_tsc_aux xaios_x86_early_prepare_tsc_aux
#define lapic_write xaios_x86_early_lapic_write
#define lapic_id xaios_x86_early_lapic_id
#define lapic_send xaios_x86_early_lapic_send
#define g_idt g_x86_idt

#define COM1_PORT UINT16_C(0x3f8)
#define PAGE_SIZE UINT64_C(4096)

/* The ten symbols entry.S lays out for the real-mode trampoline, and the entry
 * it jumps to; these declarations moved here with patch_ap_trampoline(), their
 * only user. */
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

static void bytes_copy(void *destination, const void *source, uint64_t bytes) {
  uint8_t *output = (uint8_t *)destination;
  const uint8_t *input = (const uint8_t *)source;
  for (uint64_t i = 0U; i < bytes; ++i) output[i] = input[i];
}

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

void start_application_processors(uint16_t serial_base,
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
