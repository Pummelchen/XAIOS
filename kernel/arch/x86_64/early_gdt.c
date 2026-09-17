/* x86_64 GDT/TSS construction for the BSP and for each application processor.
 *
 * Split out of kernel/arch/x86_64/early.c. Both functions moved verbatim; the
 * only edits are the seam in early_module.h -- the descriptor-table pointer
 * type install_idt and the AP entry still load, the kernel/syscall-stack
 * constants both sides use, and the two scalar accessors that replace the
 * `g_tss.rsp0` reads and writes early.c's platform hooks used to make through
 * the file-scope record.
 *
 * Position in the boot. `xaios_x86_gdt_install` is called by x86_64_kmain
 * after the boot-info copy, the serial banner and the AVX2 packed canary, and
 * before install_idt -- the gates install_idt writes need the code selector
 * this installs, and `lidt` runs after the GDT is loaded.
 * `xaios_x86_gdt_install_ap` is called from x86_64_ap_entry after that CPU has
 * reloaded the IDT, programmed CR4/XCR0 and the LAPIC spurious vector, and
 * before it publishes itself online: it runs after SIPI delivery and is not
 * part of the INIT-SIPI-SIPI sequence. Nothing here touches the AP trampoline,
 * the timer discovery or the interrupt dispatch.
 *
 * `g_gdt`, `g_tss` and `g_syscall_stack` live here now. early.c reaches the
 * BSP's rsp0 through the two scalar accessors below, never through a pointer
 * into this file's mutable state; a CPU record's own TSS still lives in the
 * record early.c owns. */

#include "early_module.h"

/* early.c's primitives, under the names early_module.h declares. */
#define serial_puts xaios_x86_early_serial_puts
#define serial_hex64 xaios_x86_early_serial_hex64
#define panic_halt xaios_x86_early_panic_halt

#define COM1_PORT UINT16_C(0x3f8)
#define PAGE_SIZE UINT64_C(4096)

/* Defined in entry.S; early.c's copies of these two declarations moved here
 * with their only remaining callers. */
extern void x86_64_load_gdt(const x86_64_idtr_t *gdtr);
extern void x86_64_load_tss(void);

static uint64_t g_gdt[7] __attribute__((aligned(16)));
static x86_64_tss_t g_tss;
static uint8_t g_syscall_stack[X86_KERNEL_STACK_SIZE]
    __attribute__((aligned(PAGE_SIZE)));

uint64_t xaios_x86_gdt_bsp_rsp0(void) { return g_tss.rsp0; }

void xaios_x86_gdt_set_bsp_rsp0(uint64_t rsp0) { g_tss.rsp0 = rsp0; }

void xaios_x86_gdt_install(uint16_t serial_base) {
  for (uint32_t i = 0U; i < 7U; ++i) g_gdt[i] = 0U;
  g_gdt[1] = UINT64_C(0x00af9a000000ffff);
  g_gdt[2] = UINT64_C(0x00cf92000000ffff);
  g_gdt[3] = UINT64_C(0x00cff2000000ffff);
  g_gdt[4] = UINT64_C(0x00affa000000ffff);
  g_tss = (x86_64_tss_t){0};
  for (uint32_t i = 0U; i < X86_KERNEL_STACK_GUARD_BYTES; ++i) {
    g_syscall_stack[i] = X86_KERNEL_STACK_GUARD_VALUE;
  }
  g_tss.rsp0 = (uint64_t)(uintptr_t)(g_syscall_stack + sizeof(g_syscall_stack));
  g_tss.io_map_base = sizeof(g_tss);
  uint64_t base = (uint64_t)(uintptr_t)&g_tss;
  uint64_t limit = sizeof(g_tss) - 1U;
  g_gdt[5] = (limit & UINT64_C(0xffff)) |
             ((base & UINT64_C(0xffffff)) << 16U) |
             (UINT64_C(0x89) << 40U) |
             ((limit & UINT64_C(0xf0000)) << 32U) |
             ((base & UINT64_C(0xff000000)) << 32U);
  g_gdt[6] = base >> 32U;
  x86_64_idtr_t gdtr = {
      .limit = (uint16_t)(sizeof(g_gdt) - 1U),
      .base = (uint64_t)(uintptr_t)g_gdt,
  };
  x86_64_load_gdt(&gdtr);
  x86_64_load_tss();
  serial_puts(serial_base, "x86_64: GDT/TSS installed rsp0=");
  serial_hex64(serial_base, g_tss.rsp0);
  serial_puts(serial_base, "\n");
}

void xaios_x86_gdt_install_ap(x86_64_cpu_record_t *record) {
  if (record == 0 || record->kernel_stack_top == 0U ||
      record->syscall_stack_top == 0U) {
    panic_halt(COM1_PORT, "AP GDT inputs");
  }
  for (uint32_t i = 0U; i < 7U; ++i) record->gdt[i] = 0U;
  record->gdt[1] = UINT64_C(0x00af9a000000ffff);
  record->gdt[2] = UINT64_C(0x00cf92000000ffff);
  record->gdt[3] = UINT64_C(0x00cff2000000ffff);
  record->gdt[4] = UINT64_C(0x00affa000000ffff);
  record->tss = (x86_64_tss_t){0};
  record->tss.rsp0 = record->syscall_stack_top;
  record->tss.io_map_base = sizeof(record->tss);
  uint64_t base = (uint64_t)(uintptr_t)&record->tss;
  uint64_t limit = sizeof(record->tss) - 1U;
  record->gdt[5] = (limit & UINT64_C(0xffff)) |
                   ((base & UINT64_C(0xffffff)) << 16U) |
                   (UINT64_C(0x89) << 40U) |
                   ((limit & UINT64_C(0xf0000)) << 32U) |
                   ((base & UINT64_C(0xff000000)) << 32U);
  record->gdt[6] = base >> 32U;
  x86_64_idtr_t gdtr = {
      .limit = (uint16_t)(sizeof(record->gdt) - 1U),
      .base = (uint64_t)(uintptr_t)record->gdt,
  };
  x86_64_load_gdt(&gdtr);
  x86_64_load_tss();
}
