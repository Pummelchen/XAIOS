/* The x86-64 IDT: the 256 gates entry.S's stubs are installed in, the two gate
 * builders, install_idt and the report it prints.
 *
 * Extracted verbatim from kernel/arch/x86_64/early.c. This is a boot-position
 * function and the storage only it fills: x86_64_kmain calls
 * xaios_x86_idt_install() once, after install_gdt_tss() and before
 * validate_exception_round_trip() runs, and that call keeps its position. No
 * register write, barrier or delay changes and no statement in early.c changes
 * -- the one statement outside this file that names the table,
 * x86_64_ap_entry's `lidt`, still loads the same object through the g_idt alias
 * early.c defines for it. The table is built once, on the BSP, before any
 * INIT-SIPI-SIPI is sent, so the module has no ordering coupling to AP startup:
 * an AP only reloads the finished table's address, which it did before too.
 *
 * early_module.h is the shared seam and declares the serial primitives and the
 * x86_64_idtr_t both loaders spell; early_idt.h declares what crosses back. */

#include "early_idt.h"

/* early.c's primitives, under the names early_module.h declares. */
#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define serial_hex64 xaios_x86_early_serial_hex64

/* The table's builders keep the name they had in early.c; the exported object
 * is the prefixed one early_idt.h declares, and early.c's alias resolves the AP
 * entry's reload to the same object. */
#define g_idt g_x86_idt

#define IDT_PRESENT UINT8_C(0x80)
#define IDT_INTERRUPT_GATE UINT8_C(0x0e)
#define IDT_TRAP_GATE UINT8_C(0x0f)

/* entry.S's stubs, installed by name: the 32 CPU-exception gates, the four
 * fixed IRQ gates, the 128 and 255 gates the syscall/ring-3 paths use, and the
 * device-gate table. */
extern void x86_64_isr_0(void);
extern void x86_64_isr_1(void);
extern void x86_64_isr_2(void);
extern void x86_64_isr_3(void);
extern void x86_64_isr_4(void);
extern void x86_64_isr_5(void);
extern void x86_64_isr_6(void);
extern void x86_64_isr_7(void);
extern void x86_64_isr_8(void);
extern void x86_64_isr_9(void);
extern void x86_64_isr_10(void);
extern void x86_64_isr_11(void);
extern void x86_64_isr_12(void);
extern void x86_64_isr_13(void);
extern void x86_64_isr_14(void);
extern void x86_64_isr_15(void);
extern void x86_64_isr_16(void);
extern void x86_64_isr_17(void);
extern void x86_64_isr_18(void);
extern void x86_64_isr_19(void);
extern void x86_64_isr_20(void);
extern void x86_64_isr_21(void);
extern void x86_64_isr_22(void);
extern void x86_64_isr_23(void);
extern void x86_64_isr_24(void);
extern void x86_64_isr_25(void);
extern void x86_64_isr_26(void);
extern void x86_64_isr_27(void);
extern void x86_64_isr_28(void);
extern void x86_64_isr_29(void);
extern void x86_64_isr_30(void);
extern void x86_64_isr_31(void);
extern void x86_64_irq_32(void);
extern void x86_64_irq_33(void);
extern void x86_64_irq_34(void);
extern void x86_64_irq_35(void);
extern void x86_64_irq_128(void);
extern void x86_64_irq_255(void);

x86_64_idt_entry_t g_x86_idt[256] __attribute__((aligned(16)));
extern void (*const x86_64_device_irq_stubs[64])(void);
/* Which vectors install_idt published, and the code selector read from %%cs:
 * both were file-scope in early.c and are file-scope here. */
static uint32_t g_exception_vectors_installed;
static uint16_t g_code_selector;

static void idt_set_gate(uint8_t vector, void (*handler)(void)) {
  uint64_t address = (uint64_t)(uintptr_t)handler;
  g_idt[vector].offset_low = (uint16_t)(address & UINT64_C(0xffff));
  g_idt[vector].selector = g_code_selector;
  g_idt[vector].ist = 0;
  g_idt[vector].type_attr = IDT_PRESENT | IDT_INTERRUPT_GATE;
  g_idt[vector].offset_mid = (uint16_t)((address >> 16) & UINT64_C(0xffff));
  g_idt[vector].offset_high = (uint32_t)(address >> 32);
  g_idt[vector].zero = 0;
}

static void idt_set_user_gate(uint8_t vector, void (*handler)(void)) {
  idt_set_gate(vector, handler);
  g_idt[vector].type_attr = IDT_PRESENT | UINT8_C(0x60) | IDT_TRAP_GATE;
}

void xaios_x86_idt_install(uint16_t serial_base) {
  void (*handlers[32])(void) = {
      x86_64_isr_0,  x86_64_isr_1,  x86_64_isr_2,  x86_64_isr_3,
      x86_64_isr_4,  x86_64_isr_5,  x86_64_isr_6,  x86_64_isr_7,
      x86_64_isr_8,  x86_64_isr_9,  x86_64_isr_10, x86_64_isr_11,
      x86_64_isr_12, x86_64_isr_13, x86_64_isr_14, x86_64_isr_15,
      x86_64_isr_16, x86_64_isr_17, x86_64_isr_18, x86_64_isr_19,
      x86_64_isr_20, x86_64_isr_21, x86_64_isr_22, x86_64_isr_23,
      x86_64_isr_24, x86_64_isr_25, x86_64_isr_26, x86_64_isr_27,
      x86_64_isr_28, x86_64_isr_29, x86_64_isr_30, x86_64_isr_31};

  __asm__ volatile("mov %%cs, %0" : "=r"(g_code_selector));
  for (uint32_t i = 0; i < 256; ++i) {
    g_idt[i] = (x86_64_idt_entry_t){0};
  }
  for (uint8_t i = 0; i < 32; ++i) {
    idt_set_gate(i, handlers[i]);
  }
  idt_set_gate(32U, x86_64_irq_32);
  idt_set_gate(33U, x86_64_irq_33);
  idt_set_gate(34U, x86_64_irq_34);
  idt_set_gate(35U, x86_64_irq_35);
  for (uint32_t vector = 64U; vector < 128U; ++vector) {
    idt_set_gate((uint8_t)vector, x86_64_device_irq_stubs[vector - 64U]);
  }
  idt_set_user_gate(128U, x86_64_irq_128);
  idt_set_gate(255U, x86_64_irq_255);

  x86_64_idtr_t idtr = {
      .limit = (uint16_t)(sizeof(g_idt) - 1U),
      .base = (uint64_t)(uintptr_t)g_idt,
  };
  __asm__ volatile("lidt %0" : : "m"(idtr) : "memory");
  g_exception_vectors_installed = 32;
  serial_puts(serial_base, "x86_64: IDT installed vectors=");
  serial_dec(serial_base, g_exception_vectors_installed);
  serial_puts(serial_base, " code_selector=");
  serial_hex64(serial_base, g_code_selector);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: early exception path online\n");
  serial_puts(serial_base, "x86_64: IRQ vector 32 installed\n");
}
