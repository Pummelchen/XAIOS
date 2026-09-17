#ifndef XAIOS_X86_64_EARLY_IDT_H
#define XAIOS_X86_64_EARLY_IDT_H

/* The private seam between kernel/arch/x86_64/early.c and
 * kernel/arch/x86_64/early_idt.c. Both files include it and nothing in it is
 * visible outside those two translation units.
 *
 * The IDT is one object shared by both sides, defined exactly once in
 * early_idt.c: install_idt fills it on the BSP and x86_64_ap_entry reloads its
 * address with `lidt` on every AP, which is why the gate layout and the table
 * are declared here rather than kept file-scope on either side. early.c names
 * the table through the g_idt alias beside its other module aliases, so the AP
 * entry's IDTR reload is the statement it always was. */

#include <xaios/types.h>

#include "early_module.h"

typedef struct x86_64_idt_entry {
  uint16_t offset_low;
  uint16_t selector;
  uint8_t ist;
  uint8_t type_attr;
  uint16_t offset_mid;
  uint32_t offset_high;
  uint32_t zero;
} __attribute__((packed)) x86_64_idt_entry_t;

/* Defined in early_idt.c: the 256 gates, and the builder x86_64_kmain calls
 * once, after install_gdt_tss and before the exception round trip. */
extern x86_64_idt_entry_t g_x86_idt[256];
void xaios_x86_idt_install(uint16_t serial_base);

#endif
