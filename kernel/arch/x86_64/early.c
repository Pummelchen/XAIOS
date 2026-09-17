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
#include "early_serial.h"
#include "early_exception.h"
#include "early_contract.h"
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

/* The paging/PM and PCI halves moved to early_mem.c and early_pci.c; these
 * aliases keep every call site in this file spelling them the way it did. */
#define early_alloc xaios_x86_mem_alloc
#define parse_memory_map xaios_x86_mem_parse_map
#define install_page_tables xaios_x86_mem_install_page_tables
#define validate_ring3_syscall xaios_x86_mem_validate_ring3
#define discover_pci xaios_x86_pci_discover
#define validate_virtio_block_operation xaios_x86_pci_validate_virtio_block
#define validate_virtio_network_operation xaios_x86_pci_validate_virtio_network

/* The GDT/TSS construction moved to early_gdt.c; these aliases keep its two
 * call sites -- x86_64_kmain and x86_64_ap_entry -- spelling it the way they
 * did. The BSP's rsp0 is reached through the scalar accessors the platform
 * hooks below call, never through a pointer into that file's state. */
#define install_gdt_tss xaios_x86_gdt_install
#define install_ap_gdt_tss xaios_x86_gdt_install_ap

/* The exception entry and its controlled round-trip moved to early_exception.c;
 * this alias keeps the one call site in x86_64_kmain spelling it the way it
 * did. The entry itself keeps its name because entry.S calls it by that name. */
#define validate_exception_round_trip xaios_x86_early_exception_round_trip

/* The OS-contract and hardware-gate reports moved to early_contract.c; these
 * aliases keep their two call sites at the end of x86_64_kmain spelling them
 * the way they did. Their report state moved with them, and neither report
 * starts an AP, sends an IPI or programs a timer. */
#define validate_x86_os_contract xaios_x86_early_validate_os_contract
#define validate_hardware_gate xaios_x86_early_validate_hardware_gate

#define COM1_PORT UINT16_C(0x3f8)
#define PAGE_SIZE UINT64_C(4096)
#define X86_EFLAGS_ID UINT64_C(1 << 21)
/* The CR4/XCR0/XSAVE control bits and the primitives that program them now
 * live in early_fpu.h, which the extended-state block below and the AVX2 canary
 * in x86_64_kmain share with early_fpu.c. MSR_IA32_APIC_BASE moved to
 * early_module.h, because the LAPIC primitives below and the calibration in
 * early_timer_discover.c both read that one register. */
/* The value RDTSCP returns in ECX: this kernel puts the CPU's ordinal there so
 * a CPU can name itself without reading the APIC (see the fast identity). */
#define MSR_IA32_TSC_AUX UINT32_C(0xc0000103)
#define APIC_BASE_ENABLE UINT64_C(1 << 11)
#define APIC_BASE_X2APIC UINT64_C(1 << 10)
#define APIC_ID UINT32_C(0x020)
#define APIC_VERSION UINT32_C(0x030)
#define APIC_EOI UINT32_C(0x0b0)
#define APIC_SPURIOUS UINT32_C(0x0f0)
#define APIC_LVT_TIMER UINT32_C(0x320)
#define APIC_ICR_LOW UINT32_C(0x300)
#define APIC_ICR_HIGH UINT32_C(0x310)
#define APIC_TIMER_INITIAL UINT32_C(0x380)
#define APIC_TIMER_CURRENT UINT32_C(0x390)
#define APIC_TIMER_DIVIDE UINT32_C(0x3e0)
#define X2APIC_MSR_BASE UINT32_C(0x800)
#define X2APIC_ICR_MSR UINT32_C(0x830)
/* X86_USER_BASE, _WINDOW_SIZE and _LOG_MAX moved to early_irq.c with the
 * ring-3 syscall dispatch that was their only user. */
/* X86_KERNEL_STACK_SIZE, _GUARD_BYTES and _GUARD_VALUE moved to
 * early_module.h: early_gdt.c sizes the BSP syscall stack with them and this
 * file guards the kernel and syscall stacks with them. */
#define IDT_PRESENT UINT8_C(0x80)
#define IDT_INTERRUPT_GATE UINT8_C(0x0e)
#define IDT_TRAP_GATE UINT8_C(0x0f)

typedef struct x86_64_idt_entry {
  uint16_t offset_low;
  uint16_t selector;
  uint8_t ist;
  uint8_t type_attr;
  uint16_t offset_mid;
  uint32_t offset_high;
  uint32_t zero;
} __attribute__((packed)) x86_64_idt_entry_t;

/* x86_64_idtr_t moved to early_module.h, where early_gdt.c's builder and the
 * two loaders in this file both read it. */

/* x86_64_exception_frame_t moved to early_module.h: the exception entry below
 * and the interrupt dispatch in early_irq.c both name it, and its layout is
 * entry.S's. */

/* x86_64_contract_state_t and x86_64_hardware_gate_state_t moved to
 * early_contract.c with the two report functions that were their only users. */

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

static x86_64_idt_entry_t g_idt[256] __attribute__((aligned(16)));
extern void (*const x86_64_device_irq_stubs[64])(void);
/* g_gdt, g_tss and g_syscall_stack moved to early_gdt.c with the builder that
 * fills them; this file reaches the BSP's rsp0 through the scalar accessors
 * xaios_x86_gdt_bsp_rsp0/_set_bsp_rsp0. A CPU record's own TSS is still here. */
/* g_contract and g_hardware_gate moved to early_contract.c with the two
 * report functions that were their only readers and writers. */
static uint32_t g_exception_vectors_installed;
static uint16_t g_code_selector;
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
/* Whether IA32_TSC_AUX holds this CPU's ordinal, so `current_ordinal_fast`
 * may use RDTSCP. Set by whichever CPU prepares first; it is a property of the
 * CPU model, not of one CPU. */
static uint32_t g_tsc_aux_ready;
/* The idle-wakeup self-test's probe pair moved to early_platform.c with its
 * setter and getter; the idle loop below still reads it through
 * xaios_x86_early_idle_probe_get. */

#if XAIOS_X86_COMMON_RUNTIME
extern void kmain(const xaios_boot_info_t *boot);
#endif

static inline uint64_t rdtsc(void);
static uint32_t lapic_id(void);
static uint32_t current_ordinal_fast(void);
static void lapic_send(uint32_t destination, uint32_t command);
static void lapic_write(uint32_t offset, uint32_t value);

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

static inline uint64_t read_cr3(void) {
  uint64_t value = 0;
  __asm__ volatile("mov %%cr3, %0" : "=r"(value));
  return value;
}

/* The CR4/XCR0/XSAVE/FXSAVE primitives, the per-CPU IRQ-state area lookup and
 * the interrupt entry's state save/restore now live in early_fpu.h and
 * early_fpu.c. The primitives are `static inline` in that header, so this file
 * still inlines them at the AVX2 canary and in x86_64_ap_entry; the two
 * save/restore entry points keep their names because entry.S calls them. */

static inline void write_cr3(uint64_t value) {
  __asm__ volatile("mov %0, %%cr3" : : "r"(value) : "memory");
}

static inline uint64_t rdmsr(uint32_t msr) {
  uint32_t low = 0;
  uint32_t high = 0;
  __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
  return ((uint64_t)high << 32) | low;
}

static inline uint64_t rdtsc(void) {
  uint32_t low = 0U;
  uint32_t high = 0U;
  __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
  return ((uint64_t)high << 32U) | low;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
  __asm__ volatile("wrmsr" : : "c"(msr), "a"((uint32_t)value),
                   "d"((uint32_t)(value >> 32)) : "memory");
}

static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                         uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
  __asm__ volatile("cpuid"
                   : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                   : "a"(leaf), "c"(subleaf));
}

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

/* install_gdt_tss and install_ap_gdt_tss moved to early_gdt.c as
 * xaios_x86_gdt_install and xaios_x86_gdt_install_ap, together with g_gdt,
 * g_tss and g_syscall_stack. The aliases at the top of this file keep both
 * call sites -- x86_64_kmain and x86_64_ap_entry -- spelling them as before. */

/* kernel_stack_guard_valid moved to early_irq.c with the syscall dispatch that
 * calls it, under the same XAIOS_X86_COMMON_RUNTIME guard. Nothing else in
 * this file used it. */

static void install_idt(uint16_t serial_base) {
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

static uint32_t lapic_read(uint32_t offset) {
  uint64_t apic_base = rdmsr(MSR_IA32_APIC_BASE);
  if ((apic_base & (APIC_BASE_ENABLE | APIC_BASE_X2APIC)) ==
      (APIC_BASE_ENABLE | APIC_BASE_X2APIC)) {
    return (uint32_t)rdmsr(X2APIC_MSR_BASE + (offset >> 4U));
  }
  volatile uint32_t *lapic = (volatile uint32_t *)(uintptr_t)(
      apic_base & UINT64_C(0xfffff000));
  return lapic[offset / sizeof(uint32_t)];
}

static void lapic_write(uint32_t offset, uint32_t value) {
  uint64_t apic_base = rdmsr(MSR_IA32_APIC_BASE);
  if ((apic_base & (APIC_BASE_ENABLE | APIC_BASE_X2APIC)) ==
      (APIC_BASE_ENABLE | APIC_BASE_X2APIC)) {
    wrmsr(X2APIC_MSR_BASE + (offset >> 4U), value);
    return;
  }
  volatile uint32_t *lapic = (volatile uint32_t *)(uintptr_t)(
      apic_base & UINT64_C(0xfffff000));
  lapic[offset / sizeof(uint32_t)] = value;
  (void)lapic[APIC_ID / sizeof(uint32_t)];
}

static uint32_t lapic_id(void) {
  uint64_t apic_base = rdmsr(MSR_IA32_APIC_BASE);
  uint32_t id = lapic_read(APIC_ID);
  return (apic_base & APIC_BASE_X2APIC) != 0U ? id : id >> 24U;
}

/* This CPU's ordinal without going to the APIC.
 *
 * `x86_64_platform_current_ordinal` reads the APIC id, which under emulation
 * is a host round trip -- too expensive to pay on every external interrupt, and
 * far too expensive to pay on every iteration of a spin loop. RDTSCP returns
 * the IA32_TSC_AUX value, bring-up puts this CPU's ordinal there, and reading
 * it costs a few cycles. A CPU whose CPUID has no RDTSCP keeps the APIC read,
 * and the ordinal is validated against the record table either way. */
static uint32_t current_ordinal_fast(void) {
  if (g_tsc_aux_ready == 0U) return x86_64_platform_current_ordinal();
  uint32_t low = 0U;
  uint32_t high = 0U;
  uint32_t aux = 0U;
  __asm__ volatile("rdtscp" : "=a"(low), "=d"(high), "=c"(aux) : : "memory");
  return aux < g_cpu_record_count ? aux : x86_64_platform_current_ordinal();
}

/* Whether this CPU can name itself with RDTSCP, and if so, teach it its own
 * ordinal. Called once per CPU, before that CPU can run anything that asks. */
static void prepare_tsc_aux(uint32_t ordinal) {
  uint32_t eax = 0U;
  uint32_t ebx = 0U;
  uint32_t ecx = 0U;
  uint32_t edx = 0U;
  cpuid(UINT32_C(0x80000000), 0U, &eax, &ebx, &ecx, &edx);
  if (eax < UINT32_C(0x80000001)) return;
  cpuid(UINT32_C(0x80000001), 0U, &eax, &ebx, &ecx, &edx);
  if ((edx & (UINT32_C(1) << 27U)) == 0U) return; /* no RDTSCP */
  wrmsr(MSR_IA32_TSC_AUX, ordinal);
  g_tsc_aux_ready = 1U;
}

static void lapic_send(uint32_t destination, uint32_t command) {
  uint64_t apic_base = rdmsr(MSR_IA32_APIC_BASE);
  if ((apic_base & APIC_BASE_X2APIC) != 0U) {
    wrmsr(X2APIC_ICR_MSR, ((uint64_t)destination << 32U) | command);
    return;
  }
  while ((lapic_read(APIC_ICR_LOW) & UINT32_C(1 << 12)) != 0U) {
    __asm__ volatile("pause");
  }
  lapic_write(APIC_ICR_HIGH, destination << 24U);
  lapic_write(APIC_ICR_LOW, command);
  while ((lapic_read(APIC_ICR_LOW) & UINT32_C(1 << 12)) != 0U) {
    __asm__ volatile("pause");
  }
}

/* The primitives early_tlb.c calls, exported under the names early_module.h
 * declares. They are the same functions above and below, not copies. */
void xaios_x86_early_lapic_send(uint32_t destination, uint32_t command) {
  lapic_send(destination, command);
}

uint32_t xaios_x86_early_current_ordinal_fast(void) {
  return current_ordinal_fast();
}

/* The two more primitives early_irq.c's interrupt dispatch calls, exported
 * under the names early_module.h declares. They are the same flag and the same
 * write the rest of this file uses, not copies. */
uint32_t xaios_x86_early_lapic_ready(void) { return g_lapic_ready; }

void xaios_x86_early_lapic_write(uint32_t offset, uint32_t value) {
  lapic_write(offset, value);
}

/* The serial and panic primitives this block used to define now live in
 * early_serial.c, which defines them once under the exported names
 * early_module.h and early_serial.h declare. */

/* The primitive early_cpu.c's placement report calls; declared in the same
 * early_module.h seam and defined here, not copied. */
void xaios_x86_early_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                           uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
  cpuid(leaf, subleaf, eax, ebx, ecx, edx);
}

/* The MSR/CR/TSC/APIC primitives early_mem.c and early_pci.c call, exported
 * under the names early_module.h declares. They are the same functions above
 * and below, not copies. */
uint64_t xaios_x86_early_rdmsr(uint32_t msr) { return rdmsr(msr); }

void xaios_x86_early_wrmsr(uint32_t msr, uint64_t value) { wrmsr(msr, value); }

uint64_t xaios_x86_early_read_cr3(void) { return read_cr3(); }

void xaios_x86_early_write_cr3(uint64_t value) { write_cr3(value); }

uint64_t xaios_x86_early_rdtsc(void) { return rdtsc(); }

uint32_t xaios_x86_early_lapic_id(void) { return lapic_id(); }

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
 * early_contract.c as xaios_x86_early_validate_os_contract and
 * xaios_x86_early_validate_hardware_gate, together with the report structs and
 * the g_contract/g_hardware_gate state they wrote. The aliases at the top of
 * this file keep their two call sites at the end of x86_64_kmain spelling them
 * as before, at the same point in the sequence. */

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
#if XAIOS_X86_COMMON_RUNTIME
  kmain(boot);
  panic_halt(serial_base, "common kernel returned");
#else
  validate_ring3_syscall(serial_base);
  klog_init(boot);
  security_self_test();
  serial_puts(serial_base,
              "x86_64: common security policy self-test passed\n");
  ai_kernel_self_test();
  serial_puts(serial_base,
              "x86_64: scalar AI kernel self-test passed\n");
  discover_pci(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 48 PCI discovery passed\n");
  validate_virtio_block_operation(serial_base);
  validate_virtio_network_operation(serial_base);
  x86_64_early_cpu_build_placement_policy(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 49 placement policy passed\n");
  validate_x86_os_contract(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 50 portable common runtime passed platform services pending\n");
  validate_hardware_gate(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 51 hardware gate blocked\n");
#endif

  for (;;) {
    __asm__ volatile("hlt");
  }
}
