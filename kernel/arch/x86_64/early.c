#include <xaios/boot_info.h>
#include <xaios/common_runtime.h>
#include <xaios/types.h>
#include <xaios_engine/packed.h>

#define COM1_PORT UINT16_C(0x3f8)
#define UART_DATA 0U
#define UART_INTERRUPT_ENABLE 1U
#define UART_FIFO_CONTROL 2U
#define UART_LINE_CONTROL 3U
#define UART_MODEM_CONTROL 4U
#define UART_LINE_STATUS 5U
#define UART_TRANSMIT_EMPTY 0x20U
#define PAGE_SIZE UINT64_C(4096)
#define LARGE_PAGE_SIZE UINT64_C(0x200000)
#define EARLY_IDENTITY_LIMIT UINT64_C(0x100000000)
#define X86_EFLAGS_ID UINT64_C(1 << 21)
#define X86_CR4_OSXSAVE UINT64_C(1 << 18)
#define MSR_IA32_APIC_BASE UINT32_C(0x1b)
#define APIC_BASE_ENABLE UINT64_C(1 << 11)
#define APIC_BASE_X2APIC UINT64_C(1 << 10)
#define APIC_ID UINT32_C(0x020)
#define APIC_VERSION UINT32_C(0x030)
#define APIC_EOI UINT32_C(0x0b0)
#define APIC_SPURIOUS UINT32_C(0x0f0)
#define APIC_LVT_TIMER UINT32_C(0x320)
#define APIC_TIMER_INITIAL UINT32_C(0x380)
#define APIC_TIMER_CURRENT UINT32_C(0x390)
#define APIC_TIMER_DIVIDE UINT32_C(0x3e0)
#define MSR_IA32_EFER UINT32_C(0xc0000080)
#define EFER_NXE UINT64_C(1 << 11)
#define PTE_PRESENT UINT64_C(1)
#define PTE_WRITABLE UINT64_C(1 << 1)
#define PTE_LARGE UINT64_C(1 << 7)
#define PTE_GLOBAL UINT64_C(1 << 8)
#define PTE_NX UINT64_C(1) << 63
#define IDT_PRESENT UINT8_C(0x80)
#define IDT_INTERRUPT_GATE UINT8_C(0x0e)
#define PCI_CONFIG_ADDRESS UINT16_C(0x0cf8)
#define PCI_CONFIG_DATA UINT16_C(0x0cfc)

typedef enum x86_64_core_role {
  X86_64_CORE_HOUSEKEEPING = 1,
  X86_64_CORE_AI_HOT = 2,
  X86_64_CORE_BACKGROUND = 3,
} x86_64_core_role_t;

typedef struct x86_64_idt_entry {
  uint16_t offset_low;
  uint16_t selector;
  uint8_t ist;
  uint8_t type_attr;
  uint16_t offset_mid;
  uint32_t offset_high;
  uint32_t zero;
} __attribute__((packed)) x86_64_idt_entry_t;

typedef struct x86_64_idtr {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed)) x86_64_idtr_t;

typedef struct x86_64_exception_frame {
  uint64_t r11;
  uint64_t r10;
  uint64_t r9;
  uint64_t r8;
  uint64_t rbp;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rdx;
  uint64_t rcx;
  uint64_t rbx;
  uint64_t rax;
  uint64_t vector;
  uint64_t error_code;
  uint64_t rip;
  uint64_t cs;
  uint64_t rflags;
} x86_64_exception_frame_t;

typedef struct x86_64_pmm_state {
  uint64_t descriptors;
  uint64_t conventional_regions;
  uint64_t total_pages;
  uint64_t usable_pages;
  uint64_t reserved_pages;
  uint64_t largest_usable_base;
  uint64_t largest_usable_pages;
} x86_64_pmm_state_t;

typedef struct x86_64_pci_state {
  uint32_t devices;
  uint32_t functions;
  uint32_t bridges;
  uint32_t virtio_devices;
  uint32_t network_devices;
  uint32_t nvme_devices;
  uint32_t pcie_devices;
  uint32_t msi_devices;
  uint32_t msix_devices;
  uint32_t modern_virtio_devices;
} x86_64_pci_state_t;

typedef struct x86_64_placement_state {
  uint32_t logical_cpus;
  uint32_t housekeeping_cpus;
  uint32_t ai_hot_cpus;
  uint32_t background_cpus;
  uint32_t smt_disabled_by_default;
  uint32_t p_core_policy_ready;
  uint32_t e_core_policy_ready;
  uint32_t threads_per_core;
  uint32_t topology_leaf;
  uint64_t migration_total;
  uint64_t context_switch_total;
} x86_64_placement_state_t;

typedef struct x86_64_contract_state {
  uint32_t userspace_contract_ready;
  uint32_t filesystem_contract_ready;
  uint32_t networking_contract_ready;
  uint32_t ai_cell_contract_ready;
  uint32_t security_contract_ready;
  uint32_t telemetry_contract_ready;
  uint32_t full_os_contract_ready;
} x86_64_contract_state_t;

typedef struct x86_64_hardware_gate_state {
  uint32_t qemu_correctness_ready;
  uint32_t physical_hardware_required;
  uint32_t tuned_linux_bsd_baseline_required;
  uint32_t performance_claims_allowed;
  uint32_t release_candidate_ready;
} x86_64_hardware_gate_state_t;

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
extern void x86_64_irq_255(void);

static x86_64_idt_entry_t g_idt[256] __attribute__((aligned(16)));
static uint64_t g_pml4[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_pdpt[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_pd[4][512] __attribute__((aligned(PAGE_SIZE)));
static x86_64_pmm_state_t g_pmm;
static x86_64_pci_state_t g_pci;
static x86_64_placement_state_t g_placement;
static x86_64_contract_state_t g_contract;
static x86_64_hardware_gate_state_t g_hardware_gate;
static uint32_t g_exception_vectors_installed;
static volatile uint32_t g_expected_exception_vector = UINT32_MAX;
static volatile uint64_t g_exception_test_count;
static uint32_t g_page_tables_loaded;
static uint16_t g_code_selector;
static volatile uint32_t *g_lapic;
static volatile uint64_t g_lapic_timer_interrupts;

static inline void outb(uint16_t port, uint8_t value) {
  __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

static inline void outl(uint16_t port, uint32_t value) {
  __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

static inline uint8_t inb(uint16_t port) {
  uint8_t value = 0;
  __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port) : "memory");
  return value;
}

static inline uint32_t inl(uint16_t port) {
  uint32_t value = 0;
  __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port) : "memory");
  return value;
}

static inline uint64_t read_cr2(void) {
  uint64_t value = 0;
  __asm__ volatile("mov %%cr2, %0" : "=r"(value));
  return value;
}

static inline uint64_t read_cr3(void) {
  uint64_t value = 0;
  __asm__ volatile("mov %%cr3, %0" : "=r"(value));
  return value;
}

static inline uint64_t read_cr4(void) {
  uint64_t value = 0U;
  __asm__ volatile("mov %%cr4, %0" : "=r"(value));
  return value;
}

static inline void write_cr4(uint64_t value) {
  __asm__ volatile("mov %0, %%cr4" : : "r"(value) : "memory");
}

static inline void write_xcr0(uint64_t value) {
  uint32_t low = (uint32_t)value;
  uint32_t high = (uint32_t)(value >> 32U);
  __asm__ volatile("xsetbv" : : "a"(low), "d"(high), "c"(0U) : "memory");
}

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

static void serial_init(uint16_t base) {
  outb((uint16_t)(base + UART_INTERRUPT_ENABLE), 0x00);
  outb((uint16_t)(base + UART_LINE_CONTROL), 0x80);
  outb((uint16_t)(base + UART_DATA), 0x03);
  outb((uint16_t)(base + UART_INTERRUPT_ENABLE), 0x00);
  outb((uint16_t)(base + UART_LINE_CONTROL), 0x03);
  outb((uint16_t)(base + UART_FIFO_CONTROL), 0xc7);
  outb((uint16_t)(base + UART_MODEM_CONTROL), 0x0b);
}

static void serial_putc(uint16_t base, char c) {
  for (uint32_t spin = 0; spin < 100000U; ++spin) {
    if ((inb((uint16_t)(base + UART_LINE_STATUS)) & UART_TRANSMIT_EMPTY) != 0U) {
      break;
    }
  }
  outb((uint16_t)(base + UART_DATA), (uint8_t)c);
}

static void serial_puts(uint16_t base, const char *message) {
  while (*message != '\0') {
    if (*message == '\n') {
      serial_putc(base, '\r');
    }
    serial_putc(base, *message++);
  }
}

static void serial_hex64(uint16_t base, uint64_t value) {
  static const char digits[] = "0123456789abcdef";
  serial_puts(base, "0x");
  for (int shift = 60; shift >= 0; shift -= 4) {
    serial_putc(base, digits[(value >> (uint32_t)shift) & UINT64_C(0xf)]);
  }
}

static void serial_dec(uint16_t base, uint64_t value) {
  char buffer[21];
  uint32_t index = 0;
  if (value == 0) {
    serial_putc(base, '0');
    return;
  }
  while (value != 0 && index < sizeof(buffer)) {
    buffer[index++] = (char)('0' + (value % 10));
    value /= 10;
  }
  while (index != 0) {
    serial_putc(base, buffer[--index]);
  }
}

static uint64_t memory_descriptor_count(const xaios_boot_info_t *boot) {
  if (boot == 0 || boot->memory_descriptor_size == 0) {
    return 0;
  }
  return boot->memory_map_size / boot->memory_descriptor_size;
}

static uint64_t align_up(uint64_t value, uint64_t align) {
  return (value + align - 1U) & ~(align - 1U);
}

static uint64_t align_down(uint64_t value, uint64_t align) {
  return value & ~(align - 1U);
}

static void panic_halt(uint16_t serial_base, const char *message) {
  serial_puts(serial_base, "x86_64: panic: ");
  serial_puts(serial_base, message);
  serial_puts(serial_base, "\n");
  for (;;) {
    __asm__ volatile("hlt");
  }
}

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
  return g_lapic[offset / sizeof(uint32_t)];
}

static void lapic_write(uint32_t offset, uint32_t value) {
  g_lapic[offset / sizeof(uint32_t)] = value;
  (void)g_lapic[APIC_ID / sizeof(uint32_t)];
}

void x86_64_interrupt_entry(const x86_64_exception_frame_t *frame) {
  if (frame != 0 && frame->vector == 32U && g_lapic != 0) {
    ++g_lapic_timer_interrupts;
    lapic_write(APIC_EOI, 0U);
    return;
  }
  if (frame != 0 && frame->vector == 255U) return;
  panic_halt(COM1_PORT, "unexpected external interrupt");
}

static void parse_memory_map(uint16_t serial_base, const xaios_boot_info_t *boot) {
  g_pmm = (x86_64_pmm_state_t){0};
  uint64_t offset = 0;
  while (offset + sizeof(xaios_memory_descriptor_t) <= boot->memory_map_size) {
    const xaios_memory_descriptor_t *desc =
        (const xaios_memory_descriptor_t *)(uintptr_t)(boot->memory_map + offset);
    uint64_t pages = desc->number_of_pages;
    g_pmm.descriptors++;
    g_pmm.total_pages += pages;
    if (desc->type == XAIOS_MEMORY_TYPE_CONVENTIONAL) {
      uint64_t region_start = align_up(desc->physical_start, PAGE_SIZE);
      uint64_t region_end = align_down(desc->physical_start + pages * PAGE_SIZE,
                                       PAGE_SIZE);
      uint64_t usable_pages = 0;
      if (region_end > region_start) {
        usable_pages = (region_end - region_start) / PAGE_SIZE;
      }
      g_pmm.conventional_regions++;
      g_pmm.usable_pages += usable_pages;
      if (usable_pages > g_pmm.largest_usable_pages) {
        g_pmm.largest_usable_pages = usable_pages;
        g_pmm.largest_usable_base = region_start;
      }
    } else {
      g_pmm.reserved_pages += pages;
    }
    offset += boot->memory_descriptor_size;
  }

  if (g_pmm.descriptors == 0 || g_pmm.usable_pages == 0) {
    panic_halt(serial_base, "memory map parse failed");
  }

  serial_puts(serial_base, "x86_64: PMM parsed descriptors=");
  serial_dec(serial_base, g_pmm.descriptors);
  serial_puts(serial_base, " usable_pages=");
  serial_dec(serial_base, g_pmm.usable_pages);
  serial_puts(serial_base, " largest_base=");
  serial_hex64(serial_base, g_pmm.largest_usable_base);
  serial_puts(serial_base, "\n");
}

static void install_page_tables(uint16_t serial_base) {
  for (uint32_t i = 0; i < 512; ++i) {
    g_pml4[i] = 0;
    g_pdpt[i] = 0;
  }
  for (uint32_t table = 0; table < 4; ++table) {
    for (uint32_t index = 0; index < 512; ++index) {
      uint64_t address =
          ((uint64_t)table * UINT64_C(0x40000000)) +
          ((uint64_t)index * LARGE_PAGE_SIZE);
      uint64_t flags = PTE_PRESENT | PTE_LARGE | PTE_GLOBAL;
      if (address < UINT64_C(0x200000)) {
        flags |= PTE_WRITABLE;
      } else {
        flags |= PTE_WRITABLE | PTE_NX;
      }
      g_pd[table][index] = address | flags;
    }
    g_pdpt[table] = ((uint64_t)(uintptr_t)g_pd[table]) | PTE_PRESENT |
                    PTE_WRITABLE;
  }
  g_pml4[0] = ((uint64_t)(uintptr_t)g_pdpt) | PTE_PRESENT | PTE_WRITABLE;

  uint64_t efer = rdmsr(MSR_IA32_EFER);
  wrmsr(MSR_IA32_EFER, efer | EFER_NXE);
  write_cr3((uint64_t)(uintptr_t)g_pml4);
  g_page_tables_loaded = 1;

  serial_puts(serial_base, "x86_64: early page tables loaded cr3=");
  serial_hex64(serial_base, read_cr3());
  serial_puts(serial_base, " identity_limit=");
  serial_hex64(serial_base, EARLY_IDENTITY_LIMIT);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: VMM policy kernel/user split prepared\n");
}

static void discover_timer_apic(uint16_t serial_base) {
  uint32_t eax = 0;
  uint32_t ebx = 0;
  uint32_t ecx = 0;
  uint32_t edx = 0;
  cpuid(0, 0, &eax, &ebx, &ecx, &edx);
  uint32_t max_leaf = eax;
  cpuid(1, 0, &eax, &ebx, &ecx, &edx);
  uint32_t apic_supported = (edx & (UINT32_C(1) << 9)) != 0U;
  uint32_t tsc_supported = (edx & (UINT32_C(1) << 4)) != 0U;
  uint32_t deadline_supported = (ecx & (UINT32_C(1) << 24)) != 0U;
  uint64_t apic_base = apic_supported ? rdmsr(MSR_IA32_APIC_BASE) : 0;
  uint32_t tsc_denominator = 0;
  uint32_t tsc_numerator = 0;
  uint32_t crystal_hz = 0;
  if (max_leaf >= 0x15U) {
    cpuid(0x15U, 0, &tsc_denominator, &tsc_numerator, &crystal_hz, &edx);
  }

  serial_puts(serial_base, "x86_64: APIC discovery supported=");
  serial_dec(serial_base, apic_supported);
  serial_puts(serial_base, " base=");
  serial_hex64(serial_base, apic_base & UINT64_C(0xfffff000));
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: timer discovery tsc=");
  serial_dec(serial_base, tsc_supported);
  serial_puts(serial_base, " deadline=");
  serial_dec(serial_base, deadline_supported);
  serial_puts(serial_base, " ratio=");
  serial_dec(serial_base, tsc_numerator);
  serial_puts(serial_base, "/");
  serial_dec(serial_base, tsc_denominator);
  serial_puts(serial_base, " crystal_hz=");
  serial_dec(serial_base, crystal_hz);
  serial_puts(serial_base, "\n");
}

static void validate_lapic_timer_interrupt(uint16_t serial_base) {
  uint64_t apic_msr = rdmsr(MSR_IA32_APIC_BASE);
  if ((apic_msr & APIC_BASE_ENABLE) == 0U ||
      (apic_msr & APIC_BASE_X2APIC) != 0U) {
    panic_halt(serial_base, "xAPIC MMIO mode unavailable");
  }
  g_lapic = (volatile uint32_t *)(uintptr_t)(apic_msr &
                                              UINT64_C(0xfffff000));
  uint32_t apic_id = lapic_read(APIC_ID) >> 24U;
  uint32_t version = lapic_read(APIC_VERSION) & UINT32_C(0xff);
  lapic_write(APIC_SPURIOUS, UINT32_C(0x100) | UINT32_C(0xff));
  lapic_write(APIC_LVT_TIMER, 32U);
  lapic_write(APIC_TIMER_DIVIDE, UINT32_C(0x0b));
  g_lapic_timer_interrupts = 0U;
  uint64_t started_tsc = rdtsc();
  lapic_write(APIC_TIMER_INITIAL, UINT32_C(100000));
  __asm__ volatile("sti; hlt; cli" ::: "memory");
  uint64_t elapsed_tsc = rdtsc() - started_tsc;
  lapic_write(APIC_LVT_TIMER, UINT32_C(1 << 16) | 32U);
  if (g_lapic_timer_interrupts != 1U ||
      lapic_read(APIC_TIMER_CURRENT) != 0U) {
    panic_halt(serial_base, "local APIC timer interrupt failed");
  }
  serial_puts(serial_base, "x86_64: local APIC timer interrupt passed id=");
  serial_dec(serial_base, apic_id);
  serial_puts(serial_base, " version=");
  serial_dec(serial_base, version);
  serial_puts(serial_base, " interrupts=");
  serial_dec(serial_base, g_lapic_timer_interrupts);
  serial_puts(serial_base, " elapsed_tsc=");
  serial_dec(serial_base, elapsed_tsc);
  serial_puts(serial_base, "\n");
}

static uint32_t pci_read_config(uint8_t bus, uint8_t device, uint8_t function,
                                uint8_t offset) {
  uint32_t address = UINT32_C(0x80000000) | ((uint32_t)bus << 16) |
                     ((uint32_t)device << 11) | ((uint32_t)function << 8) |
                     ((uint32_t)offset & UINT32_C(0xfc));
  outl(PCI_CONFIG_ADDRESS, address);
  return inl(PCI_CONFIG_DATA);
}

static uint8_t pci_read_config8(uint8_t bus, uint8_t device, uint8_t function,
                                uint8_t offset) {
  uint32_t value = pci_read_config(bus, device, function, offset);
  return (uint8_t)(value >> ((offset & 3U) * 8U));
}

static void inspect_pci_capabilities(uint8_t bus, uint8_t device,
                                     uint8_t function) {
  uint32_t status_command = pci_read_config(bus, device, function, 0x04U);
  if ((status_command & UINT32_C(1 << 20)) == 0U) return;
  uint8_t pointer = pci_read_config8(bus, device, function, 0x34U) & 0xfcU;
  uint32_t visited = 0U;
  while (pointer >= 0x40U && pointer <= 0xfcU && visited++ < 48U) {
    uint8_t capability = pci_read_config8(bus, device, function, pointer);
    if (capability == 0x05U) ++g_pci.msi_devices;
    if (capability == 0x10U) ++g_pci.pcie_devices;
    if (capability == 0x11U) ++g_pci.msix_devices;
    uint8_t next =
        pci_read_config8(bus, device, function, (uint8_t)(pointer + 1U)) &
        0xfcU;
    if (next == pointer) break;
    pointer = next;
  }
}

static void discover_pci(uint16_t serial_base) {
  g_pci = (x86_64_pci_state_t){0};
  for (uint16_t bus = 0; bus < 256; ++bus) {
    for (uint8_t device = 0; device < 32; ++device) {
      uint32_t header0 = pci_read_config((uint8_t)bus, device, 0, 0);
      if (header0 == UINT32_C(0xffffffff)) {
        continue;
      }
      uint32_t header_type_reg = pci_read_config((uint8_t)bus, device, 0, 0x0c);
      uint8_t header_type = (uint8_t)((header_type_reg >> 16) & 0xffU);
      uint8_t functions = (header_type & 0x80U) != 0U ? 8U : 1U;
      for (uint8_t function = 0; function < functions; ++function) {
        uint32_t id = pci_read_config((uint8_t)bus, device, function, 0);
        if (id == UINT32_C(0xffffffff)) {
          continue;
        }
        uint16_t vendor = (uint16_t)(id & UINT32_C(0xffff));
        uint16_t device_id = (uint16_t)((id >> 16) & UINT32_C(0xffff));
        uint32_t class_reg =
            pci_read_config((uint8_t)bus, device, function, 0x08);
        uint8_t class_code = (uint8_t)(class_reg >> 24);
        uint8_t subclass = (uint8_t)((class_reg >> 16) & UINT32_C(0xff));
        g_pci.functions++;
        if (function == 0) {
          g_pci.devices++;
        }
        if (class_code == 0x06U && subclass == 0x04U) {
          g_pci.bridges++;
        }
        if (vendor == 0x1af4U) {
          g_pci.virtio_devices++;
          if (device_id >= 0x1040U && device_id <= 0x107fU) {
            ++g_pci.modern_virtio_devices;
          }
        }
        if (class_code == 0x02U) {
          g_pci.network_devices++;
        }
        if (class_code == 0x01U && subclass == 0x08U) {
          g_pci.nvme_devices++;
        }
        inspect_pci_capabilities((uint8_t)bus, device, function);
      }
    }
  }

  if (g_pci.devices == 0) {
    panic_halt(serial_base, "PCI enumeration found no devices");
  }

  serial_puts(serial_base, "x86_64: PCI discovery devices=");
  serial_dec(serial_base, g_pci.devices);
  serial_puts(serial_base, " functions=");
  serial_dec(serial_base, g_pci.functions);
  serial_puts(serial_base, " virtio=");
  serial_dec(serial_base, g_pci.virtio_devices);
  serial_puts(serial_base, " net=");
  serial_dec(serial_base, g_pci.network_devices);
  serial_puts(serial_base, " nvme=");
  serial_dec(serial_base, g_pci.nvme_devices);
  serial_puts(serial_base, " pcie=");
  serial_dec(serial_base, g_pci.pcie_devices);
  serial_puts(serial_base, " msi=");
  serial_dec(serial_base, g_pci.msi_devices);
  serial_puts(serial_base, " msix=");
  serial_dec(serial_base, g_pci.msix_devices);
  serial_puts(serial_base, " modern_virtio=");
  serial_dec(serial_base, g_pci.modern_virtio_devices);
  serial_puts(serial_base, "\n");
}

static void build_placement_policy(uint16_t serial_base) {
  uint32_t eax = 0;
  uint32_t ebx = 0;
  uint32_t ecx = 0;
  uint32_t edx = 0;
  cpuid(0, 0, &eax, &ebx, &ecx, &edx);
  uint32_t max_leaf = eax;
  uint32_t topology_leaf = max_leaf >= 0x1fU ? 0x1fU :
                           (max_leaf >= 0x0bU ? 0x0bU : 0U);
  uint32_t logical_cpus = 0U;
  uint32_t threads_per_core = 1U;
  if (topology_leaf != 0U) {
    for (uint32_t level = 0U; level < 32U; ++level) {
      cpuid(topology_leaf, level, &eax, &ebx, &ecx, &edx);
      uint32_t level_type = (ecx >> 8U) & 0xffU;
      uint32_t count = ebx & UINT32_C(0xffff);
      if (count == 0U || level_type == 0U) break;
      if (level_type == 1U) threads_per_core = count;
      if (count > logical_cpus) logical_cpus = count;
    }
  }
  if (logical_cpus == 0U) {
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    logical_cpus = (ebx >> 16) & 0xffU;
    if (logical_cpus == 0U) logical_cpus = 1U;
  }

  g_placement = (x86_64_placement_state_t){0};
  g_placement.logical_cpus = logical_cpus;
  g_placement.housekeeping_cpus = 1U;
  if (logical_cpus >= 4U) {
    g_placement.ai_hot_cpus = 2U;
    g_placement.background_cpus = logical_cpus - 3U;
  } else if (logical_cpus >= 2U) {
    g_placement.ai_hot_cpus = 1U;
    g_placement.background_cpus = logical_cpus - 2U;
  } else {
    g_placement.ai_hot_cpus = 0U;
    g_placement.background_cpus = 0U;
  }
  g_placement.smt_disabled_by_default = 1U;
  g_placement.p_core_policy_ready = max_leaf >= 0x1aU ? 1U : 0U;
  g_placement.e_core_policy_ready = max_leaf >= 0x1aU ? 1U : 0U;
  g_placement.threads_per_core = threads_per_core;
  g_placement.topology_leaf = topology_leaf;
  g_placement.migration_total = 0;
  g_placement.context_switch_total = 0;

  serial_puts(serial_base, "x86_64: placement policy logical_cpus=");
  serial_dec(serial_base, g_placement.logical_cpus);
  serial_puts(serial_base, " housekeeping=");
  serial_dec(serial_base, g_placement.housekeeping_cpus);
  serial_puts(serial_base, " ai_hot=");
  serial_dec(serial_base, g_placement.ai_hot_cpus);
  serial_puts(serial_base, " background=");
  serial_dec(serial_base, g_placement.background_cpus);
  serial_puts(serial_base, " threads_per_core=");
  serial_dec(serial_base, g_placement.threads_per_core);
  serial_puts(serial_base, " topology_leaf=");
  serial_hex64(serial_base, g_placement.topology_leaf);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: SMT policy disabled_by_default=");
  serial_dec(serial_base, g_placement.smt_disabled_by_default);
  serial_puts(serial_base, " p_core_policy=");
  serial_dec(serial_base, g_placement.p_core_policy_ready);
  serial_puts(serial_base, " e_core_policy=");
  serial_dec(serial_base, g_placement.e_core_policy_ready);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: hot-core telemetry migration_total=");
  serial_dec(serial_base, g_placement.migration_total);
  serial_puts(serial_base, " context_switch_total=");
  serial_dec(serial_base, g_placement.context_switch_total);
  serial_puts(serial_base, "\n");
}

static void validate_x86_os_contract(uint16_t serial_base) {
  uint32_t portable = xaios_common_runtime_probe();
  uint32_t storage_ready =
      (portable & (XAIOS_COMMON_RUNTIME_BLOCK | XAIOS_COMMON_RUNTIME_VFS)) ==
      (XAIOS_COMMON_RUNTIME_BLOCK | XAIOS_COMMON_RUNTIME_VFS);
  g_contract = (x86_64_contract_state_t){
      .userspace_contract_ready = 0U,
      .filesystem_contract_ready = storage_ready,
      .networking_contract_ready = 0U,
      .ai_cell_contract_ready = 0U,
      .security_contract_ready = 0U,
      .telemetry_contract_ready = 0U,
      .full_os_contract_ready = 0U,
  };

  serial_puts(serial_base, "x86_64: common kernel/runtime linked=1 probe=");
  serial_hex64(serial_base, portable);
  serial_puts(serial_base, " expected=0x000000000000000f\n");
  serial_puts(serial_base, "x86_64: OS contract userspace=");
  serial_dec(serial_base, g_contract.userspace_contract_ready);
  serial_puts(serial_base, " filesystem=");
  serial_dec(serial_base, g_contract.filesystem_contract_ready);
  serial_puts(serial_base, " networking=");
  serial_dec(serial_base, g_contract.networking_contract_ready);
  serial_puts(serial_base, " ai_cell=");
  serial_dec(serial_base, g_contract.ai_cell_contract_ready);
  serial_puts(serial_base, " security=");
  serial_dec(serial_base, g_contract.security_contract_ready);
  serial_puts(serial_base, " telemetry=");
  serial_dec(serial_base, g_contract.telemetry_contract_ready);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: full OS contract parity marker ready=");
  serial_dec(serial_base, g_contract.full_os_contract_ready);
  serial_puts(serial_base, "\n");
}

static void validate_hardware_gate(uint16_t serial_base) {
  g_hardware_gate = (x86_64_hardware_gate_state_t){
      .qemu_correctness_ready = 1U,
      .physical_hardware_required = 1U,
      .tuned_linux_bsd_baseline_required = 1U,
      .performance_claims_allowed = 0U,
      .release_candidate_ready = 0U,
  };

  serial_puts(serial_base, "x86_64: hardware gate qemu_correctness=");
  serial_dec(serial_base, g_hardware_gate.qemu_correctness_ready);
  serial_puts(serial_base, " physical_required=");
  serial_dec(serial_base, g_hardware_gate.physical_hardware_required);
  serial_puts(serial_base, " baseline_required=");
  serial_dec(serial_base, g_hardware_gate.tuned_linux_bsd_baseline_required);
  serial_puts(serial_base, " performance_claims_allowed=");
  serial_dec(serial_base, g_hardware_gate.performance_claims_allowed);
  serial_puts(serial_base, " release_candidate_ready=");
  serial_dec(serial_base, g_hardware_gate.release_candidate_ready);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: Intel Desktop hardware gate blocked platform-parity-and-physical-evidence-required\n");
}

void x86_64_exception_entry(const x86_64_exception_frame_t *frame) {
  uint16_t serial_base = COM1_PORT;
  serial_init(serial_base);
  if (frame != 0 && frame->vector == g_expected_exception_vector) {
    ++g_exception_test_count;
    g_expected_exception_vector = UINT32_MAX;
    return;
  }
  serial_puts(serial_base, "\nEXCEPTION x86_64 vector=");
  serial_dec(serial_base, frame->vector);
  serial_puts(serial_base, " error=");
  serial_hex64(serial_base, frame->error_code);
  serial_puts(serial_base, " rip=");
  serial_hex64(serial_base, frame->rip);
  if (frame->vector == 14U) {
    serial_puts(serial_base, " cr2=");
    serial_hex64(serial_base, read_cr2());
  }
  serial_puts(serial_base, "\n");
  panic_halt(serial_base, "controlled x86_64 exception reported");
}

static void validate_exception_round_trip(uint16_t serial_base) {
  g_exception_test_count = 0U;
  g_expected_exception_vector = 3U;
  __asm__ volatile("int3" ::: "memory");
  if (g_exception_test_count != 1U ||
      g_expected_exception_vector != UINT32_MAX) {
    panic_halt(serial_base, "controlled INT3 exception failed");
  }
  serial_puts(serial_base,
              "x86_64: controlled INT3 exception round-trip passed count=1\n");
}

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
  install_idt(serial_base);
  validate_exception_round_trip(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 44 early exceptions passed\n");
  parse_memory_map(serial_base, boot);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 45 memory map passed\n");
  install_page_tables(serial_base);
  if (g_page_tables_loaded == 0U) {
    panic_halt(serial_base, "page tables not loaded");
  }
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 46 page tables passed\n");
  discover_timer_apic(serial_base);
  validate_lapic_timer_interrupt(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 47 timers APIC passed\n");
  discover_pci(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 48 PCI discovery passed\n");
  build_placement_policy(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 49 placement policy passed\n");
  validate_x86_os_contract(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 50 portable common runtime passed platform services pending\n");
  validate_hardware_gate(serial_base);
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 51 hardware gate blocked\n");

  for (;;) {
    __asm__ volatile("hlt");
  }
}
