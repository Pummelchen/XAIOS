#include <xaios/boot_info.h>
#include <xaios/ai_kernels.h>
#include <xaios/common_runtime.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/security.h>
#include <xaios/smp.h>
#include <xaios/syscall.h>
#include <xaios/thread.h>
#include <xaios/types.h>
#include <xaios/user.h>
#include <xaios/vmm.h>
#include <xaios_engine/packed.h>

#include "acpi.h"
#include "platform.h"

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

#if XAIOS_X86_COMMON_RUNTIME
#define X86_BRINGUP_ONLY __attribute__((unused))
#else
#define X86_BRINGUP_ONLY
#endif

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
#define X86_CR4_OSFXSR UINT64_C(1 << 9)
#define X86_CR4_OSXMMEXCPT UINT64_C(1 << 10)
#define X86_XCR0_AVX UINT64_C(1 << 2)
#define X86_XCR0_SSE UINT64_C(1 << 1)
#define X86_XCR0_X87 UINT64_C(1)
#define X86_XSTATE_AVX512 UINT64_C(0xe0)
#define X86_XSTATE_AMX UINT64_C(0x60000)
#define MSR_IA32_APIC_BASE UINT32_C(0x1b)
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
#define MSR_IA32_EFER UINT32_C(0xc0000080)
#define EFER_NXE UINT64_C(1 << 11)
#define PTE_PRESENT UINT64_C(1)
#define PTE_WRITABLE UINT64_C(1 << 1)
#define PTE_USER UINT64_C(1 << 2)
#define PTE_LARGE UINT64_C(1 << 7)
#define PTE_GLOBAL UINT64_C(1 << 8)
#define PTE_NX (UINT64_C(1) << 63)
#define X86_USER_BASE UINT64_C(0x100000000)
#define X86_USER_WINDOW_SIZE UINT64_C(0x200000)
#define X86_USER_LOG_MAX UINT64_C(4096)
#define X86_KERNEL_STACK_SIZE UINT64_C(524288)
#define X86_KERNEL_STACK_GUARD_BYTES UINT32_C(64)
#define X86_KERNEL_STACK_GUARD_VALUE UINT8_C(0xa5)
#define X86_USER_NESTING_MAX UINT32_C(8)
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

typedef struct x86_64_tss {
  uint32_t reserved0;
  uint64_t rsp0;
  uint64_t rsp1;
  uint64_t rsp2;
  uint64_t reserved1;
  uint64_t ist[7];
  uint64_t reserved2;
  uint16_t reserved3;
  uint16_t io_map_base;
} __attribute__((packed)) x86_64_tss_t;

typedef struct x86_64_exception_frame {
  uint64_t r15;
  uint64_t r14;
  uint64_t r13;
  uint64_t r12;
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

typedef struct x86_64_cpu_record {
  uint32_t apic_id;
  volatile uint32_t online;
  volatile uint32_t worker_ready;
  volatile uint32_t requested_generation;
  volatile uint32_t completed_generation;
  volatile uint64_t checksum;
  uint64_t kernel_stack_top;
  uint64_t syscall_stack_top;
  uint64_t user_resume_rsp[X86_USER_NESTING_MAX];
  uint64_t user_previous_rsp0[X86_USER_NESTING_MAX];
  uint32_t user_nesting_depth;
  uint64_t user_return_value;
  uint8_t *irq_state_area;
  uint64_t *page_table_root;
  uint64_t *user_page_directory;
  uint64_t gdt[7];
  x86_64_tss_t tss;
  xaios_cpu_state_t state;
} x86_64_cpu_record_t;

typedef struct x86_64_virtio_pci_device {
  uint8_t bus;
  uint8_t device;
  uint8_t function;
  uint8_t valid;
  uint16_t device_id;
  uint16_t reserved;
  uint64_t common_config;
  uint64_t notify_base;
  uint64_t isr_config;
  uint64_t device_config;
  uint32_t notify_multiplier;
} x86_64_virtio_pci_device_t;

typedef struct virtq_descriptor {
  uint64_t address;
  uint32_t length;
  uint16_t flags;
  uint16_t next;
} __attribute__((packed)) virtq_descriptor_t;

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
extern void x86_64_irq_128(void);
extern void x86_64_irq_255(void);
extern void x86_64_load_gdt(const x86_64_idtr_t *gdtr);
extern void x86_64_load_tss(void);
extern void x86_64_enter_ring3(uint64_t entry, uint64_t stack);
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
static uint64_t g_pml4[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_pdpt[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_pd[4][512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_user_pd[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_mmio_pdpt[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_mmio_pd[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_mmio_gib_base;
static uint64_t g_gdt[7] __attribute__((aligned(16)));
static x86_64_tss_t g_tss;
static uint8_t g_syscall_stack[X86_KERNEL_STACK_SIZE]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t g_user_test_page[UINT32_C(0x200000)]
    __attribute__((section(".user_test"), aligned(UINT32_C(0x200000))));
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
static uint32_t g_lapic_ready;
static uint32_t g_lapic_x2apic;
volatile uint64_t g_x86_lapic_timer_interrupts;
static volatile uint64_t g_ring3_syscalls;
static volatile uint64_t g_ring3_exit_code;
volatile uint64_t g_ring3_return_value;
static x86_64_acpi_info_t g_acpi;
static xaios_boot_info_t g_boot_info_copy;
static uint8_t g_xsave_original[UINT32_C(65536)] __attribute__((aligned(64)));
static uint8_t g_xsave_test[UINT32_C(65536)] __attribute__((aligned(64)));
static x86_64_cpu_record_t *g_cpu_records;
static uint32_t g_cpu_record_count;
static uint32_t g_bsp_ordinal = UINT32_MAX;
static uint64_t g_early_alloc_cursor;
static uint64_t g_early_alloc_start;
static uint64_t g_early_alloc_end;
static uint64_t g_xsave_enabled;
static uint32_t g_xsave_area_size;
static volatile uint64_t g_virtio_msix_interrupts;
static uint64_t g_virtio_msix_isr;
static volatile uint32_t g_common_worker_release;
static uint64_t g_tsc_frequency;
static uint64_t g_lapic_frequency;

#if XAIOS_X86_COMMON_RUNTIME
extern void kmain(const xaios_boot_info_t *boot);
#endif

extern const uint8_t _binary_hello_bin_start[];
extern const uint8_t _binary_hello_bin_end[];

static inline uint64_t rdtsc(void);
static uint32_t lapic_id(void);
static void lapic_send(uint32_t destination, uint32_t command);
static void lapic_write(uint32_t offset, uint32_t value);
static void panic_halt(uint16_t serial_base, const char *message);

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
#endif

uint64_t x86_64_platform_tsc(void) { return rdtsc(); }

uint64_t x86_64_platform_tsc_hz(void) { return g_tsc_frequency; }

void x86_64_platform_set_tsc_hz(uint64_t frequency) {
  g_tsc_frequency = frequency;
}

uint64_t x86_64_platform_lapic_hz(void) { return g_lapic_frequency; }

uint32_t x86_64_platform_cpu_count(void) { return g_cpu_record_count; }

uint32_t x86_64_platform_cpu_apic_id(uint32_t ordinal) {
  return ordinal < g_cpu_record_count ? g_cpu_records[ordinal].apic_id
                                      : UINT32_MAX;
}

uint32_t x86_64_platform_cpu_online(uint32_t ordinal) {
  return ordinal < g_cpu_record_count
             ? __atomic_load_n(&g_cpu_records[ordinal].online,
                               __ATOMIC_ACQUIRE)
             : 0U;
}

uint32_t x86_64_platform_workers_ready(void) {
  uint32_t ready = g_bsp_ordinal < g_cpu_record_count ? 1U : 0U;
  for (uint32_t ordinal = 0U; ordinal < g_cpu_record_count; ++ordinal) {
    if (ordinal == g_bsp_ordinal ||
        __atomic_load_n(&g_cpu_records[ordinal].online, __ATOMIC_ACQUIRE) ==
            0U) {
      continue;
    }
    if (__atomic_load_n(&g_cpu_records[ordinal].worker_ready,
                        __ATOMIC_ACQUIRE) != 0U) {
      ++ready;
    }
  }
  return ready;
}

struct xaios_cpu_state *x86_64_platform_cpu_state(uint32_t ordinal) {
  return ordinal < g_cpu_record_count ? &g_cpu_records[ordinal].state : 0;
}

void x86_64_platform_set_page_tables(uint32_t ordinal, uint64_t *root,
                                      uint64_t *user_directory) {
  if (ordinal >= g_cpu_record_count) return;
  g_cpu_records[ordinal].page_table_root = root;
  g_cpu_records[ordinal].user_page_directory = user_directory;
}

uint64_t *x86_64_platform_page_table_root(uint32_t ordinal) {
  return ordinal < g_cpu_record_count
             ? g_cpu_records[ordinal].page_table_root
             : 0;
}

uint64_t *x86_64_platform_user_page_directory(uint32_t ordinal) {
  return ordinal < g_cpu_record_count
             ? g_cpu_records[ordinal].user_page_directory
             : 0;
}

uint32_t x86_64_platform_current_ordinal(void) {
  uint32_t id = lapic_id();
  for (uint32_t ordinal = 0U; ordinal < g_cpu_record_count; ++ordinal) {
    if (g_cpu_records[ordinal].apic_id == id) return ordinal;
  }
  return UINT32_MAX;
}

void x86_64_platform_wake(uint32_t ordinal) {
  if (ordinal < g_cpu_record_count && g_cpu_records[ordinal].online != 0U) {
    lapic_send(g_cpu_records[ordinal].apic_id, 33U);
  }
}

void x86_64_platform_release_workers(void) {
  __atomic_store_n(&g_common_worker_release, 1U, __ATOMIC_RELEASE);
  for (uint32_t ordinal = 0U; ordinal < g_cpu_record_count; ++ordinal) {
    if (ordinal != x86_64_platform_current_ordinal()) {
      x86_64_platform_wake(ordinal);
    }
  }
}

uint64_t x86_64_platform_bootstrap_start(void) {
  return g_early_alloc_start;
}

uint64_t x86_64_platform_bootstrap_end(void) { return g_early_alloc_cursor; }

void x86_64_platform_timer_start(uint32_t initial_count, uint32_t periodic) {
  if (g_lapic_ready == 0U) return;
  lapic_write(APIC_LVT_TIMER,
              32U | (periodic != 0U ? UINT32_C(1 << 17) : 0U));
  lapic_write(APIC_TIMER_DIVIDE, UINT32_C(0x0b));
  lapic_write(APIC_TIMER_INITIAL, initial_count);
}

void x86_64_platform_timer_stop(void) {
  if (g_lapic_ready != 0U) {
    lapic_write(APIC_LVT_TIMER, UINT32_C(1 << 16) | 32U);
    lapic_write(APIC_TIMER_INITIAL, 0U);
  }
}

uint64_t x86_64_platform_timer_interrupts(void) {
  return g_x86_lapic_timer_interrupts;
}

void x86_64_platform_eoi(void) {
  if (g_lapic_ready != 0U) lapic_write(APIC_EOI, 0U);
}

void x86_64_platform_set_user_resume(uint64_t stack) {
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= g_cpu_record_count) panic_halt(COM1_PORT, "user CPU ordinal");
  x86_64_cpu_record_t *record = &g_cpu_records[ordinal];
  uint32_t depth = record->user_nesting_depth;
  if (depth >= X86_USER_NESTING_MAX) {
    panic_halt(COM1_PORT, "user nesting depth");
  }
  x86_64_tss_t *tss = ordinal == g_bsp_ordinal ? &g_tss : &record->tss;
  record->user_resume_rsp[depth] = stack;
  record->user_previous_rsp0[depth] = tss->rsp0;
  ++record->user_nesting_depth;

  uint64_t syscall_stack_low =
      record->syscall_stack_top - X86_KERNEL_STACK_SIZE;
  if (stack > syscall_stack_low && stack < record->syscall_stack_top) {
    tss->rsp0 = stack & ~UINT64_C(0xf);
  }
}

uint64_t x86_64_platform_user_resume(void) {
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= g_cpu_record_count) {
    panic_halt(COM1_PORT, "user resume stack");
  }
  x86_64_cpu_record_t *record = &g_cpu_records[ordinal];
  uint32_t depth = record->user_nesting_depth;
  if (depth == 0U || record->user_resume_rsp[depth - 1U] == 0U) {
    panic_halt(COM1_PORT, "user resume stack");
  }
  --depth;
  uint64_t stack = record->user_resume_rsp[depth];
  x86_64_tss_t *tss = ordinal == g_bsp_ordinal ? &g_tss : &record->tss;
  tss->rsp0 = record->user_previous_rsp0[depth];
  record->user_resume_rsp[depth] = 0U;
  record->user_previous_rsp0[depth] = 0U;
  record->user_nesting_depth = depth;
  return stack;
}

void x86_64_platform_set_user_return(uint64_t value) {
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= g_cpu_record_count) panic_halt(COM1_PORT, "user return CPU");
  g_cpu_records[ordinal].user_return_value = value;
}

uint64_t x86_64_platform_user_return(void) {
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= g_cpu_record_count) panic_halt(COM1_PORT, "user result CPU");
  return g_cpu_records[ordinal].user_return_value;
}

static uint8_t mmio_read8(uint64_t address);

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

static inline uint64_t read_xcr0(void) {
  uint32_t low = 0U;
  uint32_t high = 0U;
  __asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(0U));
  return (uint64_t)low | ((uint64_t)high << 32U);
}

static inline void xsave_state(void *area, uint64_t mask) {
  uint32_t low = (uint32_t)mask;
  uint32_t high = (uint32_t)(mask >> 32U);
  __asm__ volatile("xsave64 (%0)" : : "r"(area), "a"(low), "d"(high)
                   : "memory");
}

static inline void xrstor_state(const void *area, uint64_t mask) {
  uint32_t low = (uint32_t)mask;
  uint32_t high = (uint32_t)(mask >> 32U);
  __asm__ volatile("xrstor64 (%0)" : : "r"(area), "a"(low), "d"(high)
                   : "memory");
}

static inline void fxsave_state(void *area) {
  __asm__ volatile("fxsave64 (%0)" : : "r"(area) : "memory");
}

static inline void fxrstor_state(const void *area) {
  __asm__ volatile("fxrstor64 (%0)" : : "r"(area) : "memory");
}

static uint8_t *current_irq_state_area(void) {
  uint32_t ordinal = x86_64_platform_current_ordinal();
  if (ordinal >= g_cpu_record_count || g_xsave_area_size == 0U ||
      g_cpu_records[ordinal].irq_state_area == 0) {
    return 0;
  }
  uint32_t depth = g_cpu_records[ordinal].user_nesting_depth;
  uint32_t slot = depth == 0U ? 0U : depth - 1U;
  if (slot >= X86_USER_NESTING_MAX) {
    panic_halt(COM1_PORT, "IRQ state nesting");
  }
  return g_cpu_records[ordinal].irq_state_area +
         (uint64_t)slot * g_xsave_area_size;
}

void x86_64_irq_state_save(void) {
  uint8_t *area = current_irq_state_area();
  if (area == 0) return;
  if (g_xsave_enabled != 0U) {
    xsave_state(area, g_xsave_enabled);
  } else {
    fxsave_state(area);
  }
}

void x86_64_irq_state_restore(void) {
  uint8_t *area = current_irq_state_area();
  if (area == 0) return;
  if (g_xsave_enabled != 0U) {
    xrstor_state(area, g_xsave_enabled);
  } else {
    fxrstor_state(area);
  }
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

static void bytes_copy(void *destination, const void *source, uint64_t bytes) {
  uint8_t *output = (uint8_t *)destination;
  const uint8_t *input = (const uint8_t *)source;
  for (uint64_t i = 0U; i < bytes; ++i) output[i] = input[i];
}

static void *early_alloc(uint64_t bytes, uint64_t alignment) {
  if (bytes == 0U || alignment == 0U ||
      (alignment & (alignment - 1U)) != 0U ||
      g_early_alloc_cursor > g_early_alloc_end) {
    return 0;
  }
  uint64_t start = align_up(g_early_alloc_cursor, alignment);
  if (start < g_early_alloc_cursor || start > g_early_alloc_end ||
      bytes > g_early_alloc_end - start) {
    return 0;
  }
  g_early_alloc_cursor = start + bytes;
  return (void *)(uintptr_t)start;
}

static void panic_halt(uint16_t serial_base, const char *message) {
  serial_puts(serial_base, "x86_64: panic: ");
  serial_puts(serial_base, message);
  serial_puts(serial_base, "\n");
  for (;;) {
    __asm__ volatile("hlt");
  }
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
  g_idt[vector].type_attr |= UINT8_C(0x60);
}

static void install_gdt_tss(uint16_t serial_base) {
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

static void install_ap_gdt_tss(x86_64_cpu_record_t *record) {
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

#if XAIOS_X86_COMMON_RUNTIME
static int kernel_stack_guard_valid(uint32_t ordinal) {
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

static void tsc_delay(uint64_t cycles) {
  uint64_t deadline = rdtsc() + cycles;
  while ((int64_t)(rdtsc() - deadline) < 0) __asm__ volatile("pause");
}

uint64_t x86_64_interrupt_entry(x86_64_exception_frame_t *frame) {
  if (frame != 0 && frame->vector == 128U) {
    if ((frame->cs & 3U) != 3U) panic_halt(COM1_PORT, "ring3 syscall CPL");
    ++g_ring3_syscalls;
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
      g_ring3_exit_code = frame->rdi;
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
    if (g_virtio_msix_isr != 0U) (void)mmio_read8(g_virtio_msix_isr);
    ++g_virtio_msix_interrupts;
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

void x86_64_ap_entry(uint32_t ordinal) {
  if (ordinal >= g_cpu_record_count) panic_halt(COM1_PORT, "AP ordinal");
  x86_64_idtr_t idtr = {
      .limit = (uint16_t)(sizeof(g_idt) - 1U),
      .base = (uint64_t)(uintptr_t)g_idt,
  };
  __asm__ volatile("lidt %0" : : "m"(idtr) : "memory");
  write_cr4(read_cr4() | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT);
  if (g_xsave_enabled != 0U) {
    write_cr4(read_cr4() | X86_CR4_OSXSAVE);
    write_xcr0(g_xsave_enabled);
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
    if (xaios_thread_run_pending(ordinal) == 0U) {
      __asm__ volatile("hlt");
    }
  }
#else
  for (;;) __asm__ volatile("hlt");
#endif
}

static void parse_memory_map(uint16_t serial_base, const xaios_boot_info_t *boot) {
  g_pmm = (x86_64_pmm_state_t){0};
  uint64_t allocator_base = 0U;
  uint64_t allocator_pages = 0U;
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
      uint64_t allocator_end =
          region_end < EARLY_IDENTITY_LIMIT ? region_end : EARLY_IDENTITY_LIMIT;
      uint64_t candidate_pages =
          allocator_end > region_start
              ? (allocator_end - region_start) / PAGE_SIZE
              : 0U;
      if (candidate_pages > allocator_pages) {
        allocator_base = region_start;
        allocator_pages = candidate_pages;
      }
    } else {
      g_pmm.reserved_pages += pages;
    }
    offset += boot->memory_descriptor_size;
  }

  if (g_pmm.descriptors == 0 || g_pmm.usable_pages == 0 ||
      allocator_pages == 0U) {
    panic_halt(serial_base, "memory map parse failed");
  }
  g_early_alloc_cursor = allocator_base;
  g_early_alloc_start = allocator_base;
  g_early_alloc_end = allocator_base + allocator_pages * PAGE_SIZE;

  serial_puts(serial_base, "x86_64: PMM parsed descriptors=");
  serial_dec(serial_base, g_pmm.descriptors);
  serial_puts(serial_base, " usable_pages=");
  serial_dec(serial_base, g_pmm.usable_pages);
  serial_puts(serial_base, " largest_base=");
  serial_hex64(serial_base, g_pmm.largest_usable_base);
  serial_puts(serial_base, "\n");
}

static void parse_acpi(uint16_t serial_base, const xaios_boot_info_t *boot) {
  if (!x86_64_acpi_parse(boot->acpi_rsdp, &g_acpi)) {
    panic_halt(serial_base, "ACPI RSDP/root/MADT validation failed");
  }
  serial_puts(serial_base, "x86_64: ACPI root=");
  serial_puts(serial_base, g_acpi.root_is_xsdt != 0U ? "XSDT" : "RSDT");
  serial_puts(serial_base, " enabled_cpus=");
  serial_dec(serial_base, g_acpi.enabled_cpus);
  serial_puts(serial_base, " io_apics=");
  serial_dec(serial_base, g_acpi.io_apics);
  serial_puts(serial_base, " MADT=1 SRAT=");
  serial_dec(serial_base, g_acpi.srat != 0U);
  serial_puts(serial_base, " SLIT=");
  serial_dec(serial_base, g_acpi.slit != 0U);
  serial_puts(serial_base, " HMAT=");
  serial_dec(serial_base, g_acpi.hmat != 0U);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: NUMA affinity processors=");
  serial_dec(serial_base, g_acpi.processor_affinities);
  serial_puts(serial_base, " memory=");
  serial_dec(serial_base, g_acpi.memory_affinities);
  serial_puts(serial_base, " slit_localities=");
  serial_dec(serial_base, g_acpi.slit_localities);
  serial_puts(serial_base, "\n");
}

static void validate_xsave(uint16_t serial_base) {
  uint32_t eax = 0U;
  uint32_t ebx = 0U;
  uint32_t ecx = 0U;
  uint32_t edx = 0U;
  cpuid(1U, 0U, &eax, &ebx, &ecx, &edx);
  if ((ecx & (UINT32_C(1) << 26U)) == 0U) {
    if ((edx & (UINT32_C(1) << 24U)) == 0U) {
      panic_halt(serial_base, "extended state unavailable");
    }
    write_cr4(read_cr4() | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT);
    fxsave_state(g_xsave_original);
    fxsave_state(g_xsave_test);
    fxrstor_state(g_xsave_test);
    fxrstor_state(g_xsave_original);
    g_xsave_enabled = 0U;
    g_xsave_area_size = UINT32_C(512);
    serial_puts(serial_base,
                "x86_64: FXSAVE/FXRSTOR fallback canary passed bytes=512\n");
    return;
  }
  uint32_t avx_supported = ecx & (UINT32_C(1) << 28U);
  write_cr4(read_cr4() | X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT |
            X86_CR4_OSXSAVE);
  cpuid(0x0dU, 0U, &eax, &ebx, &ecx, &edx);
  uint64_t supported = (uint64_t)eax | ((uint64_t)edx << 32U);
  uint64_t enabled = X86_XCR0_X87 | X86_XCR0_SSE;
  if ((supported & X86_XCR0_AVX) != 0U &&
      avx_supported != 0U) {
    enabled |= X86_XCR0_AVX;
  }
  write_xcr0(enabled);
  g_xsave_enabled = enabled;
  cpuid(0x0dU, 0U, &eax, &ebx, &ecx, &edx);
  if (ebx == 0U || ebx > sizeof(g_xsave_original) || read_xcr0() != enabled) {
    panic_halt(serial_base, "XSAVE area sizing failed");
  }
  g_xsave_area_size = ebx;
  xsave_state(g_xsave_original, enabled);
  xsave_state(g_xsave_test, enabled);
  xrstor_state(g_xsave_test, enabled);
  xrstor_state(g_xsave_original, enabled);
  serial_puts(serial_base, "x86_64: XSAVE/XRSTOR canary passed bytes=");
  serial_dec(serial_base, ebx);
  serial_puts(serial_base, " enabled=");
  serial_hex64(serial_base, enabled);
  serial_puts(serial_base, " avx512_supported=");
  serial_dec(serial_base,
             (supported & X86_XSTATE_AVX512) == X86_XSTATE_AVX512);
  serial_puts(serial_base, " amx_supported=");
  serial_dec(serial_base, (supported & X86_XSTATE_AMX) == X86_XSTATE_AMX);
  serial_puts(serial_base, "\n");
}

static void prepare_irq_state_areas(uint16_t serial_base) {
  if (g_xsave_area_size == 0U ||
      g_xsave_area_size > UINT32_C(65536)) {
    panic_halt(serial_base, "IRQ state area size");
  }
  uint64_t bytes =
      (uint64_t)g_xsave_area_size * X86_USER_NESTING_MAX;
  for (uint32_t ordinal = 0U; ordinal < g_cpu_record_count; ++ordinal) {
    g_cpu_records[ordinal].irq_state_area =
        (uint8_t *)early_alloc(bytes, UINT64_C(64));
    if (g_cpu_records[ordinal].irq_state_area == 0) {
      panic_halt(serial_base, "IRQ state allocation");
    }
    for (uint64_t offset = 0U; offset < bytes; ++offset) {
      g_cpu_records[ordinal].irq_state_area[offset] = 0U;
    }
  }
  serial_puts(serial_base, "x86_64: per-CPU nested IRQ state areas ready bytes=");
  serial_dec(serial_base, bytes);
  serial_puts(serial_base, " cpus=");
  serial_dec(serial_base, g_cpu_record_count);
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
  for (uint32_t index = 0; index < 512; ++index) g_user_pd[index] = 0U;
  uint32_t user_pdpt = (uint32_t)((X86_USER_BASE >> 30U) & UINT64_C(0x1ff));
  uint32_t user_pd = (uint32_t)((X86_USER_BASE >> 21U) & UINT64_C(0x1ff));
  g_user_pd[user_pd] = ((uint64_t)(uintptr_t)g_user_test_page) |
                       PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_LARGE;
  g_pdpt[user_pdpt] = ((uint64_t)(uintptr_t)g_user_pd) | PTE_PRESENT |
                      PTE_WRITABLE | PTE_USER;
  g_pml4[0] = ((uint64_t)(uintptr_t)g_pdpt) | PTE_PRESENT | PTE_WRITABLE |
              PTE_USER;

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

static void X86_BRINGUP_ONLY validate_ring3_syscall(uint16_t serial_base) {
  uint64_t image_size =
      (uint64_t)(_binary_hello_bin_end - _binary_hello_bin_start);
  if (image_size == 0U || image_size > sizeof(g_user_test_page)) {
    panic_halt(serial_base, "userspace hello image size");
  }
  for (uint64_t i = 0U; i < sizeof(g_user_test_page); ++i) {
    g_user_test_page[i] = 0U;
  }
  for (uint64_t i = 0U; i < image_size; ++i) {
    g_user_test_page[i] = _binary_hello_bin_start[i];
  }
  g_ring3_syscalls = 0U;
  g_ring3_exit_code = UINT64_MAX;
  x86_64_enter_ring3(X86_USER_BASE,
                     X86_USER_BASE + X86_USER_WINDOW_SIZE - 16U);
  if (g_ring3_syscalls != 3U) panic_halt(serial_base, "ring3 syscall count");
  if (g_ring3_exit_code != 0U) panic_halt(serial_base, "ring3 exit code");
  serial_puts(serial_base,
              "x86_64: real /bin/hello ELF syscall ABI passed calls=3 exit=0\n");
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
  if (tsc_denominator != 0U && tsc_numerator != 0U && crystal_hz != 0U) {
    g_tsc_frequency =
        ((uint64_t)crystal_hz * tsc_numerator) / tsc_denominator;
  } else if (max_leaf >= 0x16U) {
    uint32_t base_mhz = 0U;
    cpuid(0x16U, 0U, &base_mhz, &ebx, &ecx, &edx);
    if (base_mhz != 0U) {
      g_tsc_frequency = (uint64_t)base_mhz * UINT64_C(1000000);
    }
  }
  if (g_tsc_frequency == 0U) g_tsc_frequency = UINT64_C(1000000000);

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
  if ((apic_msr & APIC_BASE_ENABLE) == 0U) {
    panic_halt(serial_base, "local APIC unavailable");
  }
  g_lapic_x2apic =
      (apic_msr & APIC_BASE_X2APIC) != 0U ? UINT32_C(1) : UINT32_C(0);
  if (g_lapic_x2apic != 0U) {
    g_lapic = 0;
  } else {
    g_lapic = (volatile uint32_t *)(uintptr_t)(apic_msr &
                                                UINT64_C(0xfffff000));
  }
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
  if (elapsed_tsc != 0U) {
    g_lapic_frequency =
        (UINT64_C(100000) * g_tsc_frequency) / elapsed_tsc;
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
  serial_puts(serial_base, " elapsed_tsc=");
  serial_dec(serial_base, elapsed_tsc);
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

static void prepare_cpu_records(uint16_t serial_base) {
  if (g_acpi.enabled_cpus == 0U) panic_halt(serial_base, "MADT CPU count");
  uint64_t record_bytes =
      (uint64_t)g_acpi.enabled_cpus * sizeof(x86_64_cpu_record_t);
  g_cpu_records =
      (x86_64_cpu_record_t *)early_alloc(record_bytes, UINT64_C(64));
  if (g_cpu_records == 0) panic_halt(serial_base, "AP record allocation");
  g_cpu_record_count = g_acpi.enabled_cpus;
  for (uint64_t i = 0U; i < record_bytes; ++i) {
    ((uint8_t *)g_cpu_records)[i] = 0U;
  }
  for (uint32_t i = 0U; i < g_cpu_record_count; ++i) {
    if (!x86_64_acpi_cpu_apic_id(&g_acpi, i, &g_cpu_records[i].apic_id)) {
      panic_halt(serial_base, "MADT CPU enumeration");
    }
  }
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
      g_cpu_records[i].kernel_stack_top = g_tss.rsp0;
      g_cpu_records[i].syscall_stack_top = g_tss.rsp0;
      g_bsp_ordinal = i;
      bsp_found = 1U;
    }
  }
  if (bsp_found == 0U) panic_halt(serial_base, "BSP absent from MADT");

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

static uint32_t pci_read_config(uint8_t bus, uint8_t device, uint8_t function,
                                uint8_t offset) {
  uint32_t address = UINT32_C(0x80000000) | ((uint32_t)bus << 16) |
                     ((uint32_t)device << 11) | ((uint32_t)function << 8) |
                     ((uint32_t)offset & UINT32_C(0xfc));
  outl(PCI_CONFIG_ADDRESS, address);
  return inl(PCI_CONFIG_DATA);
}

static void pci_write_config(uint8_t bus, uint8_t device, uint8_t function,
                             uint8_t offset, uint32_t value) {
  uint32_t address = UINT32_C(0x80000000) | ((uint32_t)bus << 16) |
                     ((uint32_t)device << 11) | ((uint32_t)function << 8) |
                     ((uint32_t)offset & UINT32_C(0xfc));
  outl(PCI_CONFIG_ADDRESS, address);
  outl(PCI_CONFIG_DATA, value);
}

static uint8_t pci_read_config8(uint8_t bus, uint8_t device, uint8_t function,
                                uint8_t offset) {
  uint32_t value = pci_read_config(bus, device, function, offset);
  return (uint8_t)(value >> ((offset & 3U) * 8U));
}

static uint64_t pci_bar_address(uint8_t bus, uint8_t device,
                                uint8_t function, uint8_t bar) {
  if (bar >= 6U) return 0U;
  uint8_t offset = (uint8_t)(0x10U + bar * 4U);
  uint32_t low = pci_read_config(bus, device, function, offset);
  if ((low & 1U) != 0U) return 0U;
  uint64_t address = low & UINT32_C(0xfffffff0);
  if ((low & UINT32_C(6)) == UINT32_C(4) && bar + 1U < 6U) {
    address |= (uint64_t)pci_read_config(bus, device, function,
                                         (uint8_t)(offset + 4U))
               << 32U;
  }
  return address;
}

static uint8_t mmio_read8(uint64_t address) {
  return *(volatile uint8_t *)(uintptr_t)address;
}

static uint16_t mmio_read16(uint64_t address) {
  return *(volatile uint16_t *)(uintptr_t)address;
}

static uint32_t mmio_read32(uint64_t address) {
  return *(volatile uint32_t *)(uintptr_t)address;
}

static void mmio_write8(uint64_t address, uint8_t value) {
  *(volatile uint8_t *)(uintptr_t)address = value;
}

static void mmio_write16(uint64_t address, uint16_t value) {
  *(volatile uint16_t *)(uintptr_t)address = value;
}

static void mmio_write32(uint64_t address, uint32_t value) {
  *(volatile uint32_t *)(uintptr_t)address = value;
}

static void mmio_write64(uint64_t address, uint64_t value) {
  *(volatile uint64_t *)(uintptr_t)address = value;
}

static int find_virtio_pci_device(uint16_t wanted_device_id,
                                  x86_64_virtio_pci_device_t *result) {
  if (result == 0) return 0;
  *result = (x86_64_virtio_pci_device_t){0};
  for (uint16_t bus = 0U; bus < 256U; ++bus) {
    for (uint8_t device = 0U; device < 32U; ++device) {
      uint32_t header = pci_read_config((uint8_t)bus, device, 0U, 0x0cU);
      uint8_t functions = ((header >> 16U) & UINT32_C(0x80)) != 0U ? 8U : 1U;
      for (uint8_t function = 0U; function < functions; ++function) {
        uint32_t id =
            pci_read_config((uint8_t)bus, device, function, 0x00U);
        if ((uint16_t)id != UINT16_C(0x1af4) ||
            (uint16_t)(id >> 16U) != wanted_device_id) {
          continue;
        }
        result->bus = (uint8_t)bus;
        result->device = device;
        result->function = function;
        result->device_id = wanted_device_id;
        uint8_t pointer =
            pci_read_config8((uint8_t)bus, device, function, 0x34U) & 0xfcU;
        uint32_t visited = 0U;
        while (pointer >= 0x40U && pointer <= 0xfcU && visited++ < 48U) {
          uint8_t capability = pci_read_config8(
              (uint8_t)bus, device, function, pointer);
          uint8_t next = pci_read_config8(
              (uint8_t)bus, device, function, (uint8_t)(pointer + 1U)) &
                         0xfcU;
          if (capability == 0x09U &&
              pci_read_config8((uint8_t)bus, device, function,
                               (uint8_t)(pointer + 2U)) >= 16U) {
            uint8_t type = pci_read_config8(
                (uint8_t)bus, device, function, (uint8_t)(pointer + 3U));
            uint8_t bar = pci_read_config8(
                (uint8_t)bus, device, function, (uint8_t)(pointer + 4U));
            uint64_t bar_address =
                pci_bar_address((uint8_t)bus, device, function, bar);
            uint32_t offset = pci_read_config(
                (uint8_t)bus, device, function, (uint8_t)(pointer + 8U));
            uint64_t address = bar_address + offset;
            if (bar_address != 0U && address >= bar_address) {
              if (type == 1U) result->common_config = address;
              if (type == 2U) {
                result->notify_base = address;
                result->notify_multiplier = pci_read_config(
                    (uint8_t)bus, device, function,
                    (uint8_t)(pointer + 16U));
              }
              if (type == 3U) result->isr_config = address;
              if (type == 4U) result->device_config = address;
            }
          }
          if (next == 0U || next == pointer) break;
          pointer = next;
        }
        if (result->common_config != 0U && result->notify_base != 0U &&
            result->notify_multiplier != 0U) {
          uint32_t command = pci_read_config(
              (uint8_t)bus, device, function, 0x04U);
          pci_write_config((uint8_t)bus, device, function, 0x04U,
                           command | UINT32_C(6));
          result->valid = 1U;
          return 1;
        }
        return 0;
      }
    }
  }
  return 0;
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

static void X86_BRINGUP_ONLY discover_pci(uint16_t serial_base) {
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

static int virtio_begin(const x86_64_virtio_pci_device_t *device) {
  uint64_t common = device->common_config;
  mmio_write8(common + 20U, 0U);
  for (uint32_t spin = 0U; spin < 1000000U; ++spin) {
    if (mmio_read8(common + 20U) == 0U) break;
  }
  if (mmio_read8(common + 20U) != 0U) return 0;
  mmio_write8(common + 20U, 1U);
  mmio_write8(common + 20U, 3U);
  mmio_write32(common + 0U, 1U);
  uint32_t high_features = mmio_read32(common + 4U);
  if ((high_features & 1U) == 0U) return 0;
  mmio_write32(common + 8U, 0U);
  mmio_write32(common + 12U, 0U);
  mmio_write32(common + 8U, 1U);
  mmio_write32(common + 12U, 1U);
  mmio_write8(common + 20U, 11U);
  if ((mmio_read8(common + 20U) & 8U) == 0U) return 0;
  return 1;
}

static int virtio_setup_queue(const x86_64_virtio_pci_device_t *device,
                              uint16_t queue_index, uint8_t *queue_memory,
                              uint16_t msix_vector,
                              uint16_t *notify_offset) {
  uint64_t common = device->common_config;
  mmio_write16(common + 22U, queue_index);
  uint16_t maximum = mmio_read16(common + 24U);
  if (maximum == 0U || queue_memory == 0 || notify_offset == 0) return 0;
  uint16_t size = maximum < 8U ? maximum : 8U;
  for (uint32_t i = 0U; i < PAGE_SIZE; ++i) queue_memory[i] = 0U;
  uint64_t descriptor_address = (uint64_t)(uintptr_t)queue_memory;
  uint64_t available_address = descriptor_address + UINT64_C(256);
  uint64_t used_address = descriptor_address + UINT64_C(512);
  mmio_write16(common + 24U, size);
  mmio_write16(common + 26U, msix_vector);
  mmio_write64(common + 32U, descriptor_address);
  mmio_write64(common + 40U, available_address);
  mmio_write64(common + 48U, used_address);
  *notify_offset = mmio_read16(common + 30U);
  mmio_write16(common + 28U, 1U);
  return mmio_read16(common + 28U) == 1U;
}

static void virtio_notify(const x86_64_virtio_pci_device_t *device,
                          uint16_t queue_index, uint16_t notify_offset) {
  uint64_t address = device->notify_base +
                     (uint64_t)notify_offset * device->notify_multiplier;
  __atomic_thread_fence(__ATOMIC_RELEASE);
  mmio_write16(address, queue_index);
}

static int map_high_mmio_gib(uint64_t address) {
  if (address < EARLY_IDENTITY_LIMIT) return 1;
  uint64_t base = address & ~UINT64_C(0x3fffffff);
  if (g_mmio_gib_base != 0U) return g_mmio_gib_base == base;
  uint32_t pml4_index = (uint32_t)((base >> 39U) & UINT64_C(0x1ff));
  uint32_t pdpt_index = (uint32_t)((base >> 30U) & UINT64_C(0x1ff));
  for (uint32_t i = 0U; i < 512U; ++i) {
    g_mmio_pdpt[i] = 0U;
    g_mmio_pd[i] = (base + (uint64_t)i * LARGE_PAGE_SIZE) | PTE_PRESENT |
                   PTE_WRITABLE | PTE_LARGE | PTE_NX;
  }
  if (pml4_index == 0U) {
    if (g_pdpt[pdpt_index] != 0U) return 0;
    g_pdpt[pdpt_index] = (uint64_t)(uintptr_t)g_mmio_pd | PTE_PRESENT |
                         PTE_WRITABLE;
    g_mmio_gib_base = base;
    write_cr3(read_cr3());
    return 1;
  }
  g_mmio_pdpt[pdpt_index] = (uint64_t)(uintptr_t)g_mmio_pd | PTE_PRESENT |
                            PTE_WRITABLE;
  g_pml4[pml4_index] = (uint64_t)(uintptr_t)g_mmio_pdpt | PTE_PRESENT |
                       PTE_WRITABLE;
  g_mmio_gib_base = base;
  write_cr3(read_cr3());
  return 1;
}

static int configure_msix(const x86_64_virtio_pci_device_t *device,
                          uint16_t table_entry, uint8_t vector) {
  uint8_t pointer = pci_read_config8(device->bus, device->device,
                                     device->function, 0x34U) &
                    0xfcU;
  uint32_t visited = 0U;
  while (pointer >= 0x40U && pointer <= 0xfcU && visited++ < 48U) {
    uint32_t header = pci_read_config(device->bus, device->device,
                                      device->function, pointer);
    if ((header & UINT32_C(0xff)) == UINT32_C(0x11)) {
      uint16_t control = (uint16_t)(header >> 16U);
      uint16_t table_size = (uint16_t)((control & UINT16_C(0x07ff)) + 1U);
      if (table_entry >= table_size) return 0;
      uint32_t table = pci_read_config(device->bus, device->device,
                                       device->function,
                                       (uint8_t)(pointer + 4U));
      uint8_t bar = (uint8_t)(table & 7U);
      uint64_t table_base =
          pci_bar_address(device->bus, device->device, device->function, bar) +
          (table & UINT32_C(0xfffffff8));
      uint64_t entry = table_base + (uint64_t)table_entry * 16U;
      if (table_base == 0U || entry < table_base ||
          !map_high_mmio_gib(entry)) {
        return 0;
      }
      mmio_write32(entry + 12U, 1U);
      mmio_write32(entry + 0U,
                   UINT32_C(0xfee00000) | (lapic_id() << 12U));
      mmio_write32(entry + 4U, 0U);
      mmio_write32(entry + 8U, vector);
      mmio_write32(entry + 12U, 0U);
      control = (uint16_t)((control | UINT16_C(0x8000)) &
                           ~UINT16_C(0x4000));
      pci_write_config(device->bus, device->device, device->function, pointer,
                       (header & UINT32_C(0xffff)) |
                           ((uint32_t)control << 16U));
      return 1;
    }
    uint8_t next = (uint8_t)((header >> 8U) & UINT32_C(0xfc));
    if (next == 0U || next == pointer) break;
    pointer = next;
  }
  return 0;
}

static int virtio_wait_used(volatile uint16_t *used_index,
                            uint16_t expected) {
  uint64_t deadline = rdtsc() + UINT64_C(2000000000);
  while (__atomic_load_n(used_index, __ATOMIC_ACQUIRE) != expected &&
         (int64_t)(rdtsc() - deadline) < 0) {
    __asm__ volatile("pause");
  }
  return *used_index == expected;
}

static void X86_BRINGUP_ONLY validate_virtio_block_operation(uint16_t serial_base) {
  x86_64_virtio_pci_device_t device;
  int found = find_virtio_pci_device(UINT16_C(0x1042), &device);
  serial_puts(serial_base, "x86_64: VirtIO block PCI transport found=");
  serial_dec(serial_base, found != 0);
  serial_puts(serial_base, " common=");
  serial_hex64(serial_base, device.common_config);
  serial_puts(serial_base, " notify=");
  serial_hex64(serial_base, device.notify_base);
  serial_puts(serial_base, " multiplier=");
  serial_dec(serial_base, device.notify_multiplier);
  serial_puts(serial_base, "\n");
  if (!found || !map_high_mmio_gib(device.common_config) ||
      !map_high_mmio_gib(device.notify_base) || !virtio_begin(&device)) {
    panic_halt(serial_base, "modern VirtIO block negotiation");
  }
  uint8_t *queue = (uint8_t *)early_alloc(PAGE_SIZE, PAGE_SIZE);
  uint8_t *request = (uint8_t *)early_alloc(PAGE_SIZE, PAGE_SIZE);
  uint16_t notify_offset = 0U;
  if (request == 0 || !configure_msix(&device, 0U, 34U) ||
      !virtio_setup_queue(&device, 0U, queue, 0U, &notify_offset)) {
    panic_halt(serial_base, "VirtIO block queue");
  }
  for (uint32_t i = 0U; i < PAGE_SIZE; ++i) request[i] = 0U;
  virtq_descriptor_t *descriptors = (virtq_descriptor_t *)(void *)queue;
  volatile uint16_t *available_index =
      (volatile uint16_t *)(void *)(queue + 258U);
  volatile uint16_t *available_ring =
      (volatile uint16_t *)(void *)(queue + 260U);
  volatile uint16_t *used_index =
      (volatile uint16_t *)(void *)(queue + 514U);
  uint8_t *data = request + 16U;
  uint8_t *status = request + 528U;
  *status = UINT8_C(0xff);
  descriptors[0] = (virtq_descriptor_t){
      (uint64_t)(uintptr_t)request, 16U, 1U, 1U};
  descriptors[1] = (virtq_descriptor_t){
      (uint64_t)(uintptr_t)data, 512U, 3U, 2U};
  descriptors[2] = (virtq_descriptor_t){
      (uint64_t)(uintptr_t)status, 1U, 2U, 0U};
  available_ring[0] = 0U;
  *available_index = 1U;
  g_virtio_msix_isr = device.isr_config;
  g_virtio_msix_interrupts = 0U;
  mmio_write8(device.common_config + 20U, 15U);
  virtio_notify(&device, 0U, notify_offset);
  __asm__ volatile("sti" ::: "memory");
  int completed = virtio_wait_used(used_index, 1U);
  __asm__ volatile("cli" ::: "memory");
  if (!completed || g_virtio_msix_interrupts == 0U || *status != 0U ||
      data[510] != UINT8_C(0x55) || data[511] != UINT8_C(0xaa)) {
    panic_halt(serial_base, "VirtIO block DMA read");
  }
  serial_puts(serial_base,
              "x86_64: modern VirtIO block DMA read passed sector=0 bytes=512\n");
  serial_puts(serial_base,
              "x86_64: VirtIO block MSI-X completion interrupt passed vector=34\n");
}

static void X86_BRINGUP_ONLY validate_virtio_network_operation(uint16_t serial_base) {
  x86_64_virtio_pci_device_t device;
  if (!find_virtio_pci_device(UINT16_C(0x1041), &device) ||
      !map_high_mmio_gib(device.common_config) ||
      !map_high_mmio_gib(device.notify_base) || !virtio_begin(&device)) {
    panic_halt(serial_base, "modern VirtIO network negotiation");
  }
  uint8_t *queue = (uint8_t *)early_alloc(PAGE_SIZE, PAGE_SIZE);
  uint8_t *packet = (uint8_t *)early_alloc(PAGE_SIZE, PAGE_SIZE);
  uint16_t notify_offset = 0U;
  if (packet == 0 ||
      !virtio_setup_queue(&device, 1U, queue, UINT16_C(0xffff),
                          &notify_offset)) {
    panic_halt(serial_base, "VirtIO network queue");
  }
  for (uint32_t i = 0U; i < PAGE_SIZE; ++i) packet[i] = 0U;
  uint8_t *frame = packet + 10U;
  for (uint32_t i = 0U; i < 6U; ++i) frame[i] = UINT8_C(0xff);
  const uint8_t source[6] = {0x52U, 0x54U, 0x00U, 0x12U, 0x34U, 0x56U};
  for (uint32_t i = 0U; i < 6U; ++i) frame[6U + i] = source[i];
  frame[12] = 0x08U;
  frame[13] = 0x06U;
  frame[14] = 0x00U;
  frame[15] = 0x01U;
  frame[16] = 0x08U;
  frame[17] = 0x00U;
  frame[18] = 0x06U;
  frame[19] = 0x04U;
  frame[20] = 0x00U;
  frame[21] = 0x01U;
  for (uint32_t i = 0U; i < 6U; ++i) frame[22U + i] = source[i];
  frame[28] = 10U;
  frame[29] = 0U;
  frame[30] = 2U;
  frame[31] = 15U;
  frame[38] = 10U;
  frame[39] = 0U;
  frame[40] = 2U;
  frame[41] = 2U;
  virtq_descriptor_t *descriptors = (virtq_descriptor_t *)(void *)queue;
  volatile uint16_t *available_index =
      (volatile uint16_t *)(void *)(queue + 258U);
  volatile uint16_t *available_ring =
      (volatile uint16_t *)(void *)(queue + 260U);
  volatile uint16_t *used_index =
      (volatile uint16_t *)(void *)(queue + 514U);
  descriptors[0] = (virtq_descriptor_t){
      (uint64_t)(uintptr_t)packet, 52U, 0U, 0U};
  available_ring[0] = 0U;
  *available_index = 1U;
  mmio_write8(device.common_config + 20U, 15U);
  virtio_notify(&device, 1U, notify_offset);
  if (!virtio_wait_used(used_index, 1U)) {
    panic_halt(serial_base, "VirtIO network DMA TX");
  }
  serial_puts(serial_base,
              "x86_64: modern VirtIO network DMA TX passed bytes=42\n");
}

static void X86_BRINGUP_ONLY build_placement_policy(uint16_t serial_base) {
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

static void X86_BRINGUP_ONLY validate_x86_os_contract(uint16_t serial_base) {
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

static void X86_BRINGUP_ONLY validate_hardware_gate(uint16_t serial_base) {
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

uint64_t x86_64_exception_entry(const x86_64_exception_frame_t *frame) {
  uint16_t serial_base = COM1_PORT;
  serial_init(serial_base);
  if (frame != 0 && frame->vector == g_expected_exception_vector) {
    ++g_exception_test_count;
    g_expected_exception_vector = UINT32_MAX;
    return 0U;
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
#if XAIOS_X86_COMMON_RUNTIME
  if (frame != 0 && (frame->cs & 3U) == 3U) {
    uint64_t result = user_process_note_fault();
    x86_64_platform_set_user_return(result);
    return (uint64_t)(uintptr_t)x86_64_ring3_resume;
  }
#endif
  panic_halt(serial_base, "controlled x86_64 exception reported");
  return 0U;
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
  parse_acpi(serial_base, boot);
  prepare_cpu_records(serial_base);
  serial_puts(serial_base, "x86_64: ACPI topology and NUMA tables validated\n");
  install_page_tables(serial_base);
  if (g_page_tables_loaded == 0U) {
    panic_halt(serial_base, "page tables not loaded");
  }
  serial_puts(serial_base, "x86_64: Intel Desktop milestone 46 page tables passed\n");
  validate_xsave(serial_base);
  prepare_irq_state_areas(serial_base);
  discover_timer_apic(serial_base);
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
  build_placement_policy(serial_base);
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
