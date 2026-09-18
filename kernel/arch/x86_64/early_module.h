#ifndef XAIOS_X86_64_EARLY_MODULE_H
#define XAIOS_X86_64_EARLY_MODULE_H

/* The private seam between kernel/arch/x86_64/early.c and the modules split
 * out of it (early_tlb.c, early_cpu.c, early_serial.c, early_mem.c,
 * early_pci.c, early_acpi.c, early_fpu.c, early_gdt.c, early_irq.c,
 * early_platform.c and early_timer_discover.c). Every one of those files
 * includes this header and nothing in it is visible outside
 * them: the x86_64 CPU record, the per-CPU TLB bookkeeping, the trap frame and
 * the early.c primitives the moved code calls are shared here, while the
 * globals stay file-scope in whichever file owns them.
 * Declarations and type definitions only -- the functions are defined exactly
 * once, in the file the comment beside them names. */

#include <xaios/boot_info.h>
#include <xaios/smp.h>
#include <xaios/types.h>

/* Same nesting bound early.c uses for the per-CPU user-resume stacks; the CPU
 * record's arrays are sized by it. */
#define X86_USER_NESTING_MAX UINT32_C(8)

/* The kernel and syscall stacks. early.c guards both with these and the moved
 * GDT/TSS builder in early_gdt.c sizes the BSP's syscall stack with them, so
 * they are shared here rather than defined on one side of the seam. */
#define X86_KERNEL_STACK_SIZE UINT64_C(524288)
#define X86_KERNEL_STACK_GUARD_BYTES UINT32_C(64)
#define X86_KERNEL_STACK_GUARD_VALUE UINT8_C(0xa5)

/* The MSR holding the local-APIC base and its enable/x2APIC bits. early.c's
 * LAPIC register primitives and early_timer_discover.c's calibration both read
 * it, so it is defined once here rather than on either side of the seam. */
#define MSR_IA32_APIC_BASE UINT32_C(0x1b)

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

/* The descriptor-table pointer `lgdt`/`lidt` take. Shared because early_gdt.c's
 * builder and early.c's install_idt and AP entry each load one. */
typedef struct x86_64_idtr {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed)) x86_64_idtr_t;

/* The frame entry.S pushes before it calls the C trap entry, in the order
 * entry.S itself pushes it. Shared because early.c's exception entry and
 * early_irq.c's interrupt dispatch both name it; the layout is entry.S's, so it
 * is defined once here rather than on either side of the seam. */
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

typedef struct x86_64_cpu_record {
  uint32_t apic_id;
  volatile uint32_t online;
  volatile uint32_t worker_ready;
  volatile uint32_t requested_generation;
  volatile uint32_t completed_generation;
  volatile uint64_t checksum;
  volatile uint32_t tlb_generation;
  /* What this CPU was doing when somebody asked it for a TLB shootdown, so a
   * refusal can say why it did not answer (B-123). `interrupts_taken` is a
   * liveness count: a CPU that keeps taking timer interrupts is running with
   * interrupts enabled and simply did not receive or handle the request, while
   * one whose count is frozen is not taking interrupts at all. */
  volatile uint64_t interrupts_taken;
  volatile uint32_t last_vector;
  volatile uint64_t shootdowns_handled;
  volatile uint64_t shootdowns_polled;
  volatile uint32_t shootdown_lock_wait;
  /* How many times this CPU reached its halt with a thread pending for it
   * anyway, which is a wakeup that arrived between the idle loop's check and
   * its halt and was consumed by its handler (B-120). Zero after the fix
   * except when it counts one the re-check caught. */
  volatile uint32_t idle_wakeups_raced;
  /* How many times this CPU entered the self-test's widened window, which is
   * how the test knows the wakeup it sends is inside it. */
  volatile uint32_t idle_gap_rounds;
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

/* Shared read of early.c's CPU table. early.c keeps owning the storage and the
 * pointer; this hands the TLB half the same address it used to reach through
 * the old file-scope names. */
x86_64_cpu_record_t *xaios_x86_early_cpu_records(void);
uint32_t xaios_x86_early_cpu_record_count(void);

/* early.c primitives the shootdown calls but does not own. */
void xaios_x86_early_lapic_send(uint32_t destination, uint32_t command);
uint32_t xaios_x86_early_current_ordinal_fast(void);
void xaios_x86_early_serial_puts(uint16_t base, const char *message);
void xaios_x86_early_serial_dec(uint16_t base, uint64_t value);
void xaios_x86_early_panic_halt(uint16_t serial_base, const char *message);

/* The two more early.c primitives early_irq.c's dispatch calls: the APIC-ready
 * flag and the local-APIC register write. Both are the same functions early.c
 * uses, not copies. */
uint32_t xaios_x86_early_lapic_ready(void);
void xaios_x86_early_lapic_write(uint32_t offset, uint32_t value);

/* The idle-loop probe pair now lives in early_platform.c with its setter and
 * getter; early.c's idle loop reads it through the getter, so this is the whole
 * of that knob across the seam. */
typedef struct x86_64_idle_probe_state {
  uint64_t gap_cycles;
  uint32_t legacy;
} x86_64_idle_probe_state_t;

void xaios_x86_early_idle_probe_get(x86_64_idle_probe_state_t *state);

/* The scalars early.c owns and the platform hooks in early_platform.c read or
 * write across the seam. Each hands over a value, never a pointer into
 * early.c's storage. */
uint64_t xaios_x86_early_tsc_hz(void);
void xaios_x86_early_set_tsc_hz(uint64_t frequency);
uint64_t xaios_x86_early_lapic_hz(void);
uint32_t xaios_x86_early_bsp_ordinal(void);
void xaios_x86_early_set_worker_release(uint32_t value);

/* Defined in early_timer_discover.c: measure the TSC against the PIT (B-122)
 * and report the APIC/timer capabilities, at the one point in x86_64_kmain
 * before the LAPIC timer self-test. It programs no interrupt, sends no IPI and
 * starts no AP; the frequency it determines is stored through
 * xaios_x86_early_set_tsc_hz above, and the LAPIC timer interrupt itself still
 * stays with validate_lapic_timer_interrupt in early.c. */
void xaios_x86_early_timer_discover(uint16_t serial_base);

/* Defined in early_tlb.c. */
void xaios_x86_early_tlb_note_interrupt(void);
void xaios_x86_early_tlb_acknowledge(x86_64_cpu_record_t *record,
                                     uint32_t generation);

/* The CPU-topology report in early_cpu.c needs two more early.c primitives
 * than the shootdown does; appended here rather than given a second header, so
 * all the early files share one seam. */
void xaios_x86_early_serial_hex64(uint16_t base, uint64_t value);
void xaios_x86_early_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                           uint32_t *ebx, uint32_t *ecx, uint32_t *edx);

/* Defined in early_cpu.c. */
void x86_64_early_cpu_build_placement_policy(uint16_t serial_base);

/* Defined in early_gdt.c: build and load the BSP GDT/TSS, the per-AP half, and
 * the BSP TSS rsp0 the platform hooks here read and write. The rsp0 crosses
 * the seam as a scalar, never as a pointer into early_gdt.c's mutable state. */
void xaios_x86_gdt_install(uint16_t serial_base);
void xaios_x86_gdt_install_ap(x86_64_cpu_record_t *record);
uint64_t xaios_x86_gdt_bsp_rsp0(void);
void xaios_x86_gdt_set_bsp_rsp0(uint64_t rsp0);

/* Defined in early_acpi.c: parse the RSDP/root/MADT (and note SRAT/SLIT/HMAT),
 * then allocate and enumerate the CPU records. The record storage stays owned
 * by early.c, which passes the pointer and count it wants filled. */
void xaios_x86_early_acpi_parse(uint16_t serial_base,
                                const xaios_boot_info_t *boot);
void xaios_x86_early_acpi_prepare_cpu_records(uint16_t serial_base,
                                              x86_64_cpu_record_t **records,
                                              uint32_t *record_count);

/* The paging/PM primitives early.c and early_pci.c call; defined in
 * early_mem.c. */
void xaios_x86_mem_parse_map(uint16_t serial_base,
                             const xaios_boot_info_t *boot);
void xaios_x86_mem_install_page_tables(uint16_t serial_base);
uint32_t xaios_x86_mem_page_tables_loaded(void);
void *xaios_x86_mem_alloc(uint64_t bytes, uint64_t alignment);
uint64_t xaios_x86_mem_bootstrap_start(void);
uint64_t xaios_x86_mem_bootstrap_end(void);
int xaios_x86_mem_map_mmio_gib(uint64_t address);
void xaios_x86_mem_validate_ring3(uint16_t serial_base);
void xaios_x86_mem_note_ring3_call(void);
void xaios_x86_mem_set_ring3_exit(uint64_t value);

/* The PCI/VirtIO primitives early.c calls; defined in early_pci.c. */
void xaios_x86_pci_discover(uint16_t serial_base);
void xaios_x86_pci_validate_virtio_block(uint16_t serial_base);
void xaios_x86_pci_validate_virtio_network(uint16_t serial_base);
void xaios_x86_pci_note_msix_interrupt(void);

/* The MSR/CR/TSC/APIC primitives early.c exports for early_mem.c and
 * early_pci.c; defined in early.c. */
uint64_t xaios_x86_early_rdmsr(uint32_t msr);
void xaios_x86_early_wrmsr(uint32_t msr, uint64_t value);
uint64_t xaios_x86_early_read_cr3(void);
void xaios_x86_early_write_cr3(uint64_t value);
uint64_t xaios_x86_early_rdtsc(void);
uint32_t xaios_x86_early_lapic_id(void);

/* entry.S symbols that now cross between early.c and early_irq.c.
 * g_x86_lapic_timer_interrupts is defined in early.c, which owns the timer
 * self-test that resets and prints it, and incremented by early_irq.c on the
 * vector 32 path; entry.S also polls it by name. x86_64_ring3_resume is the
 * label in entry.S the ring-3 exit paths return through. */
extern volatile uint64_t g_x86_lapic_timer_interrupts;
extern void x86_64_ring3_resume(void);

/* Defined in early_irq.c: the C half of the trap entry entry.S calls, and the
 * per-CPU trap-depth query the klog lock uses. */
uint64_t x86_64_interrupt_entry(x86_64_exception_frame_t *frame);
uint32_t xaios_cpu_in_interrupt(void);

#endif
