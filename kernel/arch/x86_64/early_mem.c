/* The x86-64 early paging and physical-memory setup: the bootstrap allocator,
 * the UEFI memory-map parse, the identity/user/MMIO page tables, and the early
 * user window the ring-3 ABI probe runs in. Split out of early.c; the bodies
 * are moved verbatim and early_module.h is the shared seam. */

#include <xaios/boot_info.h>
#include <xaios/types.h>

#include "early_module.h"

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

#if XAIOS_X86_COMMON_RUNTIME
#define X86_BRINGUP_ONLY __attribute__((unused))
#else
#define X86_BRINGUP_ONLY
#endif

#define PAGE_SIZE UINT64_C(4096)
#define LARGE_PAGE_SIZE UINT64_C(0x200000)
#define EARLY_IDENTITY_LIMIT UINT64_C(0x100000000)
#define X86_USER_BASE UINT64_C(0x100000000)
#define PTE_PRESENT UINT64_C(1)
#define PTE_WRITABLE UINT64_C(1 << 1)
#define PTE_USER UINT64_C(1 << 2)
#define PTE_LARGE UINT64_C(1 << 7)
#define PTE_GLOBAL UINT64_C(1 << 8)
#define PTE_NX (UINT64_C(1) << 63)
#define MSR_IA32_EFER UINT32_C(0xc0000080)
#define EFER_NXE UINT64_C(1 << 11)

#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define serial_hex64 xaios_x86_early_serial_hex64
#define panic_halt xaios_x86_early_panic_halt
#define rdmsr xaios_x86_early_rdmsr
#define wrmsr xaios_x86_early_wrmsr
#define read_cr3 xaios_x86_early_read_cr3
#define write_cr3 xaios_x86_early_write_cr3
#define early_alloc xaios_x86_mem_alloc

extern const uint8_t _binary_hello_bin_start[];
extern const uint8_t _binary_hello_bin_end[];
extern void x86_64_enter_ring3(uint64_t entry, uint64_t stack);

typedef struct x86_64_pmm_state {
  uint64_t descriptors;
  uint64_t conventional_regions;
  uint64_t total_pages;
  uint64_t usable_pages;
  uint64_t reserved_pages;
  uint64_t largest_usable_base;
  uint64_t largest_usable_pages;
} x86_64_pmm_state_t;

static uint64_t g_pml4[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_pdpt[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_pd[4][512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_user_pd[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_mmio_pdpt[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_mmio_pd[512] __attribute__((aligned(PAGE_SIZE)));
static uint64_t g_mmio_gib_base;

static uint8_t *g_user_test_page;
static x86_64_pmm_state_t g_pmm;

static uint32_t g_page_tables_loaded;

static volatile uint64_t g_ring3_syscalls;
static volatile uint64_t g_ring3_exit_code;

static uint64_t g_early_alloc_cursor;
static uint64_t g_early_alloc_start;
static uint64_t g_early_alloc_end;

static uint64_t align_up(uint64_t value, uint64_t align) {
  return (value + align - 1U) & ~(align - 1U);
}

static uint64_t align_down(uint64_t value, uint64_t align) {
  return value & ~(align - 1U);
}

void *xaios_x86_mem_alloc(uint64_t bytes, uint64_t alignment) {
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

void xaios_x86_mem_parse_map(uint16_t serial_base, const xaios_boot_info_t *boot) {
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

void xaios_x86_mem_install_page_tables(uint16_t serial_base) {
  if (g_user_test_page == 0) {
    g_user_test_page = (uint8_t *)early_alloc(LARGE_PAGE_SIZE, LARGE_PAGE_SIZE);
    if (g_user_test_page == 0) panic_halt(serial_base, "early user window");
  }
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

#if !XAIOS_X86_COMMON_RUNTIME
void X86_BRINGUP_ONLY xaios_x86_mem_validate_ring3(uint16_t serial_base) {
  uint64_t image_size =
      (uint64_t)(_binary_hello_bin_end - _binary_hello_bin_start);
  if (image_size == 0U || image_size > LARGE_PAGE_SIZE) {
    panic_halt(serial_base, "userspace hello image size");
  }
  for (uint64_t i = 0U; i < LARGE_PAGE_SIZE; ++i) {
    g_user_test_page[i] = 0U;
  }
  for (uint64_t i = 0U; i < image_size; ++i) {
    g_user_test_page[i] = _binary_hello_bin_start[i];
  }
  g_ring3_syscalls = 0U;
  g_ring3_exit_code = UINT64_MAX;
  x86_64_enter_ring3(X86_USER_BASE,
                     X86_USER_BASE + LARGE_PAGE_SIZE - 16U);
  if (g_ring3_syscalls != 3U) panic_halt(serial_base, "ring3 syscall count");
  if (g_ring3_exit_code != 0U) panic_halt(serial_base, "ring3 exit code");
  serial_puts(serial_base,
              "x86_64: real /bin/hello ELF syscall ABI passed calls=3 exit=0\n");
}
#else
void xaios_x86_mem_validate_ring3(uint16_t serial_base) {
  (void)serial_base;
  /* Bring-up only: the ring-3 probe needs the embedded hello image, which
     only the bring-up build links. With the common runtime the user
     application runs through the normal loader instead. */
}
#endif

int xaios_x86_mem_map_mmio_gib(uint64_t address) {
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

/* The reads early.c kept through the old file-scope names, and the two named
 * mutators its trap entry calls for the ring-3 counters now that the counters
 * live here. */
uint64_t xaios_x86_mem_bootstrap_start(void) { return g_early_alloc_start; }
uint64_t xaios_x86_mem_bootstrap_end(void) { return g_early_alloc_cursor; }
uint32_t xaios_x86_mem_page_tables_loaded(void) { return g_page_tables_loaded; }
void xaios_x86_mem_note_ring3_call(void) { ++g_ring3_syscalls; }
void xaios_x86_mem_set_ring3_exit(uint64_t value) { g_ring3_exit_code = value; }
