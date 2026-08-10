#include <xaios/assert.h>
#include <xaios/elf_loader.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/vmm.h>

#define PAGE_SIZE UINT64_C(4096)
#define ELF_MAGIC UINT32_C(0x464c457f)
#define PT_LOAD UINT32_C(1)
#define PF_X UINT32_C(1)
#define PF_W UINT32_C(2)
#define PF_R UINT32_C(4)
#define ET_EXEC UINT16_C(2)
#define EM_AARCH64 UINT16_C(183)
#define EM_X86_64 UINT16_C(62)
#if defined(__aarch64__)
#define XAIOS_ELF_MACHINE EM_AARCH64
#elif defined(__x86_64__)
#define XAIOS_ELF_MACHINE EM_X86_64
#else
#error "Unsupported XAIOS ELF target architecture"
#endif

typedef struct elf64_ehdr {
  uint8_t ident[16];
  uint16_t type;
  uint16_t machine;
  uint32_t version;
  uint64_t entry;
  uint64_t phoff;
  uint64_t shoff;
  uint32_t flags;
  uint16_t ehsize;
  uint16_t phentsize;
  uint16_t phnum;
  uint16_t shentsize;
  uint16_t shnum;
  uint16_t shstrndx;
} elf64_ehdr_t;

typedef struct elf64_phdr {
  uint32_t type;
  uint32_t flags;
  uint64_t offset;
  uint64_t vaddr;
  uint64_t paddr;
  uint64_t filesz;
  uint64_t memsz;
  uint64_t align;
} elf64_phdr_t;

static uint64_t align_down(uint64_t value, uint64_t alignment) {
  return value & ~(alignment - 1);
}

static uint64_t align_up(uint64_t value, uint64_t alignment) {
  return (value + alignment - 1) & ~(alignment - 1);
}

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static uint32_t elf_magic_value(const uint8_t *ident) {
  return ((uint32_t)ident[0]) | ((uint32_t)ident[1] << 8U) |
         ((uint32_t)ident[2] << 16U) | ((uint32_t)ident[3] << 24U);
}

static xaios_status_t validate_elf(const xaios_initramfs_file_t *file,
                                  const elf64_ehdr_t **out) {
  if (file == 0 || file->base == 0 || file->size < sizeof(elf64_ehdr_t) ||
      file->executable == 0) {
    return XAIOS_ERR_INVALID;
  }

  const elf64_ehdr_t *ehdr = (const elf64_ehdr_t *)file->base;
  if (elf_magic_value(ehdr->ident) != ELF_MAGIC || ehdr->ident[4] != 2 ||
      ehdr->ident[5] != 1 || ehdr->type != ET_EXEC ||
      ehdr->machine != XAIOS_ELF_MACHINE ||
      ehdr->phentsize != sizeof(elf64_phdr_t) || ehdr->phnum == 0 ||
      ehdr->phoff + ((uint64_t)ehdr->phnum * ehdr->phentsize) > file->size) {
    return XAIOS_ERR_INVALID;
  }
  if (ehdr->entry < XAIOS_USER_BASE || ehdr->entry >= XAIOS_USER_LIMIT) {
    return XAIOS_ERR_INVALID;
  }

  *out = ehdr;
  return XAIOS_OK;
}

static uint32_t vmm_flags_from_phdr(const elf64_phdr_t *phdr) {
  uint32_t flags = XAIOS_VMM_PRESENT | XAIOS_VMM_USER | XAIOS_VMM_NG;
  if ((phdr->flags & PF_W) != 0) {
    flags |= XAIOS_VMM_WRITABLE;
  }
  if ((phdr->flags & PF_X) != 0) {
    flags |= XAIOS_VMM_EXECUTABLE;
  }
  (void)PF_R;
  return flags;
}

static xaios_status_t reserve_page_mappings(xaios_process_aspace_t *aspace,
                                            uint32_t required) {
  uint32_t capacity = aspace->page_capacity;
  if (required <= capacity) {
    return XAIOS_OK;
  }
  if (capacity == 0U) {
    capacity = 64U;
  }
  while (capacity < required) {
    if (capacity > UINT32_MAX / 2U) {
      return XAIOS_ERR_NO_MEMORY;
    }
    capacity *= 2U;
  }
  if ((uint64_t)capacity >
      UINT64_MAX / sizeof(xaios_process_page_mapping_t)) {
    return XAIOS_ERR_NO_MEMORY;
  }
  uint64_t bytes =
      (uint64_t)capacity * sizeof(xaios_process_page_mapping_t);
  xaios_process_page_mapping_t *pages =
      (xaios_process_page_mapping_t *)kheap_calloc(bytes, 16U);
  if (pages == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (aspace->pages != 0 && aspace->page_count != 0U) {
    bytes_copy(pages, aspace->pages,
               (uint64_t)aspace->page_count * sizeof(*pages));
  }
  kheap_free(aspace->pages);
  aspace->pages = pages;
  aspace->page_capacity = capacity;
  return XAIOS_OK;
}

static xaios_status_t track_page(xaios_process_aspace_t *aspace, uint64_t va,
                                uint64_t pa) {
  if (aspace->page_count == UINT32_MAX ||
      reserve_page_mappings(aspace, aspace->page_count + 1U) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  aspace->pages[aspace->page_count].va = va;
  aspace->pages[aspace->page_count].pa = pa;
  ++aspace->page_count;
  return XAIOS_OK;
}

static xaios_status_t load_segment(const xaios_initramfs_file_t *file,
                                  const elf64_phdr_t *phdr,
                                  xaios_process_aspace_t *aspace) {
  if (phdr->memsz < phdr->filesz ||
      phdr->offset + phdr->filesz > file->size ||
      phdr->vaddr < XAIOS_USER_BASE ||
      phdr->vaddr + phdr->memsz < phdr->vaddr ||
      phdr->vaddr + phdr->memsz > XAIOS_USER_LIMIT) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t map_start = align_down(phdr->vaddr, PAGE_SIZE);
  uint64_t map_end = align_up(phdr->vaddr + phdr->memsz, PAGE_SIZE);
  uint32_t flags = vmm_flags_from_phdr(phdr);

  for (uint64_t va = map_start; va < map_end; va += PAGE_SIZE) {
    void *page = pmm_alloc_page();
    if (page == 0) {
      return XAIOS_ERR_NO_MEMORY;
    }
    bytes_zero(page, PAGE_SIZE);

    /* Copy file data into the page */
    uint64_t seg_file_start_va = phdr->vaddr;
    uint64_t seg_file_end_va = phdr->vaddr + phdr->filesz;
    if (va < seg_file_end_va && va + PAGE_SIZE > seg_file_start_va) {
      uint64_t copy_start = va > seg_file_start_va ? va : seg_file_start_va;
      uint64_t copy_end =
          va + PAGE_SIZE < seg_file_end_va ? va + PAGE_SIZE : seg_file_end_va;
      uint64_t file_offset = phdr->offset + (copy_start - phdr->vaddr);
      bytes_copy((uint8_t *)page + (copy_start - va),
                 (const uint8_t *)file->base + file_offset,
                 copy_end - copy_start);
    }

    /* Map into per-process aspace AND global tables */
    if (vmm_map_user_page(va, (uint64_t)(uintptr_t)page, flags,
                          aspace->l3_phys, aspace->l3_count) != XAIOS_OK) {
      pmm_free_page(page);
      return XAIOS_ERR_INVALID;
    }
    if (track_page(aspace, va, (uint64_t)(uintptr_t)page) != XAIOS_OK) {
      (void)vmm_unmap_user_page(va, aspace->l3_phys, aspace->l3_count);
      pmm_free_page(page);
      return XAIOS_ERR_NO_MEMORY;
    }
  }

  return XAIOS_OK;
}

xaios_status_t elf_loader_load(const xaios_initramfs_file_t *file,
                              xaios_process_aspace_t *aspace,
                              uint64_t *out_entry) {
  const elf64_ehdr_t *ehdr = 0;
  if (file == 0 || aspace == 0 || out_entry == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (validate_elf(file, &ehdr) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  /* Create per-process address space (allocates L3 tables) */
  vmm_create_user_aspace(aspace->l3_phys, XAIOS_ELF_LOADER_L3_TABLES,
                         &aspace->l3_count);
  aspace->page_count = 0;

  /* Load all PT_LOAD segments */
  const uint8_t *base = (const uint8_t *)file->base;
  for (uint16_t i = 0; i < ehdr->phnum; ++i) {
    const elf64_phdr_t *phdr =
        (const elf64_phdr_t *)(const void *)(base + ehdr->phoff +
                                             ((uint64_t)i * ehdr->phentsize));
    if (phdr->type == PT_LOAD) {
      if (load_segment(file, phdr, aspace) != XAIOS_OK) {
        elf_loader_reclaim(aspace, 0U, 0U);
        return XAIOS_ERR_INVALID;
      }
    }
  }

  *out_entry = ehdr->entry;
  klog("elf_loader: loaded entry=0x%lx pages=%u l3_count=%u\n", ehdr->entry,
       aspace->page_count, aspace->l3_count);
  return XAIOS_OK;
}

xaios_status_t elf_loader_map_stack(xaios_process_aspace_t *aspace,
                                   uint64_t stack_va, uint64_t guard_low,
                                   uint64_t guard_high) {
  if (aspace == 0) {
    return XAIOS_ERR_INVALID;
  }

  /* Unmap guard pages from global tables */
  kassert(vmm_unmap_page(guard_low) == XAIOS_OK);
  kassert(vmm_unmap_page(guard_high) == XAIOS_OK);

  if (stack_va >= guard_high || (stack_va & (PAGE_SIZE - 1U)) != 0U ||
      (guard_high & (PAGE_SIZE - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }

  for (uint64_t va = stack_va; va < guard_high; va += PAGE_SIZE) {
    void *stack_page = pmm_alloc_page();
    if (stack_page == 0) {
      return XAIOS_ERR_NO_MEMORY;
    }
    bytes_zero(stack_page, PAGE_SIZE);
    if (vmm_map_user_page(va, (uint64_t)(uintptr_t)stack_page,
                          XAIOS_VMM_PRESENT | XAIOS_VMM_USER |
                              XAIOS_VMM_WRITABLE | XAIOS_VMM_NG,
                          aspace->l3_phys, aspace->l3_count) != XAIOS_OK) {
      pmm_free_page(stack_page);
      return XAIOS_ERR_INVALID;
    }
    if (track_page(aspace, va, (uint64_t)(uintptr_t)stack_page) != XAIOS_OK) {
      (void)vmm_unmap_user_page(va, aspace->l3_phys, aspace->l3_count);
      pmm_free_page(stack_page);
      return XAIOS_ERR_NO_MEMORY;
    }
  }

  klog("elf_loader: stack mapped va=0x%lx pages=%lu guard=[0x%lx,0x%lx]\n",
       stack_va, (guard_high - stack_va) / PAGE_SIZE, guard_low, guard_high);
  return XAIOS_OK;
}

void elf_loader_reclaim(xaios_process_aspace_t *aspace, uint64_t mapped_low,
                        uint64_t mapped_high) {
  if (aspace == 0) {
    return;
  }

  /* Free all tracked pages (unmap from both per-process and global tables) */
  for (uint32_t i = 0; i < aspace->page_count; ++i) {
    uint64_t va = aspace->pages[i].va;
    uint64_t pa = aspace->pages[i].pa;
    if (pa != 0) {
      vmm_unmap_user_page(va, aspace->l3_phys, aspace->l3_count);
      pmm_free_page((void *)(uintptr_t)pa);
    }
  }
  aspace->page_count = 0;
  kheap_free(aspace->pages);
  aspace->pages = 0;
  aspace->page_capacity = 0U;

  (void)mapped_low;
  (void)mapped_high;

  /* Free per-process L3 tables */
  if (aspace->l3_count > 0) {
    vmm_switch_user_aspace(0, 0);
    vmm_destroy_user_aspace(aspace->l3_phys, aspace->l3_count);
    aspace->l3_count = 0;
  }

  klog("elf_loader: reclaimed pages from aspace\n");
}

void elf_loader_self_test(void) {
  /* Verify ELF validation rejects bad data */
  xaios_initramfs_file_t bad_file;
  bytes_zero(&bad_file, sizeof(bad_file));
  xaios_process_aspace_t test_aspace;
  bytes_zero(&test_aspace, sizeof(test_aspace));
  uint64_t entry = 0;
  kassert(elf_loader_load(&bad_file, &test_aspace, &entry) == XAIOS_ERR_INVALID);
  kassert(elf_loader_load(0, &test_aspace, &entry) == XAIOS_ERR_INVALID);
  kassert(elf_loader_load(&bad_file, 0, &entry) == XAIOS_ERR_INVALID);
  kassert(reserve_page_mappings(&test_aspace, 513U) == XAIOS_OK);
  kassert(test_aspace.page_capacity >= 513U);
  kheap_free(test_aspace.pages);
  test_aspace.pages = 0;
  test_aspace.page_capacity = 0U;
  klog("elf_loader: self-test passed dynamic_page_capacity=513\n");
}
