#include "loader_image.h"
#include "loader_platform.h"

static const efi_guid_t EFI_LOADED_IMAGE_PROTOCOL_GUID = {
    0x5b1b31a1U,
    0x9562U,
    0x11d2U,
    {0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};

static const efi_guid_t EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID = {
    0x964e5b22U,
    0x6459U,
    0x11d2U,
    {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};

efi_status_t xaios_loader_open_root(efi_handle_t image_handle,
                              efi_system_table_t *system_table,
                              efi_file_protocol_t **root) {
  efi_loaded_image_protocol_t *loaded_image = 0;
  efi_simple_file_system_protocol_t *file_system = 0;
  efi_boot_services_t *bs = system_table->boot_services;

  efi_status_t status = bs->handle_protocol(
      image_handle, (efi_guid_t *)&EFI_LOADED_IMAGE_PROTOCOL_GUID,
      (void **)&loaded_image);
  if (!is_error(status) && loaded_image != 0 &&
      loaded_image->device_handle != 0) {
    status = bs->handle_protocol(
        loaded_image->device_handle,
        (efi_guid_t *)&EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
        (void **)&file_system);
    if (!is_error(status)) {
      status = file_system->open_volume(file_system, root);
      if (!is_error(status)) {
        return status;
      }
    }
  }

  uint64_t handle_count = 0U;
  efi_handle_t *handles = 0;
  status = bs->locate_handle_buffer(
      EFI_LOCATE_BY_PROTOCOL,
      (efi_guid_t *)&EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID, 0,
      &handle_count, &handles);
  if (is_error(status) || handles == 0) {
    return status;
  }
  if (handle_count > UINT64_C(4096)) {
    (void)bs->free_pool(handles);
    return EFI_LOAD_ERROR;
  }

  for (uint64_t i = 0U; i < handle_count; ++i) {
    efi_file_protocol_t *candidate_root = 0;
    efi_file_protocol_t *kernel_file = 0;
    status = bs->handle_protocol(
        handles[i], (efi_guid_t *)&EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
        (void **)&file_system);
    if (is_error(status)) {
      continue;
    }
    status = file_system->open_volume(file_system, &candidate_root);
    if (is_error(status) || candidate_root == 0) {
      continue;
    }
    status = candidate_root->open(candidate_root, &kernel_file,
                                  XAIOS_KERNEL_PATH, EFI_FILE_MODE_READ, 0);
    if (is_error(status)) {
      status = candidate_root->open(candidate_root, &kernel_file,
                                    XAIOS_KERNEL_PATH_SHARED,
                                    EFI_FILE_MODE_READ, 0);
    }
    if (!is_error(status)) {
      (void)kernel_file->close(kernel_file);
      *root = candidate_root;
      (void)bs->free_pool(handles);
      return EFI_SUCCESS;
    }
    (void)candidate_root->close(candidate_root);
  }

  (void)bs->free_pool(handles);
  return EFI_NOT_FOUND;
}

efi_status_t xaios_loader_read_kernel_file(efi_system_table_t *system_table,
                                     efi_file_protocol_t *root,
                                     void **kernel_buffer,
                                     uint64_t *kernel_size) {
  efi_boot_services_t *bs = system_table->boot_services;
  efi_file_protocol_t *kernel_file = 0;
  efi_physical_address_t kernel_storage = 0;
  uint64_t read_size = KERNEL_MAX_SIZE;

  efi_status_t status = root->open(root, &kernel_file, XAIOS_KERNEL_PATH,
                                   EFI_FILE_MODE_READ, 0);
  if (is_error(status)) {
    status = root->open(root, &kernel_file, XAIOS_KERNEL_PATH_SHARED,
                        EFI_FILE_MODE_READ, 0);
  }
  if (is_error(status)) {
    return status;
  }

  status = bs->allocate_pages(EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA,
                              EFI_SIZE_TO_PAGES(KERNEL_MAX_SIZE),
                              &kernel_storage);
  if (is_error(status)) {
    (void)kernel_file->close(kernel_file);
    return status;
  }

  status = kernel_file->read(kernel_file, &read_size, (void *)kernel_storage);
  (void)kernel_file->close(kernel_file);
  if (is_error(status)) {
    (void)bs->free_pages(kernel_storage,
                         EFI_SIZE_TO_PAGES(KERNEL_MAX_SIZE));
    return status;
  }

  *kernel_buffer = (void *)kernel_storage;
  *kernel_size = read_size;
  return EFI_SUCCESS;
}

efi_status_t xaios_loader_read_optional_boot_image(
    efi_system_table_t *system_table, efi_file_protocol_t *root,
    uint64_t *image_base, uint64_t *image_size) {
  efi_boot_services_t *bs = system_table->boot_services;
  efi_file_protocol_t *image_file = 0;
  efi_physical_address_t image_storage = 0U;
  uint64_t read_size = BOOT_IMAGE_MAX_SIZE;

  *image_base = 0U;
  *image_size = 0U;
  efi_status_t status = root->open(root, &image_file, XAIOS_INITFS_PATH,
                                   EFI_FILE_MODE_READ, 0);
  if (status == EFI_NOT_FOUND) {
    status = root->open(root, &image_file, XAIOS_INITFS_PATH_SHARED,
                        EFI_FILE_MODE_READ, 0);
  }
  /* Still absent is not an error: a machine can boot without one. */
  if (status == EFI_NOT_FOUND) return EFI_SUCCESS;
  if (is_error(status)) return status;

  status = bs->allocate_pages(EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA,
                              EFI_SIZE_TO_PAGES(BOOT_IMAGE_MAX_SIZE),
                              &image_storage);
  if (is_error(status)) {
    (void)image_file->close(image_file);
    return status;
  }
  status = image_file->read(image_file, &read_size, (void *)image_storage);
  uint8_t overflow_probe = 0U;
  uint64_t overflow_size = read_size == BOOT_IMAGE_MAX_SIZE ? 1U : 0U;
  if (!is_error(status) && overflow_size != 0U) {
    status = image_file->read(image_file, &overflow_size, &overflow_probe);
  }
  (void)image_file->close(image_file);
  if (is_error(status) || overflow_size != 0U || read_size == 0U ||
      read_size % UINT64_C(512) != 0U) {
    (void)bs->free_pages(image_storage,
                         EFI_SIZE_TO_PAGES(BOOT_IMAGE_MAX_SIZE));
    return is_error(status) ? status : EFI_LOAD_ERROR;
  }
  *image_base = image_storage;
  *image_size = read_size;
  return EFI_SUCCESS;
}
/* Where the firmware mapped this loader, or nothing if it will not say. */
const void *xaios_loader_image_base(efi_handle_t image_handle,
                                     efi_system_table_t *system_table) {
  efi_loaded_image_protocol_t *loaded_image = 0;
  efi_status_t status = system_table->boot_services->handle_protocol(
      image_handle, (efi_guid_t *)&EFI_LOADED_IMAGE_PROTOCOL_GUID,
      (void **)&loaded_image);
  if (is_error(status) || loaded_image == 0) return 0;
  return loaded_image->image_base;
}

int xaios_loader_validate_elf(const void *kernel_buffer, uint64_t kernel_size,
                        const elf64_ehdr_t **ehdr_out) {
  if (kernel_size < sizeof(elf64_ehdr_t)) {
    return 0;
  }

  const elf64_ehdr_t *ehdr = (const elf64_ehdr_t *)kernel_buffer;
  if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
      ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
    return 0;
  }
  if (ehdr->e_ident[4] != ELFCLASS64 || ehdr->e_ident[5] != ELFDATA2LSB) {
    return 0;
  }
  /* ET_DYN is what the kernel is built as now: position-independent, so it can
     be placed wherever this machine actually has memory. ET_EXEC is still
     accepted because it loads identically -- it simply has no relocations to
     apply, and its segments land where they always did. */
  if ((ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) ||
      ehdr->e_machine != XAIOS_LOADER_EXPECTED_MACHINE) {
    return 0;
  }
  if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 ||
      ehdr->e_phentsize != sizeof(elf64_phdr_t)) {
    return 0;
  }
  if (ehdr->e_phoff + ((uint64_t)ehdr->e_phnum * sizeof(elf64_phdr_t)) >
      kernel_size) {
    return 0;
  }

  *ehdr_out = ehdr;
  return 1;
}

/* Claim a fixed physical range, even one that crosses a boundary in the
   firmware's own bookkeeping.
   
   AllocatePages(AllocateAddress) only succeeds when the whole requested range
   lies inside a single free descriptor. Firmware is free to describe one
   contiguous run of usable memory as several adjacent descriptors, and then a
   request spanning two of them is refused although every page in it is free.
   
   That is what took x86_64 down. Its kernel is linked at a fixed address and
   must land there; as it grew past ten megabytes its writable segment started
   spanning such a boundary on one firmware and not on another, and the loader
   reported "failed to load kernel segments" with nothing to say about which.
   
   So: ask for the whole thing, and if that is refused, ask page by page. A
   page that is genuinely spoken for still fails, and that failure is a real
   conflict worth reporting; a range that was only split fills in. Pages are
   claimed in ascending order and firmware merges adjacent claims of the same
   type, so this does not leave the memory map in shreds before
   ExitBootServices has to copy it. */
static efi_status_t claim_fixed_range(efi_system_table_t *system_table,
                                      uint64_t start, uint64_t bytes,
                                      uint32_t memory_type,
                                      uint64_t *conflict) {
  efi_boot_services_t *bs = system_table->boot_services;
  uint64_t pages = EFI_SIZE_TO_PAGES(bytes);
  efi_physical_address_t whole = start;
  *conflict = 0;
  efi_status_t status = bs->allocate_pages(EFI_ALLOCATE_ADDRESS, memory_type,
                                           pages, &whole);
  if (!is_error(status)) return status;
  for (uint64_t page = 0; page < pages; ++page) {
    efi_physical_address_t one = start + (page * 0x1000U);
    status = bs->allocate_pages(EFI_ALLOCATE_ADDRESS, memory_type, 1, &one);
    if (is_error(status)) {
      *conflict = start + (page * 0x1000U);
      /* Give back what this attempt took. A caller that responds to the
         conflict by asking for a smaller range would otherwise be refused its
         own pages, which is how the first version of this reported a conflict
         at the very first page of a segment it had just allocated itself. */
      for (uint64_t claimed = 0; claimed < page; ++claimed) {
        (void)bs->free_pages(start + (claimed * 0x1000U), 1);
      }
      return status;
    }
  }
  return EFI_SUCCESS;
}

efi_status_t xaios_loader_load_kernel_segments(efi_system_table_t *system_table,
                                         const void *kernel_buffer,
                                         uint64_t kernel_size,
                                         const elf64_ehdr_t *ehdr,
                                         uint64_t *kernel_base,
                                         uint64_t *kernel_end,
                                         uint64_t *kernel_vaddr_base) {
  efi_boot_services_t *bs = system_table->boot_services;
  const elf64_phdr_t *phdrs =
      (const elf64_phdr_t *)((const unsigned char *)kernel_buffer + ehdr->e_phoff);

  *kernel_base = UINT64_MAX;
  *kernel_end = 0;
  *kernel_vaddr_base = UINT64_MAX;

  /* Where the kernel was linked, and how much room the whole image needs.
     Nothing is loaded yet: this pass only measures. */
  uint64_t link_low = UINT64_MAX;
  uint64_t link_high = 0;
  for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
    const elf64_phdr_t *phdr = &phdrs[i];
    if (phdr->p_type != PT_LOAD) continue;
    uint64_t start = phdr->p_paddr & ~UINT64_C(0xfff);
    if (start < link_low) link_low = start;
    if (phdr->p_paddr + phdr->p_memsz > link_high) {
      link_high = phdr->p_paddr + phdr->p_memsz;
    }
  }
  if (link_low == UINT64_MAX || link_high <= link_low) {
    return EFI_LOAD_ERROR;
  }

  /* The bias between where the kernel was linked and where it will run.
     Zero for a fixed-address kernel; for a position-independent one it is
     whatever this machine had room for.

     Asking firmware for a specific address is what used to fail: the kernel
     was linked at 0x90000000, and a QEMU guest with a gibibyte of memory has
     none there -- its RAM ends at 0x80000000. The three hypervisors start
     their memory in three different places, so no fixed address could suit
     them all. Let firmware choose, and move the kernel to meet it.

     The span is reserved in one piece and released immediately, purely to
     find a contiguous run that fits. Segments are then placed inside it with
     their own memory types, because firmware that enforces W^X needs
     executable segments to be loader code and writable ones loader data, and
     a single allocation could only be one of the two. Nothing else runs
     between the release and the placement: UEFI boot services are
     single-threaded and this loader is the only thing executing. */
  /* The strongest alignment any segment asks for. Firmware hands back
     page-aligned memory and nothing more, and placing a kernel at a merely
     page-aligned address quietly breaks every object inside it that needs
     more: the SMMU stream table wants 16 KiB, and landing it 4 KiB off made
     the hardware reject the stream table entry and the guest panic. That
     failure appeared only on the machines whose spare memory happened to
     start at the wrong offset, which is the worst way for it to appear. */
  uint64_t alignment = 0x1000U;
  for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
    const elf64_phdr_t *phdr = &phdrs[i];
    if (phdr->p_type != PT_LOAD) continue;
    if (phdr->p_align > alignment) alignment = phdr->p_align;
  }
  if ((alignment & (alignment - 1U)) != 0U) alignment = 0x1000U;

  uint64_t span = link_high - link_low;
  uint64_t bias = 0;
  /* Only a position-independent kernel is asking to be moved. A fixed-address
     one must land where it was linked whatever this probe returns, so running
     the probe for it is not merely wasted: it fails the boot on a machine that
     has no contiguous run that large free, for a figure that would have been
     discarded on the next line. That is what took x86_64 down. The kernel had
     grown past thirteen megabytes, one firmware's low memory could no longer
     offer that in one piece, and the loader reported "failed to load kernel
     segments" without ever having tried to load one. */
  if (ehdr->e_type == ET_DYN) {
    /* Below four gibibytes, because that is how far the kernel's early
       identity map reaches: it maps the first 4 GiB before it has parsed
       anything, and a kernel placed above that cannot address itself while
       bringing the real tables up. Firmware picks the address, this only
       bounds it -- asked for anywhere at all, a machine with plenty of memory
       puts the kernel high and the early self-tests fail with no obvious
       cause. */
    efi_physical_address_t placement = XAIOS_LOADER_MAX_KERNEL_ADDRESS;
    /* Ask for enough extra to round the base up to that alignment, since
       firmware chooses the address and will not align it for us. */
    efi_status_t reserve = bs->allocate_pages(
        EFI_ALLOCATE_MAX_ADDRESS, EFI_LOADER_DATA,
        EFI_SIZE_TO_PAGES(span + alignment), &placement);
    if (is_error(reserve)) {
      /* A machine with nothing free down there is not one this kernel can
         boot, but say so by failing the allocation rather than by faulting
         later. */
      return reserve;
    }
    (void)bs->free_pages(placement, EFI_SIZE_TO_PAGES(span + alignment));
    uint64_t aligned =
        ((uint64_t)placement + alignment - 1U) & ~(alignment - 1U);
    bias = aligned - link_low;
  }

  for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
    const elf64_phdr_t *phdr = &phdrs[i];
    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    if (phdr->p_memsz < phdr->p_filesz ||
        phdr->p_offset + phdr->p_filesz > kernel_size) {
      return EFI_LOAD_ERROR;
    }

    uint64_t load_paddr = phdr->p_paddr + bias;
    uint64_t segment_start = load_paddr & ~UINT64_C(0xfff);
    uint64_t segment_offset = load_paddr - segment_start;
    uint64_t allocation_size = segment_offset + phdr->p_memsz;
    efi_physical_address_t segment_address = segment_start;

    /* Executable segments must be loader code, or firmware that enforces W^X
       leaves them execute-never. Writable segments must be loader data, for
       the same reason in reverse. */
    uint32_t segment_memory_type =
        (phdr->p_flags & PF_X) != 0U ? EFI_LOADER_CODE : EFI_LOADER_DATA;
    /* The part of the segment that comes out of the file, page-rounded. The
       loader writes here and so must own it. Everything past it is .bss: no
       file content, and nothing touches it until the kernel's own entry code
       zeroes it, which happens after ExitBootServices. */
    uint64_t file_end = segment_offset + phdr->p_filesz;
    uint64_t file_bytes = (file_end + 0xfffU) & ~UINT64_C(0xfff);
    if (file_bytes == 0U) file_bytes = 0x1000U;

    uint64_t conflict = 0;
    efi_status_t status = claim_fixed_range(system_table, segment_start,
                                            allocation_size,
                                            segment_memory_type, &conflict);
    if (is_error(status) && conflict >= segment_start + file_bytes) {
      /* Firmware holds a page in the .bss tail. It holds it for boot
         services, which are gone by the time the kernel runs and whose memory
         the kernel then owns; the loader never writes there, and the kernel's
         page manager already excludes its own .bss from what it hands out. So
         take what is needed and leave the tail to the kernel.

         This is what x86_64 needed. Its kernel is linked at a fixed address
         and its .bss reaches twelve megabytes, and one firmware keeps a page
         at eight -- a page the kernel is entitled to and was being refused
         because the loader asked for it too early. */
      xaios_loader_puts_hex(system_table, u"XAIOS loader bss tail left to kernel 0x",
                      conflict);
      status = claim_fixed_range(system_table, segment_start, file_bytes,
                                 segment_memory_type, &conflict);
    }
    if (is_error(status)) {
      /* Firmware already owns a page the loader has to write to. Which
         segment, how large, and which page -- the whole of the diagnosis, and
         all of it used to be absent from the one line this printed. */
      xaios_loader_puts_hex(system_table, u"XAIOS loader segment address 0x",
                      segment_start);
      xaios_loader_puts_hex(system_table, u"XAIOS loader segment bytes   0x",
                      allocation_size);
      xaios_loader_puts_hex(system_table, u"XAIOS loader conflict at     0x",
                      conflict);
      xaios_loader_puts_hex(system_table, u"XAIOS loader file buffer at  0x",
                      (uint64_t)(uintptr_t)kernel_buffer);
      xaios_loader_puts_hex(system_table, u"XAIOS loader file bytes      0x",
                      kernel_size);
      return status;
    }
    (void)segment_address;

    /* Only what came out of the file, and only into memory this loader owns.
       Zeroing the whole of p_memsz would write into the .bss tail, which is
       exactly the memory firmware may still be using. Both kernels zero their
       own .bss at entry -- see the entry.S of either architecture -- so the
       tail is not left uninitialised, only left alone until it is safe. */
    mem_set((void *)load_paddr, 0, phdr->p_filesz);
    mem_copy((void *)load_paddr,
             (const unsigned char *)kernel_buffer + phdr->p_offset,
             phdr->p_filesz);

    if (load_paddr < *kernel_base) {
      *kernel_base = load_paddr;
    }
    /* Unbiased on purpose. The caller computes the entry as
       kernel_base + (e_entry - kernel_vaddr_base), where kernel_base already
       carries the bias -- adding it here too cancels it out, and the first
       attempt at this jumped to the link address and took an exception on the
       first instruction. */
    if (phdr->p_vaddr < *kernel_vaddr_base) {
      *kernel_vaddr_base = phdr->p_vaddr;
    }
    if (load_paddr + phdr->p_memsz > *kernel_end) {
      *kernel_end = load_paddr + phdr->p_memsz;
    }
  }

  /* Apply the relocations the kernel carries, now that it is in place. Only
     RELATIVE entries exist -- each says "the value stored here is an address
     that must be moved by the same bias" -- so this needs no symbol table. */
  if (bias != 0U) {
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
      const elf64_phdr_t *phdr = &phdrs[i];
      if (phdr->p_type != PT_DYNAMIC) continue;
      const elf64_dyn_t *dyn =
          (const elf64_dyn_t *)(uintptr_t)(phdr->p_vaddr + bias);
      uint64_t rela = 0;
      uint64_t rela_size = 0;
      uint64_t rela_entry = sizeof(elf64_rela_t);
      for (; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == DT_RELA) rela = dyn->d_val;
        else if (dyn->d_tag == DT_RELASZ) rela_size = dyn->d_val;
        else if (dyn->d_tag == DT_RELAENT) rela_entry = dyn->d_val;
      }
      if (rela == 0 || rela_size == 0 || rela_entry == 0) continue;
      for (uint64_t offset = 0; offset + rela_entry <= rela_size;
           offset += rela_entry) {
        const elf64_rela_t *entry =
            (const elf64_rela_t *)(uintptr_t)(rela + bias + offset);
        uint32_t type = (uint32_t)(entry->r_info & UINT64_C(0xffffffff));
        if (type != R_AARCH64_RELATIVE && type != R_X86_64_RELATIVE) {
          /* Anything else needs information this loader does not have, and
             silently skipping it would produce a kernel that runs with a
             wrong address in it. Refuse instead. */
          return EFI_LOAD_ERROR;
        }
        *(uint64_t *)(uintptr_t)(entry->r_offset + bias) =
            (uint64_t)(entry->r_addend + (int64_t)bias);
      }
    }
  }

  if (*kernel_base == UINT64_MAX || *kernel_end == 0 ||
      *kernel_vaddr_base == UINT64_MAX) {
    return EFI_LOAD_ERROR;
  }

  return EFI_SUCCESS;
}
