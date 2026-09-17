/* Runtime RISC-V mappings: the walk's reader, the kernel mapping entry points,
 * range and user-buffer validation, the structural probes the self-tests ask
 * for, cache maintenance and the two architecture hooks the scheduler reads.
 *
 * The tables themselves and the walk over them live in mmu_map.c, with
 * vmm_init, which is the only writer of either root. Nothing here keeps a
 * second copy of that state: the shared root is reached through
 * riscv64_mmu_kernel_root_address() and the root the current hart runs on
 * through riscv64_mmu_current_root_address(), both of which read
 * mmu_map.c's own variables. That is deliberate -- the extraction this file
 * is a redo of split the root across two translation units and left a walk
 * starting from a null root -- so there is no setter and no shadow copy to
 * get out of step. The per-process user address spaces are in mmu_user.c.
 *
 * Page table entry, low to high: V R W X U G A D, then the physical page
 * number from bit 10. An entry with none of R, W or X is a pointer to the
 * next level; an entry with any of them is a leaf. That single rule is what
 * makes large and gigantic pages fall out of the same walk rather than
 * needing a separate path. The encoding itself is in mmu_map.h, one copy.
 */
#include <xaios/boot_info.h>
#include <xaios/elf_loader.h>
#include <xaios/pmm.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>

/* What this file used to declare for itself and now shares with the modules
   beside it -- mmu_map.c, mmu_user.c, mmu_tlb.c and mmu_selftest.c. The page
   size, the hart ceiling, the firmware-hart and page-fault-probe declarations,
   and the named entry points each side calls are declared once, in
   mmu_shootdown.h and mmu_internal.h, and included from every side so that
   nothing is defined twice. */
#include "mmu_internal.h"
#include "mmu_map.h"

/* The shared kernel root, as the pointer the walk takes. It is a number in
   mmu_map.c and a page-table pointer here; no state crosses. */
static uint64_t *kernel_root(void) {
  return (uint64_t *)(uintptr_t)riscv64_mmu_kernel_root_address();
}

/* The value a secondary hart writes into satp to join the kernel's address
   space. The per-hart tables are mmu_map.c's; this is the named entry point
   smp.c calls, kept here with the rest of the runtime interface. */
uint64_t riscv64_hart_satp(uint32_t cpu_id) {
  return riscv64_mmu_hart_satp_value(cpu_id);
}

/* The structural questions the MMU self-test in mmu_selftest.c asks of the
   shared kernel root, answered into the caller's own locals. The test used to
   read these entries through `walk` itself; a named probe is what crosses now,
   never a pointer into mmu_map.c's state. */
uint32_t riscv64_mmu_leaf_present(uint64_t virtual_address, uint32_t level) {
  uint64_t *entry = riscv64_mmu_walk(kernel_root(), virtual_address, level, 0);
  return (entry != 0 && (*entry & PTE_V) != 0U && (*entry & PTE_LEAF) != 0U)
             ? 1U
             : 0U;
}

/* Whether that leaf is an entry of the root table itself rather than of a
   table below it. Only Sv39 enters at the level a 1 GiB leaf lives on, so this
   is the one check that distinguishes the two paging modes structurally. */
uint32_t riscv64_mmu_leaf_in_root(uint64_t virtual_address, uint32_t level) {
  uint64_t *root = kernel_root();
  uint64_t *entry = riscv64_mmu_walk(root, virtual_address, level, 0);
  if (entry == 0) return 0U;
  return entry == &root[index_at(virtual_address, level)] ? 1U : 0U;
}

/* Whether this hart translates through the shared kernel root rather than the
   per-hart copy build_per_hart_roots made. */
uint32_t riscv64_mmu_on_shared_root(void) {
  return riscv64_mmu_current_root_address() ==
                 riscv64_mmu_kernel_root_address()
             ? 1U
             : 0U;
}

static xaios_status_t map_at_level(uint64_t *root, uint64_t virtual_address,
                                   uint64_t physical_address, uint32_t flags,
                                   uint32_t level) {
  uint64_t span = PAGE_SIZE << (9U * level);
  if ((virtual_address & (span - 1U)) != 0U ||
      (physical_address & (span - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t *entry = riscv64_mmu_walk(root, virtual_address, level, 1);
  if (entry == 0) {
    /* The walk refuses to descend into a larger page, which is right --
       splitting one silently would change the memory type of a range
       somebody mapped deliberately. But refusing outright is wrong when the
       larger page already says exactly what the caller is asking for.
       kmain maps the device window a page at a time after vmm_init has
       already covered it with gigantic identity leaves, and every one of
       those requests is asking for a mapping that is present and correct. So
       a request already satisfied is answered rather than refused; anything
       else -- a different physical address, or flags the existing mapping
       does not grant -- still fails, because that is a real conflict. */
    uint64_t existing_physical = 0U;
    uint32_t existing_flags = 0U;
    if (vmm_translate(virtual_address, &existing_physical, &existing_flags) ==
            XAIOS_OK &&
        existing_physical == physical_address &&
        (existing_flags & flags) == flags) {
      return XAIOS_OK;
    }
    return XAIOS_ERR_NO_MEMORY;
  }
  *entry = pte_for(physical_address, flags_to_pte(flags));
  if (root == kernel_root()) {
    riscv64_mmu_sync_kernel_hierarchy(virtual_address);
  }
  riscv64_mmu_flush_leaf(virtual_address, level);
  return XAIOS_OK;
}

static xaios_status_t unmap_at_level(uint64_t *root, uint64_t virtual_address,
                                     uint32_t level) {
  /* Splitting is permitted while unmapping, which reads oddly and is right:
     removing one page from inside a larger mapping means the larger mapping
     has to become a table first. Without it, unmapping a device page the
     boot map covered with a gigantic leaf reports not-found on a page that
     is very much mapped. */
  uint64_t *entry = riscv64_mmu_walk(root, virtual_address, level, 1);
  if (entry == 0 || (*entry & PTE_V) == 0U) {
    /* Nothing to remove -- but the walk may have split a larger leaf on the
       way down, and that replaced an entry which may itself sit at a copied
       level, so the harts still have to be told. */
    if (root == kernel_root()) {
      riscv64_mmu_sync_kernel_hierarchy(virtual_address);
    }
    return XAIOS_ERR_NOT_FOUND;
  }
  *entry = 0U;
  /* Mirrored after the entry is cleared, not before it.
   *
   * This used to be one call above the clear, covering only the split, and
   * that left removal unmirrored: a hart's root is a copy, so zeroing an
   * entry that lives *at* a copied level removed the mapping on the shared
   * root and nowhere else, and every hart -- including the one that asked --
   * went on translating an address the kernel believed it had taken away.
   * Only gigantic entries are at a copied level (Sv39's root holds them
   * directly, Sv48's copied low table one step down), which is why nothing
   * noticed: 4 KiB and 2 MiB entries live in tables the harts share by
   * pointer, and nothing outside this file has ever called the gigantic
   * unmap. The new large-page self-test called it, and the address still
   * translated afterwards.
   *
   * The split case still needs mirroring too, and the clear cannot be undone
   * by doing both, so this one call now covers both paths. */
  if (root == kernel_root()) {
    riscv64_mmu_sync_kernel_hierarchy(virtual_address);
  }
  riscv64_mmu_flush_leaf(virtual_address, level);
  return XAIOS_OK;
}

/* Page-granular, for ranges whose permissions have to be exact. */
void riscv64_mmu_identity_map_pages(uint64_t start, uint64_t end,
                                    uint32_t flags) {
  start &= ~(PAGE_SIZE - 1U);
  end = (end + PAGE_SIZE - 1U) & ~(PAGE_SIZE - 1U);
  for (uint64_t address = start; address < end; address += PAGE_SIZE) {
    if (map_at_level(kernel_root(), address, address, flags, 0U) != XAIOS_OK) {
      return;
    }
  }
}

void riscv64_mmu_identity_map_range(uint64_t start, uint64_t end,
                                    uint32_t flags) {
  start &= ~(PAGE_SIZE - 1U);
  end = (end + PAGE_SIZE - 1U) & ~(PAGE_SIZE - 1U);
  /* Never into userspace, whatever the machine has. AArch64 caps its identity
     map at XAIOS_USER_BASE for exactly the reason B-11 records -- the two
     address spaces were literally the same addresses, and which machines
     noticed depended only on how much RAM they had -- and this architecture
     had no such cap. It was unreachable at 511 GiB and it is still
     unreachable at 255, but "no machine is that big yet" is the assumption
     B-11 was, so it is a bound now rather than a hope. */
  if (end > XAIOS_USER_BASE) end = XAIOS_USER_BASE;
  if (start >= end) return;
  for (uint64_t address = start; address < end;) {
    /* Gigantic where it fits, which is what keeps the early table pool small
       enough to be static. A 256 MiB machine mapped in 4 KiB pages would need
       more tables than a kernel has before it can allocate any. */
    uint64_t gigantic = XAIOS_VMM_GIGANTIC_PAGE_SIZE;
    if ((address & (gigantic - 1U)) == 0U && end - address >= gigantic) {
      if (map_at_level(kernel_root(), address, address, flags, 2U) != XAIOS_OK) {
        return;
      }
      address += gigantic;
      continue;
    }
    uint64_t large = XAIOS_VMM_LARGE_PAGE_SIZE;
    if ((address & (large - 1U)) == 0U && end - address >= large) {
      if (map_at_level(kernel_root(), address, address, flags, 1U) != XAIOS_OK) {
        return;
      }
      address += large;
      continue;
    }
    if (map_at_level(kernel_root(), address, address, flags, 0U) != XAIOS_OK) {
      return;
    }
    address += PAGE_SIZE;
  }
}

void vmm_activate_kernel(void) {
  riscv64_mmu_flush_all();
  /* Supervisor access to user pages, which is off after reset.
   *
   * Without this the kernel cannot read or write a single byte of a user
   * process: loading an ELF segment, copying a syscall argument, and reading
   * a path all fault, and the fault reports a user address the kernel plainly
   * has mapped, which reads as a broken page table rather than a permission
   * bit. AArch64 spells the same idea backwards -- it clears PAN around the
   * syscall path and leaves it set elsewhere -- and that narrower window is
   * the better shape. It needs an interface the shared code does not have
   * yet, so this opens the access for the whole kernel and the difference is
   * recorded rather than hidden: on this architecture a stray kernel
   * dereference of a user pointer is not caught by hardware. */
  __asm__ volatile("csrs sstatus, %0" : : "r"(UINT64_C(1) << 18) : "memory");
  __asm__ volatile("csrw satp, %0" : : "r"(riscv64_hart_satp(smp_cpu_id()))
                   : "memory");
  riscv64_mmu_flush_all();
}

/* RISC-V's memory model makes these fences rather than cache maintenance.
   The architecture requires coherent instruction and data caches with respect
   to DMA on any platform that has them, so what is needed is ordering, not
   writeback -- and a fence is what expresses that. */
void vmm_clean_to_memory(const void *buffer, uint64_t bytes) {
  (void)buffer;
  (void)bytes;
  __asm__ volatile("fence ow, ow" ::: "memory");
}

void vmm_invalidate_from_memory(const void *buffer, uint64_t bytes) {
  (void)buffer;
  (void)bytes;
  __asm__ volatile("fence ir, ir" ::: "memory");
}

xaios_status_t vmm_translate(uint64_t virtual_address,
                             uint64_t *physical_address, uint32_t *flags) {
  uint64_t *root = (uint64_t *)(uintptr_t)riscv64_mmu_current_root_address();
  for (uint32_t level = 0U; level < 3U; ++level) {
    uint64_t *entry = riscv64_mmu_walk(root, virtual_address, level, 0);
    if (entry == 0) continue;
    if ((*entry & PTE_V) == 0U) continue;
    if ((*entry & PTE_LEAF) == 0U) continue;
    uint64_t span = PAGE_SIZE << (9U * level);
    if (physical_address != 0) {
      *physical_address = pte_physical(*entry) + (virtual_address & (span - 1U));
    }
    if (flags != 0) *flags = pte_to_flags(*entry);
    return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t vmm_validate_range_flags(uint64_t virtual_address, uint64_t size,
                                        uint32_t required_flags,
                                        uint32_t forbidden_flags) {
  if (size == 0U) return XAIOS_ERR_INVALID;
  uint64_t end = virtual_address + size;
  if (end < virtual_address) return XAIOS_ERR_INVALID;
  for (uint64_t address = virtual_address & ~(PAGE_SIZE - 1U); address < end;
       address += PAGE_SIZE) {
    uint32_t flags = 0U;
    if (vmm_translate(address, 0, &flags) != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
    if ((flags & required_flags) != required_flags) return XAIOS_ERR_INVALID;
    if ((flags & forbidden_flags) != 0U) return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

xaios_status_t vmm_map_page(uint64_t virtual_address, uint64_t physical_address,
                            uint32_t flags) {
  return map_at_level(kernel_root(), virtual_address, physical_address, flags,
                      0U);
}

xaios_status_t vmm_unmap_page(uint64_t virtual_address) {
  if ((virtual_address & (PAGE_SIZE - 1U)) != 0U) return XAIOS_ERR_INVALID;
  /* Unmapping an address that is already unmapped is success, which this got
     wrong by being stricter than the interface it implements. The other two
     architectures zero the entry and return OK either way, and shared code
     relies on it: a process's stack guard pages are unmapped before they are
     ever mapped, precisely so that nothing is mapped there, and that call is
     asserted. Reporting not-found for a page that is absent describes the
     state accurately and answers a question nobody asked -- the caller wants
     the address to be unmapped afterwards, and it is. */
  xaios_status_t status = unmap_at_level(kernel_root(), virtual_address, 0U);
  return status == XAIOS_ERR_NOT_FOUND ? XAIOS_OK : status;
}

/* Collision-safe kernel large and gigantic mappings.
 *
 * The shared interface these implement is documented as collision-safe --
 * AArch64 and x86-64 both refuse a second mapping over a live one with
 * XAIOS_ERR_BUSY -- and this port did not. `map_at_level` overwrites whatever
 * entry it finds, so a caller that mapped a gibibyte over something already
 * there was told it had succeeded while the previous mapping silently ceased
 * to exist. Nothing outside this file calls these four functions yet, which
 * is both why it went unnoticed and why correcting it cannot break a boot.
 *
 * The check lives at the public entry points rather than inside
 * `map_at_level`, deliberately. `identity_map_range` builds the boot map
 * through that same function, and a UEFI memory map hands the kernel
 * descriptors that overlap ranges it has already covered; refusing there
 * would abort the remainder of a range -- that loop returns on the first
 * non-OK status -- and leave a machine mapped halfway with nothing said.
 * So the contract belongs to the two entry points the boot map does not use.
 *
 * What it catches, precisely, because the difference matters: a leaf at the
 * requested level, a larger leaf above covering the address, and any table
 * below it that could hold live mappings. What it does not catch is a table
 * below that is entirely empty -- replacing that loses no mapping, only the
 * page the empty table occupies. x86-64 checks only the entry at the target
 * level and has no larger-leaf case to worry about; this is that check plus
 * the one this architecture's splitting walk makes possible.
 */
static xaios_status_t map_leaf_checked(uint64_t virtual_address,
                                       uint64_t physical_address,
                                       uint32_t flags, uint32_t level) {
  uint64_t span = PAGE_SIZE << (9U * level);
  if ((virtual_address & (span - 1U)) != 0U ||
      (physical_address & (span - 1U)) != 0U ||
      (flags & XAIOS_VMM_PRESENT) == 0U) {
    return XAIOS_ERR_INVALID;
  }
  /* Never into the userspace window through a kernel entry point. These write
     into the shared kernel root, and userspace lives in a per-hart directory
     that switching replaces per process -- a user leaf placed here would
     belong to whichever process happened to be running and outlive it. */
  if ((flags & XAIOS_VMM_USER) != 0U ||
      (virtual_address >= XAIOS_USER_BASE &&
       virtual_address < XAIOS_USER_LIMIT)) {
    return XAIOS_ERR_INVALID;
  }
  /* Asked of translate rather than of a creating walk: a creating walk would
     split a larger leaf as a side effect of a request it is about to refuse,
     and translate is the only thing here that sees all three shapes a
     collision can take. */
  if (vmm_translate(virtual_address, 0, 0) == XAIOS_OK) return XAIOS_ERR_BUSY;
  uint64_t *entry = riscv64_mmu_walk(kernel_root(), virtual_address, level, 0);
  if (entry != 0 && (*entry & PTE_V) != 0U) return XAIOS_ERR_BUSY;
  return map_at_level(kernel_root(), virtual_address, physical_address, flags,
                      level);
}

xaios_status_t vmm_map_large_page(uint64_t virtual_address,
                                  uint64_t physical_address, uint32_t flags) {
  return map_leaf_checked(virtual_address, physical_address, flags, 1U);
}

xaios_status_t vmm_unmap_large_page(uint64_t virtual_address) {
  return unmap_at_level(kernel_root(), virtual_address, 1U);
}

xaios_status_t vmm_map_gigantic_page(uint64_t virtual_address,
                                     uint64_t physical_address,
                                     uint32_t flags) {
  return map_leaf_checked(virtual_address, physical_address, flags, 2U);
}

xaios_status_t vmm_unmap_gigantic_page(uint64_t virtual_address) {
  return unmap_at_level(kernel_root(), virtual_address, 2U);
}

xaios_status_t vmm_validate_user_buffer(uint64_t virtual_address, uint64_t size,
                                        uint32_t required_flags) {
  if (virtual_address < XAIOS_USER_BASE ||
      virtual_address + size > XAIOS_USER_LIMIT ||
      virtual_address + size < virtual_address) {
    return XAIOS_ERR_INVALID;
  }
  return vmm_validate_range_flags(virtual_address, size,
                                  required_flags | XAIOS_VMM_USER, 0U);
}

/* Whether translation is on, which the spinlock implementation asks before
   using an atomic.
   Not a formality here. RISC-V's load-reserved/store-conditional pair is only
   guaranteed on memory the hart can address through the MMU, and the same
   question on AArch64 is why every secondary used to announce itself into
   memory the boot CPU was not reading (V-04). Answering it honestly means
   reading satp rather than returning a constant. */
uint32_t xaios_translation_enabled(void) {
  uint64_t satp = 0U;
  __asm__ volatile("csrr %0, satp" : "=r"(satp));
  return (satp >> 60) != 0U ? 1U : 0U;
}
