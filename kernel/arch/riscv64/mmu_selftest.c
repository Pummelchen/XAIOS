/* The MMU self-tests: the shared 4 KiB probe and the large-page test.
 *
 * This was the tail of mmu.c, moved here whole. The code is the same: the
 * 2 MiB and 1 GiB map/unmap checks in both paging modes, the gigantic-leaf
 * split, the Sv48-only high-slot window, and the shared map/translate/write/
 * unmap probe that runs before them.
 *
 * The order is also the same and must stay so. vmm_self_test runs the 4 KiB
 * case, then the large-page test, then this architecture's own ISA self-test,
 * and each depends on what ran before it: the large-page assertions read
 * their leaves back through the translate the 4 KiB case just proved, and the
 * ISA self-test reports the satp mode, which is only meaningful once
 * translation is on.
 *
 * What it reaches back into mmu.c for is named, never a pointer into that
 * file's state: riscv64_mmu_root_level(), riscv64_mmu_on_shared_root() and the
 * two shared-root leaf probes, all declared in mmu_internal.h beside the
 * definitions.
 */
#include "mmu_internal.h"

#include <xaios/pmm.h>
#include <xaios/vmm.h>

/* Where the large-page self-test does its work.
 *
 * Three gibibyte-aligned windows, chosen against four constraints at once,
 * which is why they are not the addresses x86-64 uses. They have to be
 * representable in Sv39 -- a 39-bit address space reaches 256 GiB, so
 * x86-64's 0x7000000000 (448 GiB) and 0x8000000000 (512 GiB) simply do not
 * exist on more than half the harts QEMU implements. They have to be clear
 * of the userspace window, which is the last gibibyte below 256 GiB. They
 * have to be clear of the identity map, which covers whatever RAM the machine
 * reports and is capped at XAIOS_USER_BASE. And they have to be a gibibyte
 * apart, so that the 2 MiB test and the 1 GiB test cannot see each other's
 * tables: they share a level-2 slot otherwise, and the gigantic map would
 * then be refused by the collision check for a reason that has nothing to do
 * with what is being tested.
 *
 * 192-194 GiB satisfies all four on any machine this kernel can boot on
 * today. It stops being true on a machine with 192 GiB of RAM, so the test
 * does not assume it -- it asks first, and says so if the window is occupied,
 * rather than mapping over the identity map and failing somewhere else. */
#define SELF_TEST_LARGE_VA UINT64_C(0x3000000000)    /* 192 GiB */
#define SELF_TEST_GIGANTIC_VA UINT64_C(0x3040000000) /* 193 GiB */
#define SELF_TEST_SPLIT_VA UINT64_C(0x3080000000)    /* 194 GiB */
/* Above the first top-level slot, which only Sv48 has. */
#define SELF_TEST_HIGH_VA UINT64_C(0x8000000000) /* 512 GiB */

#define SELF_TEST_LARGE_SIGNATURE UINT64_C(0x5849414f53324d49)    /* XAIOS2MI */
#define SELF_TEST_GIGANTIC_SIGNATURE UINT64_C(0x5849414f53314749) /* XAIOS1GI */

/* 2 MiB and 1 GiB mappings, in whichever paging mode this hart gave us.
 *
 * The two modes are not two spellings of the same test. Sv48 walks four
 * levels and Sv39 three, and because `index_at` is the same arithmetic
 * either way, Sv39's root table *is* the table Sv48 reaches through root slot
 * zero. So a 1 GiB leaf -- a level-2 entry -- is an entry in a table one step
 * below the root under Sv48 and an entry in the root itself under Sv39. That
 * is the only structural difference between the modes in the paging code and
 * it is exactly the difference a gigantic page lands on, which is why the test
 * asserts where the leaf ended up rather than only that translation worked.
 *
 * Every check here has a second witness where one is available, because the
 * cheap version of this test proves very little. A walk that agrees with a
 * walk is one function agreeing with itself: `vmm_translate` and `walk` read
 * the same tables, so a table built wrongly reads back wrongly and
 * consistently. The mappings are therefore also dereferenced -- a signature
 * written through the identity map and read back through the alias, then
 * written through the alias and read back through the identity map -- which
 * is the hardware's own opinion of the leaf, taken from the same page-table
 * walker a fault would use.
 *
 * What this does not prove, said plainly because it is a limit of *when* it
 * runs rather than of what it checks: nothing here says anything about any
 * TLB but this hart's. vmm_init happens long before any secondary hart has
 * been started, so there is no other TLB in existence to observe -- and this
 * comment used to end by recording that the port had no remote fence at all,
 * which was true and is no longer. The fences do reach every hart now
 * (tlb_remote_fence), and riscv64_tlb_shootdown_self_test measures that at
 * the first moment in the boot when a second hart exists: it has a remote
 * hart read an address, withdraws it, and requires that hart to fault. The
 * mirroring checks below cover the page *tables* reaching every hart, which
 * is a different question and the one that had a bug in it. */
static void vmm_large_page_self_test(void) {
  const char *mode = (riscv64_mmu_root_level() == 2U) ? "sv39" : "sv48";

  /* The windows have to be empty before anything is mapped into them. A
     machine large enough for the identity map to reach 192 GiB would
     otherwise have this test quietly replace part of its own RAM mapping,
     and the failure would appear later and elsewhere. */
  static const uint64_t windows[3] = {SELF_TEST_LARGE_VA,
                                      SELF_TEST_GIGANTIC_VA,
                                      SELF_TEST_SPLIT_VA};
  for (uint32_t i = 0U; i < 3U; ++i) {
    if (vmm_translate(windows[i], 0, 0) == XAIOS_OK) {
      vmm_panic("large-page self-test window %lx is already mapped; this "
                "machine is too large for the addresses the test picked",
                windows[i]);
    }
  }

  /* Every mapping made below goes into the shared kernel root, and this hart
     is not running on the shared kernel root -- it is running on its own
     copy, built by build_per_hart_roots. So each `vmm_translate` after a map
     is also a check that sync_kernel_hierarchy mirrored the new top-level
     entry into this hart's copy, which is the failure mode where one hart
     sees a kernel mapping and the others fault on it. That only means
     anything if the two roots really are different pages, so say so. */
  if (riscv64_mmu_on_shared_root() != 0U) {
    vmm_panic("large-page self-test is running on the shared kernel root, so "
              "its per-hart mirroring checks would prove nothing");
  }

  void *page = pmm_alloc_page();
  if (page == 0) vmm_panic("large-page self-test has no page to alias");
  uint64_t physical = (uint64_t)(uintptr_t)page;
  volatile uint64_t *identity = (volatile uint64_t *)(uintptr_t)physical;
  uint64_t observed = 0U;
  uint32_t flags = 0U;

  /* --- 2 MiB --- */
  /* Aliased onto real memory rather than onto an arbitrary physical address,
     because a leaf pointing at nothing can only be inspected, never used. The
     2 MiB block containing an allocator page is inside RAM by construction:
     RAM starts at a 2 MiB boundary and the page came from inside it. Only the
     one page's worth of that block is ever touched. */
  uint64_t large_pa = physical & ~(XAIOS_VMM_LARGE_PAGE_SIZE - 1U);
  uint64_t large_offset = physical - large_pa;
  *identity = SELF_TEST_LARGE_SIGNATURE;

  if (vmm_map_large_page(SELF_TEST_LARGE_VA, large_pa,
                         XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) != XAIOS_OK) {
    vmm_panic("could not map a 2 MiB leaf at %lx", SELF_TEST_LARGE_VA);
  }
  /* Collision-safe, as the other two architectures are. Same physical
     address and fewer flags: still a refusal, because the caller does not get
     to find out by accident that something was already there. */
  if (vmm_map_large_page(SELF_TEST_LARGE_VA, large_pa, XAIOS_VMM_PRESENT) !=
      XAIOS_ERR_BUSY) {
    vmm_panic("a second 2 MiB map over a live one was not refused");
  }
  /* The last byte of the leaf, not the first: an entry whose span was
     computed wrongly still translates its own base address correctly. */
  if (vmm_translate(SELF_TEST_LARGE_VA + XAIOS_VMM_LARGE_PAGE_SIZE - 1U,
                    &observed, &flags) != XAIOS_OK ||
      observed != large_pa + XAIOS_VMM_LARGE_PAGE_SIZE - 1U) {
    vmm_panic("2 MiB leaf translated its last byte to %lx not %lx", observed,
              large_pa + XAIOS_VMM_LARGE_PAGE_SIZE - 1U);
  }
  if (vmm_validate_range_flags(SELF_TEST_LARGE_VA, XAIOS_VMM_LARGE_PAGE_SIZE,
                               XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE,
                               XAIOS_VMM_USER | XAIOS_VMM_EXECUTABLE) !=
      XAIOS_OK) {
    vmm_panic("2 MiB leaf did not validate as writable, non-user, "
              "non-executable across its whole span");
  }
  /* Structural: it has to be a leaf at level 1, not a table of 4 KiB pages
     that happens to describe the same memory. Both translate identically. */
  if (riscv64_mmu_leaf_present(SELF_TEST_LARGE_VA, 1U) == 0U) {
    vmm_panic("the 2 MiB mapping is not a leaf at level 1");
  }
  /* The hardware's opinion, through the alias. */
  volatile uint64_t *large_alias =
      (volatile uint64_t *)(uintptr_t)(SELF_TEST_LARGE_VA + large_offset);
  if (*large_alias != SELF_TEST_LARGE_SIGNATURE) {
    vmm_panic("read through a 2 MiB leaf gave %lx not %lx", *large_alias,
              SELF_TEST_LARGE_SIGNATURE);
  }
  *large_alias = ~SELF_TEST_LARGE_SIGNATURE;
  if (*identity != ~SELF_TEST_LARGE_SIGNATURE) {
    vmm_panic("a write through a 2 MiB leaf did not reach the memory it "
              "claims to describe");
  }
  if (vmm_unmap_large_page(SELF_TEST_LARGE_VA) != XAIOS_OK) {
    vmm_panic("could not unmap the 2 MiB leaf at %lx", SELF_TEST_LARGE_VA);
  }
  if (vmm_translate(SELF_TEST_LARGE_VA, 0, 0) == XAIOS_OK) {
    vmm_panic("a 2 MiB leaf still translates after being unmapped");
  }
  /* A second, independent witness that the entry is gone rather than merely
     unreachable: unmap reports not-found for an address it has nothing to
     remove at. This is deliberately the opposite of vmm_unmap_page, which
     answers OK for an absent page because shared code unmaps guard pages that
     were never mapped; the difference is pinned here so that it stays a
     decision. */
  if (vmm_unmap_large_page(SELF_TEST_LARGE_VA) != XAIOS_ERR_NOT_FOUND) {
    vmm_panic("unmapping an absent 2 MiB leaf did not report not-found");
  }
  klog("vmm: 2 MiB large-page map/unmap self-test passed mode=%s\n", mode);

  /* --- 1 GiB --- */
  uint64_t gigantic_pa = physical & ~(XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U);
  uint64_t gigantic_offset = physical - gigantic_pa;
  *identity = SELF_TEST_GIGANTIC_SIGNATURE;

  if (vmm_map_gigantic_page(SELF_TEST_GIGANTIC_VA, gigantic_pa,
                            XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) !=
      XAIOS_OK) {
    vmm_panic("could not map a 1 GiB leaf at %lx", SELF_TEST_GIGANTIC_VA);
  }
  if (vmm_map_gigantic_page(SELF_TEST_GIGANTIC_VA, gigantic_pa,
                            XAIOS_VMM_PRESENT) != XAIOS_ERR_BUSY) {
    vmm_panic("a second 1 GiB map over a live one was not refused");
  }
  if (vmm_translate(SELF_TEST_GIGANTIC_VA + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U,
                    &observed, &flags) != XAIOS_OK ||
      observed != gigantic_pa + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U) {
    vmm_panic("1 GiB leaf translated its last byte to %lx not %lx", observed,
              gigantic_pa + XAIOS_VMM_GIGANTIC_PAGE_SIZE - 1U);
  }
  /* Where the leaf actually sits, which is the whole reason both modes have
     to be exercised. Sv39 enters at level 2, so a 1 GiB leaf is an entry in
     the root table the hardware is pointed at; Sv48 enters at level 3, so the
     same leaf is one level further down. A test that only asked whether
     translation worked would pass identically on a kernel that had the two
     confused, because `walk` starts from g_root_level and would follow
     whichever shape it built. */
  if (riscv64_mmu_leaf_present(SELF_TEST_GIGANTIC_VA, 2U) == 0U) {
    vmm_panic("the 1 GiB mapping is not a leaf at level 2");
  }
  uint32_t leaf_in_root =
      riscv64_mmu_leaf_in_root(SELF_TEST_GIGANTIC_VA, 2U);
  if (riscv64_mmu_root_level() == 2U && leaf_in_root == 0U) {
    vmm_panic("sv39: a 1 GiB leaf is not in the root table it must be in");
  }
  if (riscv64_mmu_root_level() != 2U && leaf_in_root != 0U) {
    vmm_panic("sv48: a 1 GiB leaf landed in the root table, which is a "
              "level-3 table and cannot hold one");
  }
  volatile uint64_t *gigantic_alias =
      (volatile uint64_t *)(uintptr_t)(SELF_TEST_GIGANTIC_VA +
                                       gigantic_offset);
  if (*gigantic_alias != SELF_TEST_GIGANTIC_SIGNATURE) {
    vmm_panic("read through a 1 GiB leaf gave %lx not %lx", *gigantic_alias,
              SELF_TEST_GIGANTIC_SIGNATURE);
  }
  *gigantic_alias = ~SELF_TEST_GIGANTIC_SIGNATURE;
  if (*identity != ~SELF_TEST_GIGANTIC_SIGNATURE) {
    vmm_panic("a write through a 1 GiB leaf did not reach the memory it "
              "claims to describe");
  }
  if (vmm_unmap_gigantic_page(SELF_TEST_GIGANTIC_VA) != XAIOS_OK) {
    vmm_panic("could not unmap the 1 GiB leaf at %lx", SELF_TEST_GIGANTIC_VA);
  }
  if (vmm_translate(SELF_TEST_GIGANTIC_VA, 0, 0) == XAIOS_OK) {
    vmm_panic("a 1 GiB leaf still translates after being unmapped");
  }
  klog("vmm: 1 GiB gigantic-page self-test passed mode=%s leaf_in_root=%u\n",
       mode, leaf_in_root);

  /* --- splitting a gigantic leaf --- */
  /* This is the part with no counterpart on the other two architectures, and
     it is the part most likely to be wrong here. AArch64 and x86-64 refuse to
     map a small page inside a large one; this walk splits the large one
     instead, because vmm_init covers the device window in gibibyte leaves and
     kmain then maps that window a page at a time -- refusing meant the kernel
     could not unmap a device page it had itself mapped.
     A split is only safe if it is total. Every entry of the replacement table
     has to be filled from the leaf before the leaf is replaced, or addresses
     that resolved a moment ago stop resolving, and the ones that stop are the
     ones nobody was looking at. So the checks below are about the addresses
     the caller did *not* ask about. */
  void *override_page = pmm_alloc_page();
  if (override_page == 0) {
    vmm_panic("large-page split self-test has no page to override with");
  }
  uint64_t override_physical = (uint64_t)(uintptr_t)override_page;
  /* The far neighbour is chosen in a different 2 MiB child than the page
     under test, rather than fixed at offset zero and the page required to be
     elsewhere.
     
     The check needs two things from one gibibyte: the child holding the 4 KiB
     override, and some other child that a partial split would have lost. It
     used to take offset zero for the second and panic when the page landed in
     that same first 2 MiB -- reasoning that the allocator hands out pages
     above the kernel image, which starts 2 MiB into RAM. That holds under
     -kernel and not under EDK2, where firmware owns the bottom of RAM and the
     first free page sits low in its gibibyte, so the machine booted on one
     firmware and died on a cyan screen on the other over where a page landed.
     Requiring a better page cannot work either: pages come out sequentially,
     so crossing 2 MiB would take five hundred of them.
     
     Picking the child instead is exact rather than lucky. Any child but the
     one the override is in will do, and there are 512 of them. */
  const uint64_t child_index = gigantic_offset / XAIOS_VMM_LARGE_PAGE_SIZE;
  const uint64_t far_child = (child_index == 0U) ? 1U : 0U;
  const uint64_t far_va =
      SELF_TEST_SPLIT_VA + far_child * XAIOS_VMM_LARGE_PAGE_SIZE;
  const uint64_t far_expected =
      gigantic_pa + far_child * XAIOS_VMM_LARGE_PAGE_SIZE;

  if (vmm_map_gigantic_page(SELF_TEST_SPLIT_VA, gigantic_pa,
                            XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) !=
      XAIOS_OK) {
    vmm_panic("could not map the 1 GiB leaf the split test splits");
  }
  uint64_t inner_va = SELF_TEST_SPLIT_VA + gigantic_offset + PAGE_SIZE;
  uint64_t near_va = SELF_TEST_SPLIT_VA + gigantic_offset;
  if (vmm_translate(inner_va, &observed, 0) != XAIOS_OK) {
    vmm_panic("split self-test's inner address %lx is not inside the gigantic "
              "leaf at all", inner_va);
  }
  if (observed != physical + PAGE_SIZE) {
    vmm_panic("split self-test's inner address started out at %lx not %lx",
              observed, physical + PAGE_SIZE);
  }
  /* One 4 KiB page inside the gibibyte, pointed somewhere else. Reaching it
     costs two splits: level 2 to a table of 2 MiB leaves, then level 1 to a
     table of 4 KiB pages. */
  if (vmm_map_page(inner_va, override_physical,
                   XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) != XAIOS_OK) {
    vmm_panic("could not map a 4 KiB page inside a 1 GiB leaf");
  }
  if (vmm_translate(inner_va, &observed, 0) != XAIOS_OK) {
    vmm_panic("a 4 KiB page mapped inside a gigantic leaf does not translate");
  }
  if (observed != override_physical) {
    vmm_panic("a 4 KiB page inside a split gigantic leaf translated to %lx "
              "not %lx", observed, override_physical);
  }
  /* The neighbour in the same 2 MiB table: the level-1 to level-0 split has
     to have filled it. Checked by reading the signature back, not only by
     translating, so a table filled with plausible-looking wrong entries is
     caught too. */
  if (vmm_translate(near_va, &observed, 0) != XAIOS_OK) {
    vmm_panic("splitting a gigantic leaf left its neighbour %lx unmapped",
              near_va);
  }
  if (observed != physical) {
    vmm_panic("splitting a gigantic leaf moved its neighbour to %lx not %lx",
              observed, physical);
  }
  if (*(volatile uint64_t *)(uintptr_t)near_va != ~SELF_TEST_GIGANTIC_SIGNATURE) {
    vmm_panic("the neighbour of a split page reads the wrong memory");
  }
  /* The neighbour in a different 2 MiB table: the level-2 to level-1 split
     has to have filled that one too, and it is the one a partial split would
     lose, because nothing ever walked through it. */
  if (vmm_translate(far_va, &observed, 0) != XAIOS_OK) {
    vmm_panic("splitting a gigantic leaf left a distant 2 MiB window "
              "unmapped at %lx", far_va);
  }
  if (observed != far_expected) {
    vmm_panic("splitting a gigantic leaf moved a distant 2 MiB window to %lx "
              "not %lx", observed, far_expected);
  }
  /* Removing the whole gibibyte removes the tables the split produced with
     it. The tables themselves are not returned to the allocator -- three
     pages for the life of the boot, which is the same thing every other
     table the paging code allocates does. */
  if (vmm_unmap_gigantic_page(SELF_TEST_SPLIT_VA) != XAIOS_OK) {
    vmm_panic("could not unmap a gigantic leaf that had been split");
  }
  if (vmm_translate(SELF_TEST_SPLIT_VA, 0, 0) == XAIOS_OK ||
      vmm_translate(inner_va, 0, 0) == XAIOS_OK) {
    vmm_panic("a split gigantic leaf still translates after being unmapped");
  }
  pmm_free_page(override_page);
  klog("vmm: gigantic-page split self-test passed mode=%s\n", mode);

  /* --- Sv48 only: above the first top-level slot --- */
  /* AArch64 has the same test and the same reason for it. Every address this
     kernel uses on Sv39 lives under one root entry, so a walk that assumed
     slot zero would work everywhere and fail on the first machine that used a
     second. Sv48 is where that can be asked, because its root covers 512 GiB
     a slot; Sv39's whole address space is 512 GiB, so the question does not
     exist there and this is skipped rather than faked.
     It is also the only place `sync_kernel_hierarchy` takes its l0 != 0
     branch, which mirrors a whole root slot into every hart's root instead of
     mirroring one entry of the copied low table. */
  if (riscv64_mmu_root_level() == 3U) {
    if (vmm_translate(SELF_TEST_HIGH_VA, 0, 0) == XAIOS_OK) {
      vmm_panic("sv48 high-slot window %lx is already mapped",
                SELF_TEST_HIGH_VA);
    }
    if (vmm_map_gigantic_page(SELF_TEST_HIGH_VA, gigantic_pa,
                              XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) !=
        XAIOS_OK) {
      vmm_panic("could not map a 1 GiB leaf above the first root slot");
    }
    if (vmm_translate(SELF_TEST_HIGH_VA + gigantic_offset, &observed, 0) !=
        XAIOS_OK) {
      vmm_panic("a 1 GiB leaf above the first root slot does not translate; "
                "this hart's root did not receive it");
    }
    if (observed != physical) {
      vmm_panic("a 1 GiB leaf above the first root slot translated to %lx "
                "not %lx", observed, physical);
    }
    if (*(volatile uint64_t *)(uintptr_t)(SELF_TEST_HIGH_VA +
                                          gigantic_offset) !=
        ~SELF_TEST_GIGANTIC_SIGNATURE) {
      vmm_panic("a 1 GiB leaf above the first root slot reads the wrong "
                "memory");
    }
    if (vmm_unmap_gigantic_page(SELF_TEST_HIGH_VA) != XAIOS_OK) {
      vmm_panic("could not unmap a 1 GiB leaf above the first root slot");
    }
    if (vmm_translate(SELF_TEST_HIGH_VA, 0, 0) == XAIOS_OK) {
      vmm_panic("a 1 GiB leaf above the first root slot still translates "
                "after being unmapped");
    }
    klog("vmm: gigantic page above the first root slot passed va=0x%lx\n",
         SELF_TEST_HIGH_VA);
  }

  pmm_free_page(page);
}

/* Defined in isa_self_test.c. Declared here rather than in a shared header
   because this test is its only caller. */
void riscv64_isa_self_test(void);

void vmm_self_test(void) {
  /* A mapping made, read back through the same walk a fault would take, and
     removed again. Proving translate agrees with map is the whole point:
     they are separate walks over the same tables, and a kernel where they
     disagree fails only when something dereferences the difference. */
  uint64_t probe = XAIOS_USER_BASE - XAIOS_VMM_LARGE_PAGE_SIZE;
  void *page = pmm_alloc_page();
  if (page == 0) vmm_panic("vmm self-test has no page to map");
  uint64_t physical = (uint64_t)(uintptr_t)page;

  if (vmm_map_page(probe, physical, XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) !=
      XAIOS_OK) {
    vmm_panic("vmm self-test could not map %lx", probe);
  }
  uint64_t observed = 0U;
  uint32_t flags = 0U;
  if (vmm_translate(probe, &observed, &flags) != XAIOS_OK ||
      observed != physical) {
    vmm_panic("vmm self-test translate mismatch: %lx not %lx", observed,
              physical);
  }
  if ((flags & XAIOS_VMM_WRITABLE) == 0U) {
    vmm_panic("vmm self-test lost the writable flag");
  }
  *(volatile uint64_t *)(uintptr_t)probe = UINT64_C(0x5849414f53525634);
  if (*(volatile uint64_t *)(uintptr_t)probe != UINT64_C(0x5849414f53525634)) {
    vmm_panic("vmm self-test wrote through a mapping and read back nothing");
  }
  if (vmm_unmap_page(probe) != XAIOS_OK) {
    vmm_panic("vmm self-test could not unmap %lx", probe);
  }
  if (vmm_translate(probe, 0, 0) == XAIOS_OK) {
    vmm_panic("vmm self-test unmapped a page that still translates");
  }
  pmm_free_page(page);
  klog("vmm: self-test passed (map, translate, write, unmap)\n");
  /* The large and gigantic leaves the shared interface promises, which this
     port implemented and nothing ever checked. Run after the 4 KiB case
     because it depends on it: every assertion below reads its result back
     through the same translate that has just been shown to agree with map. */
  vmm_large_page_self_test();
  /* What only this architecture has, checked once its page tables are
     live -- the satp mode is part of what is being reported, and a
     reading taken before translation is on says nothing. Shared code
     stays unaware of it, which is the rule. */
  riscv64_isa_self_test();
}
