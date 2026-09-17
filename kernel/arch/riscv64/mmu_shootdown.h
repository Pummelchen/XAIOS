/* Private interface between mmu.c and mmu_shootdown.c.
 *
 * The Sv39/Sv48 page tables, the mapping helpers and the remote TLB shootdown
 * they call all live in mmu.c. The test that proves a shootdown reaches
 * another hart's TLB used to live there too, at the bottom of the file, and is
 * now mmu_shootdown.c; this header is what the two files share.
 *
 * Nothing here is a public kernel interface. The declarations that used to sit
 * at the top of mmu.c and are needed by both sides moved here verbatim, so
 * that neither file keeps a second copy of them. What mmu.c offers the test is
 * named functions returning values into the caller's own locals -- never a
 * pointer into mmu.c's file-scope state, which is why the mode, the fence and
 * the suppression flag each get a call rather than a handed-out address.
 */
#ifndef XAIOS_ARCH_RISCV64_MMU_SHOOTDOWN_H
#define XAIOS_ARCH_RISCV64_MMU_SHOOTDOWN_H

#include <xaios/types.h>

/* The page size this architecture pages with. Shared because both files name
   it; this was mmu.c's own #define before the split. */
#define PAGE_SIZE UINT64_C(0x1000)

/* How many harts this file is prepared to describe: one set of page tables
   each, and one slot each in the shootdown's hart-mask scratch. It bounds the
   *identifier* space rather than a count, which is the distinction smp.c
   records -- firmware may hand out ids with gaps in them. */
#define VMM_MAX_HARTS 64U

/* Declared here rather than taken from xaios/klog.h and xaios/panic.h: those
   two carry a printf format attribute, and the arch sweep compiles these files
   with -Werror. This is exactly the pair of declarations mmu.c carried before
   the split, moved verbatim. */
void klog(const char *fmt, ...);
void panic_at(const char *file, int line, const char *fmt, ...)
    __attribute__((noreturn));
#define vmm_panic(...) panic_at(__FILE__, __LINE__, __VA_ARGS__)

/* Hart identity, which is firmware's numbering rather than the kernel's.
   Everything that talks to SBI -- and a remote fence is the sharpest example
   -- has to name harts the way firmware does. */
uint32_t riscv64_hart_of_cpu(uint32_t cpu_id);
/* A page fault taken on purpose, recovered rather than fatal, per hart. The
   shootdown self-test asks a secondary to dereference an address the boot
   hart has just withdrawn; without this the secondary would be killed by the
   fault the test exists to provoke. Declared here rather than added to
   xaios/exception.h because it belongs to this architecture, and that header
   is shared with two others that have no use for it. */
void exception_page_probe_begin(void);
void exception_page_probe_end(void);
int exception_page_probe_faulted(void);

/* Which paging mode the hart ended up in: level 2 for Sv39, level 3 for Sv48.
   The shootdown test names the mode in its log lines and asks nothing else of
   it, so the value is copied out and mmu.c keeps the variable. */
uint32_t riscv64_mmu_root_level(void);

/* The production remote fence, callable by name so the test can issue exactly
   the call the unmap path issues. Returns the number of remote harts fenced,
   which is what the test's mask assertion reads. */
uint32_t riscv64_mmu_remote_fence(uint64_t start, uint64_t size);

/* The test's negative control: while this is set, riscv64_mmu_remote_fence
   does nothing, which is the kernel as it stood before remote fencing existed.
   A named setter, because the caller must mutate mmu.c's state and handing out
   a pointer to it is how two translation units end up sharing a variable whose
   writers nobody can find. */
void riscv64_mmu_set_remote_fence_suppressed(uint32_t suppressed);

/* Counters and the last window actually sent, all read into the caller's
   locals. Defined in mmu.c and read by the shootdown test and nothing else. */
uint64_t riscv64_platform_tlb_shootdown_count(void);
uint64_t riscv64_platform_tlb_remote_hart_fences(void);
uint64_t riscv64_platform_tlb_remote_fence_errors(void);
uint64_t riscv64_platform_tlb_last_mask(void);
uint64_t riscv64_platform_tlb_last_base(void);
uint32_t riscv64_platform_tlb_last_windows(void);

#endif /* XAIOS_ARCH_RISCV64_MMU_SHOOTDOWN_H */
