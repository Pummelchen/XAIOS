/* RISC-V bring-up.
 *
 * This is not a port of XAIOS to RISC-V. It is the part of one that can be
 * shown to work, and it says so: SBI console and power, trap entry and
 * return, Sv39 paging, the timer, and shared kernel code running unmodified
 * on top of that. Storage, networking, userspace and SMP are absent, and the
 * summary at the end names them rather than letting a clean boot imply they
 * exist.
 *
 * Each step announces a marker the gate matches on. A step that cannot be
 * verified does not get a marker -- there is no value in a line that says a
 * thing happened when nothing checked it.
 */
#include <stdint.h>

#include <xaios/boot_info.h>
#include <xaios/kheap.h>
#include <xaios/numa.h>
#include <xaios/pmm.h>
#include <xaios/smp.h>
#include <xaios/vmm.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/sha256.h>

void klog(const char *fmt, ...);
xaios_boot_info_t *riscv64_build_boot_info(uint64_t device_tree);
void riscv64_boot(uint64_t hart_id, uint64_t device_tree);
uint64_t riscv64_trap_handler(uint64_t cause, uint64_t epc, uint64_t tval);
extern void riscv64_trap_entry(void);
extern char __kernel_start[];
extern char __kernel_end[];

/* Set by the trap handler so the code that caused a trap can prove one was
   taken rather than assuming it. Volatile because the only writer is a trap
   the compiler cannot see happening. */
static xaios_boot_info_t *g_boot;
static volatile uint64_t g_traps_taken;
static volatile uint64_t g_last_cause;

#define SCAUSE_ILLEGAL_INSTRUCTION UINT64_C(2)
#define SCAUSE_BREAKPOINT UINT64_C(3)
#define SCAUSE_ECALL_FROM_S UINT64_C(9)

uint64_t riscv64_trap_handler(uint64_t cause, uint64_t epc, uint64_t tval) {
  (void)tval;
  ++g_traps_taken;
  g_last_cause = cause;
  if ((cause & (UINT64_C(1) << 63)) != 0U) {
    return epc; /* interrupt: the interrupted instruction has not run */
  }
  /* Resume after the instruction that trapped -- but its width has to be
     read, not assumed.
     This originally returned epc + 4, on the reasoning that the exceptions
     provoked here are all 32-bit. They are not: rv64gc includes the C
     extension, and the assembler encodes a bare `ebreak` as the 16-bit
     `c.ebreak` whenever it can. Resuming four bytes on from a two-byte
     instruction lands in the middle of the next one, and what came back was
     not a crash but nonsense -- the trap self-test reported failure while
     printing exactly the values it required.
     RISC-V makes the width readable from the instruction itself: the low two
     bits are 0b11 only for 32-bit encodings, and anything else is a 16-bit
     compressed one. */
  const uint16_t *instruction = (const uint16_t *)(uintptr_t)epc;
  return epc + (((*instruction & 0x3U) == 0x3U) ? 4U : 2U);
}

static uint64_t read_time(void) {
  uint64_t value = 0U;
  __asm__ volatile("rdtime %0" : "=r"(value));
  return value;
}

void riscv64_boot(uint64_t hart_id, uint64_t device_tree) {
  klog("\nXAIOS riscv64 bring-up starting\n");
  klog("riscv64: hart=%lu device_tree=%lx\n", hart_id, device_tree);
  klog("riscv64: kernel %lx..%lx\n", (uint64_t)(uintptr_t)__kernel_start,
       (uint64_t)(uintptr_t)__kernel_end);

  /* What the firmware underneath actually offers, asked rather than assumed
     -- the same discipline the other two architectures use for their
     firmware. */
  uint64_t version = sbi_spec_version();
  klog("riscv64: sbi spec=%lu.%lu impl=%lu dbcn=%d srst=%d time=%d\n",
       (version >> 24) & UINT64_C(0x7f), version & UINT64_C(0xffffff),
       sbi_implementation_id(), sbi_probe_extension(SBI_EXT_DBCN),
       sbi_probe_extension(SBI_EXT_SRST), sbi_probe_extension(SBI_EXT_TIME));
  klog("riscv64: sbi console ready\n");

  /* Describe this machine from its device tree, which is the first step
     towards running shared kernel code that expects a boot structure. */
  {
    xaios_boot_info_t *boot = riscv64_build_boot_info(device_tree);
    g_boot = boot;
    if (boot == 0) {
      klog("riscv64: BOOT INFO FAILED -- cannot describe this machine\n");
      sbi_shutdown();
    }
    const xaios_memory_descriptor_t *map =
        (const xaios_memory_descriptor_t *)(uintptr_t)boot->memory_map;
    uint64_t regions = boot->memory_map_size / boot->memory_descriptor_size;
    uint64_t total_pages = 0U;
    for (uint64_t i = 0U; i < regions; ++i) total_pages += map[i].number_of_pages;
    klog("riscv64: device tree parsed uart=%lx regions=%lu free=%lu MiB\n",
         boot->uart_base, regions, (total_pages * 0x1000U) / (1024U * 1024U));
    for (uint64_t i = 0U; i < regions; ++i) {
      klog("riscv64:   region %lu %lx..%lx\n", i, map[i].physical_start,
           map[i].physical_start + map[i].number_of_pages * 0x1000U);
    }
  }

  /* Traps. Provoked on purpose, because a trap vector that has never been
     entered is a guess. */
  __asm__ volatile("csrw stvec, %0"
                   :
                   : "r"((uint64_t)(uintptr_t)riscv64_trap_entry)
                   : "memory");
  uint64_t before = g_traps_taken;
  __asm__ volatile("ebreak");
  if (g_traps_taken != before + 1U || g_last_cause != SCAUSE_BREAKPOINT) {
    klog("riscv64: TRAP SELF-TEST FAILED taken=%lu cause=%lu\n",
         g_traps_taken, g_last_cause);
    sbi_shutdown();
  }
  klog("riscv64: trap taken and returned from cause=%lu total=%lu\n",
       g_last_cause, g_traps_taken);

  /* Real memory management, from here on shared with the other two
     architectures: the physical allocator, Sv48 page tables, and the kernel
     heap. The bring-up's four gibibyte identity leaves are gone -- they were
     enough to prove translation could be turned on and nothing more. */
  /* NUMA first: the physical allocator takes its regions from the node table
     rather than from the boot map directly, and pmm_init says so in its own
     comment. Calling them the other way round produces a working-looking
     allocator with nothing in it. */
  numa_init(g_boot);
  pmm_init(g_boot);
  klog("riscv64: pmm total=%lu free=%lu pages\n", pmm_total_pages(),
       pmm_free_pages());
  vmm_init(g_boot);
  smp_init_platform(g_boot);
  smp_self_test();
  vmm_self_test();
  kheap_init();
  {
    /* The heap, exercised rather than assumed: a kernel that reports a heap
       and cannot hand out a byte of it has reported nothing. */
    void *block = kheap_alloc(4096U, 64U);
    if (block == 0) {
      klog("riscv64: KHEAP FAILED to allocate\n");
      sbi_shutdown();
    }
    *(volatile uint64_t *)block = UINT64_C(0x5849414f53);
    klog("riscv64: kheap serving allocations\n");
  }

  /* The timer has to be seen to move. A counter read once is a number; read
     twice with work between is a clock. */
  uint64_t t0 = read_time();
  for (volatile uint32_t spin = 0U; spin < 200000U; ++spin) {
  }
  uint64_t t1 = read_time();
  if (t1 <= t0) {
    klog("riscv64: TIMER DID NOT ADVANCE %lu -> %lu\n", t0, t1);
    sbi_shutdown();
  }
  klog("riscv64: timer advancing %lu ticks\n", t1 - t0);

  /* The point of the exercise: shared kernel code, unmodified, on a third
     architecture. sha256.c is compiled from the same source the AArch64 and
     x86-64 kernels use and asserts its own known-answer vectors. */
  sha256_self_test();
  klog("riscv64: shared kernel sha256 verified on this architecture\n");

  klog("riscv64: bring-up complete -- console, traps, sv48 paging, physical "
       "and heap allocators, smp identity, timer and shared kernel code\n");
  klog("riscv64: NOT present on this architecture: pci, virtio, "
       "storage, network, userspace\n");
  klog("riscv64: halting\n");
  sbi_shutdown();
  for (;;) {
    __asm__ volatile("wfi");
  }
}
