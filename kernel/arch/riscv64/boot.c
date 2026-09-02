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

/* Sv39: three levels, 512 entries each, 4 KiB pages.
 *
 * The map built here is a single gibibyte-aligned identity mapping made of
 * level-1 leaves, which Sv39 allows and which covers all of QEMU virt's RAM
 * and its device window in a handful of entries. A full page-table walker
 * belongs with the memory manager this port has not written; what is being
 * proven here is narrower and worth stating exactly: that translation can be
 * turned on, that execution survives it, and that the kernel can still reach
 * its own memory afterwards.
 */
#define PTE_V UINT64_C(0x001)
#define PTE_R UINT64_C(0x002)
#define PTE_W UINT64_C(0x004)
#define PTE_X UINT64_C(0x008)
#define PTE_A UINT64_C(0x040)
#define PTE_D UINT64_C(0x080)
#define SATP_MODE_SV39 (UINT64_C(8) << 60)

static uint64_t g_root_table[512] __attribute__((aligned(4096)));

static int enable_sv39(void) {
  /* One gibibyte per entry, identity mapped, read/write/execute. Entry 2
     covers 0x80000000 where RAM and this kernel live; entry 0 covers the
     device window below it, which includes the UART and the PLIC. */
  for (uint64_t gib = 0U; gib < 4U; ++gib) {
    uint64_t physical = gib << 30;
    g_root_table[gib] = ((physical >> 12) << 10) | PTE_V | PTE_R | PTE_W |
                        PTE_X | PTE_A | PTE_D;
  }
  uint64_t satp = SATP_MODE_SV39 |
                  (((uint64_t)(uintptr_t)g_root_table) >> 12);
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");
  __asm__ volatile("csrw satp, %0" : : "r"(satp) : "memory");
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");

  /* Read satp back. A write the hardware declined leaves the old value, and
     without this check a machine that ignored the request would look
     identical to one that honoured it -- the identity map means nothing
     visibly changes either way. */
  uint64_t observed = 0U;
  __asm__ volatile("csrr %0, satp" : "=r"(observed));
  return observed == satp;
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

  /* Paging. */
  if (enable_sv39() == 0) {
    klog("riscv64: SV39 REFUSED -- satp did not take the written value\n");
    sbi_shutdown();
  }
  /* Touch the kernel's own memory through the new translation. If the map
     were wrong this faults rather than returning, which the trap counter
     then reports. */
  volatile uint64_t probe = *(volatile uint64_t *)(void *)__kernel_start;
  (void)probe;
  klog("riscv64: sv39 paging enabled, kernel still addressable\n");

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

  klog("riscv64: bring-up complete -- console, traps, sv39, timer and "
       "shared kernel code\n");
  klog("riscv64: NOT present on this architecture: smp, pci, virtio, "
       "storage, network, userspace\n");
  klog("riscv64: halting\n");
  sbi_shutdown();
  for (;;) {
    __asm__ volatile("wfi");
  }
}
