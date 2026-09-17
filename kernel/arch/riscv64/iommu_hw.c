/* The RISC-V IOMMU register interface and its two queues (B-130).
 *
 * This is the half that touches the device: the MMIO accessors, the two queue
 * enable sequences, the `DDTP` write that puts the directory in charge, the
 * command queue's issue-and-retire round trip and the fault queue's drain.
 *
 * Moved here from iommu.c, which keeps the directory, the page tables and the
 * self-test. Register offsets, queue layout and the order the device is
 * programmed in are unchanged: the split is a size split.
 *
 * The device directory table itself is iommu_ddt.c's, and this file reaches it
 * by address for the one write that programs `DDTP`.
 */

#include <xaios/arch_cpu.h>
#include <xaios/klog.h>
#include <xaios/smmu.h>
#include <xaios/timer.h>
#include <xaios/types.h>

#include "iommu_internal.h"

/* One 4 KiB register page. Offsets from the 1.0 specification, section 5. */
#define IOMMU_REG_CAP   UINT32_C(0x0000)
#define IOMMU_REG_FCTL  UINT32_C(0x0008)
#define IOMMU_REG_DDTP  UINT32_C(0x0010)
#define IOMMU_REG_CQB   UINT32_C(0x0018)
#define IOMMU_REG_CQH   UINT32_C(0x0020)
#define IOMMU_REG_CQT   UINT32_C(0x0024)
#define IOMMU_REG_FQB   UINT32_C(0x0028)
#define IOMMU_REG_FQH   UINT32_C(0x0030)
#define IOMMU_REG_FQT   UINT32_C(0x0034)
#define IOMMU_REG_CQCSR UINT32_C(0x0048)
#define IOMMU_REG_FQCSR UINT32_C(0x004c)
#define IOMMU_REG_IPSR  UINT32_C(0x0054)

/* DDTP: mode in bits 3:0, busy bit 4, PPN in bits 53:10. */
#define IOMMU_DDTP_MODE_MASK UINT64_C(0xf)
#define IOMMU_DDTP_BUSY      (UINT64_C(1) << 4)
#define IOMMU_DDTP_MODE_BARE UINT64_C(1)
#define IOMMU_DDTP_MODE_1LVL UINT64_C(2)

/* Queue base and CSR fields. The base stores log2(entries) - 1 in bits 4:0. */
#define IOMMU_PPN_SHIFT         UINT32_C(10)
#define IOMMU_QUEUE_LOG2SZ_MASK UINT64_C(0x1f)
#define IOMMU_QUEUE_ENABLE      UINT32_C(1) << 0
#define IOMMU_QUEUE_MEM_FAULT   UINT32_C(1) << 8
#define IOMMU_QUEUE_OVERFLOW    UINT32_C(1) << 9
#define IOMMU_CQCSR_CMD_ILL     UINT32_C(1) << 10
#define IOMMU_QUEUE_ACTIVE      UINT32_C(1) << 16
#define IOMMU_QUEUE_BUSY        UINT32_C(1) << 17

/* Fault record header fields. */
#define IOMMU_FQ_CAUSE_MASK UINT64_C(0xfff)
#define IOMMU_FQ_TTYPE_LOW  34U
#define IOMMU_FQ_DID_LOW    40U

#define IOMMU_QUEUE_LOG2SZ 3U
#define IOMMU_QUEUE_ENTRIES (1U << (IOMMU_QUEUE_LOG2SZ + 1U))
#define IOMMU_COMMAND_BYTES 16U
#define IOMMU_FAULT_BYTES   32U

#define IOMMU_TIMEOUT_NS UINT64_C(100000000)

static volatile uint8_t *g_regs;
static uint32_t g_iommu_ready;
static uint64_t g_cap;

static uint8_t g_cq[IOMMU_QUEUE_ENTRIES * IOMMU_COMMAND_BYTES]
    __attribute__((aligned(4096)));
static uint8_t g_fq[IOMMU_QUEUE_ENTRIES * IOMMU_FAULT_BYTES]
    __attribute__((aligned(4096)));

static uint32_t g_cq_tail;
static uint64_t g_command_count;
static uint64_t g_fault_count;

static uint64_t mmio_read64(uint32_t offset) {
  return *(volatile const uint64_t *)(const void *)(g_regs + offset);
}

static uint32_t mmio_read32(uint32_t offset) {
  return *(volatile const uint32_t *)(const void *)(g_regs + offset);
}

static void mmio_write64(uint32_t offset, uint64_t value) {
  *(volatile uint64_t *)(void *)(g_regs + offset) = value;
  xaios_cpu_io_barrier();
}

static void mmio_write32(uint32_t offset, uint32_t value) {
  *(volatile uint32_t *)(void *)(g_regs + offset) = value;
  xaios_cpu_io_barrier();
}

/* A physical address in the PPN field at bits 53:10. */
static uint64_t ppn_field(uint64_t address) {
  return (address >> 12U) << IOMMU_PPN_SHIFT;
}

static int wait_bit_clear(uint32_t offset, uint32_t bit) {
  uint64_t deadline = timer_now_ns() + IOMMU_TIMEOUT_NS;
  while ((mmio_read32(offset) & bit) != 0U) {
    if (timer_now_ns() >= deadline) return 0;
  }
  return 1;
}

static int enable_command_queue(void) {
  mmio_write64(IOMMU_REG_CQB,
               ppn_field((uint64_t)(uintptr_t)g_cq) | IOMMU_QUEUE_LOG2SZ);
  mmio_write32(IOMMU_REG_CQH, 0U);
  mmio_write32(IOMMU_REG_CQT, 0U);
  mmio_write32(IOMMU_REG_CQCSR, IOMMU_QUEUE_ENABLE);
  if (wait_bit_clear(IOMMU_REG_CQCSR, IOMMU_QUEUE_BUSY) == 0 ||
      (mmio_read32(IOMMU_REG_CQCSR) & IOMMU_QUEUE_ACTIVE) == 0U) {
    klog("riscv-iommu: command queue did not come on csr=0x%x\n",
         (unsigned)mmio_read32(IOMMU_REG_CQCSR));
    return 0;
  }
  return 1;
}

static int enable_fault_queue(void) {
  mmio_write64(IOMMU_REG_FQB,
               ppn_field((uint64_t)(uintptr_t)g_fq) | IOMMU_QUEUE_LOG2SZ);
  mmio_write32(IOMMU_REG_FQH, 0U);
  mmio_write32(IOMMU_REG_FQT, 0U);
  mmio_write32(IOMMU_REG_FQCSR, IOMMU_QUEUE_ENABLE);
  if (wait_bit_clear(IOMMU_REG_FQCSR, IOMMU_QUEUE_BUSY) == 0 ||
      (mmio_read32(IOMMU_REG_FQCSR) & IOMMU_QUEUE_ACTIVE) == 0U) {
    klog("riscv-iommu: fault queue did not come on csr=0x%x\n",
         (unsigned)mmio_read32(IOMMU_REG_FQCSR));
    return 0;
  }
  return 1;
}

/* Put the device back in charge of nothing: DMA passes through unmediated
   again, which is the state the machine boots in. */
void riscv64_iommu_bail_to_bare(const char *why) {
  mmio_write64(IOMMU_REG_DDTP, IOMMU_DDTP_MODE_BARE);
  (void)wait_bit_clear(IOMMU_REG_DDTP, IOMMU_DDTP_BUSY);
  g_iommu_ready = 0U;
  klog("riscv-iommu: %s; device left in Bare and DMA is unmediated\n", why);
}

int riscv64_iommu_program_device(void) {
  /* Queues before the table, so a fault taken while the table is being
     installed has somewhere to land. */
  if (enable_command_queue() == 0 || enable_fault_queue() == 0) {
    riscv64_iommu_bail_to_bare("a queue could not be enabled");
    return 0;
  }
  /* The identity contexts are already in the page this points at, and both
     writes are one step from the machine's point of view: the moment the mode
     leaves Bare, every function the table does not describe stops. */
  mmio_write64(IOMMU_REG_DDTP,
               ppn_field(riscv64_iommu_ddt_base()) | IOMMU_DDTP_MODE_1LVL);
  if (wait_bit_clear(IOMMU_REG_DDTP, IOMMU_DDTP_BUSY) == 0 ||
      (mmio_read64(IOMMU_REG_DDTP) & IOMMU_DDTP_MODE_MASK) !=
          IOMMU_DDTP_MODE_1LVL) {
    riscv64_iommu_bail_to_bare(
        "the device directory table would not take 1LVL");
    return 0;
  }
  g_iommu_ready = 1U;
  return 1;
}

int riscv64_iommu_issue_command(uint64_t dword0, uint64_t dword1) {
  uint32_t slot = g_cq_tail & (IOMMU_QUEUE_ENTRIES - 1U);
  uint64_t *entry = (uint64_t *)(void *)(g_cq + slot * IOMMU_COMMAND_BYTES);
  entry[0] = dword0;
  entry[1] = dword1;
  xaios_cpu_io_barrier();
  ++g_cq_tail;
  mmio_write32(IOMMU_REG_CQT, g_cq_tail);
  ++g_command_count;

  uint32_t want = g_cq_tail & (IOMMU_QUEUE_ENTRIES - 1U);
  uint64_t deadline = timer_now_ns() + IOMMU_TIMEOUT_NS;
  while ((mmio_read32(IOMMU_REG_CQH) & (IOMMU_QUEUE_ENTRIES - 1U)) != want) {
    if (timer_now_ns() >= deadline) {
      klog("riscv-iommu: command 0x%lx did not retire (head=%u want=%u)\n",
           (unsigned long)dword0, (unsigned)mmio_read32(IOMMU_REG_CQH),
           (unsigned)want);
      return 0;
    }
  }

  uint32_t csr = mmio_read32(IOMMU_REG_CQCSR);
  if ((csr & (IOMMU_QUEUE_MEM_FAULT | IOMMU_CQCSR_CMD_ILL)) != 0U) {
    klog("riscv-iommu: command 0x%lx was refused csr=0x%x\n",
         (unsigned long)dword0, (unsigned)csr);
    /* Both are write-1-to-clear, and leaving one set stops the queue. */
    mmio_write32(IOMMU_REG_CQCSR,
                 csr & (IOMMU_QUEUE_MEM_FAULT | IOMMU_CQCSR_CMD_ILL));
    return 0;
  }
  return 1;
}

/* Faults are written whether or not anything is notified, so draining the
   queue is the whole of reading them. Draining is also what keeps the next
   fault from being an overflow instead of a record. */
uint64_t riscv64_iommu_drain_faults(void) {
  uint64_t drained = 0U;
  for (;;) {
    uint32_t head = mmio_read32(IOMMU_REG_FQH) & (IOMMU_QUEUE_ENTRIES - 1U);
    uint32_t tail = mmio_read32(IOMMU_REG_FQT) & (IOMMU_QUEUE_ENTRIES - 1U);
    if (head == tail) break;
    const uint64_t *record =
        (const uint64_t *)(const void *)(g_fq + head * IOMMU_FAULT_BYTES);
    uint64_t header = record[0];
    klog("riscv-iommu: fault cause=%lu did=%lu ttype=%lu iotval=0x%lx\n",
         (unsigned long)(header & IOMMU_FQ_CAUSE_MASK),
         (unsigned long)((header >> IOMMU_FQ_DID_LOW) & UINT64_C(0xffffff)),
         (unsigned long)((header >> IOMMU_FQ_TTYPE_LOW) & UINT64_C(0x3f)),
         (unsigned long)record[2]);
    ++g_fault_count;
    ++drained;
    mmio_write32(IOMMU_REG_FQH, (head + 1U) & (IOMMU_QUEUE_ENTRIES - 1U));
    if (drained >= IOMMU_QUEUE_ENTRIES) break;
  }
  return drained;
}

/* Point the register interface at the device's BAR. The self-test maps the
   page and hands the base here rather than writing the register file's
   file-scope pointer from the outside. */
void riscv64_iommu_bind(uint64_t base) {
  g_regs = (volatile uint8_t *)(uintptr_t)base;
}

/* Read `CAP` once and keep it, which is what the bring-up did when the value
   lived in the self-test's file. The caller wraps this in the deliberate-fault
   probe, because a read that faults and a read of all-ones mean the same
   thing. */
uint64_t riscv64_iommu_read_cap(void) {
  g_cap = mmio_read64(IOMMU_REG_CAP);
  return g_cap;
}

uint64_t riscv64_iommu_fault_count(void) { return g_fault_count; }
uint32_t riscv64_iommu_ready(void) { return g_iommu_ready; }
uint64_t riscv64_iommu_command_count(void) { return g_command_count; }
