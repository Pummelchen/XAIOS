/* Private interface shared by iommu.c, iommu_hw.c and iommu_ddt.c.
 *
 * iommu.c keeps the first-stage page tables, the QEMU test device and the
 * self-test that reads the machine's behaviour back out. The register
 * interface and the command and fault queues moved into iommu_hw.c, and the
 * device directory table -- the identity contexts, the translation contexts
 * and the first-stage contexts a PCI function's DMA is mediated through --
 * into iommu_ddt.c.
 *
 * The split is a size split only: register offsets, queue layout and
 * translation semantics are unchanged, and the gate's log lines are printed
 * with the same text in the same order.
 *
 * Everything the three files share is declared here once and defined once.
 * State stays behind functions: the register and queue state is iommu_hw.c's
 * and the directory and mediation state is iommu_ddt.c's, and each boundary is
 * crossed by address or by value, never with a pointer into another file's
 * mutable file-scope data.
 */
#ifndef XAIOS_ARCH_RISCV64_IOMMU_INTERNAL_H
#define XAIOS_ARCH_RISCV64_IOMMU_INTERNAL_H

#include <xaios/pci.h>
#include <xaios/types.h>

#define RISCV_IOMMU_PCI_VENDOR     XAIOS_PCI_VENDOR_REDHAT
#define RISCV_IOMMU_PCI_DEVICE     UINT16_C(0x0014)
/* The generic QEMU test device (Red Hat 0x1b36:0x0005). */
#define RISCV_IOMMU_TESTDEV_DEVICE UINT16_C(0x0005)

/* Command encodings used here. */
#define IOMMU_CMD_IOFENCE_C       UINT64_C(2)
#define IOMMU_CMD_IODIR_INVAL_DDT UINT64_C(3)
/* IOTINVAL.VMA with GV, PSCV and AV clear: every first-stage translation. */
#define IOMMU_CMD_IOTINVAL_ALL    UINT64_C(1)

/* Extended contexts, one page of them: the format QEMU selects when MSI
   translation is on, which is its reset state for this device. */
#define IOMMU_DDT_CONTEXTS 64U

/* One gibibyte: the size of a level-two leaf in the first-stage tables. */
#define IOMMU_GIB UINT64_C(0x40000000)

#define IOMMU_PTE_V UINT64_C(1)
#define IOMMU_PTE_R (UINT64_C(1) << 1)
#define IOMMU_PTE_W (UINT64_C(1) << 2)
#define IOMMU_PTE_U (UINT64_C(1) << 4)
#define IOMMU_PTE_A (UINT64_C(1) << 6)
#define IOMMU_PTE_D (UINT64_C(1) << 7)
/* Every leaf is R/W/U with A and D set by software: the context does not
   enable hardware A/D, and the specification requires U for an access with no
   process_id, which is every access here. */
#define IOMMU_PTE_LEAF                                            \
  (IOMMU_PTE_V | IOMMU_PTE_R | IOMMU_PTE_W | IOMMU_PTE_U |        \
   IOMMU_PTE_A | IOMMU_PTE_D)
#define IOMMU_FSC_MODE_SV39 (UINT64_C(8) << 60)
#define IOMMU_FSC_MODE_SV48 (UINT64_C(9) << 60)

/* Device directory and contexts, defined in iommu_ddt.c. `ddt_base` is the
   table's physical address, handed to the register side by value so that
   iommu_hw.c never holds a pointer into iommu_ddt.c's state. */
uint64_t riscv64_iommu_ddt_base(void);
int riscv64_iommu_install_identity_contexts(void);
uint32_t riscv64_iommu_identity_contexts(void);
void riscv64_iommu_install_translation_context(uint32_t device_id,
                                               uint64_t fsc);

/* The first-stage page tables, defined in iommu.c and shared with
   iommu_ddt.c because the mediation installs its own tree through them. */
uint64_t riscv64_iommu_pte_leaf(uint64_t address);
uint64_t riscv64_iommu_first_stage_fsc(const void *table, uint64_t mode);

/* Register interface and queues, defined in iommu_hw.c. */
void riscv64_iommu_bind(uint64_t base);
uint64_t riscv64_iommu_read_cap(void);
int riscv64_iommu_program_device(void);
void riscv64_iommu_bail_to_bare(const char *why);
int riscv64_iommu_issue_command(uint64_t dword0, uint64_t dword1);
uint64_t riscv64_iommu_drain_faults(void);
uint64_t riscv64_iommu_command_count(void);
uint64_t riscv64_iommu_fault_count(void);
uint32_t riscv64_iommu_ready(void);

#endif /* XAIOS_ARCH_RISCV64_IOMMU_INTERNAL_H */
