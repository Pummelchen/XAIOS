#ifndef XAIOS_SMMU_H
#define XAIOS_SMMU_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_SMMU_MMIO_BASE UINT64_C(0x09050000)
#define XAIOS_SMMU_MMIO_PAGE1 UINT64_C(0x09060000)
#define XAIOS_SMMU_MAX_STREAMS 256U

/* Page 0 register offsets */
#define SMMU_IDR0 UINT32_C(0x0000)
#define SMMU_IDR1 UINT32_C(0x0004)
#define SMMU_CR0 UINT32_C(0x0020)
#define SMMU_CR0ACK UINT32_C(0x0024)
#define SMMU_CR1 UINT32_C(0x0028)
#define SMMU_GBPA UINT32_C(0x0044)
#define SMMU_ACR UINT32_C(0x004C)
#define SMMU_GERROR UINT32_C(0x0060)

#define SMMU_STRTAB_BASE UINT32_C(0x0080)
#define SMMU_STRTAB_BASE_CFG UINT32_C(0x0088)
#define SMMU_CMDQ_BASE UINT32_C(0x0090)
#define SMMU_CMDQ_PROD UINT32_C(0x0098)
#define SMMU_CMDQ_CONS UINT32_C(0x009c)
#define SMMU_EVENTQ_BASE UINT32_C(0x00a0)
#define SMMU_EVENTQ_PROD UINT32_C(0x00a8)
#define SMMU_EVENTQ_CONS UINT32_C(0x00ac)

/* CR0 bits */
#define SMMU_CR0_SMMUEN (UINT32_C(1) << 0)
#define SMMU_CR0_EVENTQEN (UINT32_C(1) << 2)
#define SMMU_CR0_CMDQEN (UINT32_C(1) << 3)

/* GBPA bits */
#define SMMU_GBPA_UPDATE (UINT32_C(1) << 31)
#define SMMU_GBPA_ABORT (UINT32_C(1) << 20)

/* STRTAB_CFG format */
#define SMMU_STRTAB_CFG_LINEAR UINT32_C(0)
#define SMMU_STRTAB_CFG_LOG2N_MASK UINT32_C(0x1f)

/* Command opcodes */
#define SMMU_CMD_TLBI_NH_ALL UINT32_C(0x10)
#define SMMU_CMD_CFGI_STE UINT32_C(0x03)

typedef struct xaios_smmu_stream {
  uint32_t stream_id;
  uint32_t active;
  uint32_t device_type;
} xaios_smmu_stream_t;

struct xaios_boot_info;
void smmu_init(const struct xaios_boot_info *boot);
uint32_t smmu_initialized(void);
uint32_t smmu_idr0_value(void);
xaios_status_t smmu_register_stream(uint32_t stream_id, uint32_t device_type);
xaios_status_t smmu_unregister_stream(uint32_t stream_id);
xaios_status_t smmu_tlb_invalidate_all(void);
uint64_t smmu_tlb_invalidate_count(void);
uint64_t smmu_fault_count(void);
uint64_t smmu_stream_count(void);
void smmu_self_test(void);

#endif
