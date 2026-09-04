#ifndef XAIOS_RISCV64_SBI_H
#define XAIOS_RISCV64_SBI_H

#include <stdint.h>

/* SBI extension identifiers, from the RISC-V Supervisor Binary Interface
   specification. The legacy pair are the original single-purpose calls every
   implementation carries; the others are the versioned extensions that have
   to be probed before use. */
#define SBI_EXT_LEGACY_PUTCHAR UINT64_C(0x01)
#define SBI_EXT_LEGACY_SHUTDOWN UINT64_C(0x08)
#define SBI_EXT_BASE UINT64_C(0x10)
#define SBI_EXT_TIME UINT64_C(0x54494D45)  /* "TIME" */
#define SBI_EXT_SRST UINT64_C(0x53525354)  /* "SRST" */
#define SBI_EXT_DBCN UINT64_C(0x4442434E)  /* "DBCN" */
#define SBI_EXT_HSM UINT64_C(0x48534D)     /* "HSM" */
#define SBI_EXT_IPI UINT64_C(0x735049)     /* "sPI" */

#define SBI_IPI_SEND UINT64_C(0)

#define SBI_HSM_HART_START UINT64_C(0)
#define SBI_HSM_HART_STATUS UINT64_C(2)

#define SBI_BASE_GET_SPEC_VERSION UINT64_C(0)
#define SBI_BASE_GET_IMPL_ID UINT64_C(1)
#define SBI_BASE_PROBE_EXTENSION UINT64_C(3)
#define SBI_DBCN_WRITE UINT64_C(0)
#define SBI_SRST_SYSTEM_RESET UINT64_C(0)

typedef struct sbi_result {
  int64_t error;
  uint64_t value;
} sbi_result_t;

int sbi_probe_extension(uint64_t extension);
uint64_t sbi_spec_version(void);
uint64_t sbi_implementation_id(void);
void sbi_putchar(char value);
void sbi_puts(const char *text);
void sbi_put_u64_hex(uint64_t value);
void sbi_put_u64(uint64_t value);
void sbi_shutdown(void);

/* Start a hart at a physical address with translation off, passing an opaque
   value the entry code receives in a1. Returns the SBI error, zero on
   success. */
int64_t sbi_hart_start(uint64_t hart_id, uint64_t start_address,
                       uint64_t opaque);
int64_t sbi_hart_status(uint64_t hart_id);

/* Raise a supervisor software interrupt on the harts named by the mask,
   which is relative to hart_mask_base. */
int64_t sbi_send_ipi(uint64_t hart_mask, uint64_t hart_mask_base);

#endif
