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
#define SBI_EXT_RFENCE UINT64_C(0x52464E43) /* "RFNC" */

#define SBI_IPI_SEND UINT64_C(0)

#define SBI_RFENCE_REMOTE_FENCE_I UINT64_C(0)
#define SBI_RFENCE_REMOTE_SFENCE_VMA UINT64_C(1)
#define SBI_RFENCE_REMOTE_SFENCE_VMA_ASID UINT64_C(2)

/* The hart mask that means "every hart", which is how the specification
   spells it: a base of all-ones tells firmware to ignore the mask entirely.
   Not used by the shootdown path -- it builds an explicit mask so it can say
   which harts it reached -- but named here because the value is otherwise a
   bare -1 in a call that takes four unsigned arguments. */
#define SBI_HART_MASK_ALL UINT64_C(0xFFFFFFFFFFFFFFFF)

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

/* A fence on somebody else's hart.
 *
 * `sfence.vma` is hart-local by definition -- the instruction fences the hart
 * that executes it and says nothing about any other -- and a supervisor-mode
 * kernel has no way to execute an instruction on a hart it is not running on.
 * The RFENCE extension is the architecture's answer: firmware, which does run
 * on every hart, is asked to do it. That is the same shape as HSM for
 * starting a hart and IPI for waking one, and for the same reason.
 *
 * The mask is relative to `hart_mask_base`, exactly as the IPI extension's
 * is, so a caller with hart ids 0, 2 and 3 passes base 0 and mask 0b1101 --
 * and a caller whose lowest id is 2 passes base 2 and mask 0b011. Hart ids
 * are firmware's to choose and are not promised to be dense; getting the base
 * wrong fences the wrong harts and reports success.
 *
 * `size` is a byte count, not a page count. A start of zero with a size of
 * zero, or a size of all-ones, is the specification's spelling of "the whole
 * address space".
 *
 * Returns the SBI error, zero on success. */
int64_t sbi_remote_sfence_vma(uint64_t hart_mask, uint64_t hart_mask_base,
                              uint64_t start_address, uint64_t size);
int64_t sbi_remote_sfence_vma_asid(uint64_t hart_mask, uint64_t hart_mask_base,
                                   uint64_t start_address, uint64_t size,
                                   uint64_t asid);
/* Whether firmware offers RFENCE at all, probed once and remembered.
 *
 * Asked rather than assumed. OpenSBI implements it and QEMU ships OpenSBI, so
 * on every machine this port is tested on the answer is yes -- but the
 * extension is optional in the specification, the kernel already probes DBCN,
 * SRST and HSM the same way, and a kernel that assumed it would issue ecalls
 * that quietly return SBI_ERR_NOT_SUPPORTED and go on believing every hart
 * had been fenced. */
int sbi_rfence_available(void);

#endif
