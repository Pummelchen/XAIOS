#ifndef XAIOS_AARCH64_SVE_H
#define XAIOS_AARCH64_SVE_H

#include <xaios/types.h>

#define XAIOS_AARCH64_SVE_STATE_MAX_BYTES 8736U

void aarch64_sve2_self_test(void);
uint32_t aarch64_sve_enabled(void);
uint64_t aarch64_sve_state_size(void);
uint64_t aarch64_sve_irq_self_test(void);

#endif
