#ifndef XAIOS_INFLATE_H
#define XAIOS_INFLATE_H

#include <xaios/status.h>
#include <xaios/types.h>

xaios_status_t xaios_inflate_raw(const uint8_t *input, uint64_t input_size,
                                 uint8_t *output, uint64_t output_capacity,
                                 uint64_t *output_size);

#endif
