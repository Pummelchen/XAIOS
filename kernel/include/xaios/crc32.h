#ifndef XAIOS_CRC32_H
#define XAIOS_CRC32_H

#include <xaios/types.h>

uint32_t xaios_crc32_begin(void);
uint32_t xaios_crc32_update(uint32_t state, const void *data, uint64_t length);
uint32_t xaios_crc32_finish(uint32_t state);
uint32_t xaios_crc32(const void *data, uint64_t length);

#endif
