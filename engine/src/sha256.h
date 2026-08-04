#ifndef XAIOS_ENGINE_SHA256_H
#define XAIOS_ENGINE_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct xaios_sha256_context {
  uint32_t state[8];
  uint64_t total_bytes;
  uint8_t block[64];
  size_t block_size;
} xaios_engine_sha256_context_t;

void xaios_engine_sha256_init(xaios_engine_sha256_context_t *context);
void xaios_engine_sha256_update(xaios_engine_sha256_context_t *context,
                         const void *data, size_t length);
void xaios_engine_sha256_final(xaios_engine_sha256_context_t *context, uint8_t digest[32]);

#endif
