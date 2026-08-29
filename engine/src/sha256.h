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

/* Compress `count` consecutive 64-byte blocks into `state`.
 *
 * The shape a hardware implementation has to present. The scalar code is the
 * reference and always available; an accelerated one is installed at runtime
 * by whoever is in a position to ask the CPU whether it exists.
 */
typedef void (*xaios_engine_sha256_compress_fn)(uint32_t state[8],
                                                const uint8_t *blocks,
                                                size_t count);

/* The accelerated compressor for this architecture, or null where there is
 * none. Returning it does not mean this CPU can run it -- that question is the
 * caller's, because answering it is a privileged register read inside XAIOS
 * and an auxiliary vector on a host.
 */
xaios_engine_sha256_compress_fn xaios_engine_sha256_hardware_compressor(void);

/* Use `compress` for every hash from now on, or pass null to go back to the
 * scalar reference. Install it once, before anything hashes; it is a plain
 * store with no synchronisation of its own.
 */
void xaios_engine_sha256_install_compressor(
    xaios_engine_sha256_compress_fn compress);

void xaios_engine_sha256_init(xaios_engine_sha256_context_t *context);
void xaios_engine_sha256_update(xaios_engine_sha256_context_t *context,
                         const void *data, size_t length);
void xaios_engine_sha256_final(xaios_engine_sha256_context_t *context, uint8_t digest[32]);

#endif
