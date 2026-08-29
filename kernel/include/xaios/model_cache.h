#ifndef XAIOS_MODEL_CACHE_H
#define XAIOS_MODEL_CACHE_H

#include <xaios/types.h>

/*
 * A read cache for /models, held in RAM, keyed by chunk.
 *
 * The unit is one xaiFS chunk because that is the unit of verification: a
 * chunk's SHA-256 covers all of it, so a chunk can only be checked whole. A
 * chunk is admitted here after it has been read and verified, and a hit
 * therefore serves bytes that were checked once instead of checking them
 * again. That is the entire point -- the verified read path is bounded by
 * hashing, not by the disk, so what a cache buys is not avoided I/O but
 * avoided hashing.
 *
 * Only chunks of active packages are cached. Staging packages are being
 * written and their chunks change under it; the cache refuses them rather
 * than tracking their mutations.
 *
 * Every entry point must be called with the model VFS lock held. The cache
 * takes no lock of its own because it has no life outside that one.
 */

/* Reserve up to `budget_bytes` of RAM. Actual memory is taken on demand and
   given back on eviction, so a cache that is never used costs nothing. */
void model_cache_init(uint64_t budget_bytes);

/* Serve `count` bytes at `within` inside the chunk at `key`, if it is here.
   Returns 1 on a hit, 0 on a miss; a miss also records that the chunk was
   wanted, which is what later decides whether to admit it. */
int model_cache_read(uint64_t key, uint64_t within, void *destination,
                     uint64_t count);

/* Whether this chunk has been asked for often enough to be worth the RAM, and
   whether there is RAM for it -- evicting something read less often if not.
   Returns a buffer of `length` bytes to fill with the chunk's verified
   contents, or null to leave it uncached. On null the caller reads as before. */
void *model_cache_reserve(uint64_t key, uint64_t length);

/* The buffer from model_cache_reserve now holds the verified chunk. */
void model_cache_commit(uint64_t key);

/* The buffer from model_cache_reserve could not be filled; drop it. */
void model_cache_abandon(uint64_t key);

/* A commit rewrote the catalog, so chunks may have moved. Everything held
   under the old generation is discarded. */
void model_cache_invalidate(uint64_t generation);

/* Forget everything, keeping the budget. The benchmark uses this so that a
   measurement labelled cold is actually cold; nothing else should need it. */
void model_cache_drop(void);

/* Print what the cache is holding and how well it is working. */
void model_cache_report(const char *what);

/* For the benchmark: how many reads have been served from RAM and how many
   went to the volume. */
void model_cache_counters(uint64_t *hits, uint64_t *misses);

#endif
