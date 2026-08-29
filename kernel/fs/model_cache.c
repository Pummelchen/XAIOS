/* Keep the chunks that are read most often in RAM, and stop hashing them.
 *
 * A model read is not bounded by the disk. Measured, the verified read path
 * runs at 200 MB/s against a device that does 1.99 GB/s underneath it, and the
 * difference is entirely SHA-256: every byte handed out of /models is checked
 * against the digest its signed manifest fixed. That check is what makes a bit
 * that rotted on the disk a failed read rather than a wrong tensor, and it is
 * not negotiable.
 *
 * What is negotiable is doing it twice for the same bytes. A chunk that has
 * been read and verified is, until something writes to the volume, known to be
 * right. Holding it costs RAM and saves the hash, and the hash is the
 * expensive part -- so a hit here is a memcpy where a miss is a read plus a
 * megabyte of SHA-256.
 *
 * The unit is a chunk and not a page because a chunk is what the checksum
 * covers. Nothing smaller can be verified on its own, so nothing smaller can
 * be admitted. That has a second effect worth having: a small read inside a
 * large chunk used to hash the whole chunk to deliver a fraction of it -- 256
 * KiB out of 2 MiB cost eight times over -- and now pays that once and serves
 * the rest of the chunk from memory.
 *
 * Most often, not most recently. The policy is a use count per chunk, halved
 * periodically so that what was hot an hour ago cannot hold a slot against
 * what is hot now, and admission on the second read so that a single pass over
 * a package -- an ingest, a scrub, a copy -- does not evict a working set to
 * hold bytes nothing will ask for again.
 */
#include <xaios/model_cache.h>

#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>

/* How many chunks the cache can know about, resident or merely seen. Tracking
   a chunk costs one slot and no memory, and it is the tracking that decides
   what deserves memory, so there are far more slots than a budget could ever
   make resident: 256 MB of 2 MiB chunks is 128 of them. */
#define MODEL_CACHE_SLOTS 1024U

/* A chunk earns its place on the second read. The first read of a chunk is
   indistinguishable from a sequential pass over a package that will never
   come back, and filling RAM with those is how a cache makes a machine
   slower. */
#define MODEL_CACHE_ADMIT_READS 2U

/* Every this many reads, halve every count. Without it the counts are a
   record of all history rather than of recent history. */
#define MODEL_CACHE_AGE_INTERVAL 4096U

/* Halving every count preserves their order, so on its own it never lets a
   newcomer past an incumbent: measured against a working set three times the
   budget, the cache admitted sixteen chunks and then refused sixteen hundred
   times without evicting once. Frozen is not always wrong -- for a cyclic
   scan larger than the cache, holding a fixed subset beats churning, and it
   did beat it -- but a cache that can never turn over cannot follow a working
   set that moves. So under sustained refusal the resident counts alone decay,
   which lets what is being asked for now catch what was being asked for
   before. */
#define MODEL_CACHE_REFUSALS_BEFORE_DECAY 64U

/* Never take more than this fraction of what the machine has free. A cache
   that succeeds at the cost of the allocator that everything else uses has
   not succeeded. */
#define MODEL_CACHE_FREE_MEMORY_DIVISOR 4U

typedef struct model_cache_entry {
  uint64_t key;      /* the chunk's physical offset; unique within a volume */
  uint64_t length;   /* the chunk's size in bytes */
  uint8_t *bytes;    /* the chunk, or null when this slot only tracks it */
  uint64_t reads;    /* how often it has been wanted, aged */
  uint8_t used;      /* whether this slot means anything */
  uint8_t filling;   /* reserved and awaiting its contents */
} model_cache_entry_t;

static model_cache_entry_t g_entries[MODEL_CACHE_SLOTS];
static uint64_t g_budget_bytes;
static uint64_t g_resident_bytes;
static uint64_t g_resident_peak;
static uint64_t g_generation;
static uint64_t g_hits;
static uint64_t g_misses;
static uint64_t g_admissions;
static uint64_t g_evictions;
static uint64_t g_refusals;
static uint64_t g_since_aging;
static uint64_t g_refusals_since_decay;
/* A lower bound on the smallest read count among resident chunks, learned on
   the last scan. Hits only ever raise counts, so a candidate at or below this
   certainly cannot displace anything and can be refused without looking --
   which is what stops a full-cache miss storm from scanning every slot every
   time. */
static uint64_t g_coldest_hint;

/* The kernel's memcpy, which copies eight bytes at a time where the addresses
   allow it. A cache hit is a copy and nothing else, so this is the whole of
   the hit path's cost. */
void *memcpy(void *destination, const void *source, unsigned long count);

/* Slots are found by open addressing on the key. The table is never allowed to
   fill: when it is, the least-read entry is dropped to make room, which is the
   same decision eviction makes and for the same reason. */
static uint32_t slot_of(uint64_t key) {
  uint64_t mixed = key;
  mixed ^= mixed >> 33U;
  mixed *= UINT64_C(0xff51afd7ed558ccd);
  mixed ^= mixed >> 33U;
  return (uint32_t)(mixed % MODEL_CACHE_SLOTS);
}

static model_cache_entry_t *find(uint64_t key) {
  uint32_t at = slot_of(key);
  for (uint32_t probe = 0U; probe < MODEL_CACHE_SLOTS; ++probe) {
    model_cache_entry_t *entry = &g_entries[(at + probe) % MODEL_CACHE_SLOTS];
    if (entry->used == 0U) return 0;
    if (entry->key == key) return entry;
  }
  return 0;
}

static void release(model_cache_entry_t *entry) {
  if (entry->bytes != 0) {
    kheap_free(entry->bytes);
    entry->bytes = 0;
    if (g_resident_bytes >= entry->length) {
      g_resident_bytes -= entry->length;
    } else {
      g_resident_bytes = 0U;
    }
  }
  entry->filling = 0U;
}

/* Drop the resident chunk that has been read least, provided it has been read
   less than `colder_than`. That condition is what stops a sweep through cold
   data from evicting the working set in order to hold itself. Returns 1 if
   something was dropped. */
static int evict_coldest(uint64_t colder_than) {
  model_cache_entry_t *coldest = 0;
  for (uint32_t index = 0U; index < MODEL_CACHE_SLOTS; ++index) {
    model_cache_entry_t *entry = &g_entries[index];
    if (entry->used == 0U || entry->bytes == 0 || entry->filling != 0U) {
      continue;
    }
    if (coldest == 0 || entry->reads < coldest->reads) coldest = entry;
  }
  if (coldest == 0) {
    g_coldest_hint = 0U;
    return 0;
  }
  g_coldest_hint = coldest->reads;
  if (coldest->reads >= colder_than) return 0;
  release(coldest);
  ++g_evictions;
  /* The next-coldest is unknown until something looks again. */
  g_coldest_hint = 0U;
  return 1;
}

/* Halve what the resident chunks have earned, leaving what has only been
   wanted untouched. Called when admissions have been refused for long enough
   that the cache is plainly not following the workload any more. */
static void decay_resident(void) {
  for (uint32_t index = 0U; index < MODEL_CACHE_SLOTS; ++index) {
    model_cache_entry_t *entry = &g_entries[index];
    if (entry->bytes != 0) entry->reads >>= 1U;
  }
  g_coldest_hint = 0U;
}

static model_cache_entry_t *insert(uint64_t key) {
  uint32_t at = slot_of(key);
  for (uint32_t probe = 0U; probe < MODEL_CACHE_SLOTS; ++probe) {
    model_cache_entry_t *entry = &g_entries[(at + probe) % MODEL_CACHE_SLOTS];
    if (entry->used == 0U) {
      entry->key = key;
      entry->length = 0U;
      entry->bytes = 0;
      entry->reads = 0U;
      entry->used = 1U;
      entry->filling = 0U;
      return entry;
    }
    if (entry->key == key) return entry;
  }
  /* The table is full of chunks that have been seen. Forget the one seen
     least; a slot that tracks a chunk nobody returns to is worth nothing. */
  model_cache_entry_t *coldest = 0;
  for (uint32_t index = 0U; index < MODEL_CACHE_SLOTS; ++index) {
    model_cache_entry_t *entry = &g_entries[index];
    if (entry->filling != 0U) continue;
    if (coldest == 0 || entry->reads < coldest->reads) coldest = entry;
  }
  if (coldest == 0) return 0;
  release(coldest);
  coldest->key = key;
  coldest->length = 0U;
  coldest->reads = 0U;
  coldest->used = 1U;
  return coldest;
}

static void age_counts(void) {
  if (++g_since_aging < MODEL_CACHE_AGE_INTERVAL) return;
  g_since_aging = 0U;
  for (uint32_t index = 0U; index < MODEL_CACHE_SLOTS; ++index) {
    g_entries[index].reads >>= 1U;
  }
}

void model_cache_init(uint64_t budget_bytes) {
  for (uint32_t index = 0U; index < MODEL_CACHE_SLOTS; ++index) {
    release(&g_entries[index]);
    g_entries[index].used = 0U;
  }
  g_resident_bytes = 0U;
  g_resident_peak = 0U;
  g_hits = 0U;
  g_misses = 0U;
  g_admissions = 0U;
  g_evictions = 0U;
  g_refusals = 0U;
  g_since_aging = 0U;
  g_refusals_since_decay = 0U;
  g_coldest_hint = 0U;
  g_refusals_since_decay = 0U;
  g_coldest_hint = 0U;

  /* Whatever was asked for, bounded by what the machine can spare. On a small
     guest the configured figure is an intention, not a promise. */
  uint64_t spare = (pmm_free_pages() * UINT64_C(4096)) /
                   MODEL_CACHE_FREE_MEMORY_DIVISOR;
  g_budget_bytes = budget_bytes < spare ? budget_bytes : spare;
  klog("model-cache: budget=%luMB requested=%luMB free_memory=%luMB slots=%u\n",
       g_budget_bytes / UINT64_C(1048576),
       budget_bytes / UINT64_C(1048576),
       (pmm_free_pages() * UINT64_C(4096)) / UINT64_C(1048576),
       MODEL_CACHE_SLOTS);
}

int model_cache_read(uint64_t key, uint64_t within, void *destination,
                     uint64_t count) {
  if (destination == 0 || count == 0U) return 0;
  model_cache_entry_t *entry = find(key);
  if (entry != 0 && entry->bytes != 0 && entry->filling == 0U &&
      within + count <= entry->length) {
    ++entry->reads;
    ++g_hits;
    age_counts();
    (void)memcpy(destination, entry->bytes + within, (unsigned long)count);
    return 1;
  }
  /* A miss still counts as interest. The count is what decides admission, and
     a chunk that is never resident would otherwise never accumulate one. */
  if (entry == 0) entry = insert(key);
  if (entry != 0) ++entry->reads;
  ++g_misses;
  age_counts();
  return 0;
}

void *model_cache_reserve(uint64_t key, uint64_t length) {
  if (length == 0U || g_budget_bytes == 0U || length > g_budget_bytes) {
    return 0;
  }
  model_cache_entry_t *entry = find(key);
  if (entry == 0) entry = insert(key);
  if (entry == 0) return 0;
  if (entry->bytes != 0 || entry->filling != 0U) return 0;
  if (entry->reads < MODEL_CACHE_ADMIT_READS) return 0;

  if (g_resident_bytes + length > g_budget_bytes &&
      entry->reads <= g_coldest_hint) {
    /* Certainly cannot displace anything: every resident chunk has been read
       at least as often as this one. Refuse without scanning a thousand
       slots, which is what a full cache under a miss storm was doing on every
       single miss. */
    ++g_refusals;
    if (++g_refusals_since_decay >= MODEL_CACHE_REFUSALS_BEFORE_DECAY) {
      g_refusals_since_decay = 0U;
      decay_resident();
    }
    return 0;
  }

  while (g_resident_bytes + length > g_budget_bytes) {
    if (evict_coldest(entry->reads) == 0) {
      /* Nothing here is colder than the chunk asking for room, so the cache
         is already holding a better answer than this would be -- for now. */
      ++g_refusals;
      if (++g_refusals_since_decay >= MODEL_CACHE_REFUSALS_BEFORE_DECAY) {
        g_refusals_since_decay = 0U;
        decay_resident();
      }
      return 0;
    }
  }
  g_refusals_since_decay = 0U;

  /* Uniform sizes on purpose: every chunk in a package is the same length, so
     a freed block is an exact fit for the next one and the heap's free list
     never fragments under this. */
  uint8_t *bytes = (uint8_t *)kheap_alloc(length, 64U);
  if (bytes == 0) {
    ++g_refusals;
    return 0;
  }
  entry->length = length;
  entry->bytes = bytes;
  entry->filling = 1U;
  g_resident_bytes += length;
  if (g_resident_bytes > g_resident_peak) g_resident_peak = g_resident_bytes;
  return bytes;
}

void model_cache_commit(uint64_t key) {
  model_cache_entry_t *entry = find(key);
  if (entry == 0 || entry->filling == 0U) return;
  entry->filling = 0U;
  ++g_admissions;
}

void model_cache_abandon(uint64_t key) {
  model_cache_entry_t *entry = find(key);
  if (entry == 0 || entry->filling == 0U) return;
  release(entry);
}

void model_cache_invalidate(uint64_t generation) {
  if (generation == g_generation) return;
  /* A commit wrote a new catalog, so a chunk's physical offset no longer
     means what it meant. Nothing here can be trusted to be what its key says
     it is, and guessing which entries survived would be a way to serve one
     package's bytes for another's. */
  uint64_t dropped = 0U;
  for (uint32_t index = 0U; index < MODEL_CACHE_SLOTS; ++index) {
    if (g_entries[index].bytes != 0) ++dropped;
    release(&g_entries[index]);
    g_entries[index].used = 0U;
  }
  g_resident_bytes = 0U;
  g_generation = generation;
  if (dropped != 0U) {
    klog("model-cache: invalidated chunks=%lu generation=%lu\n", dropped,
         generation);
  }
}

void model_cache_drop(void) {
  for (uint32_t index = 0U; index < MODEL_CACHE_SLOTS; ++index) {
    release(&g_entries[index]);
    g_entries[index].used = 0U;
  }
  g_resident_bytes = 0U;
  g_hits = 0U;
  g_misses = 0U;
  g_admissions = 0U;
  g_evictions = 0U;
  g_refusals = 0U;
  g_since_aging = 0U;
  g_refusals_since_decay = 0U;
  g_coldest_hint = 0U;
  g_refusals_since_decay = 0U;
  g_coldest_hint = 0U;
}

void model_cache_counters(uint64_t *hits, uint64_t *misses) {
  if (hits != 0) *hits = g_hits;
  if (misses != 0) *misses = g_misses;
}

void model_cache_report(const char *what) {
  uint64_t total = g_hits + g_misses;
  /* Percent, computed without floating point and without losing the tenths
     that distinguish a cache that is working from one that is not. */
  uint64_t tenths = total == 0U ? 0U : (g_hits * UINT64_C(1000)) / total;
  klog("model-cache: %s hits=%lu misses=%lu rate=%lu.%lu%% resident=%luMB "
       "peak=%luMB budget=%luMB admitted=%lu evicted=%lu refused=%lu\n",
       what, g_hits, g_misses, tenths / 10U, tenths % 10U,
       g_resident_bytes / UINT64_C(1048576),
       g_resident_peak / UINT64_C(1048576),
       g_budget_bytes / UINT64_C(1048576), g_admissions, g_evictions,
       g_refusals);
}
