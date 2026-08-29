/* How much RAM the system itself is allowed to be, and how much it is.
 *
 * XAIOS already runs from memory. Every file in /bin -- forty-nine
 * executables, the C library, every utility -- is read off the boot medium
 * once at start-up, checked against the hash the image recorded for it, and
 * served from RAM for the rest of the machine's life. Nothing reads an
 * executable off a disk after boot, and nothing ever did.
 *
 * What was missing was the number. That residency was an unbounded
 * kheap_alloc per file: correct, invisible, and with exactly one failure mode
 * -- a boot that stops with "allocation failed" and no way to tell whether
 * /bin had grown by a kilobyte past the edge or by a hundred megabytes.
 *
 * So: a budget, in steps. Sixty-four mebibytes is roughly eight times what
 * /bin currently weighs, which is enough headroom that reaching it means
 * something has changed rather than that the figure was too tight. Growth to
 * 128 and then 256 happens on demand and says so, so a system that needs more
 * gets it and leaves a record of having needed it. Past the last step it
 * refuses, and the refusal names the file and the totals -- which is the
 * diagnosis that used to be absent.
 */
#include <xaios/ram_residency.h>

#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>

#define MEGABYTE UINT64_C(1048576)

/* The steps, in order. The first is where every boot starts; the last is the
   ceiling. Overridable at build time for a system that is known to carry more
   than a general-purpose image does. */
#ifndef XAIOS_RESIDENT_BUDGET_MB
#define XAIOS_RESIDENT_BUDGET_MB 64U
#endif
#ifndef XAIOS_RESIDENT_CEILING_MB
#define XAIOS_RESIDENT_CEILING_MB 256U
#endif

static const uint64_t k_steps_mb[] = {XAIOS_RESIDENT_BUDGET_MB, 128U,
                                      XAIOS_RESIDENT_CEILING_MB};
#define STEP_COUNT (sizeof(k_steps_mb) / sizeof(k_steps_mb[0]))

static uint64_t g_budget_bytes;
static uint32_t g_step;
static uint64_t g_resident_bytes;
static uint64_t g_reservations;

void ram_residency_init(void) {
  g_step = 0U;
  g_budget_bytes = k_steps_mb[0] * MEGABYTE;
  g_resident_bytes = 0U;
  g_reservations = 0U;
  klog("residency: budget=%luMB ceiling=%luMB steps=%u\n",
       k_steps_mb[0], k_steps_mb[STEP_COUNT - 1U], (uint32_t)STEP_COUNT);
}

/* Raise the budget one step, if there is one and the machine has the memory
   for it. A budget larger than free memory is a promise the allocator cannot
   keep, and finding that out at the allocation is worse than here. */
static int grow(uint64_t needed, const char *what) {
  while (g_step + 1U < STEP_COUNT) {
    uint64_t next = k_steps_mb[g_step + 1U] * MEGABYTE;
    uint64_t free_bytes = pmm_free_pages() * UINT64_C(4096);
    if (next - g_resident_bytes > free_bytes) {
      klog("residency: cannot grow to %luMB for %s, only %luMB free\n",
           k_steps_mb[g_step + 1U], what, free_bytes / MEGABYTE);
      return 0;
    }
    ++g_step;
    g_budget_bytes = next;
    klog("residency: grew to %luMB for %s (holding %luMB)\n",
         k_steps_mb[g_step], what, g_resident_bytes / MEGABYTE);
    if (g_resident_bytes + needed <= g_budget_bytes) return 1;
  }
  return g_resident_bytes + needed <= g_budget_bytes;
}

void *ram_residency_alloc(uint64_t bytes, uint64_t align, const char *what) {
  if (bytes == 0U) return 0;
  if (g_budget_bytes == 0U) ram_residency_init();
  if (g_resident_bytes + bytes > g_budget_bytes) {
    if (grow(bytes, what == 0 ? "(unnamed)" : what) == 0) {
      klog("residency: refused %lu bytes for %s; holding %luMB of %luMB "
           "across %lu reservations\n",
           bytes, what == 0 ? "(unnamed)" : what,
           g_resident_bytes / MEGABYTE, g_budget_bytes / MEGABYTE,
           g_reservations);
      return 0;
    }
  }
  void *memory = kheap_alloc(bytes, align);
  if (memory == 0) {
    klog("residency: heap refused %lu bytes for %s within a %luMB budget\n",
         bytes, what == 0 ? "(unnamed)" : what, g_budget_bytes / MEGABYTE);
    return 0;
  }
  g_resident_bytes += bytes;
  ++g_reservations;
  return memory;
}

uint64_t ram_residency_bytes(void) { return g_resident_bytes; }

void ram_residency_report(void) {
  /* Tenths of a percent, without floating point, because "3MB of 64MB" hides
     whether the next image is anywhere near the edge. */
  uint64_t tenths = g_budget_bytes == 0U
                        ? 0U
                        : (g_resident_bytes * UINT64_C(1000)) / g_budget_bytes;
  klog("residency: system resident=%luKB reservations=%lu budget=%luMB "
       "used=%lu.%lu%% step=%u/%u\n",
       g_resident_bytes / UINT64_C(1024), g_reservations,
       g_budget_bytes / MEGABYTE, tenths / 10U, tenths % 10U, g_step + 1U,
       (uint32_t)STEP_COUNT);
}
