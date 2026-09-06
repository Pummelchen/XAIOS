#include <xaios/device_window.h>

#include <xaios/klog.h>
#include <xaios/panic.h>
#include <xaios/vmm.h>

/* The arena. Chosen once, above every window the drivers used to name for
   themselves, and large enough that running out is a real event rather than
   an everyday one. */
#define DEVICE_WINDOW_ARENA_BASE UINT64_C(0x350000000)
#define DEVICE_WINDOW_ARENA_BYTES UINT64_C(0x010000000) /* 256 MiB */
#define DEVICE_WINDOW_PAGE UINT64_C(0x1000)
#define DEVICE_WINDOW_MAX 32U

typedef struct device_window {
  const char *owner;
  uint64_t physical;
  uint64_t virtual_base;
  uint64_t bytes;
} device_window_t;

static device_window_t g_windows[DEVICE_WINDOW_MAX];
static uint32_t g_window_count;
static uint64_t g_next = DEVICE_WINDOW_ARENA_BASE;

uint32_t device_window_count(void) { return g_window_count; }

uint64_t device_window_used_bytes(void) {
  return g_next - DEVICE_WINDOW_ARENA_BASE;
}

xaios_status_t device_window_map(const char *owner, uint64_t physical,
                                 uint64_t bytes, volatile uint8_t **out) {
  if (out == 0 || bytes == 0U) return XAIOS_ERR_INVALID;
  *out = 0;
  /* A window may start part way into a page -- an MSI-X table does -- so the
     page is what gets mapped and the offset is carried through to the
     pointer. Naming the whole page keeps the arithmetic in one place. */
  uint64_t offset = physical & (DEVICE_WINDOW_PAGE - 1U);
  uint64_t page = physical - offset;
  uint64_t span = offset + bytes;
  span = (span + DEVICE_WINDOW_PAGE - 1U) & ~(DEVICE_WINDOW_PAGE - 1U);
  if (g_window_count >= DEVICE_WINDOW_MAX) {
    klog("device-window: no room for %s; %u windows already open\n", owner,
         g_window_count);
    return XAIOS_ERR_NO_MEMORY;
  }
  /* A guard page after each window, so a driver that walks off the end of its
     registers faults instead of reaching another device's. */
  if (g_next + span + DEVICE_WINDOW_PAGE >
      DEVICE_WINDOW_ARENA_BASE + DEVICE_WINDOW_ARENA_BYTES) {
    klog("device-window: arena exhausted asking for %lu bytes for %s\n", bytes,
         owner);
    return XAIOS_ERR_NO_MEMORY;
  }
  uint64_t base = g_next;
  for (uint64_t at = 0U; at < span; at += DEVICE_WINDOW_PAGE) {
    if (vmm_map_page(base + at, page + at,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE) != XAIOS_OK) {
      klog("device-window: could not map %s at 0x%lx\n", owner, page + at);
      return XAIOS_ERR_IO;
    }
  }
  g_next = base + span + DEVICE_WINDOW_PAGE;
  g_windows[g_window_count].owner = owner;
  g_windows[g_window_count].physical = physical;
  g_windows[g_window_count].virtual_base = base + offset;
  g_windows[g_window_count].bytes = bytes;
  ++g_window_count;
  klog("device-window: %s phys=0x%lx bytes=%lu at 0x%lx\n", owner, physical,
       bytes, base + offset);
  *out = (volatile uint8_t *)(uintptr_t)(base + offset);
  return XAIOS_OK;
}

void device_window_self_test(void) {
  /* No two windows overlap, and none of them is the same address as another.
     Checked over whatever the machine actually opened rather than over a
     fixture, because the property that failed was about real drivers on a
     real machine: two of them had been given the same constant by hand. */
  for (uint32_t i = 0U; i < g_window_count; ++i) {
    uint64_t start = g_windows[i].virtual_base;
    uint64_t end = start + g_windows[i].bytes;
    for (uint32_t j = i + 1U; j < g_window_count; ++j) {
      uint64_t other_start = g_windows[j].virtual_base;
      uint64_t other_end = other_start + g_windows[j].bytes;
      if (start < other_end && other_start < end) {
        panic("device-window: %s and %s were given overlapping windows",
              g_windows[i].owner, g_windows[j].owner);
      }
    }
  }
  klog("device-window: self-test passed windows=%u used=%lu bytes, none "
       "overlapping\n",
       g_window_count, device_window_used_bytes());
}
