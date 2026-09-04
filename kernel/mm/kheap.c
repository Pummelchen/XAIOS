#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pmm.h>
#include <xaios/spinlock.h>
#include <xaios/vmm.h>

#define PAGE_SIZE UINT64_C(4096)
#define KHEAP_BASE UINT64_C(0x200000000)
#define KHEAP_SIZE UINT64_C(0x40000000)
#define KHEAP_LIMIT (KHEAP_BASE + KHEAP_SIZE)

/* Free-list header: 16 bytes per allocation */
typedef struct kheap_header {
  uint64_t size;           /* usable size (excluding header) */
  struct kheap_header *next_free; /* next block in free list (0 if allocated) */
} kheap_header_t;

#define KHEAP_HEADER_SIZE 16U

static uint64_t g_heap_next;
static uint64_t g_heap_mapped_end;
static uint64_t g_heap_pages;
static uint64_t g_heap_bytes_allocated;
static kheap_header_t *g_free_list; /* head of free list */
static xaios_spinlock_t g_kheap_lock;

static uint64_t align_up(uint64_t value, uint64_t align) {
  return (value + align - 1) & ~(align - 1);
}

void kheap_init(void) {
  g_heap_next = KHEAP_BASE;
  g_heap_mapped_end = KHEAP_BASE;
  g_heap_pages = 0;
  g_heap_bytes_allocated = 0;
  g_free_list = 0;
  xaios_spin_init(&g_kheap_lock);
  klog("kheap: initialized base=0x%lx size=%lu\n", KHEAP_BASE, KHEAP_SIZE);
}

static xaios_status_t ensure_mapped(uint64_t end) {
  uint64_t mapped = g_heap_mapped_end;
  while (mapped < end) {
    void *page = pmm_alloc_page();
    if (page == 0) {
      return XAIOS_ERR_NO_MEMORY;
    }
    if (vmm_map_page(mapped, (uint64_t)(uintptr_t)page,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      pmm_free_page(page);
      return XAIOS_ERR_INVALID;
    }
    mapped += PAGE_SIZE;
    ++g_heap_pages;
  }
  g_heap_mapped_end = mapped;
  return XAIOS_OK;
}

void *kheap_alloc(uint64_t size, uint64_t align) {
  if (size == 0 || align == 0 || (align & (align - 1)) != 0) {
    return 0;
  }

  /* Ensure alignment is at least header size */
  if (align < KHEAP_HEADER_SIZE) {
    align = KHEAP_HEADER_SIZE;
  }

  xaios_spin_lock(&g_kheap_lock);

  /* Search free list for a best-fit block */
  kheap_header_t **prev = &g_free_list;
  kheap_header_t *best = 0;
  kheap_header_t **best_prev = 0;
  for (kheap_header_t *cur = g_free_list; cur != 0; cur = cur->next_free) {
    if (cur->size >= size) {
      /* Check that data pointer (cur + header) meets alignment */
      uint64_t data_addr = (uint64_t)(uintptr_t)cur + KHEAP_HEADER_SIZE;
      if ((data_addr & (align - 1)) != 0) continue;
      if (best == 0 || cur->size < best->size) {
        best = cur;
        best_prev = prev;
      }
    }
    prev = &cur->next_free;
  }

  if (best != 0) {
    /* Remove from free list */
    *best_prev = best->next_free;
    best->next_free = 0;
    /* The block keeps the capacity it was created with, which is what free()
       will hand back. Accounting the smaller request here and the larger
       capacity there made the running total drift downward on every reuse of
       a block by a smaller allocation. */
    g_heap_bytes_allocated += best->size;
    xaios_spin_unlock(&g_kheap_lock);
    return (void *)((uint8_t *)best + KHEAP_HEADER_SIZE);
  }

  /* Bump allocate from heap — align the DATA address, not the header */
  uint64_t data_start = align_up(g_heap_next + KHEAP_HEADER_SIZE, align);
  uint64_t header_addr = data_start - KHEAP_HEADER_SIZE;
  uint64_t end = data_start + size;

  if (end < data_start || end > KHEAP_LIMIT) {
    xaios_spin_unlock(&g_kheap_lock);
    return 0;
  }

  if (ensure_mapped(align_up(end, PAGE_SIZE)) != XAIOS_OK) {
    xaios_spin_unlock(&g_kheap_lock);
    return 0;
  }

  /* Write header */
  kheap_header_t *hdr = (kheap_header_t *)(uintptr_t)header_addr;
  hdr->size = size;
  hdr->next_free = 0;

  g_heap_next = end;
  g_heap_bytes_allocated += size;
  xaios_spin_unlock(&g_kheap_lock);
  return (void *)(uintptr_t)data_start;
}

void kheap_free(void *ptr) {
  if (ptr == 0) {
    return;
  }

  /* Recover header from data pointer */
  kheap_header_t *hdr = (kheap_header_t *)((uint8_t *)ptr - KHEAP_HEADER_SIZE);

  xaios_spin_lock(&g_kheap_lock);

  /* Add to free list (prepend) */
  hdr->next_free = g_free_list;
  g_free_list = hdr;

  if (g_heap_bytes_allocated >= hdr->size) {
    g_heap_bytes_allocated -= hdr->size;
  }

  xaios_spin_unlock(&g_kheap_lock);
}

void *kheap_calloc(uint64_t size, uint64_t align) {
  uint8_t *result = (uint8_t *)kheap_alloc(size, align);
  if (result == 0) {
    return 0;
  }
  /* Word at a time where alignment allows, which it does here: kheap_alloc
     honours the requested alignment and every caller of this asks for at
     least eight. Zeroing several megabytes one byte at a time is eight times
     the work for no reason, and the largest allocation on the boot path --
     the child channel table -- is four megabytes. */
  uint64_t offset = 0U;
  if (((uint64_t)(uintptr_t)result % 8U) == 0U) {
    uint64_t *words = (uint64_t *)(void *)result;
    uint64_t whole = size / 8U;
    for (uint64_t i = 0U; i < whole; ++i) words[i] = 0U;
    offset = whole * 8U;
  }
  for (uint64_t i = offset; i < size; ++i) {
    result[i] = 0;
  }
  return result;
}

uint64_t kheap_pages_allocated(void) {
  return g_heap_pages;
}

uint64_t kheap_bytes_allocated(void) {
  return g_heap_bytes_allocated;
}

void kheap_self_test(void) {
  kheap_init();
  void *a = kheap_alloc(24, 8);
  void *b = kheap_alloc(128, 64);
  void *c = kheap_alloc(KHEAP_SIZE + 1U, 8);
  void *d = kheap_alloc(16, 3);
  uint8_t *z = (uint8_t *)kheap_calloc(32, 16);
  void *large = kheap_alloc(70496, 4096);

  kassert(a != 0);
  kassert(b != 0);
  kassert(c == 0);
  kassert(d == 0);
  kassert(z != 0);
  kassert(large != 0);
  for (uint32_t i = 0; i < 32; ++i) {
    kassert(z[i] == 0);
  }
  kassert((((uint64_t)(uintptr_t)a) & 15U) == 0); /* min alignment = header size */
  kassert((((uint64_t)(uintptr_t)b) & 63U) == 0);
  kassert((((uint64_t)(uintptr_t)z) & 15U) == 0);
  kassert((((uint64_t)(uintptr_t)large) & 4095U) == 0);

  /* Test free and reuse */
  kheap_free(a);
  void *a2 = kheap_alloc(24, 8);
  kassert(a2 != 0);

  klog("kheap: self-test passed pages=%lu bytes=%lu\n",
       g_heap_pages, g_heap_bytes_allocated);
}
