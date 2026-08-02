#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>
#include <xaios/virtio_rng.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#define VRING_DESC_F_WRITE UINT16_C(2)
#define VIRTIO_RNG_BUFFER_SIZE 256U
#define VIRTIO_DMA_ALIGNMENT 4096U

typedef struct virtio_rng_driver {
  virtio_mmio_device_t device;
  virtq_desc_t *desc;
  virtq_avail_t *avail;
  virtq_used_t *used;
  uint8_t *buffer;
  uint16_t avail_idx;
  uint16_t used_idx;
  uint32_t initialized;
  xaios_spinlock_t lock;
} virtio_rng_driver_t;

static virtio_rng_driver_t *g_rng;

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static uint64_t dma_address(const void *ptr) {
  uint64_t physical = 0;
  uint32_t flags = 0;
  kassert(vmm_translate((uint64_t)(uintptr_t)ptr, &physical, &flags) ==
          XAIOS_OK);
  kassert((flags & XAIOS_VMM_PRESENT) != 0);
  return physical;
}

static xaios_status_t allocate_driver(void) {
  if (g_rng != 0) {
    return XAIOS_OK;
  }
  g_rng = (virtio_rng_driver_t *)kheap_calloc(sizeof(*g_rng), 16U);
  if (g_rng == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  g_rng->desc = (virtq_desc_t *)kheap_calloc(
      sizeof(virtq_desc_t) * VIRTQ_SIZE, VIRTIO_DMA_ALIGNMENT);
  g_rng->avail = (virtq_avail_t *)kheap_calloc(
      sizeof(virtq_avail_t), VIRTIO_DMA_ALIGNMENT);
  g_rng->used = (virtq_used_t *)kheap_calloc(
      sizeof(virtq_used_t), VIRTIO_DMA_ALIGNMENT);
  g_rng->buffer = (uint8_t *)kheap_calloc(
      VIRTIO_RNG_BUFFER_SIZE, VIRTIO_DMA_ALIGNMENT);
  if (g_rng->desc == 0 || g_rng->avail == 0 || g_rng->used == 0 ||
      g_rng->buffer == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  xaios_spin_init(&g_rng->lock);
  return XAIOS_OK;
}

xaios_status_t virtio_rng_init(void) {
  xaios_status_t status = allocate_driver();
  if (status != XAIOS_OK) {
    return status;
  }
  if (g_rng->initialized != 0U) {
    return XAIOS_OK;
  }
  status = virtio_transport_find(VIRTIO_DEVICE_RNG, "virtio-rng",
                                 &g_rng->device);
  if (status != XAIOS_OK) {
    return status;
  }
  status = virtio_transport_negotiate_no_features(&g_rng->device);
  if (status != XAIOS_OK) {
    return status;
  }
  bytes_zero(g_rng->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_rng->avail, sizeof(*g_rng->avail));
  bytes_zero(g_rng->used, sizeof(*g_rng->used));
  status = virtio_transport_setup_queue(&g_rng->device, 0, 1U, g_rng->desc,
                                        g_rng->avail, g_rng->used);
  if (status != XAIOS_OK) {
    return status;
  }
  g_rng->desc[0].addr = dma_address(g_rng->buffer);
  g_rng->desc[0].len = VIRTIO_RNG_BUFFER_SIZE;
  g_rng->desc[0].flags = VRING_DESC_F_WRITE;
  virtio_transport_set_driver_ok(&g_rng->device);
  g_rng->initialized = 1U;
  klog("virtio-rng: secure entropy source initialized\n");
  return XAIOS_OK;
}

xaios_status_t virtio_rng_read(void *buffer, uint64_t size) {
  if (buffer == 0 || size == 0U || size > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  if (g_rng == 0 || g_rng->initialized == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }

  uint8_t *out = (uint8_t *)buffer;
  xaios_spin_lock(&g_rng->lock);
  while (size != 0U) {
    uint32_t chunk = size > VIRTIO_RNG_BUFFER_SIZE
                         ? VIRTIO_RNG_BUFFER_SIZE
                         : (uint32_t)size;
    bytes_zero(g_rng->buffer, chunk);
    g_rng->desc[0].len = chunk;
    g_rng->avail->ring[g_rng->avail_idx % 1U] = 0;
    ++g_rng->avail_idx;
    virtio_mmio_barrier();
    g_rng->avail->idx = g_rng->avail_idx;
    virtio_transport_notify(&g_rng->device, 0);
    uint16_t expected = (uint16_t)(g_rng->used_idx + 1U);
    xaios_status_t status =
        virtio_transport_wait_used(&g_rng->used->idx, expected);
    if (status != XAIOS_OK) {
      bytes_zero(out, size);
      xaios_spin_unlock(&g_rng->lock);
      return status;
    }
    virtio_mmio_barrier();
    virtq_used_elem_t elem = g_rng->used->ring[g_rng->used_idx % 1U];
    g_rng->used_idx = expected;
    virtio_transport_ack_interrupts(&g_rng->device);
    if (elem.id != 0U || elem.len != chunk) {
      bytes_zero(out, size);
      xaios_spin_unlock(&g_rng->lock);
      return XAIOS_ERR_IO;
    }
    bytes_copy(out, g_rng->buffer, chunk);
    out += chunk;
    size -= chunk;
  }
  xaios_spin_unlock(&g_rng->lock);
  return XAIOS_OK;
}

void virtio_rng_self_test(void) {
  uint8_t first[32];
  uint8_t second[32];
  xaios_status_t status = virtio_rng_init();
  if (status != XAIOS_OK) {
    klog("virtio-rng: secure entropy unavailable status=%d\n", (int)status);
    return;
  }
  kassert(virtio_rng_read(first, sizeof(first)) == XAIOS_OK);
  kassert(virtio_rng_read(second, sizeof(second)) == XAIOS_OK);
  uint8_t difference = 0;
  uint8_t first_nonzero = 0;
  for (uint32_t i = 0; i < sizeof(first); ++i) {
    difference |= first[i] ^ second[i];
    first_nonzero |= first[i];
  }
  kassert(difference != 0U);
  kassert(first_nonzero != 0U);
  bytes_zero(first, sizeof(first));
  bytes_zero(second, sizeof(second));
  klog("virtio-rng: entropy delivery self-test passed\n");
}
