#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>
#include <xaios/virtio_console.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

/* Port zero of a virtio console uses queue 0 to receive and queue 1 to
   transmit. Only transmission is needed to carry the kernel log, but the
   receive queue is still configured, because a device is entitled to expect
   every queue it advertises to be set up before DRIVER_OK. */
#define VIRTIO_CONSOLE_RECEIVE_QUEUE 0U
#define VIRTIO_CONSOLE_TRANSMIT_QUEUE 1U
#define VIRTIO_CONSOLE_BUFFER_SIZE 256U
#define VIRTIO_DMA_ALIGNMENT 4096U
#define VRING_DESC_F_WRITE UINT16_C(2)

typedef struct virtio_console_queue {
  virtq_desc_t *desc;
  virtq_avail_t *avail;
  virtq_used_t *used;
  uint8_t *buffer;
  uint16_t avail_idx;
  uint16_t used_idx;
} virtio_console_queue_t;

typedef struct virtio_console_driver {
  virtio_mmio_device_t device;
  virtio_console_queue_t receive;
  virtio_console_queue_t transmit;
  uint32_t initialized;
  /* Set while a write is in flight. The log lock is already held by the
     caller, but a fault inside the device wait would otherwise re-enter
     this path through the panic printer and hang instead of reporting. */
  uint32_t writing;
  xaios_spinlock_t lock;
} virtio_console_driver_t;

static virtio_console_driver_t *g_console;

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static uint64_t dma_address(const void *pointer) {
  uint64_t physical = 0;
  uint32_t flags = 0;
  kassert(vmm_translate((uint64_t)(uintptr_t)pointer, &physical, &flags) ==
          XAIOS_OK);
  kassert((flags & XAIOS_VMM_PRESENT) != 0);
  return physical;
}

static xaios_status_t allocate_queue(virtio_console_queue_t *queue) {
  queue->desc = (virtq_desc_t *)kheap_calloc(
      sizeof(virtq_desc_t) * VIRTQ_SIZE, VIRTIO_DMA_ALIGNMENT);
  queue->avail =
      (virtq_avail_t *)kheap_calloc(sizeof(virtq_avail_t), VIRTIO_DMA_ALIGNMENT);
  queue->used =
      (virtq_used_t *)kheap_calloc(sizeof(virtq_used_t), VIRTIO_DMA_ALIGNMENT);
  queue->buffer = (uint8_t *)kheap_calloc(VIRTIO_CONSOLE_BUFFER_SIZE,
                                          VIRTIO_DMA_ALIGNMENT);
  if (queue->desc == 0 || queue->avail == 0 || queue->used == 0 ||
      queue->buffer == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

static xaios_status_t allocate_driver(void) {
  if (g_console != 0) {
    return XAIOS_OK;
  }
  g_console =
      (virtio_console_driver_t *)kheap_calloc(sizeof(*g_console), 16U);
  if (g_console == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  xaios_status_t status = allocate_queue(&g_console->receive);
  if (status != XAIOS_OK) {
    return status;
  }
  status = allocate_queue(&g_console->transmit);
  if (status != XAIOS_OK) {
    return status;
  }
  xaios_spin_init(&g_console->lock);
  return XAIOS_OK;
}

static void reset_queue(virtio_console_queue_t *queue) {
  bytes_zero(queue->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(queue->avail, sizeof(*queue->avail));
  bytes_zero(queue->used, sizeof(*queue->used));
  queue->avail_idx = 0;
  queue->used_idx = 0;
}

xaios_status_t virtio_console_init(void) {
  xaios_status_t status = allocate_driver();
  if (status != XAIOS_OK) {
    return status;
  }
  if (g_console->initialized != 0U) {
    return XAIOS_OK;
  }
  status = virtio_transport_find(VIRTIO_DEVICE_CONSOLE, "virtio-console",
                                 &g_console->device);
  if (status != XAIOS_OK) {
    return status;
  }
  status = virtio_transport_negotiate_no_features(&g_console->device);
  if (status != XAIOS_OK) {
    return status;
  }

  reset_queue(&g_console->receive);
  reset_queue(&g_console->transmit);
  status = virtio_transport_setup_queue(
      &g_console->device, VIRTIO_CONSOLE_RECEIVE_QUEUE, 1U,
      g_console->receive.desc, g_console->receive.avail,
      g_console->receive.used);
  if (status != XAIOS_OK) {
    return status;
  }
  status = virtio_transport_setup_queue(
      &g_console->device, VIRTIO_CONSOLE_TRANSMIT_QUEUE, 1U,
      g_console->transmit.desc, g_console->transmit.avail,
      g_console->transmit.used);
  if (status != XAIOS_OK) {
    return status;
  }

  /* Offer the single receive descriptor so the device has somewhere to put
     input. Nothing reads it yet; this keeps the device from stalling. */
  g_console->receive.desc[0].addr = dma_address(g_console->receive.buffer);
  g_console->receive.desc[0].len = VIRTIO_CONSOLE_BUFFER_SIZE;
  g_console->receive.desc[0].flags = VRING_DESC_F_WRITE;

  g_console->transmit.desc[0].addr = dma_address(g_console->transmit.buffer);
  g_console->transmit.desc[0].len = 0;
  g_console->transmit.desc[0].flags = 0;

  status = virtio_transport_set_driver_ok_checked(&g_console->device);
  if (status != XAIOS_OK) {
    return status;
  }
  g_console->initialized = 1U;
  return XAIOS_OK;
}

uint32_t virtio_console_ready(void) {
  return g_console != 0 && g_console->initialized != 0U ? 1U : 0U;
}

static void transmit_chunk(const char *data, uint32_t length) {
  virtio_console_queue_t *queue = &g_console->transmit;
  for (uint32_t i = 0; i < length; ++i) {
    queue->buffer[i] = (uint8_t)data[i];
  }
  queue->desc[0].addr = dma_address(queue->buffer);
  queue->desc[0].len = length;
  queue->desc[0].flags = 0;
  queue->avail->ring[queue->avail_idx % 1U] = 0;
  ++queue->avail_idx;
  virtio_mmio_barrier();
  queue->avail->idx = queue->avail_idx;
  virtio_transport_notify(&g_console->device, VIRTIO_CONSOLE_TRANSMIT_QUEUE);

  uint16_t expected = (uint16_t)(queue->used_idx + 1U);
  if (virtio_transport_wait_used(&queue->used->idx, expected) != XAIOS_OK) {
    /* A console that stops draining must not take the kernel down with it,
       and must not be retried forever either. Give up on it. */
    g_console->initialized = 0U;
    return;
  }
  virtio_mmio_barrier();
  queue->used_idx = expected;
  virtio_transport_ack_interrupts(&g_console->device);
}

void virtio_console_write(const char *data, uint64_t length) {
  if (data == 0 || length == 0U || virtio_console_ready() == 0U) {
    return;
  }
  if (g_console->writing != 0U) {
    return;
  }
  xaios_spin_lock(&g_console->lock);
  g_console->writing = 1U;
  uint64_t offset = 0;
  while (offset < length && g_console->initialized != 0U) {
    uint64_t remaining = length - offset;
    uint32_t chunk = remaining > VIRTIO_CONSOLE_BUFFER_SIZE
                         ? VIRTIO_CONSOLE_BUFFER_SIZE
                         : (uint32_t)remaining;
    transmit_chunk(data + offset, chunk);
    offset += chunk;
  }
  g_console->writing = 0U;
  xaios_spin_unlock(&g_console->lock);
}
