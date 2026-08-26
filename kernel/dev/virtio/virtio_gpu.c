/*
 * virtio-GPU: a linear framebuffer on platforms whose firmware does not leave
 * one behind.
 *
 * Apple's Virtualization.framework publishes a Graphics Output Protocol that
 * reports PixelBltOnly with a zero framebuffer base: drawing goes through a
 * boot service that ceases to exist at ExitBootServices, so the kernel inherits
 * no memory it can write pixels into and renders its console to the serial
 * stream instead. The device to draw on is nonetheless right there on the PCI
 * bus -- the harness attaches one -- and this driver claims it.
 *
 * The protocol needs four commands to put something on a screen: create a 2-D
 * resource, give it guest memory to read from, point a scanout at it, and then
 * for every update transfer the dirty region to the host and flush it. There
 * is no shared mapping; the host copies out of the backing when told to, which
 * is why a frame is not visible until the flush.
 *
 * Everything here is synchronous. The console draws a handful of times per
 * second at most, so a queue that waits for each command costs nothing worth
 * the complexity of tracking completions, and the wait re-rings the doorbell
 * like every other virtio wait in this kernel.
 */

#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>
#include <xaios/virtio_gpu.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#define VIRTIO_GPU_CONTROL_QUEUE 0U

/* Defined per driver in this tree rather than shared; kept identical. */
#define VRING_DESC_F_NEXT UINT16_C(1)
#define VRING_DESC_F_WRITE UINT16_C(2)
#define VIRTIO_DMA_ALIGNMENT 4096U

/* Commands, from the virtio specification's GPU section. */
#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO UINT32_C(0x0100)
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D UINT32_C(0x0101)
#define VIRTIO_GPU_CMD_SET_SCANOUT UINT32_C(0x0103)
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH UINT32_C(0x0104)
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D UINT32_C(0x0105)
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING UINT32_C(0x0106)

#define VIRTIO_GPU_RESP_OK_NODATA UINT32_C(0x1100)
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO UINT32_C(0x1101)

/* The scanout expects little-endian BGRX, which matches the framebuffer format
   the rest of the kernel already knows how to draw into. */
#define VIRTIO_GPU_FORMAT_B8G8R8X8 UINT32_C(2)

#define VIRTIO_GPU_MAX_SCANOUTS 16U
#define VIRTIO_GPU_RESOURCE_ID 1U

typedef struct virtio_gpu_ctrl_header {
  uint32_t type;
  uint32_t flags;
  uint64_t fence_id;
  uint32_t ctx_id;
  uint32_t padding;
} virtio_gpu_ctrl_header_t;

typedef struct virtio_gpu_rect {
  uint32_t x;
  uint32_t y;
  uint32_t width;
  uint32_t height;
} virtio_gpu_rect_t;

typedef struct virtio_gpu_display_one {
  virtio_gpu_rect_t rect;
  uint32_t enabled;
  uint32_t flags;
} virtio_gpu_display_one_t;

typedef struct virtio_gpu_resp_display_info {
  virtio_gpu_ctrl_header_t header;
  virtio_gpu_display_one_t displays[VIRTIO_GPU_MAX_SCANOUTS];
} virtio_gpu_resp_display_info_t;

typedef struct virtio_gpu_resource_create_2d {
  virtio_gpu_ctrl_header_t header;
  uint32_t resource_id;
  uint32_t format;
  uint32_t width;
  uint32_t height;
} virtio_gpu_resource_create_2d_t;

typedef struct virtio_gpu_mem_entry {
  uint64_t addr;
  uint32_t length;
  uint32_t padding;
} virtio_gpu_mem_entry_t;

typedef struct virtio_gpu_resource_attach_backing {
  virtio_gpu_ctrl_header_t header;
  uint32_t resource_id;
  uint32_t nr_entries;
} virtio_gpu_resource_attach_backing_t;

typedef struct virtio_gpu_set_scanout {
  virtio_gpu_ctrl_header_t header;
  virtio_gpu_rect_t rect;
  uint32_t scanout_id;
  uint32_t resource_id;
} virtio_gpu_set_scanout_t;

typedef struct virtio_gpu_transfer_to_host_2d {
  virtio_gpu_ctrl_header_t header;
  virtio_gpu_rect_t rect;
  uint64_t offset;
  uint32_t resource_id;
  uint32_t padding;
} virtio_gpu_transfer_to_host_2d_t;

typedef struct virtio_gpu_resource_flush {
  virtio_gpu_ctrl_header_t header;
  virtio_gpu_rect_t rect;
  uint32_t resource_id;
  uint32_t padding;
} virtio_gpu_resource_flush_t;

/* One command in flight at a time, so a single pair of descriptors and one
   request and response buffer serve every command. */
typedef struct virtio_gpu_driver {
  virtio_mmio_device_t device;
  virtq_desc_t *desc;
  virtq_avail_t *avail;
  virtq_used_t *used;
  uint8_t *request;
  uint8_t *response;
  virtio_gpu_mem_entry_t *backing;
  uint32_t *framebuffer;
  uint32_t width;
  uint32_t height;
  uint32_t backing_entries;
  uint16_t avail_idx;
  uint16_t used_idx;
  uint32_t initialized;
  xaios_spinlock_t lock;
} virtio_gpu_driver_t;

static virtio_gpu_driver_t *g_gpu;

#define VIRTIO_GPU_REQUEST_BYTES 512U
#define VIRTIO_GPU_RESPONSE_BYTES sizeof(virtio_gpu_resp_display_info_t)

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) bytes[i] = 0U;
}

static uint64_t dma_address(const void *pointer) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  kassert(vmm_translate((uint64_t)(uintptr_t)pointer, &physical, &flags) ==
          XAIOS_OK);
  kassert((flags & XAIOS_VMM_PRESENT) != 0U);
  return physical;
}

/* Submit one command and wait for the device to finish it. The request is read
   by the device and the response written by it, which is a two-descriptor
   chain: the second carries VRING_DESC_F_WRITE. */
static xaios_status_t submit(uint32_t request_bytes, uint32_t response_bytes) {
  g_gpu->desc[0].addr = dma_address(g_gpu->request);
  g_gpu->desc[0].len = request_bytes;
  g_gpu->desc[0].flags = VRING_DESC_F_NEXT;
  g_gpu->desc[0].next = 1U;
  g_gpu->desc[1].addr = dma_address(g_gpu->response);
  g_gpu->desc[1].len = response_bytes;
  g_gpu->desc[1].flags = VRING_DESC_F_WRITE;
  g_gpu->desc[1].next = 0U;

  bytes_zero(g_gpu->response, response_bytes);
  g_gpu->avail->ring[g_gpu->avail_idx % VIRTQ_SIZE] = 0U;
  ++g_gpu->avail_idx;
  virtio_mmio_barrier();
  g_gpu->avail->idx = g_gpu->avail_idx;
  virtio_transport_notify(&g_gpu->device, VIRTIO_GPU_CONTROL_QUEUE);

  uint16_t expected = (uint16_t)(g_gpu->used_idx + 1U);
  xaios_status_t status = virtio_transport_wait_used_notifying(
      &g_gpu->device, VIRTIO_GPU_CONTROL_QUEUE, &g_gpu->used->idx, expected);
  if (status != XAIOS_OK) return status;
  virtio_mmio_barrier();
  g_gpu->used_idx = expected;

  const virtio_gpu_ctrl_header_t *header =
      (const virtio_gpu_ctrl_header_t *)g_gpu->response;
  if (header->type != VIRTIO_GPU_RESP_OK_NODATA &&
      header->type != VIRTIO_GPU_RESP_OK_DISPLAY_INFO) {
    klog("virtio-gpu: command rejected response=0x%x\n", header->type);
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

static xaios_status_t query_display(uint32_t *width, uint32_t *height) {
  virtio_gpu_ctrl_header_t *request =
      (virtio_gpu_ctrl_header_t *)g_gpu->request;
  bytes_zero(request, sizeof(*request));
  request->type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;
  xaios_status_t status =
      submit(sizeof(*request), (uint32_t)VIRTIO_GPU_RESPONSE_BYTES);
  if (status != XAIOS_OK) return status;

  const virtio_gpu_resp_display_info_t *info =
      (const virtio_gpu_resp_display_info_t *)g_gpu->response;
  for (uint32_t i = 0; i < VIRTIO_GPU_MAX_SCANOUTS; ++i) {
    if (info->displays[i].enabled != 0U &&
        info->displays[i].rect.width != 0U &&
        info->displays[i].rect.height != 0U) {
      *width = info->displays[i].rect.width;
      *height = info->displays[i].rect.height;
      return XAIOS_OK;
    }
  }
  /* A device with no enabled scanout has nothing to draw on, which is a
     configuration rather than a fault. */
  return XAIOS_ERR_UNSUPPORTED;
}

static xaios_status_t create_resource(void) {
  virtio_gpu_resource_create_2d_t *request =
      (virtio_gpu_resource_create_2d_t *)g_gpu->request;
  bytes_zero(request, sizeof(*request));
  request->header.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
  request->resource_id = VIRTIO_GPU_RESOURCE_ID;
  request->format = VIRTIO_GPU_FORMAT_B8G8R8X8;
  request->width = g_gpu->width;
  request->height = g_gpu->height;
  return submit(sizeof(*request), sizeof(virtio_gpu_ctrl_header_t));
}

/* The backing is described page by page: kheap hands out virtual pages that
   need not be physically contiguous, so one entry per page is the only
   description that is true. */
static xaios_status_t attach_backing(void) {
  virtio_gpu_resource_attach_backing_t *request =
      (virtio_gpu_resource_attach_backing_t *)g_gpu->request;
  bytes_zero(request, sizeof(*request));
  request->header.type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING;
  request->resource_id = VIRTIO_GPU_RESOURCE_ID;
  request->nr_entries = g_gpu->backing_entries;

  const uint8_t *pixels = (const uint8_t *)g_gpu->framebuffer;
  for (uint32_t i = 0; i < g_gpu->backing_entries; ++i) {
    g_gpu->backing[i].addr = dma_address(pixels + (uint64_t)i * 4096U);
    g_gpu->backing[i].length = 4096U;
    g_gpu->backing[i].padding = 0U;
  }

  /* Three descriptors: the command, the entry table, and the response. The
     table is a separate allocation because a 1280x800 scanout is a thousand
     pages, which no sensible request buffer would carry inline. */
  g_gpu->desc[0].addr = dma_address(g_gpu->request);
  g_gpu->desc[0].len = (uint32_t)sizeof(*request);
  g_gpu->desc[0].flags = VRING_DESC_F_NEXT;
  g_gpu->desc[0].next = 1U;
  g_gpu->desc[1].addr = dma_address(g_gpu->backing);
  g_gpu->desc[1].len =
      (uint32_t)((uint64_t)g_gpu->backing_entries * sizeof(g_gpu->backing[0]));
  g_gpu->desc[1].flags = VRING_DESC_F_NEXT;
  g_gpu->desc[1].next = 2U;
  g_gpu->desc[2].addr = dma_address(g_gpu->response);
  g_gpu->desc[2].len = (uint32_t)sizeof(virtio_gpu_ctrl_header_t);
  g_gpu->desc[2].flags = VRING_DESC_F_WRITE;
  g_gpu->desc[2].next = 0U;

  bytes_zero(g_gpu->response, sizeof(virtio_gpu_ctrl_header_t));
  g_gpu->avail->ring[g_gpu->avail_idx % VIRTQ_SIZE] = 0U;
  ++g_gpu->avail_idx;
  virtio_mmio_barrier();
  g_gpu->avail->idx = g_gpu->avail_idx;
  virtio_transport_notify(&g_gpu->device, VIRTIO_GPU_CONTROL_QUEUE);
  uint16_t expected = (uint16_t)(g_gpu->used_idx + 1U);
  xaios_status_t status = virtio_transport_wait_used_notifying(
      &g_gpu->device, VIRTIO_GPU_CONTROL_QUEUE, &g_gpu->used->idx, expected);
  if (status != XAIOS_OK) return status;
  virtio_mmio_barrier();
  g_gpu->used_idx = expected;
  const virtio_gpu_ctrl_header_t *header =
      (const virtio_gpu_ctrl_header_t *)g_gpu->response;
  if (header->type != VIRTIO_GPU_RESP_OK_NODATA) {
    klog("virtio-gpu: attach backing rejected response=0x%x\n", header->type);
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

static xaios_status_t set_scanout(void) {
  virtio_gpu_set_scanout_t *request = (virtio_gpu_set_scanout_t *)g_gpu->request;
  bytes_zero(request, sizeof(*request));
  request->header.type = VIRTIO_GPU_CMD_SET_SCANOUT;
  request->rect.width = g_gpu->width;
  request->rect.height = g_gpu->height;
  request->scanout_id = 0U;
  request->resource_id = VIRTIO_GPU_RESOURCE_ID;
  return submit(sizeof(*request), sizeof(virtio_gpu_ctrl_header_t));
}

xaios_status_t virtio_gpu_present(void) {
  if (g_gpu == 0 || g_gpu->initialized == 0U) return XAIOS_ERR_UNSUPPORTED;
  xaios_spin_lock(&g_gpu->lock);

  virtio_gpu_transfer_to_host_2d_t *transfer =
      (virtio_gpu_transfer_to_host_2d_t *)g_gpu->request;
  bytes_zero(transfer, sizeof(*transfer));
  transfer->header.type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D;
  transfer->rect.width = g_gpu->width;
  transfer->rect.height = g_gpu->height;
  transfer->offset = 0U;
  transfer->resource_id = VIRTIO_GPU_RESOURCE_ID;
  xaios_status_t status =
      submit(sizeof(*transfer), sizeof(virtio_gpu_ctrl_header_t));
  if (status != XAIOS_OK) {
    xaios_spin_unlock(&g_gpu->lock);
    return status;
  }

  virtio_gpu_resource_flush_t *flush =
      (virtio_gpu_resource_flush_t *)g_gpu->request;
  bytes_zero(flush, sizeof(*flush));
  flush->header.type = VIRTIO_GPU_CMD_RESOURCE_FLUSH;
  flush->rect.width = g_gpu->width;
  flush->rect.height = g_gpu->height;
  flush->resource_id = VIRTIO_GPU_RESOURCE_ID;
  status = submit(sizeof(*flush), sizeof(virtio_gpu_ctrl_header_t));
  xaios_spin_unlock(&g_gpu->lock);
  return status;
}

uint32_t *virtio_gpu_framebuffer(uint32_t *width, uint32_t *height) {
  if (g_gpu == 0 || g_gpu->initialized == 0U) return 0;
  if (width != 0) *width = g_gpu->width;
  if (height != 0) *height = g_gpu->height;
  return g_gpu->framebuffer;
}

xaios_status_t virtio_gpu_init(void) {
  if (g_gpu != 0 && g_gpu->initialized != 0U) return XAIOS_OK;
  if (g_gpu == 0) {
    g_gpu = (virtio_gpu_driver_t *)kheap_calloc(sizeof(*g_gpu), 16U);
    if (g_gpu == 0) return XAIOS_ERR_NO_MEMORY;
  }
  xaios_spin_init(&g_gpu->lock);

  xaios_status_t status = virtio_transport_find(VIRTIO_DEVICE_GPU, "virtio-gpu",
                                                &g_gpu->device);
  if (status != XAIOS_OK) {
    /* No device is a platform that cannot show anything, not a failure -- but
       say so, because a silent return is indistinguishable from a driver that
       never ran, which cost a boot to work out. */
    klog("virtio-gpu: no display device on this machine\n");
    return XAIOS_ERR_UNSUPPORTED;
  }

  g_gpu->desc = (virtq_desc_t *)kheap_calloc(
      sizeof(virtq_desc_t) * VIRTQ_SIZE, VIRTIO_DMA_ALIGNMENT);
  g_gpu->avail = (virtq_avail_t *)kheap_calloc(sizeof(virtq_avail_t),
                                               VIRTIO_DMA_ALIGNMENT);
  g_gpu->used = (virtq_used_t *)kheap_calloc(sizeof(virtq_used_t),
                                             VIRTIO_DMA_ALIGNMENT);
  g_gpu->request = (uint8_t *)kheap_calloc(VIRTIO_GPU_REQUEST_BYTES,
                                           VIRTIO_DMA_ALIGNMENT);
  g_gpu->response = (uint8_t *)kheap_calloc(VIRTIO_GPU_RESPONSE_BYTES,
                                            VIRTIO_DMA_ALIGNMENT);
  if (g_gpu->desc == 0 || g_gpu->avail == 0 || g_gpu->used == 0 ||
      g_gpu->request == 0 || g_gpu->response == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }

  status = virtio_transport_negotiate_no_features(&g_gpu->device);
  if (status != XAIOS_OK) return status;
  status = virtio_transport_setup_queue(&g_gpu->device, VIRTIO_GPU_CONTROL_QUEUE,
                                        VIRTQ_SIZE, g_gpu->desc, g_gpu->avail,
                                        g_gpu->used);
  if (status != XAIOS_OK) return status;
  virtio_transport_set_driver_ok(&g_gpu->device);

  status = query_display(&g_gpu->width, &g_gpu->height);
  if (status != XAIOS_OK) {
    klog("virtio-gpu: no enabled scanout; leaving the console on serial\n");
    return status;
  }

  uint64_t pixels = (uint64_t)g_gpu->width * (uint64_t)g_gpu->height;
  uint64_t bytes = pixels * 4U;
  uint64_t pages = (bytes + 4095U) / 4096U;
  g_gpu->framebuffer = (uint32_t *)kheap_calloc(bytes, 4096U);
  if (g_gpu->framebuffer == 0) return XAIOS_ERR_NO_MEMORY;
  g_gpu->backing_entries = (uint32_t)pages;
  g_gpu->backing = (virtio_gpu_mem_entry_t *)kheap_calloc(
      pages * sizeof(virtio_gpu_mem_entry_t), VIRTIO_DMA_ALIGNMENT);
  if (g_gpu->backing == 0) return XAIOS_ERR_NO_MEMORY;

  status = create_resource();
  if (status == XAIOS_OK) status = attach_backing();
  if (status == XAIOS_OK) status = set_scanout();
  if (status != XAIOS_OK) {
    klog("virtio-gpu: scanout setup failed status=%d\n", (int)status);
    return status;
  }

  g_gpu->initialized = 1U;
  klog("virtio-gpu: scanout %ux%u backing_pages=%u\n", g_gpu->width,
       g_gpu->height, g_gpu->backing_entries);
  return XAIOS_OK;
}
