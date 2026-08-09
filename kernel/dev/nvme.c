#include <xaios/arch_cpu.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/nvme.h>
#include <xaios/pci.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>

#define NVME_CLASS UINT8_C(0x01)
#define NVME_SUBCLASS UINT8_C(0x08)
#define NVME_PROGIF UINT8_C(0x02)

#define NVME_REG_CAP UINT32_C(0x00)
#define NVME_REG_VS UINT32_C(0x08)
#define NVME_REG_CC UINT32_C(0x14)
#define NVME_REG_CSTS UINT32_C(0x1c)
#define NVME_REG_AQA UINT32_C(0x24)
#define NVME_REG_ASQ UINT32_C(0x28)
#define NVME_REG_ACQ UINT32_C(0x30)
#define NVME_REG_DOORBELL UINT32_C(0x1000)

#define NVME_CC_ENABLE UINT32_C(1)
#define NVME_CSTS_READY UINT32_C(1)
#define NVME_CSTS_FATAL UINT32_C(2)
#define NVME_ADMIN_DELETE_IO_SQ UINT8_C(0x00)
#define NVME_ADMIN_CREATE_IO_SQ UINT8_C(0x01)
#define NVME_ADMIN_DELETE_IO_CQ UINT8_C(0x04)
#define NVME_ADMIN_CREATE_IO_CQ UINT8_C(0x05)
#define NVME_ADMIN_IDENTIFY UINT8_C(0x06)
#define NVME_IO_FLUSH UINT8_C(0x00)
#define NVME_IO_WRITE UINT8_C(0x01)
#define NVME_IO_READ UINT8_C(0x02)

#define NVME_QUEUE_DEPTH 16U
#define NVME_PAGE_SIZE UINT64_C(4096)
#define NVME_TIMEOUT_NS UINT64_C(5000000000)
#define NVME_MMIO_VIRTUAL_BASE UINT64_C(0x300000000)

typedef struct nvme_command {
  uint8_t opcode;
  uint8_t flags;
  uint16_t cid;
  uint32_t nsid;
  uint64_t reserved0;
  uint64_t metadata;
  uint64_t prp1;
  uint64_t prp2;
  uint32_t cdw10;
  uint32_t cdw11;
  uint32_t cdw12;
  uint32_t cdw13;
  uint32_t cdw14;
  uint32_t cdw15;
} __attribute__((packed)) nvme_command_t;

typedef struct nvme_completion {
  uint32_t result;
  uint32_t reserved;
  uint16_t sq_head;
  uint16_t sq_id;
  uint16_t cid;
  uint16_t status;
} __attribute__((packed)) nvme_completion_t;

typedef struct nvme_queue {
  nvme_command_t *sq;
  nvme_completion_t *cq;
  uint16_t qid;
  uint16_t sq_tail;
  uint16_t cq_head;
  uint16_t phase;
} nvme_queue_t;

typedef struct nvme_controller {
  volatile uint8_t *bar;
  uint64_t cap;
  uint32_t doorbell_stride;
  uint16_t next_cid;
  nvme_queue_t admin;
  nvme_queue_t io;
  uint8_t *identify;
  uint8_t *data;
} nvme_controller_t;

typedef char nvme_command_size_must_be_64[(sizeof(nvme_command_t) == 64) ? 1 : -1];
typedef char nvme_completion_size_must_be_16[(sizeof(nvme_completion_t) == 16) ? 1 : -1];

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static uint32_t mmio_read32(const nvme_controller_t *controller,
                            uint32_t offset) {
  return *(volatile uint32_t *)(void *)(controller->bar + offset);
}

static uint64_t mmio_read64(const nvme_controller_t *controller,
                            uint32_t offset) {
  uint32_t low = mmio_read32(controller, offset);
  uint32_t high = mmio_read32(controller, offset + 4U);
  return ((uint64_t)high << 32U) | low;
}

static void mmio_write32(const nvme_controller_t *controller, uint32_t offset,
                         uint32_t value) {
  *(volatile uint32_t *)(void *)(controller->bar + offset) = value;
  xaios_cpu_io_barrier();
}

static void mmio_write64(const nvme_controller_t *controller, uint32_t offset,
                         uint64_t value) {
  mmio_write32(controller, offset, (uint32_t)value);
  mmio_write32(controller, offset + 4U, (uint32_t)(value >> 32U));
}

static uint64_t dma_address(const void *buffer) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  if (vmm_translate((uint64_t)(uintptr_t)buffer, &physical, &flags) != XAIOS_OK ||
      (flags & XAIOS_VMM_PRESENT) == 0U) {
    return 0U;
  }
  return physical;
}

static xaios_status_t wait_ready(const nvme_controller_t *controller,
                                 uint32_t expected) {
  uint64_t started = timer_now_ns();
  for (;;) {
    uint32_t status = mmio_read32(controller, NVME_REG_CSTS);
    if ((status & NVME_CSTS_FATAL) != 0U) return XAIOS_ERR_IO;
    if ((status & NVME_CSTS_READY) == expected) return XAIOS_OK;
    if (timer_now_ns() - started >= NVME_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
}

static uint32_t doorbell_offset(const nvme_controller_t *controller,
                                uint16_t qid, uint32_t completion) {
  uint32_t index = (uint32_t)qid * 2U + completion;
  return NVME_REG_DOORBELL + index * controller->doorbell_stride;
}

static xaios_status_t submit(nvme_controller_t *controller,
                             nvme_queue_t *queue,
                             const nvme_command_t *command,
                             uint32_t *result) {
  nvme_command_t staged = *command;
  staged.cid = ++controller->next_cid;
  queue->sq[queue->sq_tail] = staged;
  xaios_cpu_io_barrier();
  queue->sq_tail = (uint16_t)((queue->sq_tail + 1U) % NVME_QUEUE_DEPTH);
  mmio_write32(controller, doorbell_offset(controller, queue->qid, 0U),
               queue->sq_tail);

  uint64_t started = timer_now_ns();
  nvme_completion_t completion;
  for (;;) {
    xaios_cpu_io_barrier();
    completion = queue->cq[queue->cq_head];
    if ((completion.status & 1U) == queue->phase) break;
    if (timer_now_ns() - started >= NVME_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
  if (completion.cid != staged.cid ||
      ((completion.status >> 1U) & UINT16_C(0x7ff)) != 0U) {
    return XAIOS_ERR_IO;
  }
  if (result != 0) *result = completion.result;
  queue->cq_head = (uint16_t)(queue->cq_head + 1U);
  if (queue->cq_head == NVME_QUEUE_DEPTH) {
    queue->cq_head = 0U;
    queue->phase ^= 1U;
  }
  mmio_write32(controller, doorbell_offset(controller, queue->qid, 1U),
               queue->cq_head);
  return XAIOS_OK;
}

static xaios_status_t allocate_queue(nvme_queue_t *queue, uint16_t qid) {
  queue->sq = (nvme_command_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  queue->cq = (nvme_completion_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  if (queue->sq == 0 || queue->cq == 0) return XAIOS_ERR_NO_MEMORY;
  queue->qid = qid;
  queue->sq_tail = 0U;
  queue->cq_head = 0U;
  queue->phase = 1U;
  return XAIOS_OK;
}

static xaios_status_t initialize_controller(nvme_controller_t *controller,
                                            uint32_t pci_index) {
  bytes_zero(controller, sizeof(*controller));
  if (pci_enable_device(pci_index) != XAIOS_OK) return XAIOS_ERR_IO;
  uint64_t bar = pci_bar_address(pci_index, 0U);
  if (bar == 0U || (bar & (NVME_PAGE_SIZE - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t offset = 0U; offset < NVME_PAGE_SIZE * 2U;
       offset += NVME_PAGE_SIZE) {
    if (vmm_map_page(NVME_MMIO_VIRTUAL_BASE + offset, bar + offset,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  controller->bar =
      (volatile uint8_t *)(uintptr_t)NVME_MMIO_VIRTUAL_BASE;
  controller->cap = mmio_read64(controller, NVME_REG_CAP);
  uint32_t mqes = (uint32_t)(controller->cap & UINT64_C(0xffff)) + 1U;
  uint32_t mpsmin = (uint32_t)((controller->cap >> 48U) & UINT64_C(0xf));
  if (mqes < NVME_QUEUE_DEPTH || mpsmin != 0U) return XAIOS_ERR_UNSUPPORTED;
  controller->doorbell_stride =
      4U << ((uint32_t)((controller->cap >> 32U) & UINT64_C(0xf)));

  uint32_t cc = mmio_read32(controller, NVME_REG_CC);
  if ((cc & NVME_CC_ENABLE) != 0U) {
    mmio_write32(controller, NVME_REG_CC, cc & ~NVME_CC_ENABLE);
    if (wait_ready(controller, 0U) != XAIOS_OK) return XAIOS_ERR_IO;
  }
  if (allocate_queue(&controller->admin, 0U) != XAIOS_OK ||
      allocate_queue(&controller->io, 1U) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  controller->identify = (uint8_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  controller->data = (uint8_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  if (controller->identify == 0 || controller->data == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }

  mmio_write32(controller, NVME_REG_AQA,
               ((NVME_QUEUE_DEPTH - 1U) << 16U) |
                   (NVME_QUEUE_DEPTH - 1U));
  mmio_write64(controller, NVME_REG_ASQ, dma_address(controller->admin.sq));
  mmio_write64(controller, NVME_REG_ACQ, dma_address(controller->admin.cq));
  mmio_write32(controller, NVME_REG_CC,
               NVME_CC_ENABLE | (6U << 16U) | (4U << 20U));
  if (wait_ready(controller, NVME_CSTS_READY) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  klog("nvme: controller ready version=0x%x mqes=%u dstrd=%u\n",
       mmio_read32(controller, NVME_REG_VS), mqes,
       controller->doorbell_stride);
  return XAIOS_OK;
}

static xaios_status_t identify(nvme_controller_t *controller, uint32_t nsid,
                               uint32_t cns) {
  bytes_zero(controller->identify, NVME_PAGE_SIZE);
  nvme_command_t command;
  bytes_zero(&command, sizeof(command));
  command.opcode = NVME_ADMIN_IDENTIFY;
  command.nsid = nsid;
  command.prp1 = dma_address(controller->identify);
  command.cdw10 = cns;
  return submit(controller, &controller->admin, &command, 0);
}

static xaios_status_t create_io_queues(nvme_controller_t *controller) {
  nvme_command_t command;
  bytes_zero(&command, sizeof(command));
  command.opcode = NVME_ADMIN_CREATE_IO_CQ;
  command.prp1 = dma_address(controller->io.cq);
  command.cdw10 = ((NVME_QUEUE_DEPTH - 1U) << 16U) | 1U;
  command.cdw11 = 1U;
  if (submit(controller, &controller->admin, &command, 0) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  bytes_zero(&command, sizeof(command));
  command.opcode = NVME_ADMIN_CREATE_IO_SQ;
  command.prp1 = dma_address(controller->io.sq);
  command.cdw10 = ((NVME_QUEUE_DEPTH - 1U) << 16U) | 1U;
  command.cdw11 = (1U << 16U) | 1U;
  return submit(controller, &controller->admin, &command, 0);
}

static xaios_status_t io_command(nvme_controller_t *controller,
                                 uint8_t opcode, uint32_t nsid,
                                 uint64_t lba) {
  nvme_command_t command;
  bytes_zero(&command, sizeof(command));
  command.opcode = opcode;
  command.nsid = nsid;
  if (opcode != NVME_IO_FLUSH) command.prp1 = dma_address(controller->data);
  command.cdw10 = (uint32_t)lba;
  command.cdw11 = (uint32_t)(lba >> 32U);
  command.cdw12 = 0U;
  return submit(controller, &controller->io, &command, 0);
}

static uint64_t read_le64(const uint8_t *bytes) {
  uint64_t value = 0U;
  for (uint32_t i = 0U; i < 8U; ++i) value |= (uint64_t)bytes[i] << (i * 8U);
  return value;
}

xaios_status_t nvme_self_test(xaios_nvme_self_test_result_t *result) {
  if (result != 0) bytes_zero(result, sizeof(*result));
  uint32_t found = UINT32_MAX;
  for (uint32_t i = 0U; i < pci_device_count(); ++i) {
    const xaios_pci_device_t *device = pci_device(i);
    if (device != 0 && device->class_code == NVME_CLASS &&
        device->subclass == NVME_SUBCLASS && device->prog_if == NVME_PROGIF) {
      found = i;
      break;
    }
  }
  if (found == UINT32_MAX) {
    klog("nvme: self-test skipped no PCI NVMe controller\n");
    return XAIOS_ERR_NOT_FOUND;
  }

  nvme_controller_t *controller =
      (nvme_controller_t *)kheap_calloc(sizeof(*controller), 64U);
  if (controller == 0) return XAIOS_ERR_NO_MEMORY;
  xaios_status_t status = initialize_controller(controller, found);
  if (status != XAIOS_OK) return status;
  if (result != 0) {
    result->controllers = 1U;
    result->queue_depth = NVME_QUEUE_DEPTH;
  }

  if (identify(controller, 0U, 1U) != XAIOS_OK) return XAIOS_ERR_IO;
  char serial[21];
  char model[41];
  for (uint32_t i = 0U; i < 20U; ++i) serial[i] = (char)controller->identify[4U + i];
  for (uint32_t i = 0U; i < 40U; ++i) model[i] = (char)controller->identify[24U + i];
  serial[20] = '\0';
  model[40] = '\0';
  klog("nvme: identify controller serial='%s' model='%s'\n", serial, model);

  if (identify(controller, 1U, 0U) != XAIOS_OK) return XAIOS_ERR_IO;
  uint64_t blocks = read_le64(controller->identify);
  uint32_t format = controller->identify[26U] & UINT8_C(0x0f);
  uint32_t lbads = controller->identify[128U + format * 4U + 2U];
  if (blocks == 0U || lbads < 9U || lbads > 12U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint32_t block_size = 1U << lbads;
  if (result != 0) {
    result->namespaces = 1U;
    result->namespace_blocks = blocks;
    result->logical_block_size = block_size;
  }
  if (create_io_queues(controller) != XAIOS_OK) return XAIOS_ERR_IO;

  for (uint32_t i = 0U; i < block_size; ++i) {
    controller->data[i] = (uint8_t)(i ^ UINT32_C(0xa5));
  }
  if (io_command(controller, NVME_IO_WRITE, 1U, 0U) != XAIOS_OK ||
      io_command(controller, NVME_IO_FLUSH, 1U, 0U) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  bytes_zero(controller->data, block_size);
  if (io_command(controller, NVME_IO_READ, 1U, 0U) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  for (uint32_t i = 0U; i < block_size; ++i) {
    if (controller->data[i] != (uint8_t)(i ^ UINT32_C(0xa5))) {
      return XAIOS_ERR_IO;
    }
  }
  if (result != 0) result->io_verified = 1U;
  klog("nvme: admin/io self-test passed namespaces=1 blocks=%lu block_size=%u queue_depth=%u write_read_flush=1\n",
       blocks, block_size, NVME_QUEUE_DEPTH);
  return XAIOS_OK;
}
