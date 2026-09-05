#include <xaios/arch_cpu.h>
#include <xaios/block_device.h>
#include <xaios/gic.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/nvme.h>
#include <xaios/pci.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
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
#define NVME_ADMIN_CREATE_IO_SQ UINT8_C(0x01)
#define NVME_ADMIN_CREATE_IO_CQ UINT8_C(0x05)
#define NVME_ADMIN_IDENTIFY UINT8_C(0x06)
#define NVME_ADMIN_SET_FEATURES UINT8_C(0x09)
#define NVME_FEATURE_NUMBER_OF_QUEUES UINT32_C(0x07)
#define NVME_IO_FLUSH UINT8_C(0x00)
#define NVME_IO_WRITE UINT8_C(0x01)
#define NVME_IO_READ UINT8_C(0x02)
#define NVME_PSDT_SGL ((uint8_t)(UINT8_C(1) << 6U))

#define NVME_QUEUE_DEPTH 16U
#define NVME_MAX_IO_QUEUES 4U
#define NVME_PAGE_SIZE UINT64_C(4096)
#define NVME_MAX_TRANSFER_BYTES UINT32_C(16384)
#define NVME_STRESS_ROUNDS 8U
#define NVME_TIMEOUT_NS UINT64_C(5000000000)
#define NVME_MMIO_VIRTUAL_BASE UINT64_C(0x300000000)

typedef struct nvme_command {
  uint8_t opcode;
  uint8_t flags;
  uint16_t cid;
  uint32_t nsid;
  uint64_t reserved0;
  uint64_t metadata;
  uint64_t data_pointer1;
  uint64_t data_pointer2;
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

typedef struct nvme_request_slot {
  xaios_block_async_request_t *request;
  uint64_t *prp_list;
  uint16_t cid;
  uint8_t active;
  uint8_t cancel_requested;
  uint8_t uses_sgl;
} nvme_request_slot_t;

typedef struct nvme_queue {
  nvme_command_t *sq;
  nvme_completion_t *cq;
  nvme_request_slot_t slots[NVME_QUEUE_DEPTH];
  xaios_spinlock_t lock;
  uint16_t qid;
  uint16_t sq_tail;
  uint16_t cq_head;
  uint16_t phase;
  uint16_t outstanding;
  uint32_t assigned_cpu;
  uint32_t interrupt_id;
  uint16_t msix_entry;
  uint64_t interrupt_completions;
  struct nvme_controller *controller;
} nvme_queue_t;

typedef struct nvme_controller {
  volatile uint8_t *bar;
  uint64_t cap;
  uint32_t doorbell_stride;
  uint16_t next_cid;
  nvme_queue_t admin;
  nvme_queue_t io[NVME_MAX_IO_QUEUES];
  uint32_t io_queue_count;
  uint32_t next_queue;
  uint32_t namespace_id;
  uint32_t block_size;
  uint64_t namespace_blocks;
  uint32_t sgl_supported;
  uint64_t async_operations;
  uint64_t cancelled_operations;
  uint64_t sgl_operations;
  uint64_t direct_operations;
  uint32_t pci_index;
  uint32_t msix_queue_count;
  uint8_t *interrupt_test_buffer;
  uint8_t *identify;
  xaios_block_device_t block_device;
} nvme_controller_t;

static nvme_controller_t *g_nvme_controller;

static uint32_t poll_queue(nvme_controller_t *controller, nvme_queue_t *queue,
                           uint32_t budget);

typedef char nvme_command_size_must_be_64[(sizeof(nvme_command_t) == 64) ? 1 : -1];
typedef char nvme_completion_size_must_be_16[(sizeof(nvme_completion_t) == 16) ? 1 : -1];

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static void copy_string(char *destination, uint64_t capacity,
                        const char *source) {
  uint64_t index = 0U;
  while (index + 1U < capacity && source[index] != '\0') {
    destination[index] = source[index];
    ++index;
  }
  if (capacity != 0U) destination[index] = '\0';
}

static uint32_t read_le32(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
         ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_le64(const uint8_t *bytes) {
  uint64_t value = 0U;
  for (uint32_t i = 0U; i < 8U; ++i) value |= (uint64_t)bytes[i] << (i * 8U);
  return value;
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

static uint16_t allocate_cid(nvme_controller_t *controller) {
  ++controller->next_cid;
  if (controller->next_cid == 0U) ++controller->next_cid;
  return controller->next_cid;
}

static int completion_fields_valid(const nvme_completion_t *completion,
                                   uint16_t qid, uint16_t expected_cid) {
  return completion != 0 && completion->sq_id == qid &&
         completion->sq_head < NVME_QUEUE_DEPTH &&
         completion->cid == expected_cid &&
         ((completion->status >> 1U) & UINT16_C(0x7ff)) == 0U;
}

static xaios_status_t completion_parser_self_test(void) {
  nvme_completion_t completion = {
      .sq_head = 1U, .sq_id = 2U, .cid = 7U, .status = 1U};
  if (!completion_fields_valid(&completion, 2U, 7U)) return XAIOS_ERR_IO;
  completion.sq_id = 3U;
  if (completion_fields_valid(&completion, 2U, 7U)) return XAIOS_ERR_IO;
  completion.sq_id = 2U;
  completion.sq_head = NVME_QUEUE_DEPTH;
  if (completion_fields_valid(&completion, 2U, 7U)) return XAIOS_ERR_IO;
  completion.sq_head = 1U;
  completion.cid = 8U;
  if (completion_fields_valid(&completion, 2U, 7U)) return XAIOS_ERR_IO;
  completion.cid = 7U;
  completion.status = UINT16_C(3);
  if (completion_fields_valid(&completion, 2U, 7U)) return XAIOS_ERR_IO;
  return XAIOS_OK;
}

static xaios_status_t submit_admin(nvme_controller_t *controller,
                                   const nvme_command_t *command,
                                   uint32_t *result) {
  nvme_queue_t *queue = &controller->admin;
  nvme_command_t staged = *command;
  staged.cid = allocate_cid(controller);
  queue->sq[queue->sq_tail] = staged;
  xaios_cpu_io_barrier();
  queue->sq_tail = (uint16_t)((queue->sq_tail + 1U) % NVME_QUEUE_DEPTH);
  mmio_write32(controller, doorbell_offset(controller, 0U, 0U), queue->sq_tail);

  uint64_t started = timer_now_ns();
  for (;;) {
    xaios_cpu_io_barrier();
    nvme_completion_t completion = queue->cq[queue->cq_head];
    if ((completion.status & 1U) == queue->phase) {
      if (!completion_fields_valid(&completion, 0U, staged.cid)) {
        return XAIOS_ERR_IO;
      }
      if (result != 0) *result = completion.result;
      queue->cq_head = (uint16_t)(queue->cq_head + 1U);
      if (queue->cq_head == NVME_QUEUE_DEPTH) {
        queue->cq_head = 0U;
        queue->phase ^= 1U;
      }
      mmio_write32(controller, doorbell_offset(controller, 0U, 1U),
                   queue->cq_head);
      return XAIOS_OK;
    }
    if (timer_now_ns() - started >= NVME_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
}

static xaios_status_t allocate_queue(nvme_queue_t *queue, uint16_t qid,
                                     uint32_t assigned_cpu,
                                     nvme_controller_t *controller) {
  queue->sq = (nvme_command_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  queue->cq = (nvme_completion_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  if (queue->sq == 0 || queue->cq == 0) return XAIOS_ERR_NO_MEMORY;
  queue->qid = qid;
  queue->phase = 1U;
  queue->assigned_cpu = assigned_cpu;
  queue->controller = controller;
  xaios_spin_init(&queue->lock);
  for (uint32_t slot = 0U; slot < NVME_QUEUE_DEPTH; ++slot) {
    queue->slots[slot].prp_list =
        (uint64_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
    if (queue->slots[slot].prp_list == 0) return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

static xaios_status_t initialize_controller(nvme_controller_t *controller,
                                            uint32_t pci_index) {
  bytes_zero(controller, sizeof(*controller));
  if (pci_enable_device(pci_index) != XAIOS_OK) return XAIOS_ERR_IO;
  uint64_t bar = pci_bar_address(pci_index, 0U);
  if (bar == 0U || (bar & (NVME_PAGE_SIZE - 1U)) != 0U) return XAIOS_ERR_INVALID;
  for (uint64_t offset = 0U; offset < NVME_PAGE_SIZE * 2U;
       offset += NVME_PAGE_SIZE) {
    if (vmm_map_page(NVME_MMIO_VIRTUAL_BASE + offset, bar + offset,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  controller->bar = (volatile uint8_t *)(uintptr_t)NVME_MMIO_VIRTUAL_BASE;
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
  if (allocate_queue(&controller->admin, 0U, 0U, controller) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  uint32_t desired = smp_online_count();
  if (desired == 0U) desired = 1U;
  if (desired > NVME_MAX_IO_QUEUES) desired = NVME_MAX_IO_QUEUES;
  for (uint32_t index = 0U; index < desired; ++index) {
    uint32_t cpu_id = index;
    (void)smp_cpu_id_at(index, &cpu_id);
    if (allocate_queue(&controller->io[index], (uint16_t)(index + 1U), cpu_id,
                       controller) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  controller->io_queue_count = desired;
  controller->pci_index = pci_index;
  controller->identify = (uint8_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  if (controller->identify == 0) return XAIOS_ERR_NO_MEMORY;

  mmio_write32(controller, NVME_REG_AQA,
               ((NVME_QUEUE_DEPTH - 1U) << 16U) | (NVME_QUEUE_DEPTH - 1U));
  mmio_write64(controller, NVME_REG_ASQ, dma_address(controller->admin.sq));
  mmio_write64(controller, NVME_REG_ACQ, dma_address(controller->admin.cq));
  mmio_write32(controller, NVME_REG_CC,
               NVME_CC_ENABLE | (6U << 16U) | (4U << 20U));
  if (wait_ready(controller, NVME_CSTS_READY) != XAIOS_OK) return XAIOS_ERR_IO;
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
  command.data_pointer1 = dma_address(controller->identify);
  command.cdw10 = cns;
  return submit_admin(controller, &command, 0);
}

static xaios_status_t negotiate_io_queues(nvme_controller_t *controller) {
  nvme_command_t command;
  bytes_zero(&command, sizeof(command));
  command.opcode = NVME_ADMIN_SET_FEATURES;
  command.cdw10 = NVME_FEATURE_NUMBER_OF_QUEUES;
  uint32_t requested = controller->io_queue_count - 1U;
  command.cdw11 = (requested << 16U) | requested;
  uint32_t result = 0U;
  if (submit_admin(controller, &command, &result) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint32_t completion_queues = (result & UINT32_C(0xffff)) + 1U;
  uint32_t submission_queues = (result >> 16U) + 1U;
  uint32_t granted = completion_queues < submission_queues
                         ? completion_queues
                         : submission_queues;
  if (granted == 0U) return XAIOS_ERR_IO;
  if (controller->io_queue_count > granted) controller->io_queue_count = granted;
  return XAIOS_OK;
}

/* Only compiled where there is something to register it with. A machine whose
   interrupt controller carries no messages never installs this, and a handler
   defined and never referenced is a build error rather than dead weight --
   which is the compiler being right: an unused interrupt handler is usually a
   wiring mistake, not an intention. */
#if !defined(__riscv)
static void nvme_interrupt_handler(uint32_t intid, void *context) {
  nvme_queue_t *queue = (nvme_queue_t *)context;
  if (queue == 0 || queue->interrupt_id != intid || queue->controller == 0) {
    return;
  }
  ++queue->interrupt_completions;
  (void)poll_queue(queue->controller, queue, NVME_QUEUE_DEPTH);
}
#endif

static xaios_status_t configure_queue_interrupts(
    nvme_controller_t *controller) {
#if defined(__x86_64__)
  for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
    nvme_queue_t *queue = &controller->io[index];
    uint32_t interrupt_id = 80U + index;
    /* The bootstrap CPU owns the canary until secondary scheduler workers are
     * released. Queue affinity is switched only after that barrier. */
    uint32_t destination = x86_64_platform_cpu_apic_id(smp_cpu_id());
    if (destination > UINT32_C(0xfffff) ||
        gic_register_interrupt(interrupt_id, nvme_interrupt_handler, queue) !=
            XAIOS_OK ||
        gic_route_interrupt(interrupt_id, smp_cpu_id()) != XAIOS_OK ||
        pci_configure_msix(controller->pci_index, (uint16_t)index,
                           UINT64_C(0xfee00000) |
                               ((uint64_t)destination << 12U),
                           interrupt_id) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    queue->interrupt_id = interrupt_id;
    queue->msix_entry = (uint16_t)index;
    ++controller->msix_queue_count;
  }
#elif defined(__riscv)
  /* No message-signalled interrupts on this machine.
   *
   * The PLIC takes wires, not messages, so there is no LPI to allocate and no
   * GICv2m frame to write into. That is a property of the interrupt
   * controller and not a defect: the driver's own wait path already polls the
   * completion queues -- wait_request calls poll_controller every turn -- so
   * the queues work, they are simply serviced by the caller rather than by an
   * interrupt. Saying so is what stops this looking like a driver that failed
   * to initialise, which is how it read before: "no LPI available for queue
   * 0" and then nothing.
   *
   * virtio makes the same choice on the same board and logs it the same way.
   * If this port grows an AIA driver, this is the branch that should stop
   * being taken. */
  (void)controller;
  klog("nvme: no message-signalled interrupts on this machine; %u queues use "
       "polled completion\n", controller->io_queue_count);
#else
  uint32_t device_id = pci_stream_id(controller->pci_index);
  uint32_t use_its = 1U;
  for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
    nvme_queue_t *queue = &controller->io[index];
    uint32_t interrupt_id = 0U;
    if (gic_allocate_lpi(&interrupt_id) != XAIOS_OK) {
      klog("nvme: no LPI available for queue %u\n", index);
      return XAIOS_ERR_IO;
    }
    uint64_t message_address = 0U;
    uint32_t message_data = 0U;
    xaios_status_t status =
        gic_its_configure_msi(device_id, index, interrupt_id,
                              queue->assigned_cpu, &message_address,
                              &message_data);
    if (status == XAIOS_ERR_UNSUPPORTED && index == 0U) {
      use_its = 0U;
      break;
    }
    if (status != XAIOS_OK ||
        gic_register_lpi(interrupt_id, queue->assigned_cpu,
                         nvme_interrupt_handler, queue) != XAIOS_OK ||
        pci_configure_msix(controller->pci_index, (uint16_t)index,
                           message_address, message_data) != XAIOS_OK) {
      klog("nvme: ITS queue setup failed queue=%u device=%u intid=%u status=%d\n",
           index, device_id, interrupt_id, (int)status);
      return XAIOS_ERR_IO;
    }
    queue->interrupt_id = interrupt_id;
    queue->msix_entry = (uint16_t)index;
    ++controller->msix_queue_count;
  }
  if (use_its != 0U) return XAIOS_OK;
  const uint64_t v2m_base = UINT64_C(0x08020000);
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  if (vmm_translate(v2m_base, &physical, &flags) != XAIOS_OK ||
      physical != v2m_base || (flags & XAIOS_VMM_DEVICE) == 0U) {
    if (vmm_map_page(v2m_base, v2m_base,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  uint32_t typer = *(volatile uint32_t *)(uintptr_t)(v2m_base + 8U);
  uint32_t spi_base = (typer >> 16U) & UINT32_C(0x3ff);
  uint32_t spi_count = typer & UINT32_C(0x3ff);
  if (spi_count < controller->io_queue_count || spi_base < 32U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
    nvme_queue_t *queue = &controller->io[index];
    uint32_t interrupt_id = spi_base + index;
    if (gic_register_interrupt(interrupt_id, nvme_interrupt_handler, queue) !=
            XAIOS_OK ||
        gic_route_interrupt(interrupt_id, queue->assigned_cpu) != XAIOS_OK ||
        pci_configure_msix(controller->pci_index, (uint16_t)index,
                           v2m_base + UINT64_C(0x40), interrupt_id) !=
            XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    queue->interrupt_id = interrupt_id;
    queue->msix_entry = (uint16_t)index;
    ++controller->msix_queue_count;
  }
#endif
  return XAIOS_OK;
}

static xaios_status_t create_io_queues(nvme_controller_t *controller) {
  for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
    nvme_queue_t *queue = &controller->io[index];
    nvme_command_t command;
    bytes_zero(&command, sizeof(command));
    command.opcode = NVME_ADMIN_CREATE_IO_CQ;
    command.data_pointer1 = dma_address(queue->cq);
    command.cdw10 = ((NVME_QUEUE_DEPTH - 1U) << 16U) | queue->qid;
    command.cdw11 = ((uint32_t)queue->msix_entry << 16U) | 3U;
    if (submit_admin(controller, &command, 0) != XAIOS_OK) return XAIOS_ERR_IO;
    bytes_zero(&command, sizeof(command));
    command.opcode = NVME_ADMIN_CREATE_IO_SQ;
    command.data_pointer1 = dma_address(queue->sq);
    command.cdw10 = ((NVME_QUEUE_DEPTH - 1U) << 16U) | queue->qid;
    command.cdw11 = ((uint32_t)queue->qid << 16U) | 1U;
    if (submit_admin(controller, &command, 0) != XAIOS_OK) return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

static xaios_status_t prepare_data_pointer(nvme_controller_t *controller,
                                           nvme_request_slot_t *slot,
                                           nvme_command_t *command,
                                           void *buffer, uint32_t length,
                                           uint32_t use_sgl) {
  if (buffer == 0 || length == 0U || length > NVME_MAX_TRANSFER_BYTES ||
      ((uintptr_t)buffer & (NVME_PAGE_SIZE - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t first = dma_address(buffer);
  if (first == 0U) return XAIOS_ERR_IO;
  uint32_t pages = (length + (uint32_t)NVME_PAGE_SIZE - 1U) /
                   (uint32_t)NVME_PAGE_SIZE;
  if (use_sgl != 0U && controller->sgl_supported != 0U) {
    for (uint32_t page = 1U; page < pages; ++page) {
      uint64_t physical = dma_address((uint8_t *)buffer +
                                      (uint64_t)page * NVME_PAGE_SIZE);
      if (physical != first + (uint64_t)page * NVME_PAGE_SIZE) {
        return XAIOS_ERR_UNSUPPORTED;
      }
    }
    command->flags = NVME_PSDT_SGL;
    command->data_pointer1 = first;
    command->data_pointer2 = length;
    slot->uses_sgl = 1U;
    return XAIOS_OK;
  }
  command->data_pointer1 = first;
  if (pages == 1U) return XAIOS_OK;
  uint64_t second = dma_address((uint8_t *)buffer + NVME_PAGE_SIZE);
  if (second == 0U) return XAIOS_ERR_IO;
  if (pages == 2U) {
    command->data_pointer2 = second;
    return XAIOS_OK;
  }
  bytes_zero(slot->prp_list, NVME_PAGE_SIZE);
  for (uint32_t page = 1U; page < pages; ++page) {
    uint64_t physical = dma_address((uint8_t *)buffer +
                                    (uint64_t)page * NVME_PAGE_SIZE);
    if (physical == 0U) return XAIOS_ERR_IO;
    slot->prp_list[page - 1U] = physical;
  }
  command->data_pointer2 = dma_address(slot->prp_list);
  return command->data_pointer2 == 0U ? XAIOS_ERR_IO : XAIOS_OK;
}

static nvme_request_slot_t *free_slot(nvme_queue_t *queue) {
  for (uint32_t index = 0U; index < NVME_QUEUE_DEPTH; ++index) {
    if (queue->slots[index].active == 0U) return &queue->slots[index];
  }
  return 0;
}

static nvme_request_slot_t *slot_for_cid(nvme_queue_t *queue, uint16_t cid) {
  for (uint32_t index = 0U; index < NVME_QUEUE_DEPTH; ++index) {
    if (queue->slots[index].active != 0U && queue->slots[index].cid == cid) {
      return &queue->slots[index];
    }
  }
  return 0;
}

static xaios_status_t submit_io(nvme_controller_t *controller,
                                uint32_t queue_index,
                                xaios_block_async_request_t *request,
                                uint32_t use_sgl) {
  if (queue_index >= controller->io_queue_count || request == 0) {
    return XAIOS_ERR_INVALID;
  }
  nvme_queue_t *queue = &controller->io[queue_index];
  xaios_spin_lock(&queue->lock);
  if (queue->outstanding >= NVME_QUEUE_DEPTH - 1U) {
    xaios_spin_unlock(&queue->lock);
    return XAIOS_ERR_BUSY;
  }
  nvme_request_slot_t *slot = free_slot(queue);
  if (slot == 0) {
    xaios_spin_unlock(&queue->lock);
    return XAIOS_ERR_BUSY;
  }
  uint64_t *prp_list = slot->prp_list;
  bytes_zero(slot, sizeof(*slot));
  slot->prp_list = prp_list;
  nvme_command_t command;
  bytes_zero(&command, sizeof(command));
  if (request->operation == XAIOS_BLOCK_ASYNC_READ) command.opcode = NVME_IO_READ;
  else if (request->operation == XAIOS_BLOCK_ASYNC_WRITE) command.opcode = NVME_IO_WRITE;
  else if (request->operation == XAIOS_BLOCK_ASYNC_FLUSH) command.opcode = NVME_IO_FLUSH;
  else {
    xaios_spin_unlock(&queue->lock);
    return XAIOS_ERR_INVALID;
  }
  command.nsid = controller->namespace_id;
  if (command.opcode != NVME_IO_FLUSH) {
    if (request->length > UINT32_MAX || request->length % controller->block_size != 0U ||
        request->byte_offset % controller->block_size != 0U ||
        prepare_data_pointer(controller, slot, &command, request->buffer,
                             (uint32_t)request->length, use_sgl) != XAIOS_OK) {
      xaios_spin_unlock(&queue->lock);
      return XAIOS_ERR_INVALID;
    }
    uint64_t lba = request->byte_offset / controller->block_size;
    command.cdw10 = (uint32_t)lba;
    command.cdw11 = (uint32_t)(lba >> 32U);
    command.cdw12 = (uint32_t)(request->length / controller->block_size - 1U);
  }
  slot->cid = allocate_cid(controller);
  slot->active = 1U;
  slot->request = request;
  command.cid = slot->cid;
  request->token = ((uint64_t)queue->qid << 32U) | slot->cid;
  request->backend_private = slot;
  queue->sq[queue->sq_tail] = command;
  xaios_cpu_io_barrier();
  queue->sq_tail = (uint16_t)((queue->sq_tail + 1U) % NVME_QUEUE_DEPTH);
  ++queue->outstanding;
  ++controller->async_operations;
  ++controller->direct_operations;
  if (slot->uses_sgl != 0U) ++controller->sgl_operations;
  uint16_t submitted_tail = queue->sq_tail;
  xaios_spin_unlock(&queue->lock);
  mmio_write32(controller, doorbell_offset(controller, queue->qid, 0U),
               submitted_tail);
  return XAIOS_OK;
}

static uint32_t poll_queue(nvme_controller_t *controller, nvme_queue_t *queue,
                           uint32_t budget) {
  uint32_t completed_count = 0U;
  while (completed_count < budget) {
    xaios_spin_lock(&queue->lock);
    xaios_cpu_io_barrier();
    nvme_completion_t completion = queue->cq[queue->cq_head];
    if ((completion.status & 1U) != queue->phase) {
      xaios_spin_unlock(&queue->lock);
      break;
    }
    nvme_request_slot_t *slot = slot_for_cid(queue, completion.cid);
    xaios_status_t status = XAIOS_ERR_IO;
    xaios_block_async_request_t *request = slot == 0 ? 0 : slot->request;
    if (slot != 0 &&
        completion_fields_valid(&completion, queue->qid, slot->cid)) {
      status = slot->cancel_requested != 0U ? XAIOS_ERR_CANCELLED : XAIOS_OK;
    }
    queue->cq_head = (uint16_t)(queue->cq_head + 1U);
    if (queue->cq_head == NVME_QUEUE_DEPTH) {
      queue->cq_head = 0U;
      queue->phase ^= 1U;
    }
    mmio_write32(controller, doorbell_offset(controller, queue->qid, 1U),
                 queue->cq_head);
    if (slot != 0) {
      slot->active = 0U;
      slot->request = 0;
      slot->cancel_requested = 0U;
      if (queue->outstanding != 0U) --queue->outstanding;
    }
    xaios_spin_unlock(&queue->lock);
    if (request != 0) block_async_complete(request, status);
    ++completed_count;
  }
  return completed_count;
}

static uint32_t poll_controller(nvme_controller_t *controller,
                                uint32_t budget) {
  uint32_t completed = 0U;
  for (uint32_t index = 0U;
       index < controller->io_queue_count && completed < budget; ++index) {
    completed += poll_queue(controller, &controller->io[index],
                            budget - completed);
  }
  return completed;
}

static xaios_status_t wait_request(nvme_controller_t *controller,
                                   xaios_block_async_request_t *request) {
  uint64_t started = timer_now_ns();
  while (request->state != XAIOS_BLOCK_ASYNC_COMPLETE) {
    (void)poll_controller(controller, NVME_QUEUE_DEPTH * NVME_MAX_IO_QUEUES);
    if (timer_now_ns() - started >= NVME_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
  return request->status;
}

static xaios_status_t nvme_backend_submit(
    void *context, xaios_block_async_request_t *request) {
  nvme_controller_t *controller = (nvme_controller_t *)context;
  uint32_t queue = __sync_fetch_and_add(&controller->next_queue, 1U) %
                   controller->io_queue_count;
  uint32_t use_sgl = controller->sgl_supported != 0U &&
                     (controller->async_operations & 1U) != 0U;
  return submit_io(controller, queue, request, use_sgl);
}

static uint32_t nvme_backend_poll(void *context, uint32_t budget) {
  return poll_controller((nvme_controller_t *)context, budget);
}

static xaios_status_t nvme_backend_cancel(
    void *context, xaios_block_async_request_t *request) {
  nvme_controller_t *controller = (nvme_controller_t *)context;
  for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
    nvme_queue_t *queue = &controller->io[index];
    xaios_spin_lock(&queue->lock);
    for (uint32_t slot_index = 0U; slot_index < NVME_QUEUE_DEPTH; ++slot_index) {
      nvme_request_slot_t *slot = &queue->slots[slot_index];
      if (slot->active != 0U && slot->request == request) {
        slot->cancel_requested = 1U;
        ++controller->cancelled_operations;
        xaios_spin_unlock(&queue->lock);
        return XAIOS_OK;
      }
    }
    xaios_spin_unlock(&queue->lock);
  }
  return XAIOS_ERR_NOT_FOUND;
}

static xaios_status_t synchronous_io(nvme_controller_t *controller,
                                     xaios_block_async_operation_t operation,
                                     uint64_t offset, void *buffer,
                                     uint64_t length) {
  xaios_block_async_request_t request;
  bytes_zero(&request, sizeof(request));
  request.operation = operation;
  request.state = XAIOS_BLOCK_ASYNC_PENDING;
  request.byte_offset = offset;
  request.buffer = buffer;
  request.length = length;
  uint32_t queue = __sync_fetch_and_add(&controller->next_queue, 1U) %
                   controller->io_queue_count;
  xaios_status_t status = submit_io(controller, queue, &request, 0U);
  return status == XAIOS_OK ? wait_request(controller, &request) : status;
}

static xaios_status_t nvme_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  return synchronous_io((nvme_controller_t *)context, XAIOS_BLOCK_ASYNC_READ,
                        offset, buffer, length);
}

static xaios_status_t nvme_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  return synchronous_io((nvme_controller_t *)context, XAIOS_BLOCK_ASYNC_WRITE,
                        offset, (void *)buffer, length);
}

static xaios_status_t nvme_flush(void *context) {
  return synchronous_io((nvme_controller_t *)context, XAIOS_BLOCK_ASYNC_FLUSH,
                        0U, 0, 0U);
}

static const xaios_block_backend_ops_t k_nvme_block_ops = {
    nvme_read, nvme_write, nvme_flush, 0, 0};
static const xaios_block_async_ops_t k_nvme_async_ops = {
    nvme_backend_submit, nvme_backend_poll, nvme_backend_cancel};

static xaios_status_t register_block_device(nvme_controller_t *controller) {
  if (controller->namespace_blocks >
      UINT64_MAX / (uint64_t)controller->block_size) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  xaios_block_device_info_t info;
  bytes_zero(&info, sizeof(info));
  copy_string(info.identifier, sizeof(info.identifier), "/dev/nvme0n1");
  copy_string(info.backend, sizeof(info.backend), "nvme");
  info.capacity_logical_sectors = controller->namespace_blocks;
  info.logical_sector_size = controller->block_size;
  info.physical_block_size = controller->block_size;
  info.capacity_bytes = controller->namespace_blocks * controller->block_size;
  info.max_transfer_bytes = NVME_MAX_TRANSFER_BYTES;
  info.flush_supported = 1U;
  xaios_status_t status = block_device_register(
      &controller->block_device, &info, &k_nvme_block_ops, controller);
  if (status != XAIOS_OK) return status;
  return block_device_set_async_ops(&controller->block_device,
                                    &k_nvme_async_ops);
}

static xaios_status_t wait_batch(nvme_controller_t *controller,
                                 xaios_block_async_request_t *requests,
                                 uint32_t count) {
  uint64_t started = timer_now_ns();
  for (;;) {
    uint32_t done = 0U;
    for (uint32_t index = 0U; index < count; ++index) {
      if (requests[index].state == XAIOS_BLOCK_ASYNC_COMPLETE) ++done;
    }
    if (done == count) return XAIOS_OK;
    (void)poll_controller(controller, NVME_QUEUE_DEPTH * NVME_MAX_IO_QUEUES);
    if (timer_now_ns() - started >= NVME_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
}

static xaios_status_t stress_io(nvme_controller_t *controller,
                                uint8_t **buffers) {
  xaios_block_async_request_t requests[NVME_MAX_IO_QUEUES];
  for (uint32_t round = 0U; round < NVME_STRESS_ROUNDS; ++round) {
    bytes_zero(requests, sizeof(requests));
    for (uint32_t queue = 0U; queue < controller->io_queue_count; ++queue) {
      for (uint32_t byte = 0U; byte < NVME_MAX_TRANSFER_BYTES; ++byte) {
        buffers[queue][byte] =
            (uint8_t)(byte ^ UINT32_C(0xa5) ^ (queue << 4U));
      }
      requests[queue].operation = XAIOS_BLOCK_ASYNC_WRITE;
      requests[queue].state = XAIOS_BLOCK_ASYNC_PENDING;
      requests[queue].byte_offset =
          (uint64_t)queue * NVME_MAX_TRANSFER_BYTES;
      requests[queue].buffer = buffers[queue];
      requests[queue].length = NVME_MAX_TRANSFER_BYTES;
      if (submit_io(controller, queue, &requests[queue], round & 1U) !=
          XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    }
    if (wait_batch(controller, requests, controller->io_queue_count) !=
        XAIOS_OK) return XAIOS_ERR_IO;
  }
  if (synchronous_io(controller, XAIOS_BLOCK_ASYNC_FLUSH, 0U, 0, 0U) !=
      XAIOS_OK) return XAIOS_ERR_IO;

  bytes_zero(requests, sizeof(requests));
  for (uint32_t queue = 0U; queue < controller->io_queue_count; ++queue) {
    bytes_zero(buffers[queue], NVME_MAX_TRANSFER_BYTES);
    requests[queue].operation = XAIOS_BLOCK_ASYNC_READ;
    requests[queue].state = XAIOS_BLOCK_ASYNC_PENDING;
    requests[queue].byte_offset = (uint64_t)queue * NVME_MAX_TRANSFER_BYTES;
    requests[queue].buffer = buffers[queue];
    requests[queue].length = NVME_MAX_TRANSFER_BYTES;
    if (submit_io(controller, queue, &requests[queue], queue & 1U) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  if (wait_batch(controller, requests, controller->io_queue_count) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  for (uint32_t queue = 0U; queue < controller->io_queue_count; ++queue) {
    for (uint32_t byte = 0U; byte < NVME_MAX_TRANSFER_BYTES; ++byte) {
      if (buffers[queue][byte] !=
          (uint8_t)(byte ^ UINT32_C(0xa5) ^ (queue << 4U))) {
        return XAIOS_ERR_IO;
      }
    }
  }

  xaios_block_async_request_t cancelled;
  bytes_zero(&cancelled, sizeof(cancelled));
  cancelled.operation = XAIOS_BLOCK_ASYNC_READ;
  cancelled.state = XAIOS_BLOCK_ASYNC_PENDING;
  cancelled.buffer = buffers[0];
  cancelled.length = NVME_MAX_TRANSFER_BYTES;
  if (submit_io(controller, 0U, &cancelled, 0U) != XAIOS_OK ||
      nvme_backend_cancel(controller, &cancelled) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  cancelled.state = XAIOS_BLOCK_ASYNC_CANCEL_REQUESTED;
  if (wait_request(controller, &cancelled) != XAIOS_ERR_CANCELLED) {
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

xaios_status_t nvme_self_test(xaios_nvme_self_test_result_t *result) {
  if (result != 0) bytes_zero(result, sizeof(*result));
  if (completion_parser_self_test() != XAIOS_OK) return XAIOS_ERR_IO;
  uint32_t found = UINT32_MAX;
  for (uint32_t index = 0U; index < pci_device_count(); ++index) {
    const xaios_pci_device_t *device = pci_device(index);
    if (device != 0 && device->class_code == NVME_CLASS &&
        device->subclass == NVME_SUBCLASS && device->prog_if == NVME_PROGIF) {
      found = index;
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
    result->malformed_completions_rejected = 4U;
  }

  if (identify(controller, 0U, 1U) != XAIOS_OK) return XAIOS_ERR_IO;
  char serial[21];
  char model[41];
  for (uint32_t i = 0U; i < 20U; ++i) serial[i] = (char)controller->identify[4U + i];
  for (uint32_t i = 0U; i < 40U; ++i) model[i] = (char)controller->identify[24U + i];
  serial[20] = '\0';
  model[40] = '\0';
  controller->sgl_supported = (read_le32(controller->identify + 536U) & 1U) != 0U;
  klog("nvme: identify controller serial='%s' model='%s' sgl=%u\n", serial,
       model, controller->sgl_supported);

  if (identify(controller, 1U, 0U) != XAIOS_OK) return XAIOS_ERR_IO;
  controller->namespace_id = 1U;
  controller->namespace_blocks = read_le64(controller->identify);
  uint32_t format = controller->identify[26U] & UINT8_C(0x0f);
  uint32_t lbads = controller->identify[128U + format * 4U + 2U];
  if (controller->namespace_blocks == 0U || lbads < 9U || lbads > 12U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  controller->block_size = 1U << lbads;
  if (NVME_MAX_TRANSFER_BYTES % controller->block_size != 0U ||
      negotiate_io_queues(controller) != XAIOS_OK ||
      configure_queue_interrupts(controller) != XAIOS_OK ||
      create_io_queues(controller) != XAIOS_OK ||
      register_block_device(controller) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint32_t blocks_per_transfer =
      NVME_MAX_TRANSFER_BYTES / controller->block_size;
  if ((uint64_t)blocks_per_transfer * controller->io_queue_count >
      controller->namespace_blocks) return XAIOS_ERR_UNSUPPORTED;

  uint8_t *buffers[NVME_MAX_IO_QUEUES] = {0};
  for (uint32_t queue = 0U; queue < controller->io_queue_count; ++queue) {
    buffers[queue] =
        (uint8_t *)kheap_calloc(NVME_MAX_TRANSFER_BYTES, NVME_PAGE_SIZE);
    if (buffers[queue] == 0) return XAIOS_ERR_NO_MEMORY;
  }
  if (stress_io(controller, buffers) != XAIOS_OK) return XAIOS_ERR_IO;
  controller->interrupt_test_buffer = buffers[0];
  g_nvme_controller = controller;

  if (result != 0) {
    result->namespaces = 1U;
    result->io_verified = 1U;
    result->io_queues = controller->io_queue_count;
    result->prp_pages = NVME_MAX_TRANSFER_BYTES / (uint32_t)NVME_PAGE_SIZE;
    result->transfer_bytes = NVME_MAX_TRANSFER_BYTES;
    result->namespace_blocks = controller->namespace_blocks;
    result->logical_block_size = controller->block_size;
    result->async_operations = controller->async_operations;
    result->cancelled_operations = controller->cancelled_operations;
    result->sgl_operations = controller->sgl_operations;
    result->direct_operations = controller->direct_operations;
  }
  klog("nvme: async self-test passed namespaces=1 blocks=%lu block_size=%u queue_depth=%u io_queues=%u prp_pages=4 transfer_bytes=16384 rounds=%u async=%lu cancelled=%lu sgl=%lu direct=%lu malformed=4 affinity=cpu msix=%u write_read_flush=1\n",
       controller->namespace_blocks, controller->block_size, NVME_QUEUE_DEPTH,
       controller->io_queue_count, NVME_STRESS_ROUNDS,
       controller->async_operations, controller->cancelled_operations,
       controller->sgl_operations, controller->direct_operations,
       controller->msix_queue_count);
  return XAIOS_OK;
}

xaios_status_t nvme_interrupt_self_test(void) {
  nvme_controller_t *controller = g_nvme_controller;
  if (controller == 0 || controller->interrupt_test_buffer == 0) {
    return XAIOS_ERR_NOT_FOUND;
  }
  /* A machine with no message-signalled interrupts has nothing to test here,
     and that is different from a machine that configured some and lost them.
     The caller can accept the first and must not accept the second, so they
     are different answers. */
  if (controller->msix_queue_count == 0U) {
    klog("nvme: MSI-X interrupt self-test skipped; queues=%u are polled\n",
         controller->io_queue_count);
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (controller->msix_queue_count != controller->io_queue_count) {
    return XAIOS_ERR_NOT_FOUND;
  }
  uint64_t delivered = 0U;
  for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
    nvme_queue_t *queue = &controller->io[index];
    uint64_t before = queue->interrupt_completions;
    if (pci_unmask_msix(controller->pci_index, queue->msix_entry) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    xaios_block_async_request_t request;
    bytes_zero(&request, sizeof(request));
    request.operation = XAIOS_BLOCK_ASYNC_READ;
    request.state = XAIOS_BLOCK_ASYNC_PENDING;
    request.buffer = controller->interrupt_test_buffer;
    request.length = controller->block_size;
    if (submit_io(controller, index, &request, 0U) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    uint64_t started = timer_now_ns();
    while (request.state != XAIOS_BLOCK_ASYNC_COMPLETE &&
           timer_now_ns() - started < NVME_TIMEOUT_NS) {
      xaios_cpu_relax();
    }
    if (request.status != XAIOS_OK ||
        queue->interrupt_completions <= before) {
      klog("nvme: MSI-X device canary failed queue=%u status=%d before=%lu after=%lu\n",
           index, (int)request.status, before, queue->interrupt_completions);
      return XAIOS_ERR_IO;
    }
    delivered += queue->interrupt_completions - before;
  }
  klog("nvme: MSI-X interrupt self-test passed queues=%u all_queues=1 completions=%lu controller=%s\n",
       controller->msix_queue_count, delivered,
#if defined(__x86_64__)
       "x86-apic"
#else
       gic_its_available() ? "gicv3-its" : "gicv2m"
#endif
  );
  return XAIOS_OK;
}
