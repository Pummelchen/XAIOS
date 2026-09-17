/* The NVMe controller bring-up and the admin command path.
 *
 * Everything here programs the controller through its registers or speaks the
 * admin queue: the register accessors, the ready-wait poll, one admin command
 * submission, the identify calls, the queue negotiation and creation, and the
 * restart the self-test drives. The I/O queue machinery is nvme_queue.c; the
 * polled waits and the self-test are nvme_selftest.c; the block backend,
 * registration and interrupt programming stay in nvme.c. nvme_driver_internal.h
 * is the interface among the three.
 */

#include "nvme_driver_internal.h"

#include <xaios/arch_cpu.h>
#include <xaios/device_window.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/smp.h>
#include <xaios/timer.h>

#define NVME_REG_CAP UINT32_C(0x00)
#define NVME_REG_VS UINT32_C(0x08)
#define NVME_REG_CC UINT32_C(0x14)
#define NVME_REG_CSTS UINT32_C(0x1c)
#define NVME_REG_AQA UINT32_C(0x24)
#define NVME_REG_ASQ UINT32_C(0x28)
#define NVME_REG_ACQ UINT32_C(0x30)

#define NVME_CC_ENABLE UINT32_C(1)
#define NVME_CSTS_READY UINT32_C(1)
#define NVME_CSTS_FATAL UINT32_C(2)
#define NVME_ADMIN_CREATE_IO_SQ UINT8_C(0x01)
#define NVME_ADMIN_CREATE_IO_CQ UINT8_C(0x05)
#define NVME_ADMIN_IDENTIFY UINT8_C(0x06)
#define NVME_ADMIN_SET_FEATURES UINT8_C(0x09)
#define NVME_FEATURE_NUMBER_OF_QUEUES UINT32_C(0x07)

static xaios_status_t wait_ready(const nvme_controller_t *controller,
                                 uint32_t expected) {
  uint64_t started = timer_now_ns();
  for (;;) {
    uint32_t status = nvme_mmio_read32(controller, NVME_REG_CSTS);
    if ((status & NVME_CSTS_FATAL) != 0U) {
      /* The controller said it had failed, and the caller names the step it
         was in; this names which of the two reasons it did not become ready.
         A fatal status and a controller that simply never came up are
         different findings, and both used to be a bare XAIOS_ERR_IO. */
      klog("nvme: controller fatal csts=0x%x expected=%u elapsed=%lu ns\n",
           (unsigned)status, (unsigned)expected,
           (unsigned long)(timer_now_ns() - started));
      return XAIOS_ERR_IO;
    }
    if ((status & NVME_CSTS_READY) == expected) return XAIOS_OK;
    if (timer_now_ns() - started >= NVME_TIMEOUT_NS) {
      klog("nvme: controller not ready csts=0x%x expected=%u elapsed=%lu ns\n",
           (unsigned)status, (unsigned)expected,
           (unsigned long)(timer_now_ns() - started));
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
}

static xaios_status_t submit_admin(nvme_controller_t *controller,
                                   const nvme_command_t *command,
                                   uint32_t *result) {
  nvme_queue_t *queue = &controller->admin;
  nvme_command_t staged = *command;
  staged.cid = nvme_allocate_cid(controller);
  queue->sq[queue->sq_tail] = staged;
  xaios_cpu_io_barrier();
  queue->sq_tail = (uint16_t)((queue->sq_tail + 1U) % NVME_QUEUE_DEPTH);
  /* Counted so the trace's `outstanding` means the same thing here as it does
     for the I/O queues: the field was written for I/O and read for the admin
     queue, where it was always zero while a command was in flight. */
  ++queue->outstanding;
  nvme_mmio_write32(controller, nvme_doorbell_offset(controller, 0U, 0U), queue->sq_tail);

  uint64_t started = timer_now_ns();
  for (;;) {
    xaios_cpu_io_barrier();
    if (completion_in_phase(queue, queue->cq_head) != 0) {
      nvme_completion_t completion = queue->cq[queue->cq_head];
      int valid = completion_fields_valid(&completion, 0U, staged.cid);
      record_completion(queue, &completion, valid ? staged.cid : 0U);
      if (!valid) {
        /* One of the two ways this function returns XAIOS_ERR_IO, and they are
           logged apart because B-100 needs them apart: a completion the device
           produced and this driver refused is a protocol error, while the
           branch below is a device that never answered. Both used to be the
           same value with nothing on the console to tell them apart. What the
           device answered with, what the driver was waiting for, and where in
           the ring it was read are all named now, because the first sighting of
           this line had every field it printed looking valid -- `status=0x0001`
           is a successful completion -- and the one value that could explain it
           was the one it did not print. */
        klog("nvme: admin completion rejected opcode=%u cid=%u expected=%u "
             "sq_head=%u sq_id=%u status=0x%04x cq_head=%u phase=%u\n",
             (unsigned)staged.opcode, (unsigned)completion.cid,
             (unsigned)staged.cid, (unsigned)completion.sq_head,
             (unsigned)completion.sq_id, (unsigned)completion.status,
             (unsigned)queue->cq_head, (unsigned)queue->phase);
        report_completion_reread(queue, &completion);
        report_sq_neighbourhood(queue, completion.sq_head);
        report_queue_trace(queue, "admin-rejected");
        return XAIOS_ERR_IO;
      }
      if (result != 0) *result = completion.result;
      if (queue->outstanding != 0U) --queue->outstanding;
      queue->cq_head = (uint16_t)(queue->cq_head + 1U);
      if (queue->cq_head == NVME_QUEUE_DEPTH) {
        queue->cq_head = 0U;
        queue->phase ^= 1U;
      }
      nvme_mmio_write32(controller, nvme_doorbell_offset(controller, 0U, 1U),
                   queue->cq_head);
      return XAIOS_OK;
    }
    if (timer_now_ns() - started >= NVME_TIMEOUT_NS) {
      /* The other way out, and the one a starved guest is most likely to take.
         Elapsed is reported because the question is not whether five seconds
         passed -- by definition they did -- but what the guest managed inside
         them. A device that never answered and a device that answered and was
         refused are different findings, and B-100 is the row that could not
         tell them apart. */
      klog("nvme: admin command timed out opcode=%u cid=%u nsid=%u elapsed=%lu "
           "ns\n",
           (unsigned)staged.opcode, (unsigned)staged.cid,
           (unsigned)staged.nsid,
           (unsigned long)(timer_now_ns() - started));
      report_queue_trace(queue, "admin-timeout");
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
}

xaios_status_t nvme_initialize_controller(nvme_controller_t *controller,
                                          uint32_t pci_index) {
  nvme_bytes_zero(controller, sizeof(*controller));
  xaios_status_t enabled = pci_enable_device(pci_index);
  if (enabled != XAIOS_OK) {
    klog("nvme: controller pci enable failed index=%u status=%d\n",
         (unsigned)pci_index, (int)enabled);
    return XAIOS_ERR_IO;
  }
  uint64_t bar = pci_bar_address(pci_index, 0U);
  if (bar == 0U || (bar & (NVME_PAGE_SIZE - 1U)) != 0U) {
    klog("nvme: controller bar unusable index=%u bar=0x%lx\n",
         (unsigned)pci_index, (unsigned long)bar);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t mapped = device_window_map("nvme", bar, NVME_PAGE_SIZE * 2U,
                                            &controller->bar);
  if (mapped != XAIOS_OK) {
    klog("nvme: controller window map failed bar=0x%lx bytes=%lu status=%d\n",
         (unsigned long)bar, (unsigned long)(NVME_PAGE_SIZE * 2U),
         (int)mapped);
    return XAIOS_ERR_IO;
  }
  controller->cap = nvme_mmio_read64(controller, NVME_REG_CAP);
  uint32_t mqes = (uint32_t)(controller->cap & UINT64_C(0xffff)) + 1U;
  uint32_t mpsmin = (uint32_t)((controller->cap >> 48U) & UINT64_C(0xf));
  if (mqes < NVME_QUEUE_DEPTH || mpsmin != 0U) {
    klog("nvme: controller unsupported mqes=%u mpsmin=%u need_mqes=%u\n",
         (unsigned)mqes, (unsigned)mpsmin, (unsigned)NVME_QUEUE_DEPTH);
    return XAIOS_ERR_UNSUPPORTED;
  }
  controller->doorbell_stride =
      4U << ((uint32_t)((controller->cap >> 32U) & UINT64_C(0xf)));

  uint32_t cc = nvme_mmio_read32(controller, NVME_REG_CC);
  if ((cc & NVME_CC_ENABLE) != 0U) {
    nvme_mmio_write32(controller, NVME_REG_CC, cc & ~NVME_CC_ENABLE);
    if (wait_ready(controller, 0U) != XAIOS_OK) return XAIOS_ERR_IO;
  }
  if (nvme_allocate_queue(&controller->admin, 0U, 0U, controller) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  uint32_t desired = smp_online_count();
  if (desired == 0U) desired = 1U;
  if (desired > NVME_MAX_IO_QUEUES) desired = NVME_MAX_IO_QUEUES;
  for (uint32_t index = 0U; index < desired; ++index) {
    uint32_t cpu_id = index;
    (void)smp_cpu_id_at(index, &cpu_id);
    if (nvme_allocate_queue(&controller->io[index], (uint16_t)(index + 1U), cpu_id,
                       controller) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  controller->io_queue_count = desired;
  controller->pci_index = pci_index;
  controller->identify = (uint8_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  if (controller->identify == 0) {
    klog("nvme: identify buffer allocation failed bytes=%u\n",
         (unsigned)NVME_PAGE_SIZE);
    return XAIOS_ERR_NO_MEMORY;
  }

  nvme_mmio_write32(controller, NVME_REG_AQA,
               ((NVME_QUEUE_DEPTH - 1U) << 16U) | (NVME_QUEUE_DEPTH - 1U));
  nvme_mmio_write64(controller, NVME_REG_ASQ, nvme_dma_address(controller->admin.sq));
  nvme_mmio_write64(controller, NVME_REG_ACQ, nvme_dma_address(controller->admin.cq));
  nvme_mmio_write32(controller, NVME_REG_CC,
               NVME_CC_ENABLE | (6U << 16U) | (4U << 20U));
  if (wait_ready(controller, NVME_CSTS_READY) != XAIOS_OK) return XAIOS_ERR_IO;
  klog("nvme: controller ready version=0x%x mqes=%u dstrd=%u\n",
       nvme_mmio_read32(controller, NVME_REG_VS), mqes,
       controller->doorbell_stride);
  /* What the device was actually programmed with, read back from its own
   * registers beside what the driver believes it handed over.
   *
   * B-100's second sighting is a completion whose `sq_head` wrapped the admin
   * submission queue -- `sq_head=0` where that field is the index plus one on
   * every completion this driver accepted -- which is what a queue whose size
   * the device disagrees about looks like from the outside, and so is a
   * submission-queue base that is not the page the driver writes. Both are
   * visible here and nowhere else: `aqa` carries the queue sizes and `asq` the
   * base, and `expect_` is what `nvme_dma_address` says the driver's own pages are.
   * One line on every NVMe boot, because the healthy value is what makes an
   * unhealthy one readable. */
  klog("nvme: controller registers cc=0x%x csts=0x%x aqa=0x%x asq=0x%lx "
       "acq=0x%lx expect_asq=0x%lx expect_acq=0x%lx\n",
       (unsigned)nvme_mmio_read32(controller, NVME_REG_CC),
       (unsigned)nvme_mmio_read32(controller, NVME_REG_CSTS),
       (unsigned)nvme_mmio_read32(controller, NVME_REG_AQA),
       (unsigned long)nvme_mmio_read64(controller, NVME_REG_ASQ),
       (unsigned long)nvme_mmio_read64(controller, NVME_REG_ACQ),
       (unsigned long)nvme_dma_address(controller->admin.sq),
       (unsigned long)nvme_dma_address(controller->admin.cq));
  return XAIOS_OK;
}

xaios_status_t nvme_identify(nvme_controller_t *controller, uint32_t nsid,
                             uint32_t cns) {
  nvme_bytes_zero(controller->identify, NVME_PAGE_SIZE);
  nvme_command_t command;
  nvme_bytes_zero(&command, sizeof(command));
  command.opcode = NVME_ADMIN_IDENTIFY;
  command.nsid = nsid;
  command.data_pointer1 = nvme_dma_address(controller->identify);
  command.cdw10 = cns;
  return submit_admin(controller, &command, 0);
}

xaios_status_t nvme_negotiate_io_queues(nvme_controller_t *controller) {
  nvme_command_t command;
  nvme_bytes_zero(&command, sizeof(command));
  command.opcode = NVME_ADMIN_SET_FEATURES;
  command.cdw10 = NVME_FEATURE_NUMBER_OF_QUEUES;
  uint32_t requested = controller->io_queue_count - 1U;
  command.cdw11 = (requested << 16U) | requested;
  uint32_t result = 0U;
  xaios_status_t submitted = submit_admin(controller, &command, &result);
  if (submitted != XAIOS_OK) {
    klog("nvme: io queue negotiation refused requested=%u status=%d\n",
         (unsigned)requested, (int)submitted);
    return XAIOS_ERR_IO;
  }
  uint32_t completion_queues = (result & UINT32_C(0xffff)) + 1U;
  uint32_t submission_queues = (result >> 16U) + 1U;
  uint32_t granted = completion_queues < submission_queues
                         ? completion_queues
                         : submission_queues;
  if (granted == 0U) {
    klog("nvme: controller granted no io queues result=0x%x requested=%u\n",
         (unsigned)result, (unsigned)requested);
    return XAIOS_ERR_IO;
  }
  if (controller->io_queue_count > granted) controller->io_queue_count = granted;
  return XAIOS_OK;
}

xaios_status_t nvme_create_io_queues(nvme_controller_t *controller) {
  for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
    nvme_queue_t *queue = &controller->io[index];
    nvme_command_t command;
    nvme_bytes_zero(&command, sizeof(command));
    command.opcode = NVME_ADMIN_CREATE_IO_CQ;
    command.data_pointer1 = nvme_dma_address(queue->cq);
    command.cdw10 = ((NVME_QUEUE_DEPTH - 1U) << 16U) | queue->qid;
    command.cdw11 = ((uint32_t)queue->msix_entry << 16U) | 3U;
    xaios_status_t completion_queue = submit_admin(controller, &command, 0);
    if (completion_queue != XAIOS_OK) {
      klog("nvme: create io completion queue refused qid=%u status=%d\n",
           (unsigned)queue->qid, (int)completion_queue);
      return XAIOS_ERR_IO;
    }
    nvme_bytes_zero(&command, sizeof(command));
    command.opcode = NVME_ADMIN_CREATE_IO_SQ;
    command.data_pointer1 = nvme_dma_address(queue->sq);
    command.cdw10 = ((NVME_QUEUE_DEPTH - 1U) << 16U) | queue->qid;
    command.cdw11 = ((uint32_t)queue->qid << 16U) | 1U;
    xaios_status_t submission_queue = submit_admin(controller, &command, 0);
    if (submission_queue != XAIOS_OK) {
      klog("nvme: create io submission queue refused qid=%u status=%d\n",
           (unsigned)queue->qid, (int)submission_queue);
      return XAIOS_ERR_IO;
    }
  }
  return XAIOS_OK;
}

/* Stop the controller and re-arm it over the memory it already has.
 *
 * Written for B-100. The emulated device answered a command the host never
 * submitted -- four times, on the admin queue and on the I/O queue -- and the
 * request behind it was then never completed, while the host's rings and the
 * device's own registers were both correct at the failure. The answer the NVMe
 * specification gives for a controller that has stopped answering is a reset
 * and a retry, so this is that: disable, wait for the device to say it is not
 * ready, put every queue back to zero over its existing pages, program the
 * admin queue registers again, enable, and re-create the I/O queues. Nothing
 * here re-maps PCI, re-allocates memory or re-registers the block device, so a
 * restart cannot disturb the rest of the machine -- and every outstanding
 * request is failed by the reset, which is why callers run it only when they
 * have already given up on one. */
xaios_status_t nvme_restart_controller(nvme_controller_t *controller) {
  uint32_t cc = nvme_mmio_read32(controller, NVME_REG_CC);
  nvme_mmio_write32(controller, NVME_REG_CC, cc & ~NVME_CC_ENABLE);
  if (wait_ready(controller, 0U) != XAIOS_OK) {
    klog("nvme: controller restart failed step=disable\n");
    return XAIOS_ERR_IO;
  }
  nvme_reset_queue(&controller->admin);
  for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
    nvme_reset_queue(&controller->io[index]);
  }
  nvme_mmio_write32(controller, NVME_REG_AQA,
               ((NVME_QUEUE_DEPTH - 1U) << 16U) | (NVME_QUEUE_DEPTH - 1U));
  nvme_mmio_write64(controller, NVME_REG_ASQ, nvme_dma_address(controller->admin.sq));
  nvme_mmio_write64(controller, NVME_REG_ACQ, nvme_dma_address(controller->admin.cq));
  nvme_mmio_write32(controller, NVME_REG_CC,
               NVME_CC_ENABLE | (6U << 16U) | (4U << 20U));
  if (wait_ready(controller, NVME_CSTS_READY) != XAIOS_OK) {
    klog("nvme: controller restart failed step=enable\n");
    return XAIOS_ERR_IO;
  }
  return nvme_create_io_queues(controller);
}
