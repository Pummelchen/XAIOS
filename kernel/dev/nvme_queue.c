/*
 * The NVMe I/O queue machinery. See nvme_internal.h.
 *
 * This is the part of the driver that owns the queue rings and the requests
 * travelling on them: allocating a queue over its pages, putting it back to
 * that state after a controller reset, turning a block request into a
 * submission-queue command (including its data pointer), and polling
 * completions back out. The controller's bring-up, the admin path, the
 * block-device registration and the self-test stay in nvme.c, which calls into
 * these functions through nvme_internal.h.
 */

#include "nvme_internal.h"

#include <xaios/arch_cpu.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/vmm.h>

/* A file-local zeroing helper, as the other drivers in this tree carry. nvme.c
 * keeps its own copy; this is not a shared symbol. */
static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

void nvme_mmio_write32(const nvme_controller_t *controller, uint32_t offset,
                       uint32_t value) {
  *(volatile uint32_t *)(void *)(controller->bar + offset) = value;
  xaios_cpu_io_barrier();
}

uint64_t nvme_dma_address(const void *buffer) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  if (vmm_translate((uint64_t)(uintptr_t)buffer, &physical, &flags) != XAIOS_OK ||
      (flags & XAIOS_VMM_PRESENT) == 0U) {
    return 0U;
  }
  return physical;
}

uint32_t nvme_doorbell_offset(const nvme_controller_t *controller,
                              uint16_t qid, uint32_t completion) {
  uint32_t index = (uint32_t)qid * 2U + completion;
  return NVME_REG_DOORBELL + index * controller->doorbell_stride;
}

uint16_t nvme_allocate_cid(nvme_controller_t *controller) {
  ++controller->next_cid;
  if (controller->next_cid == 0U) ++controller->next_cid;
  return controller->next_cid;
}

xaios_status_t nvme_allocate_queue(nvme_queue_t *queue, uint16_t qid,
                                   uint32_t assigned_cpu,
                                   nvme_controller_t *controller) {
  queue->sq = (nvme_command_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  queue->cq = (nvme_completion_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
  if (queue->sq == 0 || queue->cq == 0) {
    klog("nvme: queue ring allocation failed qid=%u sq=%u cq=%u bytes=%u\n",
         (unsigned)qid, (unsigned)(queue->sq == 0),
         (unsigned)(queue->cq == 0), (unsigned)NVME_PAGE_SIZE);
    return XAIOS_ERR_NO_MEMORY;
  }
  queue->qid = qid;
  queue->phase = 1U;
  queue->assigned_cpu = assigned_cpu;
  queue->controller = controller;
  xaios_spin_init(&queue->lock);
  for (uint32_t slot = 0U; slot < NVME_QUEUE_DEPTH; ++slot) {
    queue->slots[slot].prp_list =
        (uint64_t *)kheap_calloc(NVME_PAGE_SIZE, NVME_PAGE_SIZE);
    if (queue->slots[slot].prp_list == 0) {
      klog("nvme: queue prp list allocation failed qid=%u slot=%u bytes=%u\n",
           (unsigned)qid, (unsigned)slot, (unsigned)NVME_PAGE_SIZE);
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

/* Put a queue back to the state it was in before it carried any work, over the
 * same pages and with the same interrupt binding. */
void nvme_reset_queue(nvme_queue_t *queue) {
  bytes_zero(queue->sq, NVME_PAGE_SIZE);
  bytes_zero(queue->cq, NVME_PAGE_SIZE);
  for (uint32_t slot = 0U; slot < NVME_QUEUE_DEPTH; ++slot) {
    uint64_t *prp_list = queue->slots[slot].prp_list;
    bytes_zero(&queue->slots[slot], sizeof(queue->slots[slot]));
    queue->slots[slot].prp_list = prp_list;
  }
  queue->sq_tail = 0U;
  queue->cq_head = 0U;
  queue->phase = 1U;
  queue->outstanding = 0U;
  queue->trace_next = 0U;
  queue->completions_consumed = 0U;
}

xaios_status_t nvme_prepare_data_pointer(nvme_controller_t *controller,
                                         nvme_request_slot_t *slot,
                                         nvme_command_t *command, void *buffer,
                                         uint32_t length, uint32_t use_sgl) {
  if (buffer == 0 || length == 0U || length > NVME_MAX_TRANSFER_BYTES ||
      ((uintptr_t)buffer & (NVME_PAGE_SIZE - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t first = nvme_dma_address(buffer);
  if (first == 0U) return XAIOS_ERR_IO;
  uint32_t pages = (length + (uint32_t)NVME_PAGE_SIZE - 1U) /
                   (uint32_t)NVME_PAGE_SIZE;
  if (use_sgl != 0U && controller->sgl_supported != 0U) {
    for (uint32_t page = 1U; page < pages; ++page) {
      uint64_t physical = nvme_dma_address((uint8_t *)buffer +
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
  uint64_t second = nvme_dma_address((uint8_t *)buffer + NVME_PAGE_SIZE);
  if (second == 0U) return XAIOS_ERR_IO;
  if (pages == 2U) {
    command->data_pointer2 = second;
    return XAIOS_OK;
  }
  bytes_zero(slot->prp_list, NVME_PAGE_SIZE);
  for (uint32_t page = 1U; page < pages; ++page) {
    uint64_t physical = nvme_dma_address((uint8_t *)buffer +
                                         (uint64_t)page * NVME_PAGE_SIZE);
    if (physical == 0U) return XAIOS_ERR_IO;
    slot->prp_list[page - 1U] = physical;
  }
  command->data_pointer2 = nvme_dma_address(slot->prp_list);
  return command->data_pointer2 == 0U ? XAIOS_ERR_IO : XAIOS_OK;
}

nvme_request_slot_t *nvme_free_slot(nvme_queue_t *queue) {
  for (uint32_t index = 0U; index < NVME_QUEUE_DEPTH; ++index) {
    if (queue->slots[index].active == 0U) return &queue->slots[index];
  }
  return 0;
}

nvme_request_slot_t *nvme_slot_for_cid(nvme_queue_t *queue, uint16_t cid) {
  for (uint32_t index = 0U; index < NVME_QUEUE_DEPTH; ++index) {
    if (queue->slots[index].active != 0U && queue->slots[index].cid == cid) {
      return &queue->slots[index];
    }
  }
  return 0;
}

xaios_status_t nvme_submit_io(nvme_controller_t *controller,
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
  nvme_request_slot_t *slot = nvme_free_slot(queue);
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
        nvme_prepare_data_pointer(controller, slot, &command, request->buffer,
                                  (uint32_t)request->length, use_sgl) != XAIOS_OK) {
      xaios_spin_unlock(&queue->lock);
      return XAIOS_ERR_INVALID;
    }
    uint64_t lba = request->byte_offset / controller->block_size;
    command.cdw10 = (uint32_t)lba;
    command.cdw11 = (uint32_t)(lba >> 32U);
    command.cdw12 = (uint32_t)(request->length / controller->block_size - 1U);
  }
  slot->cid = nvme_allocate_cid(controller);
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
  nvme_mmio_write32(controller, nvme_doorbell_offset(controller, queue->qid, 0U),
                    submitted_tail);
  return XAIOS_OK;
}

uint32_t nvme_poll_queue(nvme_controller_t *controller, nvme_queue_t *queue,
                         uint32_t budget) {
  uint32_t completed_count = 0U;
  while (completed_count < budget) {
    xaios_spin_lock(&queue->lock);
    xaios_cpu_io_barrier();
    if (completion_in_phase(queue, queue->cq_head) == 0) {
      xaios_spin_unlock(&queue->lock);
      break;
    }
    nvme_completion_t completion = queue->cq[queue->cq_head];
    nvme_request_slot_t *slot = nvme_slot_for_cid(queue, completion.cid);
    /* Recorded before the outcome is decided, so a refusal is read together
       with the completions that were accepted before it. */
    record_completion(queue, &completion, slot == 0 ? 0U : slot->cid);
    xaios_status_t status = XAIOS_ERR_IO;
    xaios_block_async_request_t *request = slot == 0 ? 0 : slot->request;
    if (slot != 0 &&
        completion_fields_valid(&completion, queue->qid, slot->cid)) {
      status = slot->cancel_requested != 0U ? XAIOS_ERR_CANCELLED : XAIOS_OK;
    } else {
      /* The device-error side of the I/O path, and the reason B-100 can now
         tell it from the timeout below: a completion arrived and could not be
         matched to the request it claims to answer. A cancelled request is not
         this -- that is a completion this driver asked for and matches
         perfectly well. */
      klog("nvme: io completion rejected qid=%u cid=%u sq_id=%u sq_head=%u "
           "status=0x%04x slot=%s\n",
           (unsigned)queue->qid, (unsigned)completion.cid,
           (unsigned)completion.sq_id, (unsigned)completion.sq_head,
           (unsigned)completion.status, slot == 0 ? "none" : "mismatched");
      report_completion_reread(queue, &completion);
      report_sq_neighbourhood(queue, completion.sq_head);
      report_queue_trace(queue, "rejected");
    }
    queue->cq_head = (uint16_t)(queue->cq_head + 1U);
    if (queue->cq_head == NVME_QUEUE_DEPTH) {
      queue->cq_head = 0U;
      queue->phase ^= 1U;
    }
    nvme_mmio_write32(controller, nvme_doorbell_offset(controller, queue->qid, 1U),
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

uint32_t nvme_poll_controller(nvme_controller_t *controller,
                              uint32_t budget) {
  uint32_t completed = 0U;
  for (uint32_t index = 0U;
       index < controller->io_queue_count && completed < budget; ++index) {
    completed += nvme_poll_queue(controller, &controller->io[index],
                                 budget - completed);
  }
  return completed;
}
