/*
 * The NVMe completion path. See nvme_completion.h.
 */

#include "nvme_completion.h"

int completion_fields_valid(const nvme_completion_t *completion,
                                   uint16_t qid, uint16_t expected_cid) {
  return completion != 0 && completion->sq_id == qid &&
         completion->sq_head < NVME_QUEUE_DEPTH &&
         completion->cid == expected_cid &&
         ((completion->status >> 1U) & UINT16_C(0x7ff)) == 0U;
}

void record_completion(nvme_queue_t *queue,
                              const nvme_completion_t *completion,
                              uint16_t matched_cid) {
  nvme_completion_trace_t *trace = &queue->trace[queue->trace_next];
  trace->cq_head = queue->cq_head;
  trace->cid = completion->cid;
  trace->matched_cid = matched_cid;
  trace->sq_head = completion->sq_head;
  trace->status = completion->status;
  trace->sq_id = completion->sq_id;
  queue->trace_next = (queue->trace_next + 1U) % NVME_TRACE_ENTRIES;
  ++queue->completions_consumed;
}

void report_sq_slot(const nvme_queue_t *queue, uint16_t index) {
  if (index >= NVME_QUEUE_DEPTH) {
    klog("nvme: queue %u sq slot %u out of range\n", (unsigned)queue->qid,
         (unsigned)index);
    return;
  }
  const nvme_command_t *command = &queue->sq[index];
  klog("nvme: queue %u sq[%u] opcode=%u cid=%u nsid=%u cdw10=0x%x\n",
       (unsigned)queue->qid, (unsigned)index, (unsigned)command->opcode,
       (unsigned)command->cid, (unsigned)command->nsid,
       (unsigned)command->cdw10);
}

void report_sq_neighbourhood(const nvme_queue_t *queue, uint16_t index) {
  report_sq_slot(queue, (uint16_t)((index + NVME_QUEUE_DEPTH - 1U) %
                                   NVME_QUEUE_DEPTH));
  report_sq_slot(queue, index);
  report_sq_slot(queue, (uint16_t)((index + 1U) % NVME_QUEUE_DEPTH));
}

void report_queue_trace(const nvme_queue_t *queue, const char *reason) {
  uint32_t available = queue->completions_consumed < NVME_TRACE_ENTRIES
                           ? (uint32_t)queue->completions_consumed
                           : NVME_TRACE_ENTRIES;
  klog("nvme: queue %u completions=%lu cq_head=%u phase=%u sq_tail=%u "
       "outstanding=%u trace=%s\n",
       (unsigned)queue->qid, (unsigned long)queue->completions_consumed,
       (unsigned)queue->cq_head, (unsigned)queue->phase,
       (unsigned)queue->sq_tail, (unsigned)queue->outstanding, reason);
  for (uint32_t offset = 0U; offset < available; ++offset) {
    uint32_t index = (queue->trace_next + NVME_TRACE_ENTRIES - available +
                      offset) % NVME_TRACE_ENTRIES;
    const nvme_completion_trace_t *entry = &queue->trace[index];
    klog("nvme: queue %u trace[%u] cq_head=%u cid=%u matched=%u sq_id=%u "
         "sq_head=%u status=0x%04x\n",
         (unsigned)queue->qid, (unsigned)offset, (unsigned)entry->cq_head,
         (unsigned)entry->cid, (unsigned)entry->matched_cid,
         (unsigned)entry->sq_id, (unsigned)entry->sq_head,
         (unsigned)entry->status);
  }
}

xaios_status_t parser_check_failed(const char *check) {
  klog("nvme: completion parser self-test failed check=%s\n", check);
  return XAIOS_ERR_IO;
}

xaios_status_t completion_parser_self_test(void) {
  nvme_completion_t completion = {
      .sq_head = 1U, .sq_id = 2U, .cid = 7U, .status = 1U};
  if (!completion_fields_valid(&completion, 2U, 7U)) {
    return parser_check_failed("valid-completion");
  }
  completion.sq_id = 3U;
  if (completion_fields_valid(&completion, 2U, 7U)) {
    return parser_check_failed("wrong-queue");
  }
  completion.sq_id = 2U;
  completion.sq_head = NVME_QUEUE_DEPTH;
  if (completion_fields_valid(&completion, 2U, 7U)) {
    return parser_check_failed("head-out-of-range");
  }
  completion.sq_head = 1U;
  completion.cid = 8U;
  if (completion_fields_valid(&completion, 2U, 7U)) {
    return parser_check_failed("wrong-cid");
  }
  completion.cid = 7U;
  completion.status = UINT16_C(3);
  if (completion_fields_valid(&completion, 2U, 7U)) {
    return parser_check_failed("non-zero-status");
  }
  return XAIOS_OK;
}

void report_completion_reread(const nvme_queue_t *queue,
                                     const nvme_completion_t *first) {
  nvme_completion_t again = queue->cq[queue->cq_head];
  if (again.cid == first->cid && again.sq_head == first->sq_head &&
      again.sq_id == first->sq_id && again.status == first->status) {
    klog("nvme: queue %u completion reread agrees cid=%u sq_head=%u "
         "status=0x%04x -- the device wrote it that way\n",
         (unsigned)queue->qid, (unsigned)again.cid, (unsigned)again.sq_head,
         (unsigned)again.status);
    return;
  }
  klog("nvme: queue %u completion reread differs cid=%u sq_head=%u "
       "status=0x%04x first_cid=%u first_sq_head=%u first_status=0x%04x -- the "
       "first read raced the device\n",
       (unsigned)queue->qid, (unsigned)again.cid, (unsigned)again.sq_head,
       (unsigned)again.status, (unsigned)first->cid, (unsigned)first->sq_head,
       (unsigned)first->status);
}

int completion_in_phase(const nvme_queue_t *queue, uint16_t index) {
  const volatile uint32_t *dword =
      (const volatile uint32_t *)((const uint8_t *)&queue->cq[index] + 12U);
  uint32_t tail = __atomic_load_n(dword, __ATOMIC_ACQUIRE);
  return (uint32_t)((tail >> 16) & 1U) == queue->phase ? 1 : 0;
}
