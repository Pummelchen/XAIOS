/*
 * The NVMe completion path: phase-tagged completion parsing, the parser's own
 * checks, and the trace it leaves when a completion does not make sense.
 *
 * Split out of nvme.c, which was 1701 lines. Nothing here touches the
 * controller or the queue margins -- it reads a completion and reports on it --
 * so the module carries no file-scope state and nvme.c keeps ownership of the
 * controller.
 */

#ifndef XAIOS_KERNEL_DEV_NVME_COMPLETION_H
#define XAIOS_KERNEL_DEV_NVME_COMPLETION_H

#include <xaios/klog.h>
#include <xaios/block_device.h>
#include <xaios/nvme.h>
#include <xaios/spinlock.h>

/* Queue geometry the completion path shares with the driver. */
#define NVME_QUEUE_DEPTH 16U
#define NVME_TRACE_ENTRIES 8U



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

/* The last few completions a queue consumed, kept so that a completion the
 * driver cannot match -- and the wait it leaves behind -- can be read against
 * what came before it rather than on its own. A ring rather than a line per
 * completion: the lines would be noise on every boot and still not enough
 * context on the boot that matters. This exists because B-100 was reproduced
 * with a dropped completion (cid=0, sq_head=0, no matching request) and the
 * next question is what the device had been answering before it. */

typedef struct {
  uint16_t cq_head;
  uint16_t cid;
  uint16_t matched_cid;
  uint16_t sq_head;
  uint16_t status;
  uint16_t sq_id;
} nvme_completion_trace_t;

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
  nvme_completion_trace_t trace[NVME_TRACE_ENTRIES];
  uint32_t trace_next;
  uint64_t completions_consumed;
  struct nvme_controller *controller;
} nvme_queue_t;

int completion_fields_valid(const nvme_completion_t *completion,
                                   uint16_t qid, uint16_t expected_cid);
void record_completion(nvme_queue_t *queue,
                              const nvme_completion_t *completion,
                              uint16_t matched_cid);
void report_sq_slot(const nvme_queue_t *queue, uint16_t index);
void report_sq_neighbourhood(const nvme_queue_t *queue, uint16_t index);
void report_queue_trace(const nvme_queue_t *queue, const char *reason);
xaios_status_t parser_check_failed(const char *check);
xaios_status_t completion_parser_self_test(void);
void report_completion_reread(const nvme_queue_t *queue,
                                     const nvme_completion_t *first);
int completion_in_phase(const nvme_queue_t *queue, uint16_t index);

#endif /* XAIOS_KERNEL_DEV_NVME_COMPLETION_H */
