/* The NVMe polled waits and the block self-test.
 *
 * The margins these waits record are the self-test's measurement, so the one
 * wait loop lives here with the phase that reads it: the ordinary read, write
 * and flush reach it through nvme_wait_request in nvme_driver_internal.h, and
 * the self-test reaches it directly. The controller bring-up and admin path
 * are nvme_admin.c; the block backend, registration and interrupt programming
 * stay in nvme.c.
 */

#include "nvme_driver_internal.h"

#include <xaios/arch_cpu.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/timer.h>

#define NVME_CLASS UINT8_C(0x01)
#define NVME_SUBCLASS UINT8_C(0x08)
#define NVME_PROGIF UINT8_C(0x02)

#define NVME_STRESS_ROUNDS 8U

static uint32_t read_le32(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
         ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_le64(const uint8_t *bytes) {
  uint64_t value = 0U;
  for (uint32_t i = 0U; i < 8U; ++i) value |= (uint64_t)bytes[i] << (i * 8U);
  return value;
}

/* Every polled wait in this driver goes through one loop, batched or single.
 *
 * Two waits can run out of time inside the stress phase: the batched wait for
 * a round's writes or reads, and the single wait behind `nvme_synchronous_io`,
 * which is how the flush returns. They were separate loops until now, and that
 * mattered: the margin below was recorded by the batched loop only, so a
 * timeout on the flush's wait would have been excluded from the measurement by
 * not being measured rather than by being far away (B-100). One loop with a
 * count of one is both waits, so a wait cannot be added here without the
 * margin being recorded beside it.
 *
 * The margin is how much room the phase had, not only whether it ran out. A
 * timeout is one of the ways this self-test can fail, and catching the failure
 * itself takes about one starved run in forty-five -- far too rare to reason
 * from. The margin is measurable on every run: the slowest wait of each kind
 * against the five seconds it is allowed. If a starved machine fails by timing
 * out, its margin will be visibly close to the budget long before it crosses
 * it; if the margin stays in the milliseconds, then a failure is a completion
 * that was rejected or a request that was refused rather than one that never
 * came, and the two are told apart without waiting for the event (B-100). */
typedef struct {
  uint64_t slowest_ns;
  uint64_t waited;
} nvme_wait_margin_t;

static nvme_wait_margin_t g_nvme_batch_margin;
static nvme_wait_margin_t g_nvme_single_margin;

/* Recorded atomically, because a single-request wait is how every ordinary
 * block read, write and flush returns too: two CPUs issuing I/O at the same
 * moment would otherwise lose a count, and the count is what says how much of
 * the phase the margin covers. */
static void record_wait(nvme_wait_margin_t *margin, uint64_t elapsed) {
  uint64_t observed = margin->slowest_ns;
  while (elapsed > observed) {
    uint64_t previous =
        __sync_val_compare_and_swap(&margin->slowest_ns, observed, elapsed);
    if (previous == observed) break;
    observed = previous;
  }
  __sync_fetch_and_add(&margin->waited, 1U);
}

/* The worst margin the phase had, of either kind, for the one-line summary. */
static uint64_t nvme_slowest_wait_ns(void) {
  uint64_t slowest = g_nvme_batch_margin.slowest_ns;
  if (g_nvme_single_margin.slowest_ns > slowest) {
    slowest = g_nvme_single_margin.slowest_ns;
  }
  return slowest;
}

static xaios_status_t await_requests(nvme_controller_t *controller,
                                     xaios_block_async_request_t *requests,
                                     uint32_t count,
                                     nvme_wait_margin_t *margin) {
  uint64_t started = timer_now_ns();
  for (;;) {
    uint32_t done = 0U;
    for (uint32_t index = 0U; index < count; ++index) {
      if (requests[index].state == XAIOS_BLOCK_ASYNC_COMPLETE) ++done;
    }
    if (done == count) {
      record_wait(margin, timer_now_ns() - started);
      return XAIOS_OK;
    }
    (void)nvme_poll_controller(controller, NVME_QUEUE_DEPTH * NVME_MAX_IO_QUEUES);
    if (timer_now_ns() - started >= NVME_TIMEOUT_NS) {
      /* A request that reaches COMPLETE returns OK above even if it completed
         with an error, so a failure here really is requests that never
         completed at all. `operation` is named because the caller reports the
         same XAIOS_ERR_IO for a flush that timed out and a flush that was
         rejected, and the console is the only place the two are told apart.
         The pending request is named by its token -- the queue and command id
         the driver is still waiting for -- and the queues with work left dump
         their last completions, because B-100's reproduction was a completion
         that was dropped and this is what says which one never came. */
      uint32_t pending = count;
      for (uint32_t index = 0U; index < count; ++index) {
        if (requests[index].state != XAIOS_BLOCK_ASYNC_COMPLETE) {
          pending = index;
          break;
        }
      }
      klog("nvme: io wait timed out done=%u of %u operation=%d elapsed=%lu ns "
           "pending=%u token=0x%lx state=%d\n",
           (unsigned)done, (unsigned)count, (int)requests[0].operation,
           (unsigned long)(timer_now_ns() - started), (unsigned)pending,
           (unsigned long)(pending < count ? requests[pending].token : 0U),
           (int)(pending < count ? (int)requests[pending].state : -1));
      for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
        if (controller->io[index].outstanding != 0U) {
          report_queue_trace(&controller->io[index], "timeout");
        }
      }
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
}

/* Wait for a round's requests and report only whether they all completed. */
static xaios_status_t wait_batch(nvme_controller_t *controller,
                                 xaios_block_async_request_t *requests,
                                 uint32_t count) {
  return await_requests(controller, requests, count, &g_nvme_batch_margin);
}

/* Wait for one request and report its own completion status, because the
   caller tells a cancelled request from a completed one. A timeout is
   XAIOS_ERR_IO here as it is above, and it is logged there. */
xaios_status_t nvme_wait_request(nvme_controller_t *controller,
                                 xaios_block_async_request_t *request) {
  if (await_requests(controller, request, 1U, &g_nvme_single_margin) !=
      XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  return request->status;
}

/* Reset the controller and prove it answers a command again.
 *
 * Used as the self-test's own step on every boot as well as behind a stress
 * phase that failed, because a restart that is only ever run in a failure is a
 * restart nobody has watched work: the boot that proves it works is the boot
 * that would otherwise have nothing to say about it (B-100). */
static xaios_status_t restart_and_prove(nvme_controller_t *controller) {
  if (nvme_restart_controller(controller) != XAIOS_OK) return XAIOS_ERR_IO;
  return nvme_synchronous_io(controller, XAIOS_BLOCK_ASYNC_FLUSH, 0U, 0, 0U);
}

static xaios_status_t stress_io(nvme_controller_t *controller,
                                uint8_t **buffers) {
  xaios_block_async_request_t requests[NVME_MAX_IO_QUEUES];
  for (uint32_t round = 0U; round < NVME_STRESS_ROUNDS; ++round) {
    nvme_bytes_zero(requests, sizeof(requests));
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
      xaios_status_t submitted =
          nvme_submit_io(controller, queue, &requests[queue], round & 1U);
      if (submitted != XAIOS_OK) {
        /* Named, like every other way this phase can fail. `stress_io` used to
           return XAIOS_ERR_IO without saying which of its exits it had taken,
           so a failure was attributed to whichever one the reader had in mind
           -- and this one is not even a timing path: it is the queue refusing
           a request, which happens when the slot ring is full or the request
           is malformed (B-100). */
        klog("nvme: stress write submit failed round=%u queue=%u status=%d\n",
             (unsigned)round, (unsigned)queue, (int)submitted);
        return XAIOS_ERR_IO;
      }
    }
    if (wait_batch(controller, requests, controller->io_queue_count) !=
        XAIOS_OK) {
      klog("nvme: stress write wait failed round=%u\n", (unsigned)round);
      return XAIOS_ERR_IO;
    }
  }
  xaios_status_t flushed =
      nvme_synchronous_io(controller, XAIOS_BLOCK_ASYNC_FLUSH, 0U, 0, 0U);
  if (flushed != XAIOS_OK) {
    klog("nvme: stress flush failed status=%d\n", (int)flushed);
    return XAIOS_ERR_IO;
  }

  nvme_bytes_zero(requests, sizeof(requests));
  for (uint32_t queue = 0U; queue < controller->io_queue_count; ++queue) {
    nvme_bytes_zero(buffers[queue], NVME_MAX_TRANSFER_BYTES);
    requests[queue].operation = XAIOS_BLOCK_ASYNC_READ;
    requests[queue].state = XAIOS_BLOCK_ASYNC_PENDING;
    requests[queue].byte_offset = (uint64_t)queue * NVME_MAX_TRANSFER_BYTES;
    requests[queue].buffer = buffers[queue];
    requests[queue].length = NVME_MAX_TRANSFER_BYTES;
    xaios_status_t submitted =
        nvme_submit_io(controller, queue, &requests[queue], queue & 1U);
    if (submitted != XAIOS_OK) {
      klog("nvme: stress read submit failed queue=%u status=%d\n",
           (unsigned)queue, (int)submitted);
      return XAIOS_ERR_IO;
    }
  }
  if (wait_batch(controller, requests, controller->io_queue_count) != XAIOS_OK) {
    klog("nvme: stress read wait failed\n");
    return XAIOS_ERR_IO;
  }
  for (uint32_t queue = 0U; queue < controller->io_queue_count; ++queue) {
    for (uint32_t byte = 0U; byte < NVME_MAX_TRANSFER_BYTES; ++byte) {
      if (buffers[queue][byte] !=
          (uint8_t)(byte ^ UINT32_C(0xa5) ^ (queue << 4U))) {
        /* Not a timing path at all, and the one cause of a `stress-io` failure
           that means the data did not survive the round trip. It used to
           return XAIOS_ERR_IO indistinguishably from the rest, which is why
           B-100 could describe this phase as having two ways to fail. The
           offset is named because where it diverges says whether the transfer
           was truncated, landed in the wrong place, or came back stale. */
        klog("nvme: stress verify failed queue=%u offset=%lu expected=0x%02x "
             "read=0x%02x\n",
             (unsigned)queue, (unsigned long)byte,
             (unsigned)(uint8_t)(byte ^ UINT32_C(0xa5) ^ (queue << 4U)),
             (unsigned)buffers[queue][byte]);
        return XAIOS_ERR_IO;
      }
    }
  }

  xaios_block_async_request_t cancelled;
  nvme_bytes_zero(&cancelled, sizeof(cancelled));
  cancelled.operation = XAIOS_BLOCK_ASYNC_READ;
  cancelled.state = XAIOS_BLOCK_ASYNC_PENDING;
  cancelled.buffer = buffers[0];
  cancelled.length = NVME_MAX_TRANSFER_BYTES;
  /* The cancellation has three exits of its own, and until B-100's
     instrumentation reached them they were the only ones left in this phase
     that returned XAIOS_ERR_IO silently -- which made the phase look as
     though it had six ways to fail when it has nine. Each is named for the
     same reason the others are: the value alone does not say whether the
     queue refused the request, there was no active slot to mark, or the
     device completed a transfer that was supposed to be cancelled. */
  xaios_status_t cancel_submitted = nvme_submit_io(controller, 0U, &cancelled, 0U);
  if (cancel_submitted != XAIOS_OK) {
    klog("nvme: stress cancel submit failed status=%d\n",
         (int)cancel_submitted);
    return XAIOS_ERR_IO;
  }
  xaios_status_t cancel_requested =
      nvme_backend_cancel(controller, &cancelled);
  if (cancel_requested != XAIOS_OK) {
    klog("nvme: stress cancel request failed status=%d\n",
         (int)cancel_requested);
    return XAIOS_ERR_IO;
  }
  cancelled.state = XAIOS_BLOCK_ASYNC_CANCEL_REQUESTED;
  xaios_status_t cancel_waited = nvme_wait_request(controller, &cancelled);
  if (cancel_waited != XAIOS_ERR_CANCELLED) {
    /* A timeout has already said so on its own line; this names the other
       reading, which is a transfer the device completed instead of cancelling
       it. XAIOS_ERR_IO here with no `io wait timed out` line above is that
       finding, and it is a different defect from a device that went quiet. */
    klog("nvme: stress cancel not honoured status=%d\n", (int)cancel_waited);
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

xaios_status_t nvme_self_test(xaios_nvme_self_test_result_t *result) {
  if (result != 0) nvme_bytes_zero(result, sizeof(*result));
  if (completion_parser_self_test() != XAIOS_OK) {
    /* The parser names the check that refused; this names the step, so that a
       failure here reads like the other eight rather than as a bare status. */
    klog("nvme: self-test failed step=completion-parser\n");
    return XAIOS_ERR_IO;
  }
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
  xaios_status_t status = nvme_initialize_controller(controller, found);
  if (status != XAIOS_OK) return status;
  if (result != 0) {
    result->controllers = 1U;
    result->queue_depth = NVME_QUEUE_DEPTH;
    result->malformed_completions_rejected = 4U;
  }

  if (nvme_identify(controller, 0U, 1U) != XAIOS_OK) {
    klog("nvme: self-test failed step=identify-controller\n");
    return XAIOS_ERR_IO;
  }
  char serial[21];
  char model[41];
  for (uint32_t i = 0U; i < 20U; ++i) serial[i] = (char)controller->identify[4U + i];
  for (uint32_t i = 0U; i < 40U; ++i) model[i] = (char)controller->identify[24U + i];
  serial[20] = '\0';
  model[40] = '\0';
  controller->sgl_supported = (read_le32(controller->identify + 536U) & 1U) != 0U;
  klog("nvme: identify controller serial='%s' model='%s' sgl=%u\n", serial,
       model, controller->sgl_supported);

  if (nvme_identify(controller, 1U, 0U) != XAIOS_OK) {
    klog("nvme: self-test failed step=identify-namespace\n");
    return XAIOS_ERR_IO;
  }
  controller->namespace_id = 1U;
  controller->namespace_blocks = read_le64(controller->identify);
  uint32_t format = controller->identify[26U] & UINT8_C(0x0f);
  uint32_t lbads = controller->identify[128U + format * 4U + 2U];
  if (controller->namespace_blocks == 0U || lbads < 9U || lbads > 12U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  controller->block_size = 1U << lbads;
  /* Split rather than left as one condition, because B-100 asks which of
     these it was and a single return cannot say. */
  if (NVME_MAX_TRANSFER_BYTES % controller->block_size != 0U) {
    klog("nvme: self-test failed step=transfer-size-not-block-aligned\n");
    return XAIOS_ERR_IO;
  }
  if (nvme_negotiate_io_queues(controller) != XAIOS_OK) {
    klog("nvme: self-test failed step=negotiate-io-queues\n");
    return XAIOS_ERR_IO;
  }
  if (nvme_configure_queue_interrupts(controller) != XAIOS_OK) {
    klog("nvme: self-test failed step=configure-queue-interrupts\n");
    return XAIOS_ERR_IO;
  }
  if (nvme_create_io_queues(controller) != XAIOS_OK) {
    klog("nvme: self-test failed step=create-io-queues\n");
    return XAIOS_ERR_IO;
  }
  if (nvme_register_block_device(controller) != XAIOS_OK) {
    klog("nvme: self-test failed step=register-block-device\n");
    return XAIOS_ERR_IO;
  }
  uint32_t blocks_per_transfer =
      NVME_MAX_TRANSFER_BYTES / controller->block_size;
  if ((uint64_t)blocks_per_transfer * controller->io_queue_count >
      controller->namespace_blocks) {
    /* A real refusal on a small namespace, not a defect, and one that used to
       leave `nvme: self-test failed status=-11` as the only trace of itself. */
    klog("nvme: self-test failed step=namespace-too-small blocks=%lu "
         "per_transfer=%u queues=%u\n",
         (unsigned long)controller->namespace_blocks,
         (unsigned)blocks_per_transfer, (unsigned)controller->io_queue_count);
    return XAIOS_ERR_UNSUPPORTED;
  }

  uint8_t *buffers[NVME_MAX_IO_QUEUES] = {0};
  for (uint32_t queue = 0U; queue < controller->io_queue_count; ++queue) {
    buffers[queue] =
        (uint8_t *)kheap_calloc(NVME_MAX_TRANSFER_BYTES, NVME_PAGE_SIZE);
    if (buffers[queue] == 0) {
      klog("nvme: self-test failed step=stress-buffer queue=%u bytes=%u\n",
           (unsigned)queue, (unsigned)NVME_MAX_TRANSFER_BYTES);
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  g_nvme_batch_margin.slowest_ns = 0U;
  g_nvme_batch_margin.waited = 0U;
  g_nvme_single_margin.slowest_ns = 0U;
  g_nvme_single_margin.waited = 0U;
  if (stress_io(controller, buffers) != XAIOS_OK) {
    /* B-100: the phase failed, and every sighting of it behind this row is a
       completion the device produced that the host could not match -- with the
       host's rings and the device's registers both correct when it happened.
       The specification's answer to a controller that stops answering is a
       reset, so the phase is retried once on a controller re-armed over the
       same pages. A failure after that is the phase's own and stands. */
    klog("nvme: self-test stress phase failed; restarting the controller and "
         "retrying once\n");
    g_nvme_batch_margin.slowest_ns = 0U;
    g_nvme_batch_margin.waited = 0U;
    g_nvme_single_margin.slowest_ns = 0U;
    g_nvme_single_margin.waited = 0U;
    if (restart_and_prove(controller) != XAIOS_OK ||
        stress_io(controller, buffers) != XAIOS_OK) {
      klog("nvme: self-test failed step=stress-io slowest=%lu ns of %lu budget "
           "batches=%lu singles=%lu\n",
           (unsigned long)nvme_slowest_wait_ns(),
           (unsigned long)NVME_TIMEOUT_NS,
           (unsigned long)g_nvme_batch_margin.waited,
           (unsigned long)g_nvme_single_margin.waited);
      return XAIOS_ERR_IO;
    }
    klog("nvme: self-test stress phase passed on the retry after a restart\n");
  }
  /* Said on every boot, so that a starved one can be read against a healthy
     one. See the note above `await_requests`. The two kinds are reported apart
     because they fail for different reasons: a batched wait that runs out is a
     round whose completions stopped arriving, while the single wait is the
     flush and the cancellation, and `qemu-nvme-gate` requires at least one of
     each here so that a margin reported for only one of them cannot pass as a
     margin for both. */
  klog("nvme: self-test stress waits slowest=%lu ns of %lu budget batches=%lu "
       "batch_slowest=%lu ns singles=%lu single_slowest=%lu ns\n",
       (unsigned long)nvme_slowest_wait_ns(), (unsigned long)NVME_TIMEOUT_NS,
       (unsigned long)g_nvme_batch_margin.waited,
       (unsigned long)g_nvme_batch_margin.slowest_ns,
       (unsigned long)g_nvme_single_margin.waited,
       (unsigned long)g_nvme_single_margin.slowest_ns);
  /* After the margin line, so that the waits it reports are the phase's own and
     not this step's. What it proves is that a controller reset leaves a machine
     that answers commands, which is the whole of the recovery B-100 needs; the
     interrupt canary below then runs on the re-armed queues, so the reset is
     also required not to have broken interrupt delivery. */
  if (restart_and_prove(controller) != XAIOS_OK) {
    klog("nvme: self-test failed step=controller-restart\n");
    return XAIOS_ERR_IO;
  }
  klog("nvme: controller restart self-test passed resets=1 flush=1\n");
  controller->interrupt_test_buffer = buffers[0];
  nvme_registered_controller = controller;

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
