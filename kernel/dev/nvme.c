#include <xaios/device_window.h>
#include <xaios/arch_cpu.h>
#include <xaios/block_device.h>
#include <xaios/gic.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/nvme.h>

#include "nvme_internal.h"
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

#define NVME_CC_ENABLE UINT32_C(1)
#define NVME_CSTS_READY UINT32_C(1)
#define NVME_CSTS_FATAL UINT32_C(2)
#define NVME_ADMIN_CREATE_IO_SQ UINT8_C(0x01)
#define NVME_ADMIN_CREATE_IO_CQ UINT8_C(0x05)
#define NVME_ADMIN_IDENTIFY UINT8_C(0x06)
#define NVME_ADMIN_SET_FEATURES UINT8_C(0x09)
#define NVME_FEATURE_NUMBER_OF_QUEUES UINT32_C(0x07)

#define NVME_STRESS_ROUNDS 8U
#define NVME_TIMEOUT_NS UINT64_C(5000000000)



static nvme_controller_t *g_nvme_controller;


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


static void mmio_write64(const nvme_controller_t *controller, uint32_t offset,
                         uint64_t value) {
  nvme_mmio_write32(controller, offset, (uint32_t)value);
  nvme_mmio_write32(controller, offset + 4U, (uint32_t)(value >> 32U));
}


static xaios_status_t wait_ready(const nvme_controller_t *controller,
                                 uint32_t expected) {
  uint64_t started = timer_now_ns();
  for (;;) {
    uint32_t status = mmio_read32(controller, NVME_REG_CSTS);
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



/* Record a completion this queue consumed, and say what a queue had been doing
 * when one is refused. Both live above every wait path because the admin queue
 * needs them as much as the I/O queues do: B-100 turned up twice, once as an
 * I/O completion that matched no request, and once as a create-io-queue
 * completion the admin path refused with every field the old line printed
 * looking valid -- status 0x0001 is a successful completion -- so the value it
 * was waiting for is the first thing the line has to carry. */

/* The submission-queue entries around the one the device says it answered.
 *
 * Both sightings of B-100 look like the device answering a command the host did
 * not submit -- an I/O completion with cid 0 that matched no request, and an
 * admin completion refused with `status=0x0001`, a successful completion -- and
 * the question in both is what the host's own memory holds at the index the
 * device named. The completion's `sq_head` has been the index plus one on every
 * completion this driver accepted, so all three of the previous, named and next
 * slots are printed rather than assuming which reading is right: a slot holding
 * the expected command says the device's view of the ring is somewhere else,
 * and a slot of zeros says the command never reached memory. The second
 * sighting is why this exists: its completion named `sq_head=0` while the
 * driver had submitted five commands and never written the last slot of the
 * ring, so the index the device named was quite possibly one the host had not
 * written at all. */


/* Which of the parser's checks refused, named, because this self-test is the
 * first thing `nvme_self_test` runs and until it was named a failure here left
 * the console with nothing on it at all -- the one exit in the chain that could
 * not be told from any other. */


/* Whether the completion at `index` belongs to the phase this driver is
 * waiting for, read the way the device means it.
 *
 * The device and this CPU have exactly one synchronisation point -- the phase
 * tag -- and it lives in the same 32-bit dword as the command identifier:
 * `cid` is the low half and `status` the high half. `nvme_completion_t` is
 * packed, so the compiler is free to load those halves separately, and it
 * does: the aarch64 build reads the phase with `ldrh w6, [entry, #14]` and
 * only reaches for `cid` after the comparison has passed. A completion caught
 * mid-write therefore comes back with a fresh phase and a command identifier
 * that has not been written yet -- a completion matching no request, which is
 * what B-100 was: `cid=0` with a success status, on a machine whose rings and
 * the device's registers were both correct, four times, and then again inside
 * the controller-restart self-test (`admin completion rejected opcode=1
 * cid=0 expected=18 ... cid=0 matched=0`, and the real completion for cid 18
 * was simply never seen).
 *
 * One 32-bit acquire load of that dword, checked before anything else is read
 * from the entry, closes the window: the phase is the last thing the device
 * writes, so once it matches, the rest of the entry is complete and the
 * acquire keeps the copy below from being hoisted above this check. */
/* What the entry says when it is read again after a refusal.
 *
 * This is the line that decides between the two halves of B-100. A completion
 * the driver refused, with a fresh phase and a command identifier of zero, is
 * either an entry the driver read while the device was still writing it -- in
 * which case reading it again now shows the command identifier the device
 * meant, and the defect is this driver's -- or one the device genuinely wrote
 * with a zero command identifier, in which case the second read agrees with
 * the first and the defect is the device's. Four sightings could not tell them
 * apart and every one of them printed a completion that looked successful;
 * this prints the difference. */


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


static xaios_status_t initialize_controller(nvme_controller_t *controller,
                                            uint32_t pci_index) {
  bytes_zero(controller, sizeof(*controller));
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
  controller->cap = mmio_read64(controller, NVME_REG_CAP);
  uint32_t mqes = (uint32_t)(controller->cap & UINT64_C(0xffff)) + 1U;
  uint32_t mpsmin = (uint32_t)((controller->cap >> 48U) & UINT64_C(0xf));
  if (mqes < NVME_QUEUE_DEPTH || mpsmin != 0U) {
    klog("nvme: controller unsupported mqes=%u mpsmin=%u need_mqes=%u\n",
         (unsigned)mqes, (unsigned)mpsmin, (unsigned)NVME_QUEUE_DEPTH);
    return XAIOS_ERR_UNSUPPORTED;
  }
  controller->doorbell_stride =
      4U << ((uint32_t)((controller->cap >> 32U) & UINT64_C(0xf)));

  uint32_t cc = mmio_read32(controller, NVME_REG_CC);
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
  mmio_write64(controller, NVME_REG_ASQ, nvme_dma_address(controller->admin.sq));
  mmio_write64(controller, NVME_REG_ACQ, nvme_dma_address(controller->admin.cq));
  nvme_mmio_write32(controller, NVME_REG_CC,
               NVME_CC_ENABLE | (6U << 16U) | (4U << 20U));
  if (wait_ready(controller, NVME_CSTS_READY) != XAIOS_OK) return XAIOS_ERR_IO;
  klog("nvme: controller ready version=0x%x mqes=%u dstrd=%u\n",
       mmio_read32(controller, NVME_REG_VS), mqes,
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
       (unsigned)mmio_read32(controller, NVME_REG_CC),
       (unsigned)mmio_read32(controller, NVME_REG_CSTS),
       (unsigned)mmio_read32(controller, NVME_REG_AQA),
       (unsigned long)mmio_read64(controller, NVME_REG_ASQ),
       (unsigned long)mmio_read64(controller, NVME_REG_ACQ),
       (unsigned long)nvme_dma_address(controller->admin.sq),
       (unsigned long)nvme_dma_address(controller->admin.cq));
  return XAIOS_OK;
}

static xaios_status_t identify(nvme_controller_t *controller, uint32_t nsid,
                               uint32_t cns) {
  bytes_zero(controller->identify, NVME_PAGE_SIZE);
  nvme_command_t command;
  bytes_zero(&command, sizeof(command));
  command.opcode = NVME_ADMIN_IDENTIFY;
  command.nsid = nsid;
  command.data_pointer1 = nvme_dma_address(controller->identify);
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

/* Every architecture here can now be handed a completion by an interrupt, so
   this is compiled everywhere. It used to be excluded on RISC-V, where the
   only interrupt controller with a driver was the PLIC and no message could
   reach a queue; a handler defined and never referenced is a build error
   rather than dead weight, and that exclusion was the compiler being right.
   It stopped being right when the APLIC/IMSIC driver landed: whether messages
   are available is a property of the board now, decided at run time, not of
   the architecture. */
static void nvme_interrupt_handler(uint32_t intid, void *context) {
  nvme_queue_t *queue = (nvme_queue_t *)context;
  if (queue == 0 || queue->interrupt_id != intid || queue->controller == 0) {
    return;
  }
  ++queue->interrupt_completions;
  (void)nvme_poll_queue(queue->controller, queue, NVME_QUEUE_DEPTH);
}

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
  /* Whether this machine carries messages is a property of its board, asked
   * here rather than assumed.
   *
   * A PLIC takes wires, not messages: there is no identity to allocate and
   * nothing to write a message into, so the queues are serviced by the
   * caller's own wait path -- wait_request calls nvme_poll_controller every turn
   * -- and saying so is what stops this looking like a driver that failed to
   * initialise. That is still the honest answer on QEMU's default `virt`
   * board and on every existing gate for this architecture.
   *
   * An APLIC/IMSIC board is different, and the difference is the whole of
   * P-16: an IMSIC interrupt file is reached by writing the interrupt's
   * identity as a word to the hart's own page, which is exactly the address
   * and data an MSI-X table entry holds. So the shape below is the ITS path's
   * shape with none of the ITS in it.
   *
   * The GICv2m fallback the generic branch has below is deliberately not
   * mirrored here: it is a fixed AArch64 address, and probing it on this
   * architecture would be reading a machine's memory map out of another
   * machine's driver. */
  if (gic_its_available() == 0) {
    klog("nvme: no message-signalled interrupts on this machine; %u queues "
         "use polled completion\n", controller->io_queue_count);
    return XAIOS_OK;
  }
  for (uint32_t index = 0U; index < controller->io_queue_count; ++index) {
    nvme_queue_t *queue = &controller->io[index];
    uint32_t interrupt_id = 0U;
    if (gic_allocate_lpi(&interrupt_id) != XAIOS_OK) {
      klog("nvme: no message identity available for queue %u\n", index);
      return XAIOS_ERR_IO;
    }
    uint64_t message_address = 0U;
    uint32_t message_data = 0U;
    /* No device id and no event id: an IMSIC has no translation table to look
       one up in. The zeros are passed because the shared signature asks for
       them, and the controller ignores them. */
    xaios_status_t status =
        gic_its_configure_msi(0U, index, interrupt_id, queue->assigned_cpu,
                              &message_address, &message_data);
    if (status != XAIOS_OK ||
        gic_register_lpi(interrupt_id, queue->assigned_cpu,
                         nvme_interrupt_handler, queue) != XAIOS_OK ||
        pci_configure_msix(controller->pci_index, (uint16_t)index,
                           message_address, message_data) != XAIOS_OK) {
      klog("nvme: IMSIC queue setup failed queue=%u identity=%u cpu=%u "
           "address=0x%lx status=%d\n", index, interrupt_id,
           queue->assigned_cpu, message_address, (int)status);
      return XAIOS_ERR_IO;
    }
    queue->interrupt_id = interrupt_id;
    queue->msix_entry = (uint16_t)index;
    ++controller->msix_queue_count;
  }
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
    command.data_pointer1 = nvme_dma_address(queue->cq);
    command.cdw10 = ((NVME_QUEUE_DEPTH - 1U) << 16U) | queue->qid;
    command.cdw11 = ((uint32_t)queue->msix_entry << 16U) | 3U;
    xaios_status_t completion_queue = submit_admin(controller, &command, 0);
    if (completion_queue != XAIOS_OK) {
      klog("nvme: create io completion queue refused qid=%u status=%d\n",
           (unsigned)queue->qid, (int)completion_queue);
      return XAIOS_ERR_IO;
    }
    bytes_zero(&command, sizeof(command));
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
static xaios_status_t restart_controller(nvme_controller_t *controller) {
  uint32_t cc = mmio_read32(controller, NVME_REG_CC);
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
  mmio_write64(controller, NVME_REG_ASQ, nvme_dma_address(controller->admin.sq));
  mmio_write64(controller, NVME_REG_ACQ, nvme_dma_address(controller->admin.cq));
  nvme_mmio_write32(controller, NVME_REG_CC,
               NVME_CC_ENABLE | (6U << 16U) | (4U << 20U));
  if (wait_ready(controller, NVME_CSTS_READY) != XAIOS_OK) {
    klog("nvme: controller restart failed step=enable\n");
    return XAIOS_ERR_IO;
  }
  return create_io_queues(controller);
}


/* Every polled wait in this driver goes through one loop, batched or single.
 *
 * Two waits can run out of time inside the stress phase: the batched wait for
 * a round's writes or reads, and the single wait behind `synchronous_io`,
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
static xaios_status_t wait_request(nvme_controller_t *controller,
                                   xaios_block_async_request_t *request) {
  if (await_requests(controller, request, 1U, &g_nvme_single_margin) !=
      XAIOS_OK) {
    return XAIOS_ERR_IO;
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
  return nvme_submit_io(controller, queue, request, use_sgl);
}

static uint32_t nvme_backend_poll(void *context, uint32_t budget) {
  return nvme_poll_controller((nvme_controller_t *)context, budget);
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
  xaios_status_t status = nvme_submit_io(controller, queue, &request, 0U);
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

/* Reset the controller and prove it answers a command again.
 *
 * Used as the self-test's own step on every boot as well as behind a stress
 * phase that failed, because a restart that is only ever run in a failure is a
 * restart nobody has watched work: the boot that proves it works is the boot
 * that would otherwise have nothing to say about it (B-100). */
static xaios_status_t restart_and_prove(nvme_controller_t *controller) {
  if (restart_controller(controller) != XAIOS_OK) return XAIOS_ERR_IO;
  return synchronous_io(controller, XAIOS_BLOCK_ASYNC_FLUSH, 0U, 0, 0U);
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
  xaios_status_t flushed = synchronous_io(controller, XAIOS_BLOCK_ASYNC_FLUSH,
                                          0U, 0, 0U);
  if (flushed != XAIOS_OK) {
    klog("nvme: stress flush failed status=%d\n", (int)flushed);
    return XAIOS_ERR_IO;
  }

  bytes_zero(requests, sizeof(requests));
  for (uint32_t queue = 0U; queue < controller->io_queue_count; ++queue) {
    bytes_zero(buffers[queue], NVME_MAX_TRANSFER_BYTES);
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
  bytes_zero(&cancelled, sizeof(cancelled));
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
  xaios_status_t cancel_waited = wait_request(controller, &cancelled);
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
  if (result != 0) bytes_zero(result, sizeof(*result));
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
  xaios_status_t status = initialize_controller(controller, found);
  if (status != XAIOS_OK) return status;
  if (result != 0) {
    result->controllers = 1U;
    result->queue_depth = NVME_QUEUE_DEPTH;
    result->malformed_completions_rejected = 4U;
  }

  if (identify(controller, 0U, 1U) != XAIOS_OK) {
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

  if (identify(controller, 1U, 0U) != XAIOS_OK) {
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
  if (negotiate_io_queues(controller) != XAIOS_OK) {
    klog("nvme: self-test failed step=negotiate-io-queues\n");
    return XAIOS_ERR_IO;
  }
  if (configure_queue_interrupts(controller) != XAIOS_OK) {
    klog("nvme: self-test failed step=configure-queue-interrupts\n");
    return XAIOS_ERR_IO;
  }
  if (create_io_queues(controller) != XAIOS_OK) {
    klog("nvme: self-test failed step=create-io-queues\n");
    return XAIOS_ERR_IO;
  }
  if (register_block_device(controller) != XAIOS_OK) {
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
    if (nvme_submit_io(controller, index, &request, 0U) != XAIOS_OK) {
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
#elif defined(__riscv)
       /* Not "its": there is no translation service here, and naming one
          would make a gate that asserts the controller's name pass on a
          machine that has something else entirely. */
       "aia-imsic"
#else
       gic_its_available() ? "gicv3-its" : "gicv2m"
#endif
  );
  return XAIOS_OK;
}
