#include <xaios/device_window.h>
#include <xaios/arch_cpu.h>
#include <xaios/block_device.h>
#include <xaios/gic.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/nvme.h>

#include "nvme_driver_internal.h"
#include <xaios/pci.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>

nvme_controller_t *nvme_registered_controller;

typedef char nvme_command_size_must_be_64[(sizeof(nvme_command_t) == 64) ? 1 : -1];
typedef char nvme_completion_size_must_be_16[(sizeof(nvme_completion_t) == 16) ? 1 : -1];

void nvme_bytes_zero(void *buffer, uint64_t size) {
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

xaios_status_t nvme_configure_queue_interrupts(
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
   * caller's own wait path -- nvme_wait_request calls nvme_poll_controller every turn
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

xaios_status_t nvme_backend_cancel(
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

xaios_status_t nvme_synchronous_io(nvme_controller_t *controller,
                                     xaios_block_async_operation_t operation,
                                     uint64_t offset, void *buffer,
                                     uint64_t length) {
  xaios_block_async_request_t request;
  nvme_bytes_zero(&request, sizeof(request));
  request.operation = operation;
  request.state = XAIOS_BLOCK_ASYNC_PENDING;
  request.byte_offset = offset;
  request.buffer = buffer;
  request.length = length;
  uint32_t queue = __sync_fetch_and_add(&controller->next_queue, 1U) %
                   controller->io_queue_count;
  xaios_status_t status = nvme_submit_io(controller, queue, &request, 0U);
  return status == XAIOS_OK ? nvme_wait_request(controller, &request) : status;
}

static xaios_status_t nvme_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  return nvme_synchronous_io((nvme_controller_t *)context,
                             XAIOS_BLOCK_ASYNC_READ, offset, buffer, length);
}

static xaios_status_t nvme_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  return nvme_synchronous_io((nvme_controller_t *)context,
                             XAIOS_BLOCK_ASYNC_WRITE, offset, (void *)buffer,
                             length);
}

static xaios_status_t nvme_flush(void *context) {
  return nvme_synchronous_io((nvme_controller_t *)context,
                             XAIOS_BLOCK_ASYNC_FLUSH, 0U, 0, 0U);
}

static const xaios_block_backend_ops_t k_nvme_block_ops = {
    nvme_read, nvme_write, nvme_flush, 0, 0};
static const xaios_block_async_ops_t k_nvme_async_ops = {
    nvme_backend_submit, nvme_backend_poll, nvme_backend_cancel};

xaios_status_t nvme_register_block_device(nvme_controller_t *controller) {
  if (controller->namespace_blocks >
      UINT64_MAX / (uint64_t)controller->block_size) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  xaios_block_device_info_t info;
  nvme_bytes_zero(&info, sizeof(info));
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

xaios_status_t nvme_interrupt_self_test(void) {
  nvme_controller_t *controller = nvme_registered_controller;
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
    nvme_bytes_zero(&request, sizeof(request));
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
