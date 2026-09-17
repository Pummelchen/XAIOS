#ifndef XAIOS_VIRTIO_TRANSPORT_INTERNAL_H
#define XAIOS_VIRTIO_TRANSPORT_INTERNAL_H

/* Declarations shared by virtio_transport.c and virtio_transport_status.c,
   the two files the virtio-MMIO transport is built from.
   virtio_transport_status.c holds the device reset, feature negotiation and
   driver-status sequence; everything the two files share -- the backend rename
   block, the MMIO register map, the device status bits and the wait timeouts
   -- is defined here once. The rename block comes first, before the includes
   that declare the public transport entry points, because it renames those
   declarations too. */
#ifdef XAIOS_VIRTIO_MMIO_BACKEND
/* Built as one of two backends behind virtio_transport_dispatch.c.
   The public names belong to the dispatcher, so take private ones. */
#define virtio_mmio_read32 virtio_mmio_backend_mmio_read32
#define virtio_mmio_read8 virtio_mmio_backend_mmio_read8
#define virtio_mmio_write32 virtio_mmio_backend_mmio_write32
#define virtio_mmio_barrier virtio_mmio_backend_mmio_barrier
#define virtio_transport_find virtio_mmio_backend_transport_find
#define virtio_transport_find_from virtio_mmio_backend_transport_find_from
#define virtio_transport_find_at virtio_mmio_backend_transport_find_at
#define virtio_transport_find_nth virtio_mmio_backend_transport_find_nth
#define virtio_transport_setup_queue_vectored virtio_mmio_backend_transport_setup_queue_vectored
#define virtio_transport_queue_has_vector virtio_mmio_backend_transport_queue_has_vector
#define virtio_transport_register_queue_interrupt virtio_mmio_backend_transport_register_queue_interrupt
#define virtio_transport_reset virtio_mmio_backend_transport_reset
#define virtio_transport_reset_checked virtio_mmio_backend_transport_reset_checked
#define virtio_transport_negotiate_no_features virtio_mmio_backend_transport_negotiate_no_features
#define virtio_transport_negotiate_features virtio_mmio_backend_transport_negotiate_features
#define virtio_transport_setup_queue virtio_mmio_backend_transport_setup_queue
#define virtio_transport_set_driver_ok virtio_mmio_backend_transport_set_driver_ok
#define virtio_transport_set_driver_ok_checked virtio_mmio_backend_transport_set_driver_ok_checked
#define virtio_transport_notify virtio_mmio_backend_transport_notify
#define virtio_transport_wait_used virtio_mmio_backend_transport_wait_used
#define virtio_transport_device_status virtio_mmio_backend_transport_device_status
#define virtio_transport_ack_interrupts virtio_mmio_backend_transport_ack_interrupts
#define virtio_transport_interrupt_id virtio_mmio_backend_transport_interrupt_id
#define virtio_transport_register_interrupt virtio_mmio_backend_transport_register_interrupt
#define virtio_transport_unregister_interrupt virtio_mmio_backend_transport_unregister_interrupt
#define virtio_transport_slot virtio_mmio_backend_transport_slot
#endif

#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/timer.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#define VIRTIO_WAIT_TIMEOUT_NS UINT64_C(5000000000)
#define VIRTIO_WAIT_FALLBACK_SPINS UINT64_C(100000000)
#define VIRTIO_RESET_TIMEOUT_NS UINT64_C(1000000000)

#define VIRTIO_MMIO_MAGIC 0x000U
#define VIRTIO_MMIO_VERSION 0x004U
#define VIRTIO_MMIO_DEVICE_ID 0x008U
#define VIRTIO_MMIO_VENDOR_ID 0x00cU
#define VIRTIO_MMIO_DEVICE_FEATURES 0x010U
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014U
#define VIRTIO_MMIO_DRIVER_FEATURES 0x020U
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024U
#define VIRTIO_MMIO_QUEUE_SEL 0x030U
#define VIRTIO_MMIO_QUEUE_NUM_MAX 0x034U
#define VIRTIO_MMIO_QUEUE_NUM 0x038U
#define VIRTIO_MMIO_QUEUE_READY 0x044U
#define VIRTIO_MMIO_QUEUE_NOTIFY 0x050U
#define VIRTIO_MMIO_INTERRUPT_STATUS 0x060U
#define VIRTIO_MMIO_INTERRUPT_ACK 0x064U
#define VIRTIO_MMIO_STATUS 0x070U
#define VIRTIO_MMIO_QUEUE_DESC_LOW 0x080U
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084U
#define VIRTIO_MMIO_QUEUE_DRIVER_LOW 0x090U
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH 0x094U
#define VIRTIO_MMIO_QUEUE_DEVICE_LOW 0x0a0U
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH 0x0a4U

#define VIRTIO_MAGIC UINT32_C(0x74726976)

#define VIRTIO_STATUS_ACKNOWLEDGE UINT32_C(1)
#define VIRTIO_STATUS_DRIVER UINT32_C(2)
#define VIRTIO_STATUS_DRIVER_OK UINT32_C(4)
#define VIRTIO_STATUS_FEATURES_OK UINT32_C(8)
#define VIRTIO_STATUS_FAILED UINT32_C(128)

#endif /* XAIOS_VIRTIO_TRANSPORT_INTERNAL_H */
