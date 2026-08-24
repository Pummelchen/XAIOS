#ifndef XAIOS_VIRTIO_CONSOLE_H
#define XAIOS_VIRTIO_CONSOLE_H

#include <xaios/status.h>
#include <xaios/types.h>

/* Probe the virtio console and prepare its transmit queue. Returns
   XAIOS_ERR_NOT_FOUND on platforms that do not offer one, which is the
   normal case under QEMU where the kernel logs to a PL011 instead. */
xaios_status_t virtio_console_init(void);
/* Write bytes to the host. Synchronous: the queue is one descriptor deep and
   the call returns once the device has consumed the buffer. */
void virtio_console_write(const char *data, uint64_t length);
uint32_t virtio_console_ready(void);

#endif
