#ifndef XAIOS_VIRTIO_GPU_H
#define XAIOS_VIRTIO_GPU_H

#include <xaios/status.h>
#include <xaios/types.h>

/*
 * A linear framebuffer for platforms whose firmware leaves none behind.
 *
 * Nothing here is required for a machine to run: a platform with no virtio-GPU,
 * or one whose scanout is disabled, returns XAIOS_ERR_UNSUPPORTED and the
 * console stays on the serial stream exactly as before.
 */
xaios_status_t virtio_gpu_init(void);

/* The buffer to draw into, and the size the scanout expects, or null when no
   display was claimed. Pixels are little-endian BGRX. */
uint32_t *virtio_gpu_framebuffer(uint32_t *width, uint32_t *height);

/* Copy the buffer to the host and show it. Nothing drawn is visible until
   this runs: the device reads the backing when told to, not continuously. */
/* Make the given region of the framebuffer visible. Coordinates are pixels
   from the top left; the region is clamped to the scanout. */
xaios_status_t virtio_gpu_present(uint32_t x, uint32_t y, uint32_t width,
                                  uint32_t height);

/* Log how many pixels the region tracking actually saved. Call once, after the
   boot drawing is done. */
void virtio_gpu_report_transfer_cost(void);

#endif
