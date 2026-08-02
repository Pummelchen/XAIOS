#ifndef XAIOS_VIRTIO_RNG_H
#define XAIOS_VIRTIO_RNG_H

#include <xaios/status.h>
#include <xaios/types.h>

xaios_status_t virtio_rng_init(void);
xaios_status_t virtio_rng_read(void *buffer, uint64_t size);
void virtio_rng_self_test(void);

#endif
