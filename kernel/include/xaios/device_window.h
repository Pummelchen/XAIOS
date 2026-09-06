#ifndef XAIOS_DEVICE_WINDOW_H
#define XAIOS_DEVICE_WINDOW_H

#include <xaios/status.h>
#include <xaios/types.h>

/* Virtual windows for device registers, handed out rather than chosen.
 *
 * Every driver here used to name its own base address as a constant, and two
 * of them named the same one: AHCI's registers and VMXNET3's doorbell window
 * were both 0x330000000. Storage probes first, so on any machine with a SATA
 * controller the network driver's doorbell writes landed on the disk
 * controller's read-only capability register -- silently, because the page
 * was already mapped and the second request for it succeeded. The device was
 * never told a descriptor was ready, transmit timed out on every packet, and
 * nothing anywhere said why. That is F-02.
 *
 * A constant chosen by hand cannot be checked by anything. These are handed
 * out in order from one arena, with a guard page between windows and the
 * owner recorded, so two drivers cannot be given the same address and a
 * driver that asks twice is told. */

xaios_status_t device_window_map(const char *owner, uint64_t physical,
                                 uint64_t bytes, volatile uint8_t **out);

/* How many windows are open and how much of the arena is used, for the
   self-test and for anything reporting on the machine. */
uint32_t device_window_count(void);
uint64_t device_window_used_bytes(void);
void device_window_self_test(void);

#endif
