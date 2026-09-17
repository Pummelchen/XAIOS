/*
 * The syscall families lifted out of `syscall_dispatch`, and the
 * dispatch helpers they still share with the dispatcher.
 *
 * Split out of syscall.c, which was 2157 lines. Each family reproduces
 * its blocks of the original if-chain verbatim -- same guards, same order,
 * same error reasons -- and syscall_dispatch keeps its guards and calls the
 * family. No syscall number, name or error code changes.
 */

#ifndef XAIOS_KERNEL_USER_SYSCALL_FAMILY_H
#define XAIOS_KERNEL_USER_SYSCALL_FAMILY_H

#include <stdint.h>

#include <xaios/socket_buffer.h>
#include <xaios/status.h>
#include <xaios/syscall.h>

#define XAIOS_SYSCALL_LOG_MAX_BYTES UINT64_C(4096)
#define XAIOS_SYSCALL_IO_MAX_BYTES UINT64_C(65536)
#define XAIOS_SYSCALL_NETWORK_IO_MAX_BYTES ((uint64_t)SOCKET_BUFFER_SIZE)

/* How long wait_events sleeps between looks at the things it waits for:
   a millisecond at first, and each quiet look doubles the next, to eight.
   Anything that raises no interrupt is noticed within the slice, and a
   machine with nothing to do looks a hundred and twenty-five times a
   second rather than a thousand. */
#define XAIOS_WAIT_SLICE_NS UINT64_C(1000000)
#define XAIOS_WAIT_SLICE_MAX_NS UINT64_C(8000000)
/* How often the network stack is driven when nothing has arrived: retransmit
   timers, ping timeouts, NTP and the operations tick all live behind it, and
   none of them need a millisecond. Where the device raises no interrupt this
   is not used -- such a link has to be emptied at the receive cadence. */
#define XAIOS_WAIT_HOUSEKEEPING_NS UINT64_C(50000000)

/* The dispatcher-owned helpers the families call. Each keeps the exact
   bookkeeping -- syscall notes, control-plane counters, the rejection log
   -- that the original inline body performed. */
uint64_t syscall_dispatch_reject(uint64_t syscall, uint64_t arg0,
                                 uint64_t arg1, const char *reason);
uint64_t syscall_dispatch_complete(uint64_t value);
void syscall_dispatch_bytes_copy(void *dst, const void *src,
                                 uint64_t size);

/* One entry per family. `syscall` is the number being dispatched; `arg2` is
   carried because the file family reads it. Each entry owns exactly the
   syscall numbers the dispatcher routes to it. */
uint64_t syscall_file(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                       uint64_t arg2);
uint64_t syscall_process(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                       uint64_t arg2);
uint64_t syscall_compute(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                       uint64_t arg2);
uint64_t syscall_time(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                       uint64_t arg2);
uint64_t syscall_net(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                       uint64_t arg2);
uint64_t syscall_netio(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                       uint64_t arg2);
uint64_t syscall_control(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                       uint64_t arg2);

#endif /* XAIOS_KERNEL_USER_SYSCALL_FAMILY_H */
