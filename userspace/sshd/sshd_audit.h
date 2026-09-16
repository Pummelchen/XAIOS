#ifndef SSHD_AUDIT_H
#define SSHD_AUDIT_H

#include <stdint.h>

/* The audit buffer's size, and how much of it is waiting.
 *
 * The buffer itself lives in sshd_audit.c. The service loop reads the count
 * after a connection closes to decide whether that close is worth the fsync a
 * flush costs, so both the size and the count cross this header. */
#define SSHD_AUDIT_BUFFER_BYTES 3072U

/* Everything held, in one write. Safe to call with nothing buffered. */
void ssh_audit_flush(void);

/* Bytes waiting in the buffer above. */
uint32_t ssh_audit_buffered(void);

/* The durable-write totals the service loop reports and resets.
 *
 * ssh_audit_write_ns is cumulative across the run; load_authorized_keys()
 * samples it around its own work to subtract the audit cost that work itself
 * caused. ssh_audit_pass_durable_ns covers only the pass in progress, which
 * report_service_loop_stall() prints, and ssh_audit_pass_reset() is what
 * starts that pass. */
uint64_t ssh_audit_write_ns(void);
uint64_t ssh_audit_pass_durable_ns(void);
void ssh_audit_pass_reset(void);

/* The per-close durable-cost line.
 *
 * It spans two sections: the audit write counters belong to this module, and
 * the authorized-key loader's counters stay with the key cache in sshd.c, so
 * the latter cross as arguments rather than being exported as state. */
void log_durable_cost(uint32_t connections, uint32_t key_load_calls,
                      uint32_t key_file_reads, uint64_t key_load_ns);

#endif
