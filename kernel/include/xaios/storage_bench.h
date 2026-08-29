#ifndef XAIOS_STORAGE_BENCH_H
#define XAIOS_STORAGE_BENCH_H

/*
 * Time the block path against a real device and report throughput.
 *
 * Under emulation the absolute figure is not a disk speed -- TCG sits between
 * the guest and the host and dominates it. The comparison between two runs on
 * the same host is real, which is what a change to the transfer size needs.
 */
void storage_bench_run(const char *identifier);

/*
 * Time /models instead of the device under it: every byte read out of a model
 * package is hashed against the checksum the signed manifest fixed, and that
 * cost does not appear in the block figure at all. Reported twice, once for a
 * chunk-aligned read and once for a small window inside a chunk, because a
 * partial read still hashes the whole chunk and the gap between the two is
 * what that costs.
 */
void storage_bench_model(void);

#endif
