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

#endif
