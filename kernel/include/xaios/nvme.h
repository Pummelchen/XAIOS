#ifndef XAIOS_NVME_H
#define XAIOS_NVME_H

#include <xaios/status.h>
#include <xaios/types.h>

typedef struct xaios_nvme_self_test_result {
  uint32_t controllers;
  uint32_t namespaces;
  uint32_t io_verified;
  uint32_t queue_depth;
  uint32_t io_queues;
  uint32_t prp_pages;
  uint32_t transfer_bytes;
  uint64_t namespace_blocks;
  uint32_t logical_block_size;
} xaios_nvme_self_test_result_t;

xaios_status_t nvme_self_test(xaios_nvme_self_test_result_t *result);

#endif
