#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <xaios/block_device.h>

#define MOCK_EXTENTS 16U
#define MOCK_BYTES 4096U

typedef struct mock_extent {
  uint64_t offset;
  uint64_t length;
  uint8_t bytes[MOCK_BYTES];
  uint32_t valid;
} mock_extent_t;

typedef struct mock_backend {
  mock_extent_t extents[MOCK_EXTENTS];
  uint64_t reads;
  uint64_t writes;
  uint64_t flushes;
  uint64_t discards;
  uint64_t zeroes;
  uint64_t next_token;
  xaios_block_async_request_t *pending;
} mock_backend_t;

static xaios_status_t mock_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  mock_backend_t *mock = (mock_backend_t *)context;
  uint8_t *out = (uint8_t *)buffer;
  memset(out, 0, (size_t)length);
  ++mock->reads;
  for (uint32_t i = 0U; i < MOCK_EXTENTS; ++i) {
    mock_extent_t *extent = &mock->extents[i];
    if (extent->valid == 0U || extent->offset != offset ||
        extent->length != length) {
      continue;
    }
    memcpy(out, extent->bytes, (size_t)length);
    return XAIOS_OK;
  }
  return XAIOS_OK;
}

static xaios_status_t mock_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  mock_backend_t *mock = (mock_backend_t *)context;
  if (length > MOCK_BYTES) return XAIOS_ERR_INVALID;
  ++mock->writes;
  for (uint32_t i = 0U; i < MOCK_EXTENTS; ++i) {
    mock_extent_t *extent = &mock->extents[i];
    if (extent->valid != 0U && extent->offset != offset) continue;
    extent->offset = offset;
    extent->length = length;
    extent->valid = 1U;
    memcpy(extent->bytes, buffer, (size_t)length);
    return XAIOS_OK;
  }
  return XAIOS_ERR_NO_MEMORY;
}

static xaios_status_t mock_flush(void *context) {
  ++((mock_backend_t *)context)->flushes;
  return XAIOS_OK;
}

static xaios_status_t mock_discard(void *context, uint64_t offset,
                                   uint64_t length) {
  mock_backend_t *mock = (mock_backend_t *)context;
  ++mock->discards;
  for (uint32_t i = 0U; i < MOCK_EXTENTS; ++i) {
    mock_extent_t *extent = &mock->extents[i];
    if (extent->valid != 0U && extent->offset >= offset &&
        extent->offset + extent->length <= offset + length) {
      extent->valid = 0U;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t mock_write_zeroes(void *context, uint64_t offset,
                                       uint64_t length) {
  mock_backend_t *mock = (mock_backend_t *)context;
  (void)offset;
  (void)length;
  ++mock->zeroes;
  return XAIOS_OK;
}

static const xaios_block_backend_ops_t k_mock_ops = {
    mock_read, mock_write, mock_flush, mock_discard, mock_write_zeroes};

static xaios_status_t mock_async_submit(
    void *context, xaios_block_async_request_t *request) {
  mock_backend_t *mock = (mock_backend_t *)context;
  if (mock->pending != 0) return XAIOS_ERR_BUSY;
  request->token = ++mock->next_token;
  request->backend_private = mock;
  mock->pending = request;
  return XAIOS_OK;
}

static uint32_t mock_async_poll(void *context, uint32_t budget) {
  mock_backend_t *mock = (mock_backend_t *)context;
  if (budget == 0U || mock->pending == 0) return 0U;
  xaios_block_async_request_t *request = mock->pending;
  mock->pending = 0;
  if (request->state == XAIOS_BLOCK_ASYNC_CANCEL_REQUESTED) {
    block_async_complete(request, XAIOS_ERR_CANCELLED);
    return 1U;
  }
  xaios_status_t status;
  if (request->operation == XAIOS_BLOCK_ASYNC_READ) {
    status = mock_read(mock, request->byte_offset, request->buffer,
                       request->length);
  } else if (request->operation == XAIOS_BLOCK_ASYNC_WRITE) {
    status = mock_write(mock, request->byte_offset, request->buffer,
                        request->length);
  } else {
    status = mock_flush(mock);
  }
  block_async_complete(request, status);
  return 1U;
}

static xaios_status_t mock_async_cancel(
    void *context, xaios_block_async_request_t *request) {
  mock_backend_t *mock = (mock_backend_t *)context;
  return mock->pending == request ? XAIOS_OK : XAIOS_ERR_NOT_FOUND;
}

static const xaios_block_async_ops_t k_mock_async_ops = {
    mock_async_submit, mock_async_poll, mock_async_cancel};

static void count_completion(xaios_block_async_request_t *request,
                             void *context) {
  uint32_t *count = (uint32_t *)context;
  assert(request->state == XAIOS_BLOCK_ASYNC_COMPLETE);
  ++*count;
}

static xaios_block_device_info_t mock_info(const char *identifier) {
  xaios_block_device_info_t info;
  memset(&info, 0, sizeof(info));
  memcpy(info.identifier, identifier, strlen(identifier) + 1U);
  memcpy(info.backend, "mock", 5U);
  info.capacity_bytes = UINT64_C(8) << 40U;
  info.logical_sector_size = 4096U;
  info.capacity_logical_sectors =
      info.capacity_bytes / info.logical_sector_size;
  info.physical_block_size = 4096U;
  info.max_transfer_bytes = 4096U;
  info.flush_supported = 1U;
  info.discard_supported = 1U;
  info.discard_granularity = 8192U;
  info.discard_alignment = 0U;
  info.max_discard_bytes = 16384U;
  info.max_discard_ranges = 1U;
  info.write_zeroes_supported = 1U;
  info.max_write_zeroes_bytes = 8192U;
  return info;
}

int main(void) {
  xaios_block_device_t device;
  xaios_block_device_t unsupported;
  xaios_block_device_t read_only;
  mock_backend_t backend;
  mock_backend_t unsupported_backend;
  mock_backend_t read_only_backend;
  memset(&device, 0, sizeof(device));
  memset(&unsupported, 0, sizeof(unsupported));
  memset(&read_only, 0, sizeof(read_only));
  memset(&backend, 0, sizeof(backend));
  memset(&unsupported_backend, 0, sizeof(unsupported_backend));
  memset(&read_only_backend, 0, sizeof(read_only_backend));
  assert(block_device_test_reset() == XAIOS_OK);

  xaios_block_device_info_t info = mock_info("/dev/mock0");
  assert(block_device_register(&device, &info, &k_mock_ops, &backend) ==
         XAIOS_OK);
  assert(block_device_register(&unsupported, &info, &k_mock_ops,
                               &unsupported_backend) == XAIOS_ERR_BUSY);
  xaios_block_device_info_t overflow_info = mock_info("/dev/overflow");
  overflow_info.logical_sector_size = 4096U;
  overflow_info.capacity_logical_sectors = UINT64_MAX / 4096U + 1U;
  overflow_info.capacity_bytes = UINT64_MAX;
  assert(block_device_register(&unsupported, &overflow_info, &k_mock_ops,
                               &unsupported_backend) == XAIOS_ERR_INVALID);

  uint64_t count = 0U;
  xaios_block_device_info_t listed[1];
  assert(block_device_list(listed, 1U, &count) == XAIOS_OK);
  assert(count == 1U);
  assert(strcmp(listed[0].identifier, "/dev/mock0") == 0);

  xaios_block_device_t *opened = 0;
  assert(block_device_open("/dev/missing", &opened) == XAIOS_ERR_NOT_FOUND);
  assert(block_device_open("/dev/mock0", &opened) == XAIOS_OK);
  assert(opened == &device);
  assert(block_device_test_reset() == XAIOS_ERR_BUSY);

  uint8_t async_data[4096];
  memset(async_data, 0x5a, sizeof(async_data));
  xaios_block_async_request_t fallback_request;
  memset(&fallback_request, 0, sizeof(fallback_request));
  uint32_t completions = 0U;
  assert(block_async_submit(opened, &fallback_request,
                            XAIOS_BLOCK_ASYNC_WRITE, 0U, async_data,
                            sizeof(async_data), count_completion,
                            &completions) == XAIOS_OK);
  assert(fallback_request.state == XAIOS_BLOCK_ASYNC_COMPLETE);
  assert(fallback_request.status == XAIOS_OK);
  assert(completions == 1U);
  assert(block_async_cancel(&fallback_request) == XAIOS_ERR_INVALID);

  assert(block_device_set_async_ops(opened, &k_mock_async_ops) == XAIOS_OK);
  assert(block_device_set_async_ops(opened, &k_mock_async_ops) ==
         XAIOS_ERR_BUSY);
  xaios_block_async_request_t pending_request;
  memset(&pending_request, 0, sizeof(pending_request));
  assert(block_async_submit(opened, &pending_request, XAIOS_BLOCK_ASYNC_READ,
                            0U, async_data, sizeof(async_data),
                            count_completion, &completions) == XAIOS_OK);
  assert(pending_request.state == XAIOS_BLOCK_ASYNC_PENDING);
  assert(pending_request.token != 0U);
  assert(block_async_submit(opened, &pending_request,
                            XAIOS_BLOCK_ASYNC_READ, 0U, async_data,
                            sizeof(async_data), 0, 0) == XAIOS_ERR_INVALID);
  assert(block_async_poll(opened, 1U) == 1U);
  assert(pending_request.state == XAIOS_BLOCK_ASYNC_COMPLETE);
  assert(pending_request.status == XAIOS_OK);
  assert(completions == 2U);

  xaios_block_async_request_t cancelled_request;
  memset(&cancelled_request, 0, sizeof(cancelled_request));
  assert(block_async_submit(opened, &cancelled_request,
                            XAIOS_BLOCK_ASYNC_WRITE, 4096U, async_data,
                            sizeof(async_data), count_completion,
                            &completions) == XAIOS_OK);
  assert(block_async_cancel(&cancelled_request) == XAIOS_OK);
  assert(cancelled_request.state == XAIOS_BLOCK_ASYNC_CANCEL_REQUESTED);
  assert(block_async_cancel(&cancelled_request) == XAIOS_ERR_INVALID);
  assert(block_async_poll(opened, 1U) == 1U);
  assert(cancelled_request.status == XAIOS_ERR_CANCELLED);
  assert(completions == 3U);

  uint8_t write_data[8192];
  uint8_t read_data[8192];
  for (uint32_t i = 0U; i < sizeof(write_data); ++i) {
    write_data[i] = (uint8_t)(i ^ 0xa5U);
  }
  const uint64_t high_offset = (UINT64_C(4) << 30U) + 4096U;
  assert(block_write(opened, high_offset, write_data, sizeof(write_data)) ==
         XAIOS_OK);
  assert(backend.writes == 3U);
  memset(read_data, 0, sizeof(read_data));
  assert(block_read(opened, high_offset, read_data, sizeof(read_data)) ==
         XAIOS_OK);
  assert(memcmp(write_data, read_data, sizeof(write_data)) == 0);
  assert(backend.reads == 3U);

  assert(block_read(opened, high_offset + 1U, read_data, 4096U) ==
         XAIOS_ERR_INVALID);
  assert(block_read(opened, UINT64_MAX - 4095U, read_data, 8192U) ==
         XAIOS_ERR_INVALID);
  assert(block_write(opened, info.capacity_bytes, write_data, 4096U) ==
         XAIOS_ERR_INVALID);
  assert(block_flush(opened) == XAIOS_OK);
  assert(backend.flushes == 1U);

  assert(block_discard(opened, high_offset, 8192U) ==
         XAIOS_ERR_INVALID);
  assert(block_discard(opened, high_offset + 4096U, 12288U) ==
         XAIOS_ERR_INVALID);
  assert(block_discard(opened, high_offset + 4096U, 32768U) ==
         XAIOS_OK);
  assert(backend.discards == 2U);
  assert(block_write_zeroes(opened, high_offset, 24576U) == XAIOS_OK);
  assert(backend.zeroes == 3U);

  xaios_block_device_info_t measured;
  assert(block_device_info(opened, &measured) == XAIOS_OK);
  assert(measured.write_bytes == sizeof(write_data) + sizeof(async_data));
  assert(measured.read_bytes == sizeof(read_data) + sizeof(async_data));
  assert(measured.discard_operations == 2U);
  assert(measured.discarded_bytes == 32768U);
  assert(measured.write_zeroes_operations == 3U);
  assert(measured.write_zeroes_bytes == 24576U);

  xaios_block_device_info_t unsupported_info = mock_info("/dev/mock1");
  unsupported_info.discard_supported = 0U;
  unsupported_info.write_zeroes_supported = 0U;
  unsupported_info.discard_granularity = 0U;
  unsupported_info.discard_alignment = 0U;
  unsupported_info.max_discard_bytes = 0U;
  unsupported_info.max_discard_ranges = 0U;
  unsupported_info.max_write_zeroes_bytes = 0U;
  assert(block_device_register(&unsupported, &unsupported_info, &k_mock_ops,
                               &unsupported_backend) == XAIOS_OK);
  assert(block_write(&unsupported, high_offset, write_data, 4096U) ==
         XAIOS_OK);
  assert(block_discard(&unsupported, 0U, 4096U) == XAIOS_ERR_UNSUPPORTED);
  assert(block_write_zeroes(&unsupported, 0U, 4096U) ==
         XAIOS_ERR_UNSUPPORTED);
  assert(unsupported_backend.discards == 0U);
  assert(unsupported_backend.zeroes == 0U);
  memset(read_data, 0, 4096U);
  assert(block_read(&unsupported, high_offset, read_data, 4096U) == XAIOS_OK);
  assert(memcmp(read_data, write_data, 4096U) == 0);

  xaios_block_device_info_t read_only_info = mock_info("/dev/mock2");
  read_only_info.read_only = 1U;
  assert(block_device_register(&read_only, &read_only_info, &k_mock_ops,
                               &read_only_backend) == XAIOS_OK);
  assert(block_write(&read_only, 0U, write_data, 4096U) ==
         XAIOS_ERR_UNSUPPORTED);
  assert(block_discard(&read_only, 0U, 8192U) == XAIOS_ERR_UNSUPPORTED);

  assert(block_device_close(opened) == XAIOS_OK);
  assert(block_device_unregister(&device) == XAIOS_OK);
  assert(block_device_unregister(&unsupported) == XAIOS_OK);
  assert(block_device_unregister(&read_only) == XAIOS_OK);
  assert(block_device_test_reset() == XAIOS_OK);
  puts("block-device: 64-bit I/O, overflow, capabilities, and splitting passed");
  return 0;
}
