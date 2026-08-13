#ifndef XAIOS_BLOCK_DEVICE_H
#define XAIOS_BLOCK_DEVICE_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_BLOCK_DEVICE_ID_MAX 48U
#define XAIOS_BLOCK_BACKEND_MAX 24U
#define XAIOS_BLOCK_MAX_DEVICES 32U

typedef struct xaios_block_device_info {
  char identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
  char backend[XAIOS_BLOCK_BACKEND_MAX];
  uint64_t capacity_bytes;
  uint64_t capacity_logical_sectors;
  uint64_t logical_sector_size;
  uint64_t physical_block_size;
  uint64_t max_transfer_bytes;
  uint64_t discard_granularity;
  uint64_t discard_alignment;
  uint64_t max_discard_bytes;
  uint64_t max_discard_ranges;
  uint64_t max_write_zeroes_bytes;
  uint64_t read_operations;
  uint64_t read_bytes;
  uint64_t write_operations;
  uint64_t write_bytes;
  uint64_t flush_operations;
  uint64_t discard_operations;
  uint64_t discarded_bytes;
  uint64_t write_zeroes_operations;
  uint64_t write_zeroes_bytes;
  uint64_t io_errors;
  uint32_t read_only;
  uint32_t flush_supported;
  uint32_t discard_supported;
  uint32_t write_zeroes_supported;
} xaios_block_device_info_t;

typedef struct xaios_block_backend_ops {
  xaios_status_t (*read)(void *context, uint64_t byte_offset, void *buffer,
                         uint64_t length);
  xaios_status_t (*write)(void *context, uint64_t byte_offset,
                          const void *buffer, uint64_t length);
  xaios_status_t (*flush)(void *context);
  xaios_status_t (*discard)(void *context, uint64_t byte_offset,
                            uint64_t length);
  xaios_status_t (*write_zeroes)(void *context, uint64_t byte_offset,
                                uint64_t length);
} xaios_block_backend_ops_t;

typedef enum xaios_block_async_operation {
  XAIOS_BLOCK_ASYNC_READ = 1,
  XAIOS_BLOCK_ASYNC_WRITE = 2,
  XAIOS_BLOCK_ASYNC_FLUSH = 3,
} xaios_block_async_operation_t;

typedef enum xaios_block_async_state {
  XAIOS_BLOCK_ASYNC_IDLE = 0,
  XAIOS_BLOCK_ASYNC_PENDING = 1,
  XAIOS_BLOCK_ASYNC_CANCEL_REQUESTED = 2,
  XAIOS_BLOCK_ASYNC_COMPLETE = 3,
} xaios_block_async_state_t;

struct xaios_block_async_request;
typedef void (*xaios_block_async_completion_t)(
    struct xaios_block_async_request *request, void *context);

typedef struct xaios_block_async_request {
  xaios_block_async_operation_t operation;
  xaios_block_async_state_t state;
  uint64_t byte_offset;
  void *buffer;
  uint64_t length;
  uint64_t token;
  xaios_status_t status;
  xaios_block_async_completion_t completion;
  void *completion_context;
  struct xaios_block_device *device;
  void *backend_private;
} xaios_block_async_request_t;

typedef struct xaios_block_async_ops {
  xaios_status_t (*submit)(void *context,
                           xaios_block_async_request_t *request);
  uint32_t (*poll)(void *context, uint32_t budget);
  xaios_status_t (*cancel)(void *context,
                           xaios_block_async_request_t *request);
} xaios_block_async_ops_t;

typedef struct xaios_block_device {
  xaios_block_device_info_t info;
  const xaios_block_backend_ops_t *ops;
  const xaios_block_async_ops_t *async_ops;
  void *context;
  uint32_t registered;
  uint32_t open_count;
} xaios_block_device_t;

xaios_status_t block_device_register(
    xaios_block_device_t *device, const xaios_block_device_info_t *info,
    const xaios_block_backend_ops_t *ops, void *context);
xaios_status_t block_device_unregister(xaios_block_device_t *device);
xaios_status_t block_device_set_async_ops(
    xaios_block_device_t *device, const xaios_block_async_ops_t *ops);
xaios_status_t block_device_list(xaios_block_device_info_t *devices,
                                 uint64_t capacity, uint64_t *out_count);
xaios_status_t block_device_open(const char *identifier,
                                 xaios_block_device_t **out_device);
xaios_status_t block_device_close(xaios_block_device_t *device);
xaios_status_t block_device_info(const xaios_block_device_t *device,
                                 xaios_block_device_info_t *out_info);
xaios_status_t block_device_open_count(const xaios_block_device_t *device,
                                       uint32_t *out_count);
xaios_status_t block_read(xaios_block_device_t *device, uint64_t byte_offset,
                          void *buffer, uint64_t length);
xaios_status_t block_write(xaios_block_device_t *device, uint64_t byte_offset,
                           const void *buffer, uint64_t length);
xaios_status_t block_flush(xaios_block_device_t *device);
xaios_status_t block_flush_all(uint64_t *flushed, uint64_t *unsupported,
                               uint64_t *failed);
xaios_status_t block_discard(xaios_block_device_t *device,
                             uint64_t byte_offset, uint64_t length);
xaios_status_t block_write_zeroes(xaios_block_device_t *device,
                                  uint64_t byte_offset, uint64_t length);
xaios_status_t block_async_submit(
    xaios_block_device_t *device, xaios_block_async_request_t *request,
    xaios_block_async_operation_t operation, uint64_t byte_offset,
    void *buffer, uint64_t length, xaios_block_async_completion_t completion,
    void *completion_context);
uint32_t block_async_poll(xaios_block_device_t *device, uint32_t budget);
xaios_status_t block_async_cancel(xaios_block_async_request_t *request);
void block_async_complete(xaios_block_async_request_t *request,
                          xaios_status_t status);

/* Test isolation for hosted unit tests. Refuses reset while a device is open. */
xaios_status_t block_device_test_reset(void);

#endif
