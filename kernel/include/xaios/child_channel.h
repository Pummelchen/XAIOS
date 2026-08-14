#ifndef XAIOS_CHILD_CHANNEL_H
#define XAIOS_CHILD_CHANNEL_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_CHILD_CHANNEL_CAPACITY 64U
#define XAIOS_CHILD_CHANNEL_BUFFER_BYTES 32768U

typedef enum xaios_child_channel_state {
  XAIOS_CHILD_CHANNEL_RUNNING = 1U,
  XAIOS_CHILD_CHANNEL_EXITED = 2U,
  XAIOS_CHILD_CHANNEL_CANCELLED = 3U,
  XAIOS_CHILD_CHANNEL_FAILED = 4U
} xaios_child_channel_state_t;

void child_channel_init(void);
xaios_status_t child_channel_open(uint32_t parent_pid, uint64_t session_id,
                                  uint64_t *channel_id);
xaios_status_t child_channel_bind_child(uint64_t channel_id,
                                        uint32_t child_pid);
xaios_status_t child_channel_write(uint64_t channel_id, uint32_t sender_pid,
                                   const void *data, uint64_t size);
xaios_status_t child_channel_read(uint64_t channel_id, uint32_t reader_pid,
                                  void *data, uint64_t capacity,
                                  uint64_t *out_size);
xaios_status_t child_channel_status(uint64_t channel_id, uint32_t owner_pid,
                                    uint64_t *out_status);
xaios_status_t child_channel_finish(uint64_t channel_id, uint32_t child_pid,
                                    int exit_code);
xaios_status_t child_channel_cancel(uint64_t channel_id,
                                    uint32_t parent_pid);
xaios_status_t child_channel_release(uint64_t channel_id,
                                     uint32_t parent_pid);
void child_channel_self_test(void);

#endif
