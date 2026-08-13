#ifndef XAIOS_SSH_CHILD_IPC_H
#define XAIOS_SSH_CHILD_IPC_H

#include <xaios/types.h>

#define SSH_CHILD_IPC_MAGIC UINT32_C(0x58414950)
#define SSH_CHILD_IPC_HEADER_SIZE 12U
#define SSH_CHILD_IPC_PAYLOAD_MAX 8192U

enum ssh_child_ipc_type {
  SSH_CHILD_IPC_INPUT = 1U,
  SSH_CHILD_IPC_OUTPUT = 2U,
  SSH_CHILD_IPC_AGENT_REQUEST = 3U,
  SSH_CHILD_IPC_AGENT_RESPONSE = 4U
};

static inline void ssh_child_ipc_write_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24U);
  output[1] = (uint8_t)(value >> 16U);
  output[2] = (uint8_t)(value >> 8U);
  output[3] = (uint8_t)value;
}

static inline uint32_t ssh_child_ipc_read_u32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24U) | ((uint32_t)input[1] << 16U) |
         ((uint32_t)input[2] << 8U) | (uint32_t)input[3];
}

static inline void ssh_child_ipc_header(uint8_t *output, uint32_t type,
                                        uint32_t length) {
  ssh_child_ipc_write_u32(output, SSH_CHILD_IPC_MAGIC);
  ssh_child_ipc_write_u32(output + 4U, type);
  ssh_child_ipc_write_u32(output + 8U, length);
}

#endif
