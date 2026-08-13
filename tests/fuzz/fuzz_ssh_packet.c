#include <stddef.h>
#include <stdint.h>

#include "ssh_protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ssh_packet_t packet;
  if (size > UINT32_MAX) return 0;
  (void)ssh_packet_decode_plain(data, (uint32_t)size, &packet);
  return 0;
}
