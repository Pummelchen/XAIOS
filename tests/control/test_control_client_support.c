#include <stdint.h>
#include <xaios_control_client.h>

#include "test_control_client_internal.h"

/* Host stand-ins for the freestanding library symbols the control
   client links against, plus the response builders its fake service
   uses. The service calls tcc_copy_bytes, tcc_respond and
   tcc_respond_status, which are defined here exactly once. */

static u64 g_clock_ns;

u64 xaios_strlen(const char *text) {
  u64 length = 0;
  while (text != 0 && text[length] != '\0') ++length;
  return length;
}

void xaios_memzero(void *buffer, u64 size) {
  unsigned char *bytes = (unsigned char *)buffer;
  for (u64 i = 0; i < size; ++i) bytes[i] = 0;
}

u64 xaios_clock_nanos(void) {
  g_clock_ns += 1000000ULL;
  return g_clock_ns;
}

void tcc_copy_bytes(void *dst, const void *src, u64 size) {
  unsigned char *out = (unsigned char *)dst;
  const unsigned char *in = (const unsigned char *)src;
  for (u64 i = 0; i < size; ++i) out[i] = in[i];
}

int tcc_respond(const xaios_control_request_header_user_t *request,
                   u32 payload_type, const void *payload, u64 payload_size,
                   void *response, u64 response_size, u64 *out_size) {
  xaios_control_response_header_user_t header;
  if (response_size < sizeof(header) + payload_size) return -1;
  xaios_memzero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (u16)sizeof(header);
  header.operation = request->operation;
  header.status = XAIOS_CONTROL_STATUS_OK;
  header.request_id = request->request_id;
  header.payload_type = payload_type;
  header.payload_length = payload_size;
  tcc_copy_bytes(response, &header, sizeof(header));
  tcc_copy_bytes((unsigned char *)response + sizeof(header), payload, payload_size);
  *out_size = sizeof(header) + payload_size;
  return 0;
}

int tcc_respond_status(const xaios_control_request_header_user_t *request,
                          u32 status, void *response, u64 response_size,
                          u64 *out_size) {
  xaios_control_response_header_user_t header;
  if (response_size < sizeof(header)) return -1;
  xaios_memzero(&header, sizeof(header));
  header.magic = XAIOS_CONTROL_MAGIC;
  header.version = XAIOS_CONTROL_VERSION;
  header.header_size = (u16)sizeof(header);
  header.operation = request->operation;
  header.status = status;
  header.request_id = request->request_id;
  tcc_copy_bytes(response, &header, sizeof(header));
  *out_size = sizeof(header);
  return 0;
}
