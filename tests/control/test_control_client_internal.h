#ifndef XAIOS_TESTS_CONTROL_TEST_CONTROL_CLIENT_INTERNAL_H
#define XAIOS_TESTS_CONTROL_TEST_CONTROL_CLIENT_INTERNAL_H

#include <xaios_control_client.h>

/* Response encoding helpers shared by the fake control service and the host
   support shims in this directory. The shims live in
   test_control_client_support.c; the fake service lives in
   test_control_client_server.c. Each symbol is defined exactly once, in the
   support translation unit, and declared here for the service. */

void tcc_copy_bytes(void *dst, const void *src, u64 size);

int tcc_respond(const xaios_control_request_header_user_t *request,
                u32 payload_type, const void *payload, u64 payload_size,
                void *response, u64 response_size, u64 *out_size);

int tcc_respond_status(const xaios_control_request_header_user_t *request,
                       u32 status, void *response, u64 response_size,
                       u64 *out_size);

#endif
