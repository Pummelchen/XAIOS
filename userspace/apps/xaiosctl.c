#include <xaios_control_client.h>

static void copy_bytes(void *dst, const void *src, u64 size) {
  unsigned char *out = (unsigned char *)dst;
  const unsigned char *in = (const unsigned char *)src;
  for (u64 i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static int contains(const char *text, const char *needle) {
  if (text == 0 || needle == 0 || needle[0] == '\0') {
    return 0;
  }
  for (u64 i = 0; text[i] != '\0'; ++i) {
    u64 j = 0;
    while (needle[j] != '\0' && text[i + j] == needle[j]) {
      ++j;
    }
    if (needle[j] == '\0') {
      return 1;
    }
  }
  return 0;
}

static int run_checked(const char *command, int expected_result,
                       const char *marker) {
  char output[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  u64 output_size = 0ULL;
  int result = xaios_control_run(command, output, sizeof(output), &output_size);
  if (result != expected_result || output_size == 0ULL ||
      !contains(output, marker)) {
    return -1;
  }
  return 0;
}

static int protocol_negative_tests(void) {
  xaios_control_request_header_user_t request;
  xaios_control_response_header_user_t response_header;
  unsigned char response[256];
  u64 response_size = 0ULL;
  xaios_memzero(&request, sizeof(request));
  request.magic = XAIOS_CONTROL_MAGIC;
  request.version = XAIOS_CONTROL_VERSION;
  request.header_size = (u16)sizeof(request);
  request.operation = XAIOS_CONTROL_OP_VERSION;
  request.request_id = 9001ULL;
  request.principal_role = XAIOS_CONTROL_ROLE_ADMIN;
  request.timeout_ms = 1000ULL;
  if (xaios_control_query(&request, sizeof(request), response,
                          sizeof(response), &response_size) != 0 ||
      response_size < sizeof(response_header)) {
    return -1;
  }
  copy_bytes(&response_header, response, sizeof(response_header));
  if (response_header.status != XAIOS_CONTROL_STATUS_DENIED) {
    return -1;
  }

  request.principal_role = XAIOS_CONTROL_ROLE_OBSERVER;
  request.magic = 0U;
  if (xaios_control_query(&request, sizeof(request), response,
                          sizeof(response), &response_size) != 0 ||
      response_size < sizeof(response_header)) {
    return -1;
  }
  copy_bytes(&response_header, response, sizeof(response_header));
  return response_header.status == XAIOS_CONTROL_STATUS_INVALID_REQUEST ? 0
                                                                        : -1;
}

int main(void) {
  static const struct command_test {
    const char *human;
    const char *json;
    const char *human_marker;
    const char *json_marker;
    int expected_result;
  } tests[] = {
      {"xaiosctl version", "xaiosctl version --json", "git_commit=",
       "\"control_protocol_version\":1", 0},
      {"xaiosctl status", "xaiosctl status --json", "readiness=degraded",
       "\"production_models_loaded\":0", 0},
      {"xaiosctl health", "xaiosctl health --json", "overall=degraded",
       "\"model_readiness\":\"fixture-only\"", 1},
      {"xaiosctl capabilities", "xaiosctl capabilities --json",
       "real_model_inference=unsupported",
       "\"model_v2\":\"interface-only\"", 0},
      {"xaiosctl hardware", "xaiosctl hardware --json",
       "cpu_vendor=unknown", "\"avx2\":\"unknown\"", 0},
      {"xaiosctl metrics", "xaiosctl metrics --json",
       "tokens_generated=unknown", "\"network_rx_bytes\":null", 0},
      {"xaiosctl logs --limit 2 --component kernel",
       "xaiosctl logs --limit 2 --component kernel --json", "next_cursor=",
       "\"records\":", 0},
      {"xaiosctl config show", "xaiosctl config show --json",
       "password_auth=disabled", "\"validated\":1", 0},
      {"xaiosctl auth key list", "xaiosctl auth key list --json",
       "revoked_count=0", "\"keys\":[]", 0},
      {"xaiosctl audit show --limit 2",
       "xaiosctl audit show --limit 2 --json", "record_count=",
       "\"records\":", 0},
      {"xaiosctl storage device list", "xaiosctl storage device list --json",
       "device=/dev/vblk", "\"devices\":[", 0},
      {"xaiosctl storage device show /dev/vblk4",
       "xaiosctl storage device show /dev/vblk4 --json", "capacity_bytes=",
       "\"logical_sector_size\":512", 0},
      {"xaiosctl storage filesystem list",
       "xaiosctl storage filesystem list --json", "filesystem=ModelFS",
       "\"filesystems\":[", 0},
      {"xaiosctl storage usage /models",
       "xaiosctl storage usage /models --json", "mount=/models",
       "\"staging_writable\":1", 0},
  };

  xaios_log("/bin/xaiosctl: starting control protocol client tests\n");
  for (u64 i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
    if (run_checked(tests[i].human, tests[i].expected_result,
                    tests[i].human_marker) != 0 ||
        run_checked(tests[i].json, tests[i].expected_result,
                    tests[i].json_marker) != 0) {
      xaios_log("/bin/xaiosctl: command rendering test failed\n");
      return 1;
    }
  }
  if (run_checked("xaiosctl invalid --json", -1,
                  "\"code\":\"unknown_operation\"") != 0 ||
      run_checked("xaiosctl version --node 7 --json", -1,
                  "\"code\":\"unknown_node\"") != 0 ||
      protocol_negative_tests() != 0) {
    xaios_log("/bin/xaiosctl: negative protocol test failed\n");
    return 1;
  }
  xaios_log("/bin/xaiosctl: control commands passed human=14 json=14\n");
  xaios_log(
      "/bin/xaiosctl: negative tests passed malformed=1 authorization=1 "
      "node=1\n");
  return 0;
}
