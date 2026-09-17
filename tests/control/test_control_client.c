#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xaios_control_client.h>

static int contains(const char *text, const char *needle) {
  return strstr(text, needle) != NULL;
}

static int run_case(const char *command, int expected_result,
                    const char *marker) {
  char output[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  u64 output_size = 0ULL;
  int result = xaios_control_run(command, output, sizeof(output), &output_size);
  if (result != expected_result || output_size == 0ULL ||
      !contains(output, marker)) {
    fprintf(stderr, "control client case failed: %s rc=%d output=%s\n",
            command, result, output);
    return -1;
  }
  return 0;
}

static int run_case_as(const char *command, u32 role, const char *principal,
                       int expected_result, const char *marker) {
  char output[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  u64 output_size = 0ULL;
  int result = xaios_control_run_as(command, role, principal, output,
                                    sizeof(output), &output_size);
  if (result != expected_result || output_size == 0ULL ||
      !contains(output, marker)) {
    fprintf(stderr, "control client role case failed: %s rc=%d output=%s\n",
            command, result, output);
    return -1;
  }
  return 0;
}

int main(void) {
  char exact[XAIOS_CONTROL_MAX_RESPONSE_BYTES];
  u64 exact_size = 0ULL;
  static const char expected[] =
      "{\"schema_version\":1,\"request_id\":\"1\",\"status\":\"ok\","
      "\"data\":{\"product_version\":\"9.9.9\","
      "\"build_identifier\":\"host-test\",\"git_commit\":"
      "\"abc123\",\"kernel_abi_version\":1,\"control_protocol_version\":1,"
      "\"model_package_version\":2,\"xai_fs_version\":1,"
      "\"architecture\":\"aarch64\",\"build_mode\":\"development\"}}\n";
  static const char expected_error[] =
      "{\"schema_version\":1,\"request_id\":\"2\",\"status\":\"error\","
      "\"data\":null,\"error\":{\"code\":\"unknown_operation\","
      "\"message\":\"Unknown xaiosctl command.\"}}\n";
  if (xaios_control_run("xaiosctl version --json", exact, sizeof(exact),
                        &exact_size) != 0 ||
      strcmp(exact, expected) != 0 || exact_size != strlen(expected)) {
    fprintf(stderr, "deterministic JSON mismatch: %s\n", exact);
    return 1;
  }
  if (xaios_control_run("xaiosctl bogus --json", exact, sizeof(exact),
                        &exact_size) != -1 ||
      strcmp(exact, expected_error) != 0 ||
      exact_size != strlen(expected_error)) {
    fprintf(stderr, "deterministic error JSON mismatch: %s\n", exact);
    return 1;
  }
  if (run_case("xaiosctl version", 0, "git_commit=abc123") != 0 ||
      run_case("xaiosctl status --json", 0, "\"queue_depth\":null") != 0 ||
      run_case("xaiosctl health --json", 1,
               "\"overall\":\"degraded\"") != 0 ||
      run_case("xaiosctl capabilities --json", 0,
               "\"model_v2\":\"interface-only\"") != 0 ||
      run_case("xaiosctl hardware --json", 0,
               "\"cpu_vendor\":\"unknown\"") != 0 ||
      run_case("xaiosctl metrics --json", 0,
               "\"tokens_generated\":null") != 0 ||
      run_case("xaiosctl logs --json --limit 1", 0,
               "\"records\":\"seq=7") != 0 ||
      run_case("xaiosctl config show --json", 0,
               "\"command_rate_per_minute\":60") != 0 ||
      run_case("xaiosctl config validate /tmp/config --json", 0,
               "\"validated\":1") != 0 ||
      run_case("xaiosctl config diff /tmp/config", 0,
               "change_mask=8") != 0 ||
      run_case("xaiosctl auth key list --json", 0,
               "\"principal\":\"ci-admin\"") != 0 ||
      run_case("xaiosctl audit show --json --limit 1", 0,
               "\"operation\":\"config.apply\"") != 0 ||
      run_case_as("xaiosctl config apply /tmp/config --operation-id 41 --json",
                  XAIOS_CONTROL_ROLE_OPERATOR, "ci-operator", 0,
                  "\"validated\":1") != 0 ||
      run_case_as("xaiosctl auth key add /tmp/key.pub --principal ci-admin-2 "
                  "--role administrator --operation-id 42 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"key_count\":1") != 0 ||
      run_case_as("xaiosctl auth key remove "
                  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
                  "--operation-id 43 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"revoked_count\":1") != 0 ||
      run_case_as("xaiosctl auth host-key rotate --operation-id 44 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"changed\":1") != 0 ||
      run_case_as(
          "xaiosctl model register "
          "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
          "--model-uuid 00112233445566778899aabbccddeeff "
          "--signer-key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
          "--signature 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
          "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
          "--source-revision ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100 "
          "--architecture qwen-test --target portable --size 5GiB "
          "--operation-id 46 --json",
          XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0, "\"generation\":9") != 0 ||
      run_case_as("xaiosctl model verify "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"generation\":10") != 0 ||
      run_case_as("xaiosctl model activate "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--operation-id 47 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"changed\":1") != 0 ||
      run_case_as("xaiosctl model cleanup "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--operation-id 49 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"reclaimed_bytes\":4194304") != 0 ||
      run_case("xaiosctl storage device list --json", 0,
               "\"identifier\":\"/dev/vblk4\"") != 0 ||
      run_case("xaiosctl storage device show /dev/vblk4", 0,
               "capacity_bytes=137438953472") != 0 ||
      run_case("xaiosctl storage filesystem list --json", 0,
               "\"filesystem\":\"xaiFS\"") != 0 ||
      run_case("xaiosctl storage mount-status", 0,
               "mount=/models") != 0 ||
      run_case("xaiosctl storage filesystem show /models --json", 0,
               "\"staging_writable\":1") != 0 ||
      run_case("xaiosctl storage usage /models", 0,
               "free_bytes=137436856320") != 0 ||
      run_case("xaiosctl storage partition list /dev/vblk5 --json", 0,
               "\"identifier\":\"/dev/vblk5p1\"") != 0 ||
      run_case("xaiosctl storage partition verify /dev/vblk5", 0,
               "copies_consistent=1") != 0 ||
      run_case("xaiosctl storage format-plan /dev/vblk5p1 --type modelfs "
               "--label models --block-size 4096 --checksum-data "
               "--chunk-size 4MiB --json",
               0, "\"dry_run\":1") != 0 ||
      run_case("xaiosctl storage format /dev/vblk5p1 --type modelfs "
               "--label models --block-size 4096 --checksum-data --dry-run",
               0, "dry_run=1") != 0 ||
      run_case_as("xaiosctl storage format /dev/vblk5p1 --type modelfs "
                  "--label models --block-size 4096 --checksum-data "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 601 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"check_state\":\"clean\"") != 0 ||
      run_case_as("xaiosctl storage mount /dev/vblk5p1 /models "
                  "--read-only --operation-id 602",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "target=/dev/vblk5p1") != 0 ||
      run_case_as("xaiosctl storage unmount /models --operation-id 603 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"target\":\"/models\"") != 0 ||
      run_case("xaiosctl storage fsck /dev/vblk5p1 --check --verify-data --json",
               0, "\"checked_bytes\":0") != 0 ||
      run_case_as("xaiosctl storage fsck /dev/vblk5p1 --repair "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 604",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "check_state=repaired") != 0 ||
      run_case_as("xaiosctl storage repair-from-replica /dev/vblk5p1 "
                  "/dev/vblk6p1 "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 606",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "check_state=repaired") != 0 ||
      run_case("xaiosctl storage resize-plan /dev/vblk5p1 --grow-to max --json",
               0, "\"dry_run\":1") != 0 ||
      run_case_as("xaiosctl storage resize /dev/vblk5p1 --grow-to 2GiB "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 605",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "generation=2") != 0 ||
      run_case_as("xaiosctl storage scrub /models --start "
                  "--operation-id 606 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"state\":\"running\"") != 0 ||
      run_case("xaiosctl storage scrub /models --status --json", 0,
               "\"checked_bytes\":4194304") != 0 ||
      run_case_as("xaiosctl storage scrub /models --pause "
                  "--operation-id 607",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "state=paused") != 0 ||
      run_case_as("xaiosctl storage scrub /models --resume "
                  "--operation-id 608 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"state\":\"running\"") != 0 ||
      run_case_as("xaiosctl storage scrub /models --cancel "
                  "--operation-id 609",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "state=cancelled") != 0 ||
      run_case("xaiosctl storage trim /models --all-free --dry-run --json", 0,
               "\"dry_run\":1") != 0 ||
      run_case("xaiosctl storage trim /models --dry-run --json", 0,
               "\"all_free\":1") != 0 ||
      run_case_as("xaiosctl storage trim /models --range 1MiB:2MiB "
                  "--operation-id 610",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "requested_offset=1048576") != 0 ||
      run_case("xaiosctl storage trim-status /models --json", 0,
               "\"state\":\"complete\"") != 0 ||
      run_case_as("xaiosctl storage trim-cancel /models --operation-id 611",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "state=cancelled") != 0 ||
      run_case("xaiosctl storage partition plan-create /dev/vblk5 "
               "--type model --size 2GiB --name models --json",
               0, "\"dry_run\":1") != 0 ||
      run_case("xaiosctl storage partition create /dev/vblk5 "
               "--type model --size 2GiB --name models --dry-run --json",
               0, "\"dry_run\":1") != 0 ||
      run_case_as("xaiosctl storage partition create /dev/vblk5 "
                  "--type model --size 2GiB --name models "
                  "--confirm-device 11111111-2222-5333-8444-555555555555 "
                  "--operation-id 51 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"dry_run\":0") != 0 ||
      /* Installing is the most destructive thing this surface can do, so the
         cases that matter are the refusals: no named actor, no confirmation,
         and no source. A parser that let any of those through would let a
         mistyped device name overwrite a disk. */
      run_case("xaiosctl storage install /dev/vblk5 from /dev/vblk16p0",
               -1, "invalid_install") != 0 ||
      run_case("xaiosctl storage install /dev/vblk5", -1,
               "invalid_install") != 0 ||
      run_case_as("xaiosctl storage install /dev/vblk5 from /dev/vblk16p0 "
                  "--operation-id 60 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", -1,
                  "invalid_install") != 0 ||
      run_case_as("xaiosctl storage partition resize /dev/vblk5p1 "
                  "--grow-to 3GiB "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 52 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"affected_bytes\":2147483648") != 0 ||
      run_case_as("xaiosctl storage partition delete /dev/vblk5p1 "
                  "--confirm-partition aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee "
                  "--operation-id 53 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"changed\":1") != 0 ||
      run_case_as("xaiosctl storage partition repair /dev/vblk5 "
                  "--confirm-device 11111111-2222-5333-8444-555555555555 "
                  "--operation-id 54 --json",
                  XAIOS_CONTROL_ROLE_ADMIN, "ci-admin", 0,
                  "\"partition\":null") != 0 ||
      run_case_as("xaiosctl model activate "
                  "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
                  "--operation-id 48 --json",
                  XAIOS_CONTROL_ROLE_OPERATOR, "ci-operator", -1,
                  "\"code\":\"permission_denied\"") != 0 ||
      run_case_as("xaiosctl auth host-key rotate --operation-id 45 --json",
                  XAIOS_CONTROL_ROLE_OPERATOR, "ci-operator", -1,
                  "\"code\":\"permission_denied\"") != 0 ||
      run_case("xaiosctl config apply /tmp/config --json", -1,
               "\"code\":\"operation_id_required\"") != 0 ||
      run_case("xaiosctl model activate "
               "da3246a8df558dd6d9da385adb58976cd964a76d413f9a5f395f65a861e1333f "
               "--json",
               -1, "\"code\":\"operation_id_required\"") != 0 ||
      run_case("xaiosctl storage trim /models --json", -1,
               "\"code\":\"trim_scope_required\"") != 0 ||
      run_case("xaiosctl storage partition create /dev/vblk5 --type model "
               "--size 2GiB --name models --json",
               -1, "\"code\":\"confirmation_required\"") != 0 ||
      run_case("xaiosctl storage partition resize /dev/vblk5p1 --json", -1,
               "\"code\":\"resize_target_required\"") != 0 ||
      run_case("xaiosctl storage partition plan-create /dev/vblk5 "
               "--type invalid --size 2GiB --name models --json",
               -1, "\"code\":\"invalid_partition_type\"") != 0 ||
      run_case("xaiosctl auth key add /tmp/key.pub --principal bad "
               "--role invalid --operation-id 46 --json",
               -1, "\"code\":\"invalid_role\"") != 0 ||
      run_case("xaiosctl bogus --json", -1,
               "\"code\":\"unknown_operation\"") != 0 ||
      run_case("xaiosctl version --node 8 --json", -1,
               "\"code\":\"unknown_node\"") != 0 ||
      run_case("xaiosctl version --timeout 61s --json", -1,
               "\"code\":\"invalid_timeout\"") != 0) {
    return 1;
  }
  char fuzz_command[160];
  char fuzz_output[2048];
  uint32_t fuzz_state = UINT32_C(0x4354524c);
  for (uint32_t case_id = 0U; case_id < 4096U; ++case_id) {
    fuzz_state = fuzz_state * UINT32_C(1664525) + UINT32_C(1013904223);
    uint32_t length = fuzz_state % (sizeof(fuzz_command) - 1U);
    for (uint32_t index = 0U; index < length; ++index) {
      fuzz_state =
          fuzz_state * UINT32_C(1664525) + UINT32_C(1013904223);
      fuzz_command[index] = (char)(32U + ((fuzz_state >> 24U) % 95U));
    }
    fuzz_command[length] = '\0';
    u64 output_size = 0U;
    (void)xaios_control_run_as(fuzz_command, XAIOS_CONTROL_ROLE_OBSERVER,
                               "fuzz-observer", fuzz_output,
                               sizeof(fuzz_output), &output_size);
    if (output_size > sizeof(fuzz_output)) return 1;
  }
  puts("control-client: typed behavior and deterministic malformed corpus passed");
  return 0;
}
