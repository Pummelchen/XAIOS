/*
 * The credential-material scanner, moved out of kernel/runtime/security.c so
 * no source file exceeds 500 lines.
 *
 * It owns the credential field patterns and the two reject entry points that
 * the filesystem, workspace, sandbox, rollback, admin and update checks call
 * before they authorize anything. Every body is the one the unsplit file
 * held; the credential-reject counter stays file-scope in security.c, and the
 * single atomic increment each rejection performed inline is performed here
 * through security_note_credential_reject() at the same point in the same
 * order. The `contains` and `cstr_length` primitives stay in security.c and
 * are reached through the private header.
 */

#include "security_internal.h"

#include <xaios/security.h>

static const char k_pat_credential_pattern[] = {
    'g', 'i', 't', 'h', 'u', 'b', '_', 'p', 'a', 't', '_', '\0'};
static const char k_short_credential_pattern[] = {'g', 'h', 'p', '_', '\0'};
static const char k_pass_field_pattern[] = {
    'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '=', '\0'};
static const char k_token_field_pattern[] = {
    't', 'o', 'k', 'e', 'n', '=', '\0'};
static const char k_secret_field_pattern[] = {
    's', 'e', 'c', 'r', 'e', 't', '=', '\0'};
static const char k_private_begin_pattern[] = {
    'B', 'E', 'G', 'I', 'N', ' ', '\0'};
static const char k_private_key_pattern[] = {
    'P', 'R', 'I', 'V', 'A', 'T', 'E', ' ', 'K', 'E', 'Y', '\0'};

static int contains_buffer(const char *text, uint64_t length,
                           const char *needle) {
  uint64_t needle_len = security_cstr_length(needle);
  if (text == 0 || needle == 0 || needle_len == 0 || length < needle_len) {
    return 0;
  }

  for (uint64_t cursor = 0; cursor <= length - needle_len; ++cursor) {
    uint64_t i = 0;
    while (i < needle_len && text[cursor + i] == needle[i]) {
      ++i;
    }
    if (i == needle_len) {
      return 1;
    }
  }

  return 0;
}

xaios_status_t security_reject_credential_material(const char *text) {
  if (text == 0) {
    security_note_credential_reject();
    return reject_security_operation("null-input");
  }

  if (security_contains(text, k_pat_credential_pattern) ||
      security_contains(text, k_short_credential_pattern) ||
      security_contains(text, k_private_begin_pattern) ||
      security_contains(text, k_private_key_pattern) ||
      security_contains(text, k_pass_field_pattern) ||
      security_contains(text, k_token_field_pattern) ||
      security_contains(text, k_secret_field_pattern)) {
    security_note_credential_reject();
    return reject_security_operation("credential-material");
  }

  return XAIOS_OK;
}

xaios_status_t security_reject_credential_material_buffer(const char *text,
                                                         uint64_t length) {
  if (text == 0) {
    security_note_credential_reject();
    return reject_security_operation("null-input");
  }
  if (contains_buffer(text, length, k_pat_credential_pattern) ||
      contains_buffer(text, length, k_short_credential_pattern) ||
      contains_buffer(text, length, k_private_begin_pattern) ||
      contains_buffer(text, length, k_private_key_pattern) ||
      contains_buffer(text, length, k_pass_field_pattern) ||
      contains_buffer(text, length, k_token_field_pattern) ||
      contains_buffer(text, length, k_secret_field_pattern)) {
    security_note_credential_reject();
    return reject_security_operation("credential-material");
  }
  return XAIOS_OK;
}
