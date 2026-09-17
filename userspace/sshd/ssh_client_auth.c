/* Authentication and the credential/prompt path, split out of ssh_client.c.
 *
 * One contiguous run of the client -- the userauth service request, the
 * password, public-key and forwarded-agent exchanges, the credential prompt
 * and the identity-file state question -- moved here unchanged. The `#if
 * defined(XAIOS_SSH_CLIENT_APP)` guard around the forwarded-agent exchange is
 * preserved exactly as it stood in ssh_client.c. `append_string` stays
 * non-static because ssh_sftp.h declares it and the kex, handshake and sftp
 * halves call it.
 *
 * Private to ssh_client.c, ssh_client_auth.c and ssh_client_command.c.
 */

#include "ssh_client.h"

#include "ssh_client_shared.h"
#include "ssh_client_internal.h"

#include "ssh_channel.h"
#include "ssh_crypto.h"
#include "ssh_identity.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>

uint32_t append_string(uint8_t *buffer, uint32_t position,
                              uint32_t capacity, const uint8_t *value,
                              uint32_t value_length) {
  if (position > capacity || value_length > capacity - position - 4U)
    return UINT32_MAX;
  ssh_write_u32_be(buffer + position, value_length);
  position += 4U;
  ssh_mem_copy(buffer + position, value, value_length);
  return position + value_length;
}

static int send_service_request(ssh_client_context_t *client,
                                const char *service) {
  uint8_t packet[96];
  packet[0] = SSH_MSG_SERVICE_REQUEST;
  uint32_t length = ssh_str_len(service);
  uint32_t position = append_string(packet, 1U, sizeof(packet),
                                    (const uint8_t *)service, length);
  return position == UINT32_MAX ? -1 :
      ssh_packet_write_encrypted((int)client->sockfd, packet, position);
}

int sshclient_authenticate_password(ssh_client_context_t *client,
                                 uint64_t deadline) {
  if (send_service_request(client, "ssh-userauth") != 0) return -1;
  ssh_packet_t *packet = &client->packet_workspace;
  if (wait_encrypted_packet(client, packet, deadline) != 0 ||
      packet->len < 1U || packet->data[0] != SSH_MSG_SERVICE_ACCEPT) return -1;

  uint8_t request[512];
  uint32_t position = 0U;
  request[position++] = SSH_MSG_USERAUTH_REQUEST;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)client->user,
                           ssh_str_len(client->user));
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-connection", 14U);
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"password", 8U);
  if (position == UINT32_MAX || position + 1U > sizeof(request)) return -1;
  request[position++] = 0U;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)client->password,
                           client->password_length);
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0)
    return -1;
  ssh_mem_zero(request, sizeof(request));
  ssh_mem_zero(client->password, sizeof(client->password));
  client->password_length = 0U;
  if (wait_encrypted_packet(client, packet, deadline) != 0 || packet->len < 1U)
    return -1;
  return packet->data[0] == SSH_MSG_USERAUTH_SUCCESS ? 0 : -1;
}

int sshclient_authenticate_public_key(ssh_client_context_t *client,
                                   uint64_t deadline,
                                   const ssh_identity_t *identity) {
  if (send_service_request(client, "ssh-userauth") != 0) return -1;
  ssh_packet_t *response = &client->packet_workspace;
  if (wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len < 1U || response->data[0] != SSH_MSG_SERVICE_ACCEPT)
    return -1;

  uint8_t public_blob[64];
  uint32_t public_length = append_string(
      public_blob, 0U, sizeof(public_blob),
      (const uint8_t *)"ssh-ed25519", 11U);
  public_length = append_string(public_blob, public_length,
                                sizeof(public_blob), identity->public_key, 32U);
  if (public_length == UINT32_MAX) return -1;

  uint8_t request[512];
  uint32_t position = 0U;
  request[position++] = SSH_MSG_USERAUTH_REQUEST;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)client->user,
                           ssh_str_len(client->user));
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-connection", 14U);
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"publickey", 9U);
  if (position == UINT32_MAX || position >= sizeof(request)) return -1;
  uint32_t signature_flag_position = position;
  request[position++] = 0U;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-ed25519", 11U);
  position = append_string(request, position, sizeof(request), public_blob,
                           public_length);
  if (position == UINT32_MAX) return -1;

  if (ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0 ||
      wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len != 1U + 4U + 11U + 4U + public_length ||
      response->data[0] != SSH_MSG_USERAUTH_PK_OK ||
      ssh_read_u32_be(response->data + 1U) != 11U ||
      !sshclient_bytes_equal(response->data + 5U, (const uint8_t *)"ssh-ed25519", 11U) ||
      ssh_read_u32_be(response->data + 16U) != public_length ||
      !sshclient_bytes_equal(response->data + 20U, public_blob, public_length)) return -1;
  request[signature_flag_position] = 1U;

  uint8_t signed_data[512];
  uint32_t signed_length = append_string(
      signed_data, 0U, sizeof(signed_data), client->transport->session_id, 32U);
  if (signed_length == UINT32_MAX || position > sizeof(signed_data) - signed_length)
    return -1;
  ssh_mem_copy(signed_data + signed_length, request, position);
  signed_length += position;
  uint8_t signature[64];
  if (xaios_ed25519_sign(signature, signed_data, signed_length,
                         identity->public_key, identity->seed) != 0)
    return -1;
  uint8_t signature_blob[96];
  uint32_t signature_length = append_string(
      signature_blob, 0U, sizeof(signature_blob),
      (const uint8_t *)"ssh-ed25519", 11U);
  signature_length = append_string(signature_blob, signature_length,
                                   sizeof(signature_blob), signature, 64U);
  position = append_string(request, position, sizeof(request), signature_blob,
                           signature_length);
  ssh_mem_zero(signature, sizeof(signature));
  ssh_mem_zero(signed_data, sizeof(signed_data));
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0)
    return -1;
  ssh_mem_zero(request, sizeof(request));
  if (wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len < 1U) return -1;
  return response->data[0] == SSH_MSG_USERAUTH_SUCCESS ? 0 : -1;
}

#if defined(XAIOS_SSH_CLIENT_APP)
static int agent_exchange_payload(const uint8_t *payload,
                                  uint32_t payload_length, uint8_t *response,
                                  uint32_t response_capacity,
                                  uint32_t *response_length,
                                  uint64_t deadline) {
  uint8_t request[1024];
  if (payload == 0 || payload_length == 0U ||
      payload_length > sizeof(request) - 4U) return -1;
  ssh_write_u32_be(request, payload_length);
  ssh_mem_copy(request + 4U, payload, payload_length);
  return ssh_client_app_agent_exchange(request, payload_length + 4U, response,
                                       response_capacity, response_length,
                                       deadline);
}

static int agent_first_ed25519(uint8_t *public_blob,
                               uint32_t *public_blob_length,
                               uint64_t deadline) {
  uint8_t response[4096];
  uint32_t response_length = 0U;
  static const uint8_t request_identities = 11U;
  if (agent_exchange_payload(&request_identities, 1U, response,
                             sizeof(response), &response_length,
                             deadline) != 0 ||
      response_length < 9U || ssh_read_u32_be(response) + 4U != response_length ||
      response[4U] != 12U) return -1;
  uint32_t count = ssh_read_u32_be(response + 5U);
  uint32_t position = 9U;
  for (uint32_t i = 0U; i < count; ++i) {
    if (position > response_length || response_length - position < 4U)
      return -1;
    uint32_t key_length = ssh_read_u32_be(response + position);
    position += 4U;
    if (key_length > response_length - position) return -1;
    const uint8_t *key = response + position;
    position += key_length;
    if (response_length - position < 4U) return -1;
    uint32_t comment_length = ssh_read_u32_be(response + position);
    position += 4U;
    if (comment_length > response_length - position) return -1;
    position += comment_length;
    if (key_length == 51U && ssh_read_u32_be(key) == 11U &&
        sshclient_bytes_equal(key + 4U, (const uint8_t *)"ssh-ed25519", 11U) &&
        ssh_read_u32_be(key + 15U) == 32U) {
      ssh_mem_copy(public_blob, key, key_length);
      *public_blob_length = key_length;
      return 0;
    }
  }
  return -1;
}

static int agent_sign(const uint8_t *public_blob, uint32_t public_blob_length,
                      const uint8_t *data, uint32_t data_length,
                      uint8_t *signature_blob, uint32_t signature_capacity,
                      uint32_t *signature_length, uint64_t deadline) {
  uint8_t payload[1024];
  uint8_t response[512];
  uint32_t position = 0U;
  uint32_t response_length = 0U;
  payload[position++] = 13U;
  position = append_string(payload, position, sizeof(payload), public_blob,
                           public_blob_length);
  position = append_string(payload, position, sizeof(payload), data,
                           data_length);
  if (position == UINT32_MAX || position + 4U > sizeof(payload)) return -1;
  ssh_write_u32_be(payload + position, 0U);
  position += 4U;
  if (agent_exchange_payload(payload, position, response, sizeof(response),
                             &response_length, deadline) != 0 ||
      response_length < 9U || ssh_read_u32_be(response) + 4U != response_length ||
      response[4U] != 14U) return -1;
  uint32_t length = ssh_read_u32_be(response + 5U);
  if (length != response_length - 9U || length > signature_capacity ||
      length != 83U || ssh_read_u32_be(response + 9U) != 11U ||
      !sshclient_bytes_equal(response + 13U, (const uint8_t *)"ssh-ed25519", 11U) ||
      ssh_read_u32_be(response + 24U) != 64U) return -1;
  ssh_mem_copy(signature_blob, response + 9U, length);
  *signature_length = length;
  return 0;
}

int sshclient_authenticate_agent(ssh_client_context_t *client,
                              uint64_t deadline) {
  uint8_t public_blob[64];
  uint32_t public_length = 0U;
  if (send_service_request(client, "ssh-userauth") != 0) return -1;
  ssh_packet_t *response = &client->packet_workspace;
  if (wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len < 1U || response->data[0] != SSH_MSG_SERVICE_ACCEPT ||
      agent_first_ed25519(public_blob, &public_length, deadline) != 0)
    return -1;

  uint8_t request[512];
  uint32_t position = 0U;
  request[position++] = SSH_MSG_USERAUTH_REQUEST;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)client->user,
                           ssh_str_len(client->user));
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-connection", 14U);
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"publickey", 9U);
  if (position == UINT32_MAX || position >= sizeof(request)) return -1;
  uint32_t signature_flag_position = position;
  request[position++] = 0U;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-ed25519", 11U);
  position = append_string(request, position, sizeof(request), public_blob,
                           public_length);
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0 ||
      wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len != 1U + 4U + 11U + 4U + public_length ||
      response->data[0] != SSH_MSG_USERAUTH_PK_OK) return -1;
  request[signature_flag_position] = 1U;

  uint8_t signed_data[512];
  uint32_t signed_length = append_string(
      signed_data, 0U, sizeof(signed_data), client->transport->session_id, 32U);
  if (signed_length == UINT32_MAX || position > sizeof(signed_data) - signed_length)
    return -1;
  ssh_mem_copy(signed_data + signed_length, request, position);
  signed_length += position;
  uint8_t signature_blob[96];
  uint32_t signature_length = 0U;
  if (agent_sign(public_blob, public_length, signed_data, signed_length,
                 signature_blob, sizeof(signature_blob), &signature_length,
                 deadline) != 0) return -1;
  position = append_string(request, position, sizeof(request), signature_blob,
                           signature_length);
  ssh_mem_zero(signed_data, sizeof(signed_data));
  ssh_mem_zero(signature_blob, sizeof(signature_blob));
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0 ||
      wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len < 1U) return -1;
  return response->data[0] == SSH_MSG_USERAUTH_SUCCESS ? 0 : -1;
}
#endif

static int client_prompt_password(ssh_client_context_t *client,
                                  const ssh_channel_t *channel) {
  char prompt[SSH_CLIENT_USER_MAX + SSH_CLIENT_HOST_MAX + 24U];
  uint32_t used = 0U;
  uint32_t user_length = ssh_str_len(client->user);
  uint32_t host_length = ssh_str_len(client->host);
  ssh_mem_copy(prompt + used, client->user, user_length);
  used += user_length;
  prompt[used++] = '@';
  ssh_mem_copy(prompt + used, client->host, host_length);
  used += host_length;
  static const char password_suffix[] = "'s password: ";
  static const char passphrase_suffix[] = " key passphrase: ";
  static const char agent_suffix[] = " forwarded agent: ";
  const char *suffix = client->use_agent != 0U
                           ? agent_suffix
                           : (client->use_identity != 0U ? passphrase_suffix
                                                        : password_suffix);
  uint32_t suffix_length = ssh_str_len(suffix);
  ssh_mem_copy(prompt + used, suffix, suffix_length);
  used += suffix_length;
  if (ssh_channel_send_data((int)channel->owner_sockfd, channel->remote_id,
                            (const uint8_t *)prompt, used) != 0) {
    return -1;
  }
  client->prompting = 1U;
  client->prompt_deadline = xaios_clock_nanos() + SSH_CLIENT_PROMPT_IDLE_NS;
  return 0;
}

/* What the identity file at `path` needs before it can be used:
   0 -- nothing, it is stored unencrypted and was parsed here;
   1 -- a passphrase, it is readable but will not parse without one;
  -1 -- it cannot be read at all.

   An OpenSSH private key says in its header which it is: the cipher field is
   "none" for a key with no passphrase and names a cipher for one with. This
   asks the question by loading the key with an empty passphrase rather than
   by reading that field separately, because the loader already refuses an
   encrypted key when the passphrase is empty, and one parser cannot disagree
   with itself. A key that needs nothing is therefore never asked about --
   which is the whole of B-37's first half, since the prompt used to go out
   for every identity file regardless. */
static int identity_state(const char *path) {
  xaios_xbfs_stat_user_t info;
  ssh_identity_t identity;
  if (path == 0 || path[0] == '\0' || xaios_fs_stat(path, &info) != 0)
    return -1;
  int loaded = ssh_identity_load(path, "", &identity);
  ssh_mem_zero(&identity, sizeof(identity));
  return loaded == 0 ? 0 : 1;
}

/* The credential the next handshake needs, and how it is obtained.
   0 -- nothing is needed, go straight on;
   1 -- a prompt has been sent and its answer is awaited;
  -1 -- it cannot be had here, and the reason has been printed. */
int sshclient_request_credential(ssh_client_context_t *client,
                                 ssh_channel_t *channel) {
  if (client->use_identity != 0U) {
    int state = identity_state(client->identity_path);
    if (state == 0) return 0;
    if (state < 0) {
      (void)sshclient_output_text(client, "ssh: identity file cannot be read\r\n");
      return -1;
    }
  }
  if (client->batch_mode != 0U) {
    (void)sshclient_output_text(
        client,
        client->use_identity != 0U
            ? "ssh: identity file needs a passphrase and BatchMode=yes is set\r\n"
            : "ssh: password authentication needs a terminal and BatchMode=yes is set\r\n");
    return -1;
  }
  return client_prompt_password(client, channel) == 0 ? 1 : -1;
}
