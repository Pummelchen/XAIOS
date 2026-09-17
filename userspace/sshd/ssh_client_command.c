/* Command-line option parsing and ssh_client_prepare, split out of
 * ssh_client.c.
 *
 * The tokenizer, the port and destination parsers, the one understood -o
 * option, the remote-specification scan, the usage text and
 * `ssh_client_prepare` itself moved here unchanged. `resolve_local_path` and
 * the app working directory stayed in ssh_client.c because they read
 * `g_client_app_cwd`; `ssh_client_prepare` calls across to them.
 *
 * Private to ssh_client.c, ssh_client_auth.c and ssh_client_command.c.
 */

#include "ssh_client.h"

#include "ssh_client_scp.h"
#include "ssh_client_shared.h"
#include "ssh_client_internal.h"

#include "ssh_channel.h"
#include "ssh_utils.h"

static int parse_port(const char *text, uint16_t *port) {
  uint32_t value = 0U;
  if (text == 0 || text[0] == '\0') return -1;
  for (uint32_t i = 0U; text[i] != '\0'; ++i) {
    if (text[i] < '0' || text[i] > '9') return -1;
    uint32_t digit = (uint32_t)(text[i] - '0');
    if (value > (65535U - digit) / 10U) return -1;
    value = value * 10U + digit;
  }
  if (value == 0U) return -1;
  *port = (uint16_t)value;
  return 0;
}

static int next_token(const char *command, uint32_t *position, char *token,
                      uint32_t capacity) {
  uint32_t used = 0U;
  while (command[*position] == ' ' || command[*position] == '\t') ++*position;
  if (command[*position] == '\0') return -1;
  char quote = 0;
  while (command[*position] != '\0') {
    char value = command[*position];
    if (quote == 0 && (value == ' ' || value == '\t')) break;
    ++*position;
    if (value == '\\' && command[*position] != '\0') value = command[(*position)++];
    else if (value == '\'' || value == '"') {
      if (quote == 0) { quote = value; continue; }
      if (quote == value) { quote = 0; continue; }
    }
    if (used + 1U >= capacity) return -1;
    token[used++] = value;
  }
  if (quote != 0) return -1;
  token[used] = '\0';
  return 0;
}

static int parse_destination(ssh_client_context_t *client, const char *text) {
  uint32_t at = UINT32_MAX;
  uint32_t length = ssh_str_len(text);
  for (uint32_t i = 0U; i < length; ++i) if (text[i] == '@') at = i;
  uint32_t host_start = at + 1U;
  uint32_t host_end = length;
  if (host_start < length && text[host_start] == '[') {
    if (length < host_start + 3U || text[length - 1U] != ']') return -1;
    ++host_start;
    --host_end;
  }
  uint32_t host_length = host_end - host_start;
  if (at == 0U || at == UINT32_MAX || host_length == 0U ||
      at >= sizeof(client->user) || host_length >= sizeof(client->host)) {
    return -1;
  }
  ssh_mem_copy(client->user, text, at);
  client->user[at] = '\0';
  ssh_mem_copy(client->host, text + host_start, host_length);
  client->host[host_length] = '\0';
  return 0;
}

static int parse_proxy_destination(ssh_client_context_t *client,
                                   const char *text) {
  uint32_t length = ssh_str_len(text);
  uint32_t at = UINT32_MAX;
  for (uint32_t i = 0U; i < length; ++i) {
    if (text[i] == '@') at = i;
  }
  if (at == 0U || at == UINT32_MAX || at + 1U >= length ||
      at >= sizeof(client->proxy_user)) return -1;
  uint32_t host_start = at + 1U;
  uint32_t host_end = length;
  uint16_t port = 22U;
  if (text[host_start] == '[') {
    uint32_t close = host_start + 1U;
    while (close < length && text[close] != ']') ++close;
    if (close == host_start + 1U || close == length) return -1;
    host_start += 1U;
    host_end = close;
    if (close + 1U != length) {
      if (text[close + 1U] != ':' ||
          parse_port(text + close + 2U, &port) != 0) return -1;
    }
  } else {
    uint32_t colon = UINT32_MAX;
    for (uint32_t i = host_start; i < length; ++i) {
      if (text[i] != ':') continue;
      if (colon != UINT32_MAX) return -1;
      colon = i;
    }
    if (colon != UINT32_MAX) {
      host_end = colon;
      if (parse_port(text + colon + 1U, &port) != 0) return -1;
    }
  }
  uint32_t host_length = host_end - host_start;
  if (host_length == 0U || host_length >= sizeof(client->proxy_host)) return -1;
  for (uint32_t i = 0U; i < at; ++i) {
    char value = text[i];
    if (value == '@' || value == '/' || value == '\\' || value == '\r' ||
        value == '\n') return -1;
  }
  for (uint32_t i = 0U; i < host_length; ++i) {
    char value = text[host_start + i];
    if (value == '@' || value == '/' || value == '\\' || value == '\r' ||
        value == '\n') return -1;
  }
  ssh_mem_copy(client->proxy_user, text, at);
  client->proxy_user[at] = '\0';
  ssh_mem_copy(client->proxy_host, text + host_start, host_length);
  client->proxy_host[host_length] = '\0';
  client->proxy_port = port;
  return 0;
}

static char lower_case(char value) {
  return value >= 'A' && value <= 'Z' ? (char)(value - 'A' + 'a') : value;
}

static int equal_fold(const char *left, const char *right) {
  for (uint32_t i = 0U;; ++i) {
    if (lower_case(left[i]) != lower_case(right[i])) return 0;
    if (left[i] == '\0') return 1;
  }
}

/* `-o Name=value`, spelled the way OpenSSH spells it. BatchMode is the only
   name this client has an answer for, and anything else is refused rather
   than ignored: an option that is accepted and does nothing is worse than
   one that is not accepted, because the caller believes it took effect. */
static int client_set_option(ssh_client_context_t *client, const char *text) {
  static const char batch_mode[] = "batchmode";
  uint32_t split = 0U;
  while (text[split] != '\0' && text[split] != '=') ++split;
  if (text[split] != '=' || split != sizeof(batch_mode) - 1U) return -1;
  for (uint32_t i = 0U; i < split; ++i)
    if (lower_case(text[i]) != batch_mode[i]) return -1;
  const char *value = text + split + 1U;
  if (equal_fold(value, "yes") != 0) {
    client->batch_mode = 1U;
    return 0;
  }
  if (equal_fold(value, "no") != 0) {
    client->batch_mode = 0U;
    return 0;
  }
  return -1;
}

static int remote_specification(const char *text, uint32_t *colon) {
  uint32_t at = UINT32_MAX;
  uint32_t bracket = 0U;
  for (uint32_t i = 0U; text[i] != '\0'; ++i) {
    if (text[i] == '@') at = i;
    if (text[i] == '[' && at != UINT32_MAX) bracket = 1U;
    if (text[i] == ']' && bracket != 0U) bracket = 0U;
    if (text[i] == ':' && bracket == 0U && at != UINT32_MAX && i > at + 1U) {
      *colon = i;
      return 1;
    }
  }
  return 0;
}

static void client_usage(const ssh_channel_t *channel, int scp) {
  const char *usage = scp
      ? "usage: scp [-r] [-B] [-i key] [-o BatchMode=yes] [-P port] "
        "SOURCE DESTINATION\r\n"
      : "usage: ssh [-J user@host[:port]] [-i key] [-o BatchMode=yes] "
        "[-p port] user@host [command]\r\n";
  (void)ssh_channel_send_data((int)channel->owner_sockfd, channel->remote_id,
                              (const uint8_t *)usage, ssh_str_len(usage));
}

int ssh_client_prepare(struct ssh_channel *channel, const char *command) {
  uint32_t position = 0U;
  char token[SSH_CLIENT_COMMAND_MAX];
  if (next_token(command, &position, token, sizeof(token)) != 0) return 0;
  int is_ssh = ssh_str_eq(token, "ssh");
  int is_scp = ssh_str_eq(token, "scp");
  if (!is_ssh && !is_scp) return 0;
  ssh_client_context_t *client = sshclient_client_allocate(channel);
  if (client == 0) {
    static const char busy[] = "ssh: outbound client capacity reached\r\n";
    (void)ssh_channel_send_data((int)channel->owner_sockfd, channel->remote_id,
                                (const uint8_t *)busy, sizeof(busy) - 1U);
    return -1;
  }
  client->mode = is_ssh ? SSH_CLIENT_MODE_SHELL : SSH_CLIENT_MODE_SCP_UPLOAD;
  if (is_scp) {
    char source[SSH_CLIENT_PATH_MAX + SSH_CLIENT_HOST_MAX];
    char destination[SSH_CLIENT_PATH_MAX + SSH_CLIENT_HOST_MAX];
    for (;;) {
      uint32_t saved = position;
      if (next_token(command, &position, token, sizeof(token)) != 0) {
        client_usage(channel, 1);
        sshclient_client_release(channel, client);
        return -1;
      }
      if (ssh_str_eq(token, "-P")) {
        if (next_token(command, &position, token, sizeof(token)) != 0 ||
            parse_port(token, &client->port) != 0) {
          client_usage(channel, 1);
          sshclient_client_release(channel, client);
          return -1;
        }
        continue;
      }
      if (ssh_str_eq(token, "-r")) {
        client->recursive = 1U;
        continue;
      }
      /* -B is what OpenSSH's scp calls batch mode, and it means what
         -o BatchMode=yes means: ask for nothing. */
      if (ssh_str_eq(token, "-B")) {
        client->batch_mode = 1U;
        continue;
      }
      if (token[0] == '-' && token[1] == 'o') {
        const char *option = token + 2U;
        if (option[0] == '\0') {
          if (next_token(command, &position, token, sizeof(token)) != 0) {
            client_usage(channel, 1);
            sshclient_client_release(channel, client);
            return -1;
          }
          option = token;
        }
        if (client_set_option(client, option) != 0) {
          (void)sshclient_output_text(
              client,
              "scp: only -o BatchMode=yes|no is understood\r\n");
          sshclient_client_release(channel, client);
          return -1;
        }
        continue;
      }
      if (ssh_str_eq(token, "-A")) {
        client->use_agent = 1U;
        continue;
      }
      if (ssh_str_eq(token, "-i")) {
        if (next_token(command, &position, client->identity_path,
                       sizeof(client->identity_path)) != 0) {
          client_usage(channel, 1);
          sshclient_client_release(channel, client);
          return -1;
        }
        client->use_identity = 1U;
        continue;
      }
      if (token[0] == '-') {
        client_usage(channel, 1);
        sshclient_client_release(channel, client);
        return -1;
      }
      position = saved;
      break;
    }
    if (next_token(command, &position, source, sizeof(source)) != 0 ||
        next_token(command, &position, destination, sizeof(destination)) != 0) {
      client_usage(channel, 1);
      sshclient_client_release(channel, client);
      return -1;
    }
    while (command[position] == ' ' || command[position] == '\t') ++position;
    if (command[position] != '\0') {
      client_usage(channel, 1);
      sshclient_client_release(channel, client);
      return -1;
    }
    uint32_t source_colon = 0U;
    uint32_t destination_colon = 0U;
    int source_remote = remote_specification(source, &source_colon);
    int destination_remote =
        remote_specification(destination, &destination_colon);
    if (source_remote == destination_remote) {
      client_usage(channel, 1);
      sshclient_client_release(channel, client);
      return -1;
    }
    char endpoint[SSH_CLIENT_HOST_MAX + SSH_CLIENT_USER_MAX];
    const char *remote = source_remote ? source : destination;
    uint32_t colon = source_remote ? source_colon : destination_colon;
    if (colon == 0U || colon >= sizeof(endpoint) || remote[colon + 1U] == '\0') {
      client_usage(channel, 1);
      sshclient_client_release(channel, client);
      return -1;
    }
    ssh_mem_copy(endpoint, remote, colon);
    endpoint[colon] = '\0';
    if (parse_destination(client, endpoint) != 0 ||
        sshclient_string_copy(client->remote_path, sizeof(client->remote_path),
                    remote + colon + 1U) != ssh_str_len(remote + colon + 1U) ||
        sshclient_resolve_local_path(channel, source_remote ? destination : source,
                                     client->local_path,
                                     sizeof(client->local_path)) != 0) {
      client_usage(channel, 1);
      sshclient_client_release(channel, client);
      return -1;
    }
    client->mode = source_remote ? SSH_CLIENT_MODE_SCP_DOWNLOAD
                                 : SSH_CLIENT_MODE_SCP_UPLOAD;
    goto send_password_prompt;
  }
  for (;;) {
    uint32_t saved = position;
    if (next_token(command, &position, token, sizeof(token)) != 0) {
      sshclient_client_release(channel, client);
      client_usage(channel, 0);
      return -1;
    }
    if (ssh_str_eq(token, "-p")) {
      if (next_token(command, &position, token, sizeof(token)) != 0 ||
          parse_port(token, &client->port) != 0) {
        sshclient_client_release(channel, client);
        client_usage(channel, 0);
        return -1;
      }
      continue;
    }
    if (ssh_str_eq(token, "-J")) {
      if (client->proxy_enabled != 0U ||
          next_token(command, &position, token, sizeof(token)) != 0 ||
          parse_proxy_destination(client, token) != 0) {
        sshclient_client_release(channel, client);
        client_usage(channel, 0);
        return -1;
      }
      client->proxy_enabled = 1U;
      continue;
    }
    if (ssh_str_eq(token, "-A")) {
      client->use_agent = 1U;
      continue;
    }
    if (token[0] == '-' && token[1] == 'o') {
      const char *option = token + 2U;
      if (option[0] == '\0') {
        if (next_token(command, &position, token, sizeof(token)) != 0) {
          sshclient_client_release(channel, client);
          client_usage(channel, 0);
          return -1;
        }
        option = token;
      }
      if (client_set_option(client, option) != 0) {
        (void)sshclient_output_text(client,
                          "ssh: only -o BatchMode=yes|no is understood\r\n");
        sshclient_client_release(channel, client);
        return -1;
      }
      continue;
    }
    if (ssh_str_eq(token, "-i")) {
      if (next_token(command, &position, client->identity_path,
                     sizeof(client->identity_path)) != 0) {
        sshclient_client_release(channel, client);
        client_usage(channel, 0);
        return -1;
      }
      client->use_identity = 1U;
      continue;
    }
    if (token[0] == '-') {
      sshclient_client_release(channel, client);
      client_usage(channel, 0);
      return -1;
    }
    position = saved;
    break;
  }
  if (next_token(command, &position, token, sizeof(token)) != 0 ||
      parse_destination(client, token) != 0) {
    sshclient_client_release(channel, client);
    client_usage(channel, 0);
    return -1;
  }
  while (command[position] == ' ' || command[position] == '\t') ++position;
  if (command[position] != '\0') {
    if (sshclient_string_copy(client->command, sizeof(client->command),
                    command + position) != ssh_str_len(command + position)) {
      sshclient_client_release(channel, client);
      client_usage(channel, 0);
      return -1;
    }
    client->mode = SSH_CLIENT_MODE_EXEC;
  }
  if (client->proxy_enabled != 0U) {
    if (client->use_agent != 0U) {
      (void)sshclient_output_text(client,
                        "ssh: -J with forwarded-agent authentication is not supported\r\n");
      sshclient_client_release(channel, client);
      return -1;
    }
    if (sshclient_string_copy(client->target_host, sizeof(client->target_host),
                    client->host) != ssh_str_len(client->host) ||
        sshclient_string_copy(client->target_user, sizeof(client->target_user),
                    client->user) != ssh_str_len(client->user)) {
      sshclient_client_release(channel, client);
      client_usage(channel, 0);
      return -1;
    }
    client->target_port = client->port;
    client->target_use_identity = client->use_identity;
    sshclient_string_copy(client->host, sizeof(client->host), client->proxy_host);
    sshclient_string_copy(client->user, sizeof(client->user), client->proxy_user);
    client->port = client->proxy_port;
    client->use_identity = 0U;
    client->use_agent = 0U;
  }
send_password_prompt:
  if (client->use_agent != 0U && client->use_identity != 0U) {
    client_usage(channel, is_scp);
    sshclient_client_release(channel, client);
    return -1;
  }
  if (client->use_agent != 0U) {
    if (sshclient_output_text(client, "ssh: authenticating with forwarded agent\r\n") != 0)
      goto agent_failed;
    int handshake = sshclient_handshake(client, channel);
    if (handshake != 0) goto agent_failed;
    if (client->mode == SSH_CLIENT_MODE_SCP_UPLOAD ||
        client->mode == SSH_CLIENT_MODE_SCP_DOWNLOAD) {
      int transfer = sshclient_scp_transfer(client);
      (void)sshclient_output_text(client, transfer == 0 ? "scp: transfer complete\r\n"
                                                : "scp: transfer failed\r\n");
      sshclient_client_release(channel, client);
      return transfer == 0 ? 1 : -1;
    }
    return 1;
agent_failed:
    (void)sshclient_output_text(client,
                      "ssh: forwarded-agent authentication failed\r\n");
    sshclient_client_release(channel, client);
    return -1;
  }
  /* B-37. The prompt is no longer unconditional: an identity file with no
     passphrase is loaded without asking anybody anything, which is what lets
     a run with no terminal finish. When something genuinely has to be asked
     for and there is nobody to ask -- BatchMode -- that is an error here,
     and an error here is a non-zero exit rather than a wait. */
  int credential = sshclient_request_credential(client, channel);
  if (credential < 0) {
    sshclient_client_release(channel, client);
    return -1;
  }
  if (credential > 0) return 1;
  return sshclient_client_proceed(client, channel, 0) < 0 ? -1 : 1;
}
