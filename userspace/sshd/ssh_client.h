#ifndef XAIOS_SSH_CLIENT_H
#define XAIOS_SSH_CLIENT_H

#include <xaios/types.h>

struct ssh_channel;

/* Returns 1 when command is an outbound ssh/scp command, 0 otherwise. */
int ssh_client_prepare(struct ssh_channel *channel, const char *command);
int ssh_client_password_input(struct ssh_channel *channel,
                              const uint8_t *data, uint32_t length);
int ssh_client_forward_input(struct ssh_channel *channel,
                             const uint8_t *data, uint32_t length);
int ssh_client_tick(struct ssh_channel *channel, uint64_t now_ns);
void ssh_client_close(struct ssh_channel *channel);
int ssh_client_is_prompting(const struct ssh_channel *channel);
int ssh_client_is_active(const struct ssh_channel *channel);
int ssh_client_agent_response(struct ssh_channel *channel,
                              const uint8_t *data, uint32_t length);
int ssh_client_agent_ready(struct ssh_channel *channel);

void ssh_client_app_set_cwd(const char *cwd);
#if defined(XAIOS_SSH_CLIENT_APP)
int ssh_client_app_agent_exchange(const uint8_t *request,
                                  uint32_t request_length, uint8_t *response,
                                  uint32_t response_capacity,
                                  uint32_t *response_length,
                                  uint64_t deadline);
#endif

#endif
