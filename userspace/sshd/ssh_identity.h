#ifndef XAIOS_SSH_IDENTITY_H
#define XAIOS_SSH_IDENTITY_H

#include <xaios/types.h>

typedef struct ssh_identity {
  uint8_t public_key[32];
  uint8_t seed[32];
} ssh_identity_t;

int ssh_identity_parse_openssh(const char *pem, uint32_t pem_length,
                               const char *passphrase,
                               ssh_identity_t *identity);
int ssh_identity_load(const char *path, const char *passphrase,
                      ssh_identity_t *identity);

#endif
