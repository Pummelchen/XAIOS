#ifndef SSH_HOST_KEY_H
#define SSH_HOST_KEY_H

#include <xaios/types.h>

/* Persistent Ed25519 host identity seeded from the kernel entropy service. */
int ssh_host_key_init(void);
/* True when the active host key could not be persisted, so it will not
   survive this boot and clients will report it as changed. */
int ssh_host_key_is_ephemeral(void);
int ssh_host_key_reload(void);
int ssh_host_key_get_private(uint8_t priv[32]);
int ssh_host_key_get_public(uint8_t pub[32]);

#endif
