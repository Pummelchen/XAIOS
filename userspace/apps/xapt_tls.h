#ifndef XAIOS_XAPT_TLS_H
#define XAIOS_XAPT_TLS_H

#include <xaios_user.h>

/* Open a TLS 1.2 session. With rsa_modulus_hex null or empty the presented
   chain is validated against the compiled-in roots, including server name and
   validity window; otherwise that exact leaf RSA key is required and the rest
   of the certificate is ignored. */
int xapt_tls_open(u64 socket, const char *server_name,
                  const char *rsa_modulus_hex);
int xapt_tls_write(const void *data, u64 size);
int xapt_tls_read(void *data, u64 size);
int xapt_tls_close(void);
int xapt_tls_last_error(void);

#endif
