#ifndef SSH_CRYPTO_INTERNAL_H
#define SSH_CRYPTO_INTERNAL_H

#include <xaios/types.h>

/* Big-endian 32-bit load shared by the SHA-256 compressor in ssh_crypto.c and
   the AES-128/256 key schedule in ssh_crypto_symmetric.c. It is defined exactly
   once, in ssh_crypto.c, the translation unit every configuration compiles
   (the UEFI loader's hashes-only build included). */
uint32_t ssh_crypto_be32(const uint8_t *p);

#endif
