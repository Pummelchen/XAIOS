#ifndef XAIOS_TWEETNACL_SUBSET_H
#define XAIOS_TWEETNACL_SUBSET_H

#include <xaios/types.h>

int xaios_x25519(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32]);
int xaios_x25519_base(uint8_t out[32], const uint8_t scalar[32]);
void xaios_ed25519_public_key(uint8_t public_key[32],
                             const uint8_t seed[32]);
int xaios_ed25519_sign(uint8_t signature[64], const uint8_t *message,
                       uint32_t message_len, const uint8_t public_key[32],
                       const uint8_t seed[32]);
int xaios_ed25519_verify(const uint8_t signature[64], const uint8_t *message,
                         uint32_t message_len,
                         const uint8_t public_key[32]);

#endif
