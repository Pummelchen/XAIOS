#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "mlkem_native.h"

int randombytes(uint8_t *output, size_t length) {
  static uint32_t state = 0x5841494fU;
  for (size_t i = 0U; i < length; ++i) {
    state ^= state << 13U;
    state ^= state >> 17U;
    state ^= state << 5U;
    output[i] = (uint8_t)state;
  }
  return 0;
}

static int equal_bytes(const uint8_t *left, const uint8_t *right,
                       size_t length) {
  uint8_t difference = 0U;
  for (size_t i = 0U; i < length; ++i) difference |= left[i] ^ right[i];
  return difference == 0U;
}

int main(void) {
  uint8_t public_key[MLKEM768_PUBLICKEYBYTES];
  uint8_t secret_key[MLKEM768_SECRETKEYBYTES];
  uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
  uint8_t keygen_coins[2U * MLKEM_SYMBYTES];
  uint8_t encapsulation_coins[MLKEM_SYMBYTES];
  uint8_t sender_secret[MLKEM_BYTES];
  uint8_t receiver_secret[MLKEM_BYTES];
  uint8_t rejected_secret[MLKEM_BYTES];

  for (size_t i = 0U; i < sizeof(keygen_coins); ++i)
    keygen_coins[i] = (uint8_t)(i * 29U + 7U);
  for (size_t i = 0U; i < sizeof(encapsulation_coins); ++i)
    encapsulation_coins[i] = (uint8_t)(i * 17U + 3U);

  if (crypto_kem_keypair_derand(public_key, secret_key, keygen_coins) != 0 ||
      crypto_kem_enc_derand(ciphertext, sender_secret, public_key,
                            encapsulation_coins) != 0 ||
      crypto_kem_dec(receiver_secret, ciphertext, secret_key) != 0 ||
      !equal_bytes(sender_secret, receiver_secret, sizeof(sender_secret))) {
    fputs("ML-KEM-768 deterministic round trip failed\n", stderr);
    return 1;
  }

  ciphertext[MLKEM768_CIPHERTEXTBYTES / 2U] ^= 0x80U;
  if (crypto_kem_dec(rejected_secret, ciphertext, secret_key) != 0 ||
      equal_bytes(sender_secret, rejected_secret, sizeof(sender_secret))) {
    fputs("ML-KEM-768 implicit rejection failed\n", stderr);
    return 1;
  }

  puts("ML-KEM-768 hosted tests passed");
  return 0;
}
