#include "ssh_mlkem.h"

#include "ssh_crypto.h"
#include "ssh_utils.h"
#include "mlkem_native.h"

int randombytes(uint8_t *output, size_t length) {
  if (length > UINT32_MAX) return -1;
  return crypto_random_bytes(output, (uint32_t)length);
}

int ssh_mlkem768_keypair(uint8_t public_key[SSH_MLKEM768_PUBLIC_KEY_SIZE],
                         uint8_t secret_key[SSH_MLKEM768_SECRET_KEY_SIZE]) {
  return crypto_kem_keypair(public_key, secret_key);
}

int ssh_mlkem768_encapsulate(
    uint8_t ciphertext[SSH_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[SSH_MLKEM768_SHARED_SECRET_SIZE],
    const uint8_t public_key[SSH_MLKEM768_PUBLIC_KEY_SIZE]) {
  return crypto_kem_enc(ciphertext, shared_secret, public_key);
}

int ssh_mlkem768_decapsulate(
    uint8_t shared_secret[SSH_MLKEM768_SHARED_SECRET_SIZE],
    const uint8_t ciphertext[SSH_MLKEM768_CIPHERTEXT_SIZE],
    const uint8_t secret_key[SSH_MLKEM768_SECRET_KEY_SIZE]) {
  return crypto_kem_dec(shared_secret, ciphertext, secret_key);
}

int ssh_mlkem768_self_test(void) {
  uint8_t public_key[SSH_MLKEM768_PUBLIC_KEY_SIZE];
  uint8_t secret_key[SSH_MLKEM768_SECRET_KEY_SIZE];
  uint8_t ciphertext[SSH_MLKEM768_CIPHERTEXT_SIZE];
  uint8_t sender_secret[SSH_MLKEM768_SHARED_SECRET_SIZE];
  uint8_t receiver_secret[SSH_MLKEM768_SHARED_SECRET_SIZE];
  int result = ssh_mlkem768_keypair(public_key, secret_key);
  if (result == 0)
    result = ssh_mlkem768_encapsulate(ciphertext, sender_secret, public_key);
  if (result == 0)
    result = ssh_mlkem768_decapsulate(receiver_secret, ciphertext, secret_key);
  uint8_t difference = 0U;
  for (uint32_t i = 0U; i < sizeof(sender_secret); ++i)
    difference |= sender_secret[i] ^ receiver_secret[i];
  if (result == 0 && difference != 0U) result = -1;
  ssh_mem_zero(secret_key, sizeof(secret_key));
  ssh_mem_zero(sender_secret, sizeof(sender_secret));
  ssh_mem_zero(receiver_secret, sizeof(receiver_secret));
  return result;
}
