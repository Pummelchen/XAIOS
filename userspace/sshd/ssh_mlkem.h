#ifndef XAIOS_SSH_MLKEM_H
#define XAIOS_SSH_MLKEM_H

#include <xaios/types.h>

#define SSH_MLKEM768_PUBLIC_KEY_SIZE 1184U
#define SSH_MLKEM768_SECRET_KEY_SIZE 2400U
#define SSH_MLKEM768_CIPHERTEXT_SIZE 1088U
#define SSH_MLKEM768_SHARED_SECRET_SIZE 32U

int ssh_mlkem768_keypair(uint8_t public_key[SSH_MLKEM768_PUBLIC_KEY_SIZE],
                         uint8_t secret_key[SSH_MLKEM768_SECRET_KEY_SIZE]);
int ssh_mlkem768_encapsulate(
    uint8_t ciphertext[SSH_MLKEM768_CIPHERTEXT_SIZE],
    uint8_t shared_secret[SSH_MLKEM768_SHARED_SECRET_SIZE],
    const uint8_t public_key[SSH_MLKEM768_PUBLIC_KEY_SIZE]);
int ssh_mlkem768_decapsulate(
    uint8_t shared_secret[SSH_MLKEM768_SHARED_SECRET_SIZE],
    const uint8_t ciphertext[SSH_MLKEM768_CIPHERTEXT_SIZE],
    const uint8_t secret_key[SSH_MLKEM768_SECRET_KEY_SIZE]);
int ssh_mlkem768_self_test(void);

#endif
