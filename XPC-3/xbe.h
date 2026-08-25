#ifndef XBE_H
#define XBE_H

#include "xpc_types.h"

typedef struct {
    uint8_t round_keys[XPC_ROUNDS][32];
} xbe_key_schedule_t;

/**
 * Derives 24 round keys from XPC key and Synthetic IV.
 */
int xbe_init_key_schedule(const uint8_t xpc_key[XPC_KEY_LEN],
                          const uint8_t siv[32],
                          xbe_key_schedule_t *ks);

/**
 * Encrypts a single 64-byte block using 24-round Feistel network.
 */
int xbe_encrypt_block(const uint8_t in_block[XPC_BLOCK_SIZE],
                      uint8_t out_block[XPC_BLOCK_SIZE],
                      const xbe_key_schedule_t *ks);

/**
 * Decrypts a single 64-byte block using 24-round Feistel network.
 */
int xbe_decrypt_block(const uint8_t in_block[XPC_BLOCK_SIZE],
                      uint8_t out_block[XPC_BLOCK_SIZE],
                      const xbe_key_schedule_t *ks);

#endif /* XBE_H */
