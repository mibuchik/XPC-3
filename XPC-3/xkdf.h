#ifndef XKDF_H
#define XKDF_H

#include "xpc_types.h"

/**
 * Derives master key and subkeys from password and salt using XKDF (Memory-Hard KDF).
 *
 * @param password      User password string
 * @param pass_len      Length of password
 * @param salt          Salt buffer (XPC_SALT_LEN = 64 bytes)
 * @param out_xpc_key   Output XPC-3 key buffer (64 bytes)
 * @param out_aes_key   Output AES-256 key buffer (32 bytes)
 * @param out_cha_key   Output ChaCha20 key buffer (32 bytes)
 * @return              XPC_OK on success, or error code
 */
int xkdf_derive_keys(const char *password, size_t pass_len,
                    const uint8_t salt[XPC_SALT_LEN],
                    uint8_t out_xpc_key[XPC_KEY_LEN],
                    uint8_t out_aes_key[AES_KEY_LEN],
                    uint8_t out_cha_key[CHA_KEY_LEN]);

#endif /* XKDF_H */
