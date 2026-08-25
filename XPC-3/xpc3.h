#ifndef XPC3_H
#define XPC3_H

#include "xpc_types.h"

/**
 * Encrypts an in-memory buffer using XPC-3 triple cascade.
 */
int xpc3_encrypt_buffer(const uint8_t *plain, size_t plain_len,
                        const char *password, size_t pass_len,
                        uint8_t **out_cipher, size_t *out_cipher_len);

/**
 * Decrypts an in-memory XPC-3 ciphertext buffer.
 */
int xpc3_decrypt_buffer(const uint8_t *cipher, size_t cipher_len,
                        const char *password, size_t pass_len,
                        uint8_t **out_plain, size_t *out_plain_len);

/**
 * Encrypts a file on disk using XPC-3.
 */
int xpc3_encrypt_file(const char *in_filepath, const char *out_filepath,
                      const char *password);

/**
 * Decrypts a file on disk using XPC-3.
 */
int xpc3_decrypt_file(const char *in_filepath, const char *out_filepath,
                      const char *password);

#endif /* XPC3_H */
