#ifndef XCM_H
#define XCM_H

#include "xbe.h"

/**
 * Encrypts data buffer in XCM mode (CBC+CTR hybrid via XBE).
 * Length must be a multiple of XPC_BLOCK_SIZE (64 bytes).
 */
int xcm_encrypt(const uint8_t *in_data, size_t len,
                uint8_t *out_data,
                const uint8_t siv[32],
                const xbe_key_schedule_t *ks);

/**
 * Decrypts data buffer in XCM mode.
 * Length must be a multiple of XPC_BLOCK_SIZE (64 bytes).
 */
int xcm_decrypt(const uint8_t *in_data, size_t len,
                uint8_t *out_data,
                const uint8_t siv[32],
                const xbe_key_schedule_t *ks);

#endif /* XCM_H */
