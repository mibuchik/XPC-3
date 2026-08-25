#include "xbe.h"
#include <string.h>
#include <openssl/evp.h>

static int sha3_256(const uint8_t *in1, size_t in1_len,
                     const uint8_t *in2, size_t in2_len,
                     const uint8_t *in3, size_t in3_len,
                     uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return XPC_ERR_MEMORY;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1 ||
        (in1 && in1_len > 0 && EVP_DigestUpdate(ctx, in1, in1_len) != 1) ||
        (in2 && in2_len > 0 && EVP_DigestUpdate(ctx, in2, in2_len) != 1) ||
        (in3 && in3_len > 0 && EVP_DigestUpdate(ctx, in3, in3_len) != 1) ||
        EVP_DigestFinal_ex(ctx, out, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return XPC_ERR_CRYPTO;
    }

    EVP_MD_CTX_free(ctx);
    return XPC_OK;
}

int xbe_init_key_schedule(const uint8_t xpc_key[XPC_KEY_LEN],
                          const uint8_t siv[32],
                          xbe_key_schedule_t *ks) {
    if (!xpc_key || !siv || !ks) return XPC_ERR_MEMORY;

    for (uint8_t r = 0; r < XPC_ROUNDS; r++) {
        int res = sha3_256(xpc_key, XPC_KEY_LEN, siv, 32, &r, 1, ks->round_keys[r]);
        if (res != XPC_OK) return res;
    }
    return XPC_OK;
}

int xbe_encrypt_block(const uint8_t in_block[XPC_BLOCK_SIZE],
                      uint8_t out_block[XPC_BLOCK_SIZE],
                      const xbe_key_schedule_t *ks) {
    if (!in_block || !out_block || !ks) return XPC_ERR_MEMORY;

    uint8_t L[32], R[32];
    memcpy(L, in_block, 32);
    memcpy(R, in_block + 32, 32);

    for (uint8_t r = 0; r < XPC_ROUNDS; r++) {
        uint8_t f_out[32];
        int res = sha3_256(R, 32, ks->round_keys[r], 32, &r, 1, f_out);
        if (res != XPC_OK) return res;

        uint8_t next_R[32];
        for (int i = 0; i < 32; i++) {
            next_R[i] = L[i] ^ f_out[i];
        }

        memcpy(L, R, 32);
        memcpy(R, next_R, 32);
    }

    memcpy(out_block, L, 32);
    memcpy(out_block + 32, R, 32);
    return XPC_OK;
}

int xbe_decrypt_block(const uint8_t in_block[XPC_BLOCK_SIZE],
                      uint8_t out_block[XPC_BLOCK_SIZE],
                      const xbe_key_schedule_t *ks) {
    if (!in_block || !out_block || !ks) return XPC_ERR_MEMORY;

    uint8_t L[32], R[32];
    memcpy(L, in_block, 32);
    memcpy(R, in_block + 32, 32);

    for (int r = XPC_ROUNDS - 1; r >= 0; r--) {
        uint8_t round_byte = (uint8_t)r;
        uint8_t f_out[32];
        int res = sha3_256(L, 32, ks->round_keys[r], 32, &round_byte, 1, f_out);
        if (res != XPC_OK) return res;

        uint8_t prev_L[32];
        for (int i = 0; i < 32; i++) {
            prev_L[i] = R[i] ^ f_out[i];
        }

        memcpy(R, L, 32);
        memcpy(L, prev_L, 32);
    }

    memcpy(out_block, L, 32);
    memcpy(out_block + 32, R, 32);
    return XPC_OK;
}
