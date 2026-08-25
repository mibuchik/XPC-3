#include "xkdf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static void secure_memzero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static int sha3_512(const uint8_t *in1, size_t in1_len,
                     const uint8_t *in2, size_t in2_len,
                     uint8_t out[64]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return XPC_ERR_MEMORY;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1 ||
        (in1 && in1_len > 0 && EVP_DigestUpdate(ctx, in1, in1_len) != 1) ||
        (in2 && in2_len > 0 && EVP_DigestUpdate(ctx, in2, in2_len) != 1) ||
        EVP_DigestFinal_ex(ctx, out, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return XPC_ERR_CRYPTO;
    }

    EVP_MD_CTX_free(ctx);
    return XPC_OK;
}

static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len) {
    uint8_t prk[32];
    unsigned int prk_len = 32;

    /* HKDF-Extract */
    if (!salt || salt_len == 0) {
        static const uint8_t zero_salt[32] = {0};
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }

    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, (int)ikm_len, prk, &prk_len)) {
        return XPC_ERR_CRYPTO;
    }

    /* HKDF-Expand */
    size_t n = (okm_len + 31) / 32;
    uint8_t t[32];
    size_t t_len = 0;
    size_t okm_pos = 0;

    for (size_t i = 1; i <= n; i++) {
        HMAC_CTX *hctx = HMAC_CTX_new();
        if (!hctx) return XPC_ERR_MEMORY;

        if (!HMAC_Init_ex(hctx, prk, (int)prk_len, EVP_sha256(), NULL) ||
            (t_len > 0 && !HMAC_Update(hctx, t, t_len)) ||
            (info && info_len > 0 && !HMAC_Update(hctx, info, info_len))) {
            HMAC_CTX_free(hctx);
            return XPC_ERR_CRYPTO;
        }

        uint8_t counter = (uint8_t)i;
        if (!HMAC_Update(hctx, &counter, 1)) {
            HMAC_CTX_free(hctx);
            return XPC_ERR_CRYPTO;
        }

        unsigned int len = 0;
        if (!HMAC_Final(hctx, t, &len)) {
            HMAC_CTX_free(hctx);
            return XPC_ERR_CRYPTO;
        }
        HMAC_CTX_free(hctx);

        t_len = len;
        size_t to_copy = (okm_pos + t_len > okm_len) ? (okm_len - okm_pos) : t_len;
        memcpy(okm + okm_pos, t, to_copy);
        okm_pos += to_copy;
    }

    secure_memzero(prk, sizeof(prk));
    secure_memzero(t, sizeof(t));
    return XPC_OK;
}

int xkdf_derive_keys(const char *password, size_t pass_len,
                    const uint8_t salt[XPC_SALT_LEN],
                    uint8_t out_xpc_key[XPC_KEY_LEN],
                    uint8_t out_aes_key[AES_KEY_LEN],
                    uint8_t out_cha_key[CHA_KEY_LEN]) {
    if (!password || !salt || !out_xpc_key || !out_aes_key || !out_cha_key) {
        return XPC_ERR_MEMORY;
    }

    /* Allocate 64 MiB memory buffer for memory-hard seeding */
    uint8_t (*buffer)[XKDF_BLOCK_SIZE] = malloc(XKDF_MEM_SIZE);
    if (!buffer) {
        return XPC_ERR_MEMORY;
    }

    uint8_t state[64];
    int res = sha3_512((const uint8_t *)password, pass_len, salt, XPC_SALT_LEN, state);
    if (res != XPC_OK) {
        free(buffer);
        return res;
    }

    /* Step 2: Memory-hard seeding */
    for (size_t i = 0; i < XKDF_NUM_BLOCKS; i++) {
        res = sha3_512(state, sizeof(state), NULL, 0, buffer[i]);
        if (res != XPC_OK) {
            secure_memzero(buffer, XKDF_MEM_SIZE);
            free(buffer);
            return res;
        }
        res = sha3_512(state, sizeof(state), buffer[i], XKDF_BLOCK_SIZE, state);
        if (res != XPC_OK) {
            secure_memzero(buffer, XKDF_MEM_SIZE);
            free(buffer);
            return res;
        }
    }

    /* Step 3: Data-dependent mixing (3 passes) */
    for (int pass = 0; pass < XKDF_PASSES; pass++) {
        for (size_t i = 0; i < XKDF_NUM_BLOCKS; i++) {
            uint64_t raw_idx;
            memcpy(&raw_idx, state, sizeof(uint64_t));
            size_t idx = (size_t)(raw_idx % XKDF_NUM_BLOCKS);

            res = sha3_512(state, sizeof(state), buffer[idx], XKDF_BLOCK_SIZE, state);
            if (res != XPC_OK) {
                secure_memzero(buffer, XKDF_MEM_SIZE);
                free(buffer);
                return res;
            }

            for (size_t k = 0; k < XKDF_BLOCK_SIZE; k++) {
                buffer[idx][k] ^= state[k];
            }
        }
    }

    /* Step 4: Finalization */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        secure_memzero(buffer, XKDF_MEM_SIZE);
        free(buffer);
        return XPC_ERR_MEMORY;
    }

    uint8_t master_key[XPC_MASTER_KEY_LEN];
    if (EVP_DigestInit_ex(md_ctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, state, sizeof(state)) != 1) {
        EVP_MD_CTX_free(md_ctx);
        secure_memzero(buffer, XKDF_MEM_SIZE);
        free(buffer);
        return XPC_ERR_CRYPTO;
    }

    for (size_t i = 0; i < XKDF_NUM_BLOCKS; i += 1024) {
        if (EVP_DigestUpdate(md_ctx, buffer[i], XKDF_BLOCK_SIZE) != 1) {
            EVP_MD_CTX_free(md_ctx);
            secure_memzero(buffer, XKDF_MEM_SIZE);
            free(buffer);
            return XPC_ERR_CRYPTO;
        }
    }

    if (EVP_DigestFinal_ex(md_ctx, master_key, NULL) != 1) {
        EVP_MD_CTX_free(md_ctx);
        secure_memzero(buffer, XKDF_MEM_SIZE);
        free(buffer);
        return XPC_ERR_CRYPTO;
    }
    EVP_MD_CTX_free(md_ctx);

    /* Free XKDF memory buffer */
    secure_memzero(buffer, XKDF_MEM_SIZE);
    free(buffer);

    /* HKDF key derivation to split master key into subkeys */
    res = hkdf_sha256(master_key, XPC_MASTER_KEY_LEN, salt, XPC_SALT_LEN,
                      (const uint8_t *)"xpc3_key", 8, out_xpc_key, XPC_KEY_LEN);
    if (res == XPC_OK) {
        res = hkdf_sha256(master_key, XPC_MASTER_KEY_LEN, salt, XPC_SALT_LEN,
                          (const uint8_t *)"aes_key", 7, out_aes_key, AES_KEY_LEN);
    }
    if (res == XPC_OK) {
        res = hkdf_sha256(master_key, XPC_MASTER_KEY_LEN, salt, XPC_SALT_LEN,
                          (const uint8_t *)"chacha_key", 10, out_cha_key, CHA_KEY_LEN);
    }

    secure_memzero(master_key, sizeof(master_key));
    secure_memzero(state, sizeof(state));
    return res;
}
