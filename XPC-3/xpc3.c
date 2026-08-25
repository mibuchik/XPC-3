#include "xpc3.h"
#include "xkdf.h"
#include "xbe.h"
#include "xcm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

static void secure_memzero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32]) {
    unsigned int len = 32;
    if (!HMAC(EVP_sha256(), key, (int)key_len, data, (int)data_len, out, &len)) {
        return XPC_ERR_CRYPTO;
    }
    return XPC_OK;
}

static int aes_gcm_encrypt(const uint8_t *in, size_t in_len,
                           const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *out, uint8_t tag[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return XPC_ERR_MEMORY;

    int len = 0, out_len = 0, final_len = 0;
    int res = XPC_ERR_CRYPTO;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        (aad == NULL || aad_len == 0 || EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1) &&
        EVP_EncryptUpdate(ctx, out, &out_len, in, (int)in_len) == 1 &&
        EVP_EncryptFinal_ex(ctx, out + out_len, &final_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1) {
        res = XPC_OK;
    }

    EVP_CIPHER_CTX_free(ctx);
    return res;
}

static int aes_gcm_decrypt(const uint8_t *in, size_t in_len,
                           const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t tag[16], uint8_t *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return XPC_ERR_MEMORY;

    int len = 0, out_len = 0, final_len = 0;
    int res = XPC_ERR_AUTH_FAILED;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        (aad == NULL || aad_len == 0 || EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1) &&
        EVP_DecryptUpdate(ctx, out, &out_len, in, (int)in_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) == 1) {
        if (EVP_DecryptFinal_ex(ctx, out + out_len, &final_len) == 1) {
            res = XPC_OK;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return res;
}

static int chacha_poly_encrypt(const uint8_t *in, size_t in_len,
                               const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *aad, size_t aad_len,
                               uint8_t *out, uint8_t tag[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return XPC_ERR_MEMORY;

    int len = 0, out_len = 0, final_len = 0;
    int res = XPC_ERR_CRYPTO;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        (aad == NULL || aad_len == 0 || EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1) &&
        EVP_EncryptUpdate(ctx, out, &out_len, in, (int)in_len) == 1 &&
        EVP_EncryptFinal_ex(ctx, out + out_len, &final_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1) {
        res = XPC_OK;
    }

    EVP_CIPHER_CTX_free(ctx);
    return res;
}

static int chacha_poly_decrypt(const uint8_t *in, size_t in_len,
                               const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t tag[16], uint8_t *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return XPC_ERR_MEMORY;

    int len = 0, out_len = 0, final_len = 0;
    int res = XPC_ERR_AUTH_FAILED;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        (aad == NULL || aad_len == 0 || EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) == 1) &&
        EVP_DecryptUpdate(ctx, out, &out_len, in, (int)in_len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) == 1) {
        if (EVP_DecryptFinal_ex(ctx, out + out_len, &final_len) == 1) {
            res = XPC_OK;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return res;
}

int xpc3_encrypt_buffer(const uint8_t *plain, size_t plain_len,
                        const char *password, size_t pass_len,
                        uint8_t **out_cipher, size_t *out_cipher_len) {
    if (!plain || plain_len == 0 || !password || !out_cipher || !out_cipher_len) {
        return XPC_ERR_MEMORY;
    }

    /* 1. Compression via zlib */
    uLongf comp_bound = compressBound(plain_len);
    uint8_t *comp_buf = malloc(comp_bound);
    if (!comp_buf) return XPC_ERR_MEMORY;

    uLongf comp_len = comp_bound;
    if (compress2(comp_buf, &comp_len, plain, plain_len, 9) != Z_OK) {
        free(comp_buf);
        return XPC_ERR_COMPRESSION;
    }

    /* 2. Block Padding to 64 bytes */
    size_t rem = comp_len % XPC_BLOCK_SIZE;
    uint8_t pad_len = (uint8_t)(XPC_BLOCK_SIZE - rem);
    size_t l1_len = comp_len + pad_len;

    uint8_t *l1_plain = malloc(l1_len);
    if (!l1_plain) {
        free(comp_buf);
        return XPC_ERR_MEMORY;
    }
    memcpy(l1_plain, comp_buf, comp_len);
    free(comp_buf);

    if (RAND_bytes(l1_plain + comp_len, pad_len) != 1) {
        memset(l1_plain + comp_len, 0, pad_len);
    }
    l1_plain[l1_len - 1] = pad_len;

    /* 3. Random Salt & Nonces */
    uint8_t salt[XPC_SALT_LEN];
    uint8_t aes_nonce[XPC_AES_NONCE_LEN];
    uint8_t cha_nonce[XPC_CHA_NONCE_LEN];

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        RAND_bytes(aes_nonce, sizeof(aes_nonce)) != 1 ||
        RAND_bytes(cha_nonce, sizeof(cha_nonce)) != 1) {
        secure_memzero(l1_plain, l1_len);
        free(l1_plain);
        return XPC_ERR_CRYPTO;
    }

    /* 4. Derive Keys via XKDF */
    uint8_t k_xpc[XPC_KEY_LEN];
    uint8_t k_aes[AES_KEY_LEN];
    uint8_t k_cha[CHA_KEY_LEN];

    int res = xkdf_derive_keys(password, pass_len, salt, k_xpc, k_aes, k_cha);
    if (res != XPC_OK) {
        secure_memzero(l1_plain, l1_len);
        free(l1_plain);
        return res;
    }

    /* 5. Layer 1 (XPC-3: XBE + XCM + SIV) */
    uint8_t inner_hmac[XPC_HMAC_LEN];
    res = hmac_sha256(k_xpc, sizeof(k_xpc), l1_plain, l1_len, inner_hmac);
    if (res != XPC_OK) {
        secure_memzero(l1_plain, l1_len);
        free(l1_plain);
        return res;
    }

    xbe_key_schedule_t ks;
    res = xbe_init_key_schedule(k_xpc, inner_hmac, &ks);
    if (res != XPC_OK) {
        secure_memzero(l1_plain, l1_len);
        free(l1_plain);
        return res;
    }

    uint8_t *l1_cipher = malloc(l1_len);
    if (!l1_cipher) {
        secure_memzero(l1_plain, l1_len);
        free(l1_plain);
        return XPC_ERR_MEMORY;
    }

    res = xcm_encrypt(l1_plain, l1_len, l1_cipher, inner_hmac, &ks);
    secure_memzero(l1_plain, l1_len);
    free(l1_plain);
    if (res != XPC_OK) {
        free(l1_cipher);
        return res;
    }

    /* 6. Layer 2 (AES-256-GCM) */
    uint8_t *l2_cipher = malloc(l1_len);
    uint8_t aes_tag[16];
    if (!l2_cipher) {
        free(l1_cipher);
        return XPC_ERR_MEMORY;
    }

    res = aes_gcm_encrypt(l1_cipher, l1_len, k_aes, aes_nonce, salt, sizeof(salt), l2_cipher, aes_tag);
    free(l1_cipher);
    if (res != XPC_OK) {
        free(l2_cipher);
        return res;
    }

    /* 7. Layer 3 (ChaCha20-Poly1305) */
    size_t l2_payload_len = l1_len + sizeof(aes_tag);
    uint8_t *l2_payload = malloc(l2_payload_len);
    if (!l2_payload) {
        free(l2_cipher);
        return XPC_ERR_MEMORY;
    }
    memcpy(l2_payload, l2_cipher, l1_len);
    memcpy(l2_payload + l1_len, aes_tag, sizeof(aes_tag));
    free(l2_cipher);

    /* Outer AAD = Salt (64B) + AES Nonce (12B) */
    uint8_t outer_aad[XPC_SALT_LEN + XPC_AES_NONCE_LEN];
    memcpy(outer_aad, salt, XPC_SALT_LEN);
    memcpy(outer_aad + XPC_SALT_LEN, aes_nonce, XPC_AES_NONCE_LEN);

    uint8_t *l3_cipher = malloc(l2_payload_len);
    uint8_t poly_tag[16];
    if (!l3_cipher) {
        free(l2_payload);
        return XPC_ERR_MEMORY;
    }

    res = chacha_poly_encrypt(l2_payload, l2_payload_len, k_cha, cha_nonce,
                             outer_aad, sizeof(outer_aad), l3_cipher, poly_tag);
    free(l2_payload);
    if (res != XPC_OK) {
        free(l3_cipher);
        return res;
    }

    /* 8. Assemble final ciphertext output buffer */
    size_t total_cipher_len = XPC_HEADER_LEN + l2_payload_len + sizeof(poly_tag) + XPC_TRAILER_LEN;
    uint8_t *final_cipher = malloc(total_cipher_len);
    if (!final_cipher) {
        free(l3_cipher);
        return XPC_ERR_MEMORY;
    }

    uint8_t *ptr = final_cipher;
    memcpy(ptr, salt, XPC_SALT_LEN); ptr += XPC_SALT_LEN;
    memcpy(ptr, aes_nonce, XPC_AES_NONCE_LEN); ptr += XPC_AES_NONCE_LEN;
    memcpy(ptr, cha_nonce, XPC_CHA_NONCE_LEN); ptr += XPC_CHA_NONCE_LEN;

    memcpy(ptr, l3_cipher, l2_payload_len); ptr += l2_payload_len;
    free(l3_cipher);

    memcpy(ptr, poly_tag, sizeof(poly_tag)); ptr += sizeof(poly_tag);

    memcpy(ptr, inner_hmac, XPC_HMAC_LEN); ptr += XPC_HMAC_LEN;
    *ptr = pad_len;

    *out_cipher = final_cipher;
    *out_cipher_len = total_cipher_len;

    secure_memzero(k_xpc, sizeof(k_xpc));
    secure_memzero(k_aes, sizeof(k_aes));
    secure_memzero(k_cha, sizeof(k_cha));
    return XPC_OK;
}

int xpc3_decrypt_buffer(const uint8_t *cipher, size_t cipher_len,
                        const char *password, size_t pass_len,
                        uint8_t **out_plain, size_t *out_plain_len) {
    if (!cipher || !password || !out_plain || !out_plain_len) {
        return XPC_ERR_MEMORY;
    }

    size_t min_len = XPC_HEADER_LEN + 16 + 16 + XPC_TRAILER_LEN;
    if (cipher_len < min_len) {
        return XPC_ERR_INVALID_FORMAT;
    }

    /* Parse Header & Trailer */
    const uint8_t *salt = cipher;
    const uint8_t *aes_nonce = cipher + XPC_SALT_LEN;
    const uint8_t *cha_nonce = cipher + XPC_SALT_LEN + XPC_AES_NONCE_LEN;

    const uint8_t *trailer = cipher + cipher_len - XPC_TRAILER_LEN;
    const uint8_t *expected_hmac = trailer;
    uint8_t pad_len = trailer[XPC_HMAC_LEN];

    size_t encrypted_payload_len = cipher_len - XPC_HEADER_LEN - XPC_TRAILER_LEN - 16; /* 16 is Poly1305 tag */
    const uint8_t *l3_cipher = cipher + XPC_HEADER_LEN;
    const uint8_t *poly_tag = l3_cipher + encrypted_payload_len;

    /* Derive Keys via XKDF */
    uint8_t k_xpc[XPC_KEY_LEN];
    uint8_t k_aes[AES_KEY_LEN];
    uint8_t k_cha[CHA_KEY_LEN];

    int res = xkdf_derive_keys(password, pass_len, salt, k_xpc, k_aes, k_cha);
    if (res != XPC_OK) return res;

    /* 1. Decrypt Layer 3 (ChaCha20-Poly1305) */
    uint8_t outer_aad[XPC_SALT_LEN + XPC_AES_NONCE_LEN];
    memcpy(outer_aad, salt, XPC_SALT_LEN);
    memcpy(outer_aad + XPC_SALT_LEN, aes_nonce, XPC_AES_NONCE_LEN);

    uint8_t *l2_payload = malloc(encrypted_payload_len);
    if (!l2_payload) {
        secure_memzero(k_xpc, sizeof(k_xpc));
        secure_memzero(k_aes, sizeof(k_aes));
        secure_memzero(k_cha, sizeof(k_cha));
        return XPC_ERR_MEMORY;
    }

    res = chacha_poly_decrypt(l3_cipher, encrypted_payload_len, k_cha, cha_nonce,
                              outer_aad, sizeof(outer_aad), poly_tag, l2_payload);
    if (res != XPC_OK) {
        free(l2_payload);
        secure_memzero(k_xpc, sizeof(k_xpc));
        secure_memzero(k_aes, sizeof(k_aes));
        secure_memzero(k_cha, sizeof(k_cha));
        return XPC_ERR_AUTH_FAILED;
    }

    /* 2. Decrypt Layer 2 (AES-256-GCM) */
    size_t l1_len = encrypted_payload_len - 16; /* 16 is AES GCM tag */
    const uint8_t *l2_cipher = l2_payload;
    const uint8_t *aes_tag = l2_payload + l1_len;

    uint8_t *l1_cipher = malloc(l1_len);
    if (!l1_cipher) {
        free(l2_payload);
        secure_memzero(k_xpc, sizeof(k_xpc));
        secure_memzero(k_aes, sizeof(k_aes));
        secure_memzero(k_cha, sizeof(k_cha));
        return XPC_ERR_MEMORY;
    }

    res = aes_gcm_decrypt(l2_cipher, l1_len, k_aes, aes_nonce, salt, XPC_SALT_LEN, aes_tag, l1_cipher);
    free(l2_payload);
    if (res != XPC_OK) {
        free(l1_cipher);
        secure_memzero(k_xpc, sizeof(k_xpc));
        secure_memzero(k_aes, sizeof(k_aes));
        secure_memzero(k_cha, sizeof(k_cha));
        return XPC_ERR_AUTH_FAILED;
    }

    /* 3. Decrypt Layer 1 (XPC-3: XBE + XCM + SIV) */
    uint8_t *l1_plain = malloc(l1_len);
    if (!l1_plain) {
        free(l1_cipher);
        secure_memzero(k_xpc, sizeof(k_xpc));
        secure_memzero(k_aes, sizeof(k_aes));
        secure_memzero(k_cha, sizeof(k_cha));
        return XPC_ERR_MEMORY;
    }

    xbe_key_schedule_t ks;
    res = xbe_init_key_schedule(k_xpc, expected_hmac, &ks);
    if (res != XPC_OK) {
        free(l1_cipher);
        free(l1_plain);
        secure_memzero(k_xpc, sizeof(k_xpc));
        secure_memzero(k_aes, sizeof(k_aes));
        secure_memzero(k_cha, sizeof(k_cha));
        return res;
    }

    res = xcm_decrypt(l1_cipher, l1_len, l1_plain, expected_hmac, &ks);
    free(l1_cipher);
    if (res != XPC_OK) {
        free(l1_plain);
        secure_memzero(k_xpc, sizeof(k_xpc));
        secure_memzero(k_aes, sizeof(k_aes));
        secure_memzero(k_cha, sizeof(k_cha));
        return res;
    }

    /* 4. Verify Inner HMAC over decrypted padded payload */
    uint8_t computed_hmac[XPC_HMAC_LEN];
    res = hmac_sha256(k_xpc, sizeof(k_xpc), l1_plain, l1_len, computed_hmac);
    if (res != XPC_OK || CRYPTO_memcmp(computed_hmac, expected_hmac, XPC_HMAC_LEN) != 0) {
        secure_memzero(l1_plain, l1_len);
        free(l1_plain);
        secure_memzero(k_xpc, sizeof(k_xpc));
        secure_memzero(k_aes, sizeof(k_aes));
        secure_memzero(k_cha, sizeof(k_cha));
        return XPC_ERR_AUTH_FAILED;
    }

    /* Validate Padding */
    if (pad_len == 0 || pad_len > XPC_BLOCK_SIZE || pad_len > l1_len) {
        secure_memzero(l1_plain, l1_len);
        free(l1_plain);
        return XPC_ERR_INVALID_FORMAT;
    }

    size_t comp_len = l1_len - pad_len;

    /* 5. Decompress via zlib */
    uLongf plain_bound = comp_len * 10 + 1024;
    uint8_t *plain_buf = malloc(plain_bound);
    if (!plain_buf) {
        secure_memzero(l1_plain, l1_len);
        free(l1_plain);
        return XPC_ERR_MEMORY;
    }

    uLongf plain_actual_len = plain_bound;
    int z_res = uncompress(plain_buf, &plain_actual_len, l1_plain, comp_len);
    secure_memzero(l1_plain, l1_len);
    free(l1_plain);

    if (z_res != Z_OK) {
        free(plain_buf);
        return XPC_ERR_DECOMPRESSION;
    }

    *out_plain = plain_buf;
    *out_plain_len = (size_t)plain_actual_len;

    secure_memzero(k_xpc, sizeof(k_xpc));
    secure_memzero(k_aes, sizeof(k_aes));
    secure_memzero(k_cha, sizeof(k_cha));
    return XPC_OK;
}

int xpc3_encrypt_file(const char *in_filepath, const char *out_filepath,
                      const char *password) {
    FILE *f_in = fopen(in_filepath, "rb");
    if (!f_in) return XPC_ERR_FILE_IO;

    fseek(f_in, 0, SEEK_END);
    long f_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);

    if (f_size <= 0) {
        fclose(f_in);
        return XPC_ERR_FILE_IO;
    }

    uint8_t *plain = malloc(f_size);
    if (!plain) {
        fclose(f_in);
        return XPC_ERR_MEMORY;
    }

    if (fread(plain, 1, f_size, f_in) != (size_t)f_size) {
        free(plain);
        fclose(f_in);
        return XPC_ERR_FILE_IO;
    }
    fclose(f_in);

    uint8_t *cipher = NULL;
    size_t cipher_len = 0;
    int res = xpc3_encrypt_buffer(plain, (size_t)f_size, password, strlen(password),
                                 &cipher, &cipher_len);
    secure_memzero(plain, f_size);
    free(plain);

    if (res != XPC_OK) return res;

    FILE *f_out = fopen(out_filepath, "wb");
    if (!f_out) {
        free(cipher);
        return XPC_ERR_FILE_IO;
    }

    if (fwrite(cipher, 1, cipher_len, f_out) != cipher_len) {
        free(cipher);
        fclose(f_out);
        return XPC_ERR_FILE_IO;
    }

    fclose(f_out);
    free(cipher);
    return XPC_OK;
}

int xpc3_decrypt_file(const char *in_filepath, const char *out_filepath,
                      const char *password) {
    FILE *f_in = fopen(in_filepath, "rb");
    if (!f_in) return XPC_ERR_FILE_IO;

    fseek(f_in, 0, SEEK_END);
    long f_size = ftell(f_in);
    fseek(f_in, 0, SEEK_SET);

    if (f_size <= 0) {
        fclose(f_in);
        return XPC_ERR_FILE_IO;
    }

    uint8_t *cipher = malloc(f_size);
    if (!cipher) {
        fclose(f_in);
        return XPC_ERR_MEMORY;
    }

    if (fread(cipher, 1, f_size, f_in) != (size_t)f_size) {
        free(cipher);
        fclose(f_in);
        return XPC_ERR_FILE_IO;
    }
    fclose(f_in);

    uint8_t *plain = NULL;
    size_t plain_len = 0;
    int res = xpc3_decrypt_buffer(cipher, (size_t)f_size, password, strlen(password),
                                 &plain, &plain_len);
    free(cipher);

    if (res != XPC_OK) return res;

    FILE *f_out = fopen(out_filepath, "wb");
    if (!f_out) {
        secure_memzero(plain, plain_len);
        free(plain);
        return XPC_ERR_FILE_IO;
    }

    if (fwrite(plain, 1, plain_len, f_out) != plain_len) {
        secure_memzero(plain, plain_len);
        free(plain);
        fclose(f_out);
        return XPC_ERR_FILE_IO;
    }

    fclose(f_out);
    secure_memzero(plain, plain_len);
    free(plain);
    return XPC_OK;
}
