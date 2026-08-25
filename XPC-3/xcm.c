#include "xcm.h"
#include <string.h>

static void increment_counter(uint8_t counter[XPC_BLOCK_SIZE]) {
    for (int i = XPC_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

int xcm_encrypt(const uint8_t *in_data, size_t len,
                uint8_t *out_data,
                const uint8_t siv[32],
                const xbe_key_schedule_t *ks) {
    if (!in_data || !out_data || !siv || !ks || (len % XPC_BLOCK_SIZE != 0)) {
        return XPC_ERR_MEMORY;
    }

    uint8_t counter[XPC_BLOCK_SIZE];
    memset(counter, 0, XPC_BLOCK_SIZE);
    memcpy(counter, siv, 32);

    uint8_t prev_block[XPC_BLOCK_SIZE];
    memset(prev_block, 0, XPC_BLOCK_SIZE);

    size_t num_blocks = len / XPC_BLOCK_SIZE;

    for (size_t b = 0; b < num_blocks; b++) {
        const uint8_t *in_blk = in_data + (b * XPC_BLOCK_SIZE);
        uint8_t *out_blk = out_data + (b * XPC_BLOCK_SIZE);

        uint8_t keystream[XPC_BLOCK_SIZE];
        int res = xbe_encrypt_block(counter, keystream, ks);
        if (res != XPC_OK) return res;

        uint8_t mixed[XPC_BLOCK_SIZE];
        for (int i = 0; i < XPC_BLOCK_SIZE; i++) {
            mixed[i] = in_blk[i] ^ prev_block[i] ^ keystream[i];
        }

        res = xbe_encrypt_block(mixed, out_blk, ks);
        if (res != XPC_OK) return res;

        memcpy(prev_block, out_blk, XPC_BLOCK_SIZE);
        increment_counter(counter);
    }

    return XPC_OK;
}

int xcm_decrypt(const uint8_t *in_data, size_t len,
                uint8_t *out_data,
                const uint8_t siv[32],
                const xbe_key_schedule_t *ks) {
    if (!in_data || !out_data || !siv || !ks || (len % XPC_BLOCK_SIZE != 0)) {
        return XPC_ERR_MEMORY;
    }

    uint8_t counter[XPC_BLOCK_SIZE];
    memset(counter, 0, XPC_BLOCK_SIZE);
    memcpy(counter, siv, 32);

    uint8_t prev_block[XPC_BLOCK_SIZE];
    memset(prev_block, 0, XPC_BLOCK_SIZE);

    size_t num_blocks = len / XPC_BLOCK_SIZE;

    for (size_t b = 0; b < num_blocks; b++) {
        const uint8_t *in_blk = in_data + (b * XPC_BLOCK_SIZE);
        uint8_t *out_blk = out_data + (b * XPC_BLOCK_SIZE);

        uint8_t keystream[XPC_BLOCK_SIZE];
        int res = xbe_encrypt_block(counter, keystream, ks);
        if (res != XPC_OK) return res;

        uint8_t mixed[XPC_BLOCK_SIZE];
        res = xbe_decrypt_block(in_blk, mixed, ks);
        if (res != XPC_OK) return res;

        for (int i = 0; i < XPC_BLOCK_SIZE; i++) {
            out_blk[i] = mixed[i] ^ prev_block[i] ^ keystream[i];
        }

        memcpy(prev_block, in_blk, XPC_BLOCK_SIZE);
        increment_counter(counter);
    }

    return XPC_OK;
}
