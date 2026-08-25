#ifndef XPC_TYPES_H
#define XPC_TYPES_H

#include <stddef.h>
#include <stdint.h>

#define XPC_SALT_LEN       64
#define XPC_AES_NONCE_LEN  12
#define XPC_CHA_NONCE_LEN  12
#define XPC_HMAC_LEN       32
#define XPC_HEADER_LEN     (XPC_SALT_LEN + XPC_AES_NONCE_LEN + XPC_CHA_NONCE_LEN)
#define XPC_TRAILER_LEN    (XPC_HMAC_LEN + 1) /* 32 bytes HMAC + 1 byte pad_len */

#define XPC_BLOCK_SIZE     64
#define XPC_ROUNDS         24

#define XKDF_MEM_SIZE      (64 * 1024 * 1024) /* 64 MiB */
#define XKDF_BLOCK_SIZE    64
#define XKDF_NUM_BLOCKS    (XKDF_MEM_SIZE / XKDF_BLOCK_SIZE) /* 1,048,576 blocks */
#define XKDF_PASSES        3

#define XPC_MASTER_KEY_LEN 64
#define XPC_KEY_LEN        64
#define AES_KEY_LEN        32
#define CHA_KEY_LEN        32

typedef enum {
    XPC_OK = 0,
    XPC_ERR_MEMORY = -1,
    XPC_ERR_INVALID_PASS = -2,
    XPC_ERR_AUTH_FAILED = -3,
    XPC_ERR_COMPRESSION = -4,
    XPC_ERR_DECOMPRESSION = -5,
    XPC_ERR_FILE_IO = -6,
    XPC_ERR_INVALID_FORMAT = -7,
    XPC_ERR_CRYPTO = -8
} xpc_error_t;

#endif /* XPC_TYPES_H */
