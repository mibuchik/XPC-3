#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <openssl/crypto.h>
#include "xpc3.h"

#define XPC3_VERSION "3.1.0-hardened"

static void print_usage(const char *prog_name) {
    printf("Xalether Primal Cipher v3 (XPC-3) CLI Utility v%s\n", XPC3_VERSION);
    printf("Usage:\n");
    printf("  %s enc -i <input_file> -o <output_file> [-p <password>]\n", prog_name);
    printf("  %s dec -i <input_file> -o <output_file> [-p <password>]\n", prog_name);
    printf("\nCommands:\n");
    printf("  enc, encrypt    Encrypt file using XPC-3 triple cascade cipher\n");
    printf("  dec, decrypt    Decrypt XPC-3 encrypted file\n");
    printf("\nOptions:\n");
    printf("  -i, --input     Path to input file\n");
    printf("  -o, --output    Path to output file\n");
    printf("  -p, --password  Secret password (optional; securely prompted if omitted)\n");
    printf("  -v, --version   Display version and architecture info\n");
    printf("  -h, --help      Display this help message\n");
}

static int get_password_secure(char *buf, size_t max_len) {
    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        if (!fgets(buf, (int)max_len, stdin)) return -1;
    } else {
        newt = oldt;
        newt.c_lflag &= ~(ECHO);
        printf("🔑 Enter secret passphrase: ");
        fflush(stdout);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
            return -1;
        }
        if (!fgets(buf, (int)max_len, stdin)) {
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            return -1;
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        printf("\n");
    }

    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    if (strcmp(mode, "-h") == 0 || strcmp(mode, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }
    if (strcmp(mode, "-v") == 0 || strcmp(mode, "--version") == 0) {
        printf("XPC-3 Suite %s (XKDF 64MB + XBE/XCM Feistel + AES-256-GCM + ChaCha20-Poly1305)\n", XPC3_VERSION);
        return 0;
    }

    int is_encrypt = 0;
    if (strcmp(mode, "enc") == 0 || strcmp(mode, "encrypt") == 0) {
        is_encrypt = 1;
    } else if (strcmp(mode, "dec") == 0 || strcmp(mode, "decrypt") == 0) {
        is_encrypt = 0;
    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n\n", mode);
        print_usage(argv[0]);
        return 1;
    }

    const char *in_file = NULL;
    const char *out_file = NULL;
    char pass_buf[1024] = {0};
    int has_pass = 0;

    for (int i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) && i + 1 < argc) {
            in_file = argv[++i];
        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            out_file = argv[++i];
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) && i + 1 < argc) {
            i++;
            strncpy(pass_buf, argv[i], sizeof(pass_buf) - 1);
            has_pass = 1;
            /* Wipe argv string in-place to avoid exposure in /proc/pid/cmdline */
            OPENSSL_cleanse(argv[i], strlen(argv[i]));
        }
    }

    if (!in_file || !out_file) {
        fprintf(stderr, "Error: Missing required input (-i) or output (-o) arguments\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if (!has_pass || strcmp(pass_buf, "-") == 0) {
        if (get_password_secure(pass_buf, sizeof(pass_buf)) != 0 || strlen(pass_buf) == 0) {
            fprintf(stderr, "Error: Passphrase cannot be empty\n");
            OPENSSL_cleanse(pass_buf, sizeof(pass_buf));
            return 1;
        }
    }

    printf("🔐 XPC-3 %s mode initialized\n", is_encrypt ? "Encryption" : "Decryption");
    printf("  Input File:  %s\n", in_file);
    printf("  Output File: %s\n", out_file);
    printf("  Executing Memory-Hard XKDF (64 MiB RAM, 3 passes)... ");
    fflush(stdout);

    int res = 0;
    if (is_encrypt) {
        res = xpc3_encrypt_file(in_file, out_file, pass_buf);
    } else {
        res = xpc3_decrypt_file(in_file, out_file, pass_buf);
    }

    OPENSSL_cleanse(pass_buf, sizeof(pass_buf));

    if (res == XPC_OK) {
        printf("DONE!\n");
        printf("✨ Operation completed successfully -> %s\n", out_file);
        return 0;
    } else {
        printf("FAILED!\n");
        switch (res) {
            case XPC_ERR_MEMORY:
                fprintf(stderr, "❌ Error: Memory allocation failure (could not allocate 64 MiB buffer)\n");
                break;
            case XPC_ERR_AUTH_FAILED:
            case XPC_ERR_INVALID_PASS:
                fprintf(stderr, "❌ Error: Authentication failed (incorrect password or tampered file)\n");
                break;
            case XPC_ERR_FILE_IO:
                fprintf(stderr, "❌ Error: File I/O error reading '%s' or writing '%s'\n", in_file, out_file);
                break;
            case XPC_ERR_INVALID_FORMAT:
                fprintf(stderr, "❌ Error: Invalid XPC-3 file format\n");
                break;
            case XPC_ERR_DECOMPRESSION:
                fprintf(stderr, "❌ Error: Decompression failed\n");
                break;
            default:
                fprintf(stderr, "❌ Error: Cryptographic processing error (code %d)\n", res);
                break;
        }
        return 1;
    }
}
