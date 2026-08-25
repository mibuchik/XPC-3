#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xpc3.h"

static void print_usage(const char *prog_name) {
    printf("Xalether Primal Cipher v3 (XPC-3) CLI Utility\n");
    printf("Usage:\n");
    printf("  %s enc -i <input_file> -o <output_file> -p <password>\n", prog_name);
    printf("  %s dec -i <input_file> -o <output_file> -p <password>\n", prog_name);
    printf("\nCommands:\n");
    printf("  enc    Encrypt file using XPC-3 triple cascade cipher\n");
    printf("  dec    Decrypt XPC-3 encrypted file\n");
    printf("\nOptions:\n");
    printf("  -i, --input     Path to input file\n");
    printf("  -o, --output    Path to output file\n");
    printf("  -p, --password  Secret password for encryption/decryption\n");
    printf("  -h, --help      Display this help message\n");
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
    const char *password = NULL;

    for (int i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) && i + 1 < argc) {
            in_file = argv[++i];
        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            out_file = argv[++i];
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--password") == 0) && i + 1 < argc) {
            password = argv[++i];
        }
    }

    if (!in_file || !out_file || !password) {
        fprintf(stderr, "Error: Missing required arguments (-i, -o, -p)\n\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("🔐 XPC-3 %s mode initialized\n", is_encrypt ? "Encryption" : "Decryption");
    printf("  Input File:  %s\n", in_file);
    printf("  Output File: %s\n", out_file);
    printf("  Executing Memory-Hard XKDF (64 MiB RAM, 3 passes)... ");
    fflush(stdout);

    int res = 0;
    if (is_encrypt) {
        res = xpc3_encrypt_file(in_file, out_file, password);
    } else {
        res = xpc3_decrypt_file(in_file, out_file, password);
    }

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
