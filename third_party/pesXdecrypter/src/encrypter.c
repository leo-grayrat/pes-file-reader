/*
    This is free and unencumbered software released into the public domain.

    For more information, please refer to <http://unlicense.org>
 */

#include <stdio.h>
#include <stdint.h>

#include "masterkey.h"
#include "crypt.h"


int main(int argc, const char *argv[])
{
    if (argc == 3) {
        encrypt_ex(argv[1], argv[2]);
    }
    else if (argc == 4) {
        uint32_t size;
        uint8_t *key = readFile(argv[3], &size);
        if (size != MASTER_KEY_LENGTH) {
            printf("Invalid key size!\n");
            return -1;
        }
        encryptWithKey_ex(argv[1], argv[2], key);
    }
    else {
        printf("Usage: encrypter [input_dir] [output_file] [[master_key_file]]\n");
        return -1;
    }

    return 0;
}