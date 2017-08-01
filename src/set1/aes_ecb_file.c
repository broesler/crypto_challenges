/*==============================================================================
 *     File: aes_ecb_file.c
 *  Created: 07/28/2017, 14:53
 *   Author: Bernie Roesler
 *
 *  Description: Decrypt a file encrypted in AES 128-bit ECB mode
 *
 *============================================================================*/
#include <stdio.h>

#include "aes_openssl.h"
#include "header.h"
#include "crypto_util.h"
#include "crypto1.h"

int main(int argc, char **argv)
{
    char *b64_file = NULL;

    /* Get one more argument of filename */
    if (argc > 1) {
        b64_file = argv[1];
    } else {
        fprintf(stderr, "Usage: %s [base64_file]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Read file into memory */
    char *b64 = NULL;
    (void)fileToString(&b64, b64_file);
    char *b64_clean = strrmchr(b64, "\n");  /* strip newlines */

    /* Convert to byte array for decryption */
    BYTE *byte = NULL;
    size_t nbyte = b642byte(&byte, b64_clean);

    /* Initialize the OpenSSL library */
    /* OpenSSL_init(); */

    /* Define the key -- 16 byte == 128 bit key */
    BYTE key[] = "YELLOW SUBMARINE";
    BYTE *plaintext = NULL;
    size_t plaintext_len = 0;

    /*---------- Break the code! ----------*/
    if (0 != aes_128_ecb_cipher(&plaintext, &plaintext_len, byte, nbyte, key, 0)) {
        ERROR("Invalid padding!");
    }

    /* Write to stdout */
    printall(plaintext, plaintext_len); /* works even for non-printables */

    /* Clean up */
    /* OpenSSL_cleanup(); */
    free(b64);
    free(b64_clean);
    free(byte);
    free(plaintext);
    return 0;
}

/*==============================================================================
 *============================================================================*/
