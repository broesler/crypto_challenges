/*==============================================================================
 *     File: aes_cbc_file.c
 *  Created: 07/28/2017, 15:35
 *   Author: Bernie Roesler
 *
 *  Description: 
 *
 *============================================================================*/
#include <stdio.h>

#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "crypto2.h"

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

    /* Define the key -- 16 byte == 128 bit key */
    BYTE key[] = "YELLOW SUBMARINE";
    BYTE *plaintext = NULL;
    BYTE iv[BLOCK_SIZE] = "";   /* BLOCK_SIZE-length array of '\0' chars */

    /*---------- Break the code! ----------*/
    int plaintext_len = aes_128_cbc_decrypt(&plaintext, byte, nbyte, key, iv);

    /* Write to stdout */
    printall(plaintext, plaintext_len); /* works even for non-printables */

    /* Clean up */
    free(b64);
    free(b64_clean);
    free(byte);
    free(plaintext);
    return 0;
}

/*==============================================================================
 *============================================================================*/
