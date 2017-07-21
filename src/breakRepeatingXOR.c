/*==============================================================================
 *     File: breakRepeatingXOR.c
 *  Created: 07/20/2017, 16:43
 *   Author: Bernie Roesler
 *
 *  Description: Separate breakRepeatingXOR function call for shell usage
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

    /* Get filename */
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

    /*---------- Break the code! ----------*/
    XOR_NODE *out = breakRepeatingXOR(byte, nbyte);

    /* Write to stdout */
    printall(out->plaintext, nbyte); /* works even for non-printables */

    /* clean-up */
    free(b64);
    free(b64_clean);
    free(byte);
    free(out);

    return 0;
}
/*==============================================================================
 *============================================================================*/
