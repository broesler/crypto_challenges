/*==============================================================================
 *     File: breakRepeatingXOR.c
 *  Created: 07/20/2017, 16:43
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 6: Break repeating key XOR cipher
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
    int v_flag = 0;
    int c;

    /* Get flags */
    while ((c = getopt(argc, argv, "v")) != -1) {
        switch (c)
        {
            case 'v':
                v_flag = 1;
                break;
            default:
                abort();
        }
    }

    /* Get one more argument of filename */
    if (optind < argc) {
        b64_file = argv[optind];
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

    if (v_flag) {
        printf("key = '%s'\n", out->key);
        printf("Decrypted text =\n");
    }

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
