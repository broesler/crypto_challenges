/*==============================================================================
 *     File: break_CTR_subs.c
 *  Created: 05/04/2018, 10:03
 *   Author: Bernie Roesler
 *
 *  Description: Break fixed-nonce CTR using simple substitutions
 *
 *============================================================================*/

/* User-defined headers */
#include "header.h"
#include "crypto_util.h"
#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"
#include "crypto3.h"

int main(int argc, char **argv)
{
    char *b64_file = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [base64_file]\n", argv[0]);
        exit(EXIT_FAILURE);
    } else {
        b64_file = argv[1];
    }

    /* For each line in file
     *  Read base64 line
     *  Convert to byte array
     *  Store in file_lines array
     */
    FILE *fp = fopen(b64_file, "r");
    if (!fp) {
        snprintf(message, 2*MAX_STR_LEN, "File %s could not be read!", b64_file);
        LOG(message);
        exit(-1);
    }

    /* char *b64 = init_str(MAX_WORD_LEN); */
    /* while (fgets(b64,  */
    /* char *b64_clean = strrmchr(b64, "\n");  #<{(| strip newlines |)}># */
    /*  */
    /* #<{(| Convert to byte array for decryption |)}># */
    /* BYTE *byte = NULL; */
    /* size_t nbyte = b642byte(&byte, b64_clean); */

    return 0;
}


/*==============================================================================
 *============================================================================*/
