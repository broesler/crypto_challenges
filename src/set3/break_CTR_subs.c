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
        ERROR("File %s could not be read!", b64_file);
    }
    
    /* Count lines in file */
    /* size_t Nl = lines_in_file(fp); */
    size_t Nl = 40;

    BYTE **byte_arr = malloc(Nl*sizeof(char *));
    MALLOC_CHECK(byte_arr);
    int *byte_num = init_int(Nl);

#ifdef LOGSTATUS
        LOG("Reading from file %s...", b64_file);
#endif
    char *line = init_str(MAX_LINE_LEN);
    while (fgets(line, MAX_LINE_LEN, fp)) {
#ifdef LOGSTATUS
        LOG("Reading from file %s...", b64_file);
#endif
        char *b64_clean = strrmchr(line, "\n");  /* strip newlines */

        /* Convert to byte array for decryption */
        BYTE *byte = NULL;
        size_t nbyte = b642byte(&byte, b64_clean);

        /* Store in array */
        *byte_arr++ = byte;
        *byte_num++ = nbyte;
    }
    fclose(fp);

    for (size_t i = 0; i < Nl; i++) {
        printf("byte_arr[%lu] = ", i);
        printall(*(byte_arr+i), *(byte_num+i));
        printf("\n");
    }

    return 0;
}


/*==============================================================================
 *============================================================================*/
