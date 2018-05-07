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
#include "fmemopen.h"
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
     *  Encrypt byte array with fixed-nonce CTR
     *  Store encrypted text in file_lines array
     */
    FILE *fp = fopen(b64_file, "r");
    if (!fp) {
        ERROR("File %s could not be read!", b64_file);
    }
    
    size_t Nl = lines_in_file(fp);
    BYTE **y_lines = malloc(Nl*sizeof(char *));
    MALLOC_CHECK(y_lines);
    int *y_nums = init_int(Nl);

    /* Fixed key and nonce */
    BYTE *key = (BYTE *)"YELLOW SUBMARINE";
    BYTE *nonce = init_byte(BLOCK_SIZE/2);

    BYTE **yl = y_lines;
    int *yn = y_nums;
    char *line = init_str(MAX_LINE_LEN);

#ifdef LOGSTATUS
        LOG("Reading from file '%s'...", b64_file);
#endif
    while (fgets(line, MAX_LINE_LEN, fp)) {
        char *b64_clean = strrmchr(line, "\n");  /* strip newlines */

        /* Convert to byte array for encryption */
        BYTE *byte = NULL;
        size_t nbyte = b642byte(&byte, b64_clean);

        FILE *xs = fmemopen(byte, nbyte, "r");
        FILE *ys = tmpfile();

        /* Encrypt using CTR with fixed nonce and key */
        if (aes_128_ctr(xs, ys, key, nonce)) {
            ERROR("Encryption failed!\n    line = '%s'", b64_clean);
        }

        /* Store in array */
        BYTE *y = init_byte(nbyte);
        if (!fread(y, 1, nbyte, ys)) {
            ERROR("File read error!\n    line = '%s'", b64_clean);
        }

        *yl++ = y;
        *yn++ = nbyte;

        free(byte);
        free(b64_clean);
        fclose(xs);
        fclose(ys);
    }
    fclose(fp);

    for (size_t i = 0; i < Nl; i++) {
        printf("y_lines[%2lu] = ", i);
        printall(*(y_lines+i), *(y_nums+i));
        printf("\n");
    }

    /* free_str_arr((char **)y_lines, Nl); */
    free(line);
    free(nonce);
    free(y_nums);
    return 0;
}


/*==============================================================================
 *============================================================================*/
