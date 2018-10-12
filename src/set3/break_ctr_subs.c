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

BYTE *key = (BYTE *)"YELLOW SUBMARINE";

size_t read_and_encrypt_file(char *b64_file, BYTE **y_lines, int *y_nums);

int main(int argc, char **argv)
{
    char *b64_file = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [base64_file]\n", argv[0]);
        exit(EXIT_FAILURE);
    } else {
        b64_file = argv[1];
    }

    /* Allocate array to store encrypted byte arrays */
    size_t Nl = lines_in_file(b64_file);
    BYTE **y_lines = calloc(Nl, sizeof(BYTE *));
    MALLOC_CHECK(y_lines);
    int *y_nums = init_int(Nl);  /* array of nbytes per line */

    if (read_and_encrypt_file(b64_file, y_lines, y_nums) != Nl) {
        ERROR("Not all lines read from file!");
    }

    /* Print encrypted bytes */
#ifdef LOGSTATUS
    LOG("y_lines:");
    for (size_t i = 0; i < Nl; i++) {
        printf("[%2lu]: \"", i);
        print_blocks(*(y_lines+i), *(y_nums+i), BLOCK_SIZE, 0);
        printf("\"\n");
    }
#endif

    /* Decrypt results */

    free_str_arr((char **)y_lines, Nl);
    free(y_nums);
    return 0;
}

/*------------------------------------------------------------------------------
 *          Function definitions        
 *----------------------------------------------------------------------------*/
size_t read_and_encrypt_file(char *b64_file, BYTE **y_lines, int *y_nums)
{
    size_t n_lines = 0;

    /* Fixed key and nonce */
    BYTE *nonce = init_byte(BLOCK_SIZE/2);


#ifdef LOGSTATUS
    LOG("Reading from file '%s'...", b64_file);
#endif
    /* For each line in file:
     * - Read base64 line
     * - Convert to byte array
     * - Encrypt byte array with fixed-nonce CTR
     * - Store encrypted text in file_lines array
     */
    FILE *fp = fopen(b64_file, "r");
    if (!fp) {
        ERROR("File %s could not be read!", b64_file);
    }

    char *line = init_str(MAX_LINE_LEN);  /* buffer for each file line */
    BYTE **yl = y_lines;         /* temp pointers to arrays */
    int *yn = y_nums;

    while (fgets(line, MAX_LINE_LEN, fp)) {
        n_lines++;
        char *b64_clean = strrmchr(line, "\n");  /* strip newlines */

        /* Convert to byte array for encryption */
        BYTE *byte = NULL;
        size_t nbyte = b642byte(&byte, b64_clean);

        /* Encrypt using CTR with fixed nonce and key */
        FILE *xs = fmemopen(byte, nbyte, "r");
        FILE *ys = tmpfile();
        if (aes_128_ctr(ys, xs, key, nonce)) {
            ERROR("Encryption failed!\n    line = '%s'", b64_clean);
        }

        /* Store encrypted bytes in array */
        BYTE *yb = init_byte(nbyte);
        if (!fread(yb, 1, nbyte, ys)) {
            ERROR("File read error!\n    line = '%s'", b64_clean);
        }

        *yl++ = yb;
        *yn++ = nbyte;

        free(byte);
        free(b64_clean);
        fclose(xs);
        fclose(ys);
    } /* end read from file */

    free(line);
    free(nonce);
    fclose(fp);

    return n_lines;
}

/*==============================================================================
 *============================================================================*/
