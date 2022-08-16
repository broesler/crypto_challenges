/*==============================================================================
 *     File: break_ctr_subs.c
 *  Created: 05/04/2018, 10:03
 *   Author: Bernie Roesler
 *
 *  Description: Break fixed-nonce CTR using simple substitutions... just
 *  kidding. Do it statistically because I'm lazy.
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

/*------------------------------------------------------------------------------
 *          Function definitions        
 *----------------------------------------------------------------------------*/
size_t max_val(int *arr, size_t len)
{
    /* Return maximum value from array */
    size_t the_max = arr[0];
    for (size_t i = 1; i < len; i++) {
        if (arr[i] > the_max) {
            the_max = arr[i];
        }
    }
    return the_max;
}

size_t read_and_encrypt_file(char *b64_file, BYTE **y_lines, int *y_lens)
{
    BYTE *key = (BYTE *)"YELLOW SUBMARINE";
    size_t n_lines = 0;

    /* Fixed nonce = 0 */
    BYTE *nonce = init_byte(BLOCK_SIZE/2);

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

    char *line = init_str(MAX_LINE_LEN);
    BYTE **yl = y_lines;  /* temp pointers to arrays */
    int *yn = y_lens;

    while (fgets(line, MAX_LINE_LEN, fp)) 
    {
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


/*------------------------------------------------------------------------------
 *         Main 
 *----------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    char *b64_file = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [base64_file]\n", argv[0]);
        exit(EXIT_FAILURE);
    } else {
        b64_file = argv[1];
    }

    /* TODO move these lines to read_and_encrypt_file() */
    /* Allocate array to store encrypted byte arrays */
    size_t Nl = lines_in_file(b64_file);
    BYTE **y_lines = calloc(Nl, sizeof(BYTE *));
    MALLOC_CHECK(y_lines);
    int *y_lens = init_int(Nl);  /* array of nbytes per line */

#ifdef LOGSTATUS
    LOG("Reading from file '%s'...", b64_file);
#endif
    /* Read base64 file, encrypt each line, store in array */
    int Nlines = read_and_encrypt_file(b64_file, y_lines, y_lens);
    assert(Nlines == Nl);

    /* Print encrypted bytes */
#ifdef VERBOSE
    LOG("y_lines:");
    for (size_t i = 0; i < Nl; i++) {
        printf("[%2lu]: \"", i);
        print_blocks(*(y_lines+i), *(y_lens+i), BLOCK_SIZE, 0);
        printf("\"\n");
    }
#endif

    /* Get length of longest line */
    int key_len = max_val(y_lens, Nl);
    BYTE *keystream = init_byte(key_len);

    /* Get the keystream one "column" at a time */
#ifdef LOGSTATUS
    printf("Nl = %lu, key_len = %d\n", Nl, key_len);
#endif
    for (int j = 0; j < key_len; j++) {
        BYTE *col = init_byte(Nl);
        int col_len = 0;

        for (size_t i = 0; i < Nl; i++) {
            if (j < y_lens[i]) {
                col[col_len] = y_lines[i][j];
                col_len++;
            }
        }

        XOR_NODE *t = single_byte_xor_decode(col, col_len);
        *(keystream + j) = *(t->key);

        free(t);
        free(col);
    }

    /* Decrypte the ciphertexts using the known keystream */
    BYTE **x_lines = calloc(Nl, sizeof(BYTE *));  /* decrypted lines */
    MALLOC_CHECK(x_lines);

    for (size_t i = 0; i < Nl; i++) {
        x_lines[i] = repeating_key_xor(y_lines[i], keystream, y_lens[i], key_len);
        printall(x_lines[i], y_lens[i]);
        printf("\n");
    }

    free_str_arr((char **)y_lines, Nl);
    free(y_lens);
    free(keystream);
    free_str_arr((char **)x_lines, Nl);
    return 0;
}

/*==============================================================================
 *============================================================================*/
