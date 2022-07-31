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

/* Globals */
BYTE *key = (BYTE *)"YELLOW SUBMARINE";

/*------------------------------------------------------------------------------
 *          Function definitions        
 *----------------------------------------------------------------------------*/
size_t min_val(int *arr, size_t len)
{
    /* Return minimum value from array */
    size_t the_min = arr[0];
    for (size_t i = 1; i < len; i++) {
        if (arr[i] < the_min) {
            the_min = arr[i];
        }
    }
    return the_min;
}

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

void flatten_arr(BYTE **byte, size_t *nbyte, BYTE **arr, 
                size_t Nl, size_t line_len)
{
    /* Collapse 2D arr into 1D byte array of length Nl*line_len. */
    *nbyte = Nl*line_len;
    *byte = init_byte(*nbyte);
    for (size_t i = 0; i < Nl; i++) {
        memcpy(*byte + i*line_len, *(arr + i), line_len);
    }
    return;
}

void reshape_arr(BYTE **x_lines, BYTE *byte, size_t Nl, size_t line_len)
{
    /* Expand 1D byte array into 2D arr of shape [Nl, line_len] */
    for (size_t i = 0; i < Nl; i++) {
        *(x_lines + i) = init_byte(line_len);
        memcpy(*(x_lines + i), byte + i*line_len, line_len);
    }
    return;
}

size_t read_and_encrypt_file(char *b64_file, BYTE **y_lines, int *y_lens)
{
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

    /* Get length of shortest line */
    size_t key_len = min_val(y_lens, Nl);
    size_t max_len = max_val(y_lens, Nl);

#ifdef LOGSTATUS
    LOG("Decrypting results with key length %lu...", key_len);
#endif

    /* TODO rewrite this code so that we do NOT have to truncate all of the
     * ciphertexts. 
     *  * Possibly use components of break_repeating_xor to get best
     *    keystream byte each time. 
     *  * Or, call a version of flatten_arr() from min(y_lens) to
     *    max(y_lens) that only acts on indices where len(arr) > key_len */
    /* NOTE break_repeating_xor is written to take a flattened array where each
     * row is the same length. In this case, we have many different length
     * strings. We could rewrite break_repeating_xor to handle different
     * lengths, or take each "column" of `y_lines` at a time, and call
     * single_byte_xor_decode on each one individually. */

    /* In order to use this function, we need to truncate the encrypted lines to
     * the length of the shortest line, then re-concatenate them into `byte` */
    BYTE *byte = NULL;
    size_t nbyte = 0;
    flatten_arr(&byte, &nbyte, y_lines, Nl, key_len);
    assert(nbyte == Nl*key_len);

    /* Decrypt results as if it were a repeating key XOR cipher */
    XOR_NODE *out = break_repeating_xor(byte, nbyte, (int)key_len);
    printf("key = ");
    printall(out->key, key_len);
    printf("\n");
    printf("key_len = %lu\n", key_len);

    /* Reshape decrypted text back into individual lines */
    BYTE **x_lines = calloc(Nl, sizeof(BYTE *));
    MALLOC_CHECK(x_lines);
    reshape_arr(x_lines, out->plaintext, Nl, key_len);
    printf("Decrypted text =\n");
    for (size_t i = 0; i < Nl; i++) {
        printall(*(x_lines+i), key_len);
        printf("\n");
    }

    free_str_arr((char **)y_lines, Nl);
    free(y_lens);
    free(byte);
    free(out);
    free_str_arr((char **)x_lines, Nl);
    return 0;
}

/*==============================================================================
 *============================================================================*/
