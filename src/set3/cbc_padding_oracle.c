/*==============================================================================
 *     File: cbc_padding_oracle.c
 *  Created: 04/29/2018, 17:39
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for CBC padding oracle.
 *
 *============================================================================*/

#include "cbc_padding_oracle.h"

/*------------------------------------------------------------------------------
 *         Decrypt a block of CBC-encrypted ciphertext 
 *----------------------------------------------------------------------------*/
int block_decrypt(BYTE **Dy, BYTE *y) {
    /* NOTE output needs to be XOR'd with y_{i-1} to get x!
     * This function assumes Dy,y are size BLOCK_SIZE.
     *   Dy      : decrypted y block
     *   y       : input ciphertext block
     *   returns : 0 upon success, -1 on failure
     */
    size_t b = BLOCK_SIZE;

    /* Get last byte[s] of block */
    size_t n_found = 0;
    last_byte(Dy, &n_found, y);

    BYTE *rf = init_byte(b);
    memcpy(rf, (BYTE *)"THREE WORD CHANT", BLOCK_SIZE);
    BYTE *r  = init_byte(b);
    BYTE *ry = init_byte(2*b);

    /* for each remaining byte in the block */
    for (size_t j = b - n_found; j > 0; j--) {

        /* Set values of r_k to produce correct padding */
        for (size_t k = j; k < b; k++) {
            rf[k] = (*Dy)[k] ^ (b - j + 1); 
        }

        /* Guess (j-1)th byte */
        for (size_t i = 0; i < 0x100; i++) {
            /* Reset r to random bytes */
            BZERO(r, b);
            memcpy(r, rf, b);

            /* Set choice of byte in chosen ciphertxt */
            r[j-1] ^= i;

            /* Concatenate string to pass to oracle */
            BZERO(ry, 2*b);
            memcpy(ry,   r, b);
            memcpy(ry+b, y, b);

            /* Check if O(r|y) produces valid padding */
            /* NOTE oracle returns:
             *   n_pad : valid padding
             *     0   : no padding
             *    -1   : invalid padding
             */
            if (0 < padding_oracle(ry, 2*b)) { 
                /* Set (j-1)th byte to desired value */
                (*Dy)[j-1] = r[j-1] ^ (b - j + 1);
                break;
            }
        }
    }

    free(rf);
    free(r);
    free(ry);
    return 0;
}

/*------------------------------------------------------------------------------
 *         Decrypt last byte(s) of ciphertext block
 *----------------------------------------------------------------------------*/
int last_byte(BYTE **Dy, size_t *n_found, BYTE *y) 
{
    /* NOTE output needs to be XOR'd with y_{i-1} to get x!
     * Dy     : decrypted last byte(s) of ciphertext
     * n_found : number of bytes decrypted
     * y      : single ciphertext block
     */
    size_t b = BLOCK_SIZE;
    size_t i_found = 0;

    /* Initialize output array */
    *Dy = init_byte(b);

    BYTE *rf = init_byte(b);  /* fixed random input ciphertext */
    memcpy(rf, (BYTE *)"THREE WORD CHANT", BLOCK_SIZE);
    BYTE *r  = init_byte(b); /* temp  random input ciphertext */
    memcpy(r, rf, b);        /* copy rf values into r */

    BYTE *ry = init_byte(2*b);  /* composite (r||y) for pass to oracle */

    /* Guess last byte to give correct padding */
    for (size_t i = 0; i < 0x100; i++) { 
        r[b-1] = rf[b-1] ^ i;

        /* Concatenate string to pass to oracle */
        BZERO(ry, 2*b);
        memcpy(ry,   r, b);
        memcpy(ry+b, y, b);

        /* Check if O(r|y) is true */
        if (0 < padding_oracle(ry, 2*b)) { 
            /* Store found values */
            i_found = i;
            rf[b-1] ^= i_found;
            break;
        }
    }

    /* Check if valid padding is NOT 1 */
    /* Strategy: 
     *   Take block
     *       [a b c ... p  \x04  \x04 \x04 \x04],
     *   and XOR one byte from 0..b-1 with \x01, starting with the first and
     *   moving towards the last. When we reach the first padding byte, we will
     *   have block
     *       [a b c ... p *\x03* \x04 \x04 \x04],
     *   which produces an invalid padding error from the oracle! 
     */
    for (size_t n = b; n > 1; n--) {
        /* n s.t. index of r[b-n] goes from 0..b-1 */
        /* Reset random block */
        BZERO(r, b);
        memcpy(r, rf, b);

        /* XOR test byte */
        r[b-n] ^= 1;

        /* Concatenate byte array to pass to oracle */
        BZERO(ry, 2*b);
        memcpy(ry,   r, b);
        memcpy(ry+b, y, b);

        /* If padding is invalid, then we've found the byte where the valid
         * padding ends, and n is the number of valid padding bytes */
        if (0 > padding_oracle(ry, 2*b)) { 
            *n_found = n;
            /* XOR last n bytes with n to recover D(y) */
            for (size_t j = b-n; j < b; j++) {
                (*Dy)[j] = rf[j] ^ n;
            }
            free(r);
            free(ry);
            return 0;
        }
    }

    /* Valid padding is 1 */
    *n_found = 1;
    (*Dy)[b-1] = rf[b-1] ^ 1;

    free(r);
    free(ry);
    return 0;
}

/*------------------------------------------------------------------------------
 *          Encryption oracle
 *----------------------------------------------------------------------------*/
int encryption_oracle(BYTE **y, size_t *y_len, int choice)
{
    /* Randomly select one of possible inputs */
    /* int choice = RAND_RANGE(0, 9); */
    const char *x_b64 = POSSIBLE_X[choice];

    /* Convert to byte array */
    BYTE *x = NULL;
    size_t x_len = b642byte(&x, x_b64);

    *y_len = 0;

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
        printf("global_key set to: ");
        print_blocks(global_key, BLOCK_SIZE, BLOCK_SIZE, 0);
        printf("\n");
    }

    /* Generate a random IV ONCE */
    if (!global_iv) {
        global_iv = rand_byte(BLOCK_SIZE);
        printf("global_iv  set to: ");
        print_blocks(global_iv, BLOCK_SIZE, BLOCK_SIZE, 0);
        printf("\n");
    }

    /* Encrypt using CBC mode */
    aes_128_cbc_encrypt(y, y_len, x, x_len, global_key, global_iv);
    free(x);
    return 0;
}

/*------------------------------------------------------------------------------
 *          Decrypt and Check Padding
 *----------------------------------------------------------------------------*/
int padding_oracle(BYTE *y, size_t y_len)
{
    /* Decrypt y report if padding is valid or not, but do not return x */
    BYTE *x = NULL;
    size_t x_len = 0;
    int test = aes_128_cbc_decrypt(&x, &x_len, y, y_len, global_key, global_iv);
    free(x);
    return test;
}

/*==============================================================================
 *============================================================================*/
