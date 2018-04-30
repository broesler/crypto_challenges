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
int block_decrypt(BYTE **x, BYTE *y) {
    /* NOTE this function assumes x,y are size BLOCK_SIZE
     *   x : address of output block
     *   y : pointer to input block
     *   returns : 0 upon success, -1 on failure
     */
    size_t b = BLOCK_SIZE;
    BYTE *xp = NULL;
    size_t xp_len = 0;

    *x = init_byte(b);

    /* Get last byte[s] of block */
    last_byte(&xp, &xp_len, y);
    memcpy(*x + (b - xp_len), xp, xp_len);

    BYTE *rf = rand_byte(b);
    BYTE *r     = init_byte(b);
    BYTE *ry    = init_byte(2*b);

    /* for each remaining byte in the block */
    for (size_t j = b - xp_len; j > 0; j--) {

        /* Set values of r_k */
        for (size_t k = j; k < b; k++) {
            rf[k] = (*x)[k] ^ (b - j + 1); 
        }

        /* Guess (j-1)th byte */
        for (size_t i = 0; i < 0x100; i++) {
            /* Reset r to random bytes */
            memcpy(r, rf, b);

            /* Set choice of byte in chosen ciphertxt */
            r[j-1] ^= i;

            /* Concatenate string to pass to oracle */
            BZERO(ry, 2*b);
            memcpy(ry,   r, b);
            memcpy(ry+b, y, b);

            /* Check if O(r|y) produces valid padding */
            /* NOTE oracle returns -1 on invalid padding, 0 on NO padding, or
             * Npad on valid padding. Need a positive value for valid padding */
            if (0 < padding_oracle(ry, 2*b)) { 
                /* Set (j-1)th byte to desired value */
                (*x)[j-1] = r[j-1] ^ (b - j + 1);
                break;
            }
        }
    }

    free(rf);
    free(r);
    free(ry);
    free(xp);
    return 0;
}

/*------------------------------------------------------------------------------
 *         Decrypt last byte(s) of ciphertext block
 *----------------------------------------------------------------------------*/
int last_byte(BYTE **xp, size_t *xp_len, BYTE *y) 
{
    size_t b = BLOCK_SIZE;
    size_t i = 0;

    /* Fixed random input ciphertext */
    BYTE *rf = rand_byte(b);
    BYTE *r  = init_byte(b);
    BYTE *ry = init_byte(2*b);

    /* Copy rf values into temp array for loop */
    memcpy(r, rf, b);

    /* Guess last byte to give correct padding */
    for (i = 0; i < 0x100; i++) { 
        r[b-1] = rf[b-1] ^ i;

        /* Concatenate string to pass to oracle */
        BZERO(ry, 2*b);
        memcpy(ry,   r, b);
        memcpy(ry+b, y, b);

        int n_pad = padding_oracle(ry, 2*b);

        /* Check if O(r|y) is true */
        if (0 < n_pad) { 
            break;
        }
    }

    /* TODO Test this code: */
    /* Check if valid padding is NOT 1 */
    /* for (size_t n = b-1; n > 0; n--) { */
    /*     #<{(| Reset random block |)}># */
    /*     memcpy(r, rf, b); */
    /*  */
    /*     #<{(| XOR given byte |)}># */
    /*     r[b-n] ^= 1; */
    /*  */
    /*     #<{(| Concatenate string to pass to oracle |)}># */
    /*     BZERO(ry, 2*b); */
    /*     memcpy(ry,   r, b); */
    /*     memcpy(ry+b, y, b); */
    /*  */
    /*     if (0 < padding_oracle(ry, 2*b)) {  */
    /*         memcpy(*xp, r[b-n], n); */
    /*         return 0; */
    /*     } */
    /* } */

    /* Valid padding is 1 */
    *xp_len = 1;
    *xp = init_byte(*xp_len);
    **xp = r[b-1] ^ 1;

    free(rf);
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

#ifdef LOGSTATUS
    LOG("Chose string:");
    printf("    %d: %s\n", choice, x_b64);
#endif

    /* Convert to byte array */
    BYTE *x = NULL;
    size_t x_len = b642byte(&x, x_b64);

    *y_len = 0;

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
    }

    /* Generate a random IV ONCE */
    if (!global_iv) {
        global_iv = rand_byte(BLOCK_SIZE);
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
