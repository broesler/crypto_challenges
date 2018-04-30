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
    BYTE *xb = NULL;
    size_t xb_len = 0;

    *x = init_byte(b);

    /* Get last byte[s] of block */
    /* if xb_len > 1, got multiple bytes already! */
    last_byte(&xb, &xb_len, y);
    memcpy(*x + (b - xb_len), xb, xb_len);

    BYTE *r_fix = rand_byte(b);
    BYTE *r     = init_byte(b);
    BYTE *ry    = init_byte(2*b);

    /* for each remaining byte in the block */
    for (size_t j = b - xb_len; j > 0; j--) {

        /* Set values of r_k */
        for (size_t k = j; k < b; k++) {
            r_fix[k] = (*x)[k] ^ (b - j + 1); 
        }
        print_blocks(r, b, b, 0);
        printf("\n");

        /* Guess (j-1)th byte */
        for (size_t i = 0; i < 0x100; i++) {
            /* Reset r to random bytes */
            memcpy(r, r_fix, b);

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

    free(r_fix);
    free(r);
    free(ry);
    free(xb);
    return 0;
}

/*------------------------------------------------------------------------------
 *         Decrypt last byte(s) of ciphertext block
 *----------------------------------------------------------------------------*/
int last_byte(BYTE **xb, size_t *xb_len, BYTE *y) 
{
    size_t b = BLOCK_SIZE;
    size_t i = 0;

    /* BYTE *r_fix = rand_byte(b); */
    /* for test, encrypted bytes from x1 = "FIRETRUCK RACES!" */
    BYTE *r_fix = (BYTE *) "\x70\x69\xAF\x3F\x83\xEE\x46\xF1" \
                           "\xBD\x18\x2C\x5B\x81\x30\xC2\x7D";
    BYTE *r     = init_byte(b);
    BYTE *ry    = init_byte(2*b);

    /* Copy r_fix values into temp array for loop */
    memcpy(r, r_fix, b);

    /* Guess last byte to give correct padding */
    for (i = 0; i < 0x100; i++) { 
    /* for (i = 0x44; i < 0x45; i++) {  */
        r[b-1] = r_fix[b-1] ^ i;

        /* Concatenate string to pass to oracle */
        BZERO(ry, 2*b);
        memcpy(ry,   r, b);
        memcpy(ry+b, y, b);

        int n_pad = padding_oracle(ry, 2*b);

        /* Check if O(r|y) is true */
        if (0 < n_pad) { 
            printf("\\x%.2lX : valid! n_pad = %2d\n", i, n_pad);
#ifdef LOGSTATUS
            LOG("data:");
            printf("r_fix = \""); 
            print_blocks(r_fix, b, b, 0);
            printf("\"\nr     = \"");
            print_blocks(r, b, b, 0);
            printf("\"\nr[b-1] ^ 1 = \\x%.2X\n", r[b-1] ^ 1);
#endif
            break;
        /* } else if (0 == n_pad) { */
        /*     printf("\\x%.2lX : no padding\n", i); */
        /* } else { */
        /*     printf("\\x%.2lX : invalid\n", i); */
        }
    }

    /* #<{(| Check if valid padding is NOT 1 |)}># */
    /* for (size_t n = b-1; n > 0; n--) { */
    /*     #<{(| Reset random block |)}># */
    /*     memcpy(r, r_fix, b); */
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
    /*         memcpy(*xb, r[b-n], n); */
    /*         return 0; */
    /*     } */
    /* } */

    /* Valid padding is 1 */
    *xb_len = 1;
    *xb = init_byte(*xb_len);
    (*xb)[0] = r[b-1] ^ 1;
    /* (*xb)[0] = i ^ 1; */

    /* free(r_fix); */
    free(r);
    free(ry);
    return 0;
}

/*------------------------------------------------------------------------------
 *          Encryption oracle
 *----------------------------------------------------------------------------*/
int encryption_oracle(BYTE **y, size_t *y_len)
{
    /* Randomly select one of possible inputs */
    int choice = RAND_RANGE(0, 9);
    const char *x = POSSIBLE_X[choice];
    size_t x_len = strlen(x);

    *y_len = 0;

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
    }

    /* Generate a random IV ONCE */
    if (!global_iv) {
        global_iv = rand_byte(BLOCK_SIZE);
    }

#ifdef LOGSTATUS
    printf("Chose string %d: %s\n", choice, x);
#endif

    /* Encrypt using CBC mode */
    aes_128_cbc_encrypt(y, y_len, (BYTE *)x, x_len, global_key, global_iv);
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
