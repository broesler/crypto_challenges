/*==============================================================================
 *     File: cbc_padding_oracle.c
 *  Created: 08/01/2017, 22:51
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 17: CBC decryption with padding oracle
 *
 *============================================================================*/

#include "cbc_padding_oracle.h"

// Global key, iv used in tests
static BYTE *global_key = NULL;
static BYTE *global_iv  = NULL;

int main(int argc, char **argv)
{
    BYTE *y = NULL;
    size_t y_len = 0;

    /* initialize PRNG */
    srand(SRAND_INIT);
    /* srand(time(NULL)); */

    /* Encrypt random string */
    encryption_oracle(&y, &y_len);

    /* size_t Nb = y_len / BLOCK_SIZE; */
    BYTE *x = init_byte(y_len);

    /* start at 1 because we don't have IV */
    /* for (size_t i = 1; i < Nb; i++) { */
    for (size_t i = 1; i < 2; i++) {
        size_t idx = i*BLOCK_SIZE;
        /* Decrypt block */
        BYTE *xbl = NULL;
        block_decrypt(&xbl, y+idx);
        /* Store in output array */
        memcpy(x+idx, xbl, BLOCK_SIZE);
        free(xbl);
    }

    /* print result */
    printf("\nx = \"");
    print_blocks(x, y_len, BLOCK_SIZE, 1);
    printf("\"\n");

    free(x);
    free(y);
    free(global_key);
    free(global_iv);
    return 0;
}

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
        /* Set values of r_k from k = j,...,b */
        for (size_t k = j; k < b; k++) {
            r_fix[k] = (*x)[k] ^ (b - j + 1); 
        }
        printall(r, b);
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

            /* Check if O(r|y) is true */
            if (0 > padding_oracle(ry, 2*b)) { 
                /* Set (j-1)th byte to desired value */
                (*x)[j-1] = r[j-1] ^ i ^ (b - j + 1);
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

    BYTE *r_fix = rand_byte(b);
    BYTE *r     = init_byte(b);
    BYTE *ry    = init_byte(2*b);

    for (size_t i = 0; i < b; i++) { 
        /* Reset random block */
        memcpy(r, r_fix, b);

        /* Guess last byte to give correct padding */
        r[b-1] ^= i; /* subtract 1 to make "b" an index */

        /* Concatenate string to pass to oracle */
        BZERO(ry, 2*b);
        memcpy(ry,   r, b);
        memcpy(ry+b, y, b);

        /* Check if O(r|y) is true */
        if (0 > padding_oracle(ry, 2*b)) { 
            break;
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
    /*     if (0 > padding_oracle(ry, 2*b)) {  */
    /*         memcpy(*xb, r[b-n], n); */
    /*         return 0; */
    /*     } */
    /* } */

    /* Valid padding was 1 */
    *xb_len = 1;
    *xb = init_byte(*xb_len);
    (*xb)[0] = r[b-1] ^ 1;

    /* #<{(| DUMMY OUT |)}># */
    /* *xb = init_byte(3); */
    /* memcpy(*xb, "ABC", 3); */
    /* *xb_len = 3; */

    free(r_fix);
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
