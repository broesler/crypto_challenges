/*==============================================================================
 *     File: detect_block_mode.c
 *  Created: 07/28/2017, 16:42
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 11: detect whether oracle is in ECB or CBC mode
 *
 *============================================================================*/
#include <stdio.h>

#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "crypto2.h"

#define SRAND_INIT 0

int encryption_oracle(BYTE **y, size_t *y_len, BYTE *x, size_t x_len);

/*------------------------------------------------------------------------------
 *         Main function
 *----------------------------------------------------------------------------*/
int main(void)
{
    srand(SRAND_INIT);
    int test = isECB(encryption_oracle, BLOCK_SIZE);

    if (test) {
        printf("ECB\n");
    } else {
        printf("CBC\n");
    }

    return 0;
}

/*------------------------------------------------------------------------------
 *          Randomly encrypt with ECB or CBC
 *----------------------------------------------------------------------------*/
int encryption_oracle(BYTE **y, size_t *y_len, BYTE *x, size_t x_len)
{
    size_t x_aug_len = 0;
    BYTE *prepend,
         *append,
         *iv,
         *key,
         *x_aug;
    int n_prepend,
        n_append,
        heads;

    *y_len = 0;

    /* Randomly generate 5-10 bytes to pre-/append to input */
    n_prepend = RAND_RANGE(5,10);
    n_append  = RAND_RANGE(5,10);
    prepend = rand_byte(n_prepend);
    append  = rand_byte(n_append);

    /* Build actual input to oracle */
    x_aug_len = n_prepend + x_len + n_append;
    x_aug = init_byte(x_aug_len);

    /* Move pointer along each chunk of bytes */
    memcpy(x_aug,                  prepend,  n_prepend);
    memcpy(x_aug+n_prepend,        x,        x_len);
    memcpy(x_aug+n_prepend+x_len,  append,   n_append);

#ifdef VERBOSE
    printf("n_prepend = %d, n_append = %d\n", n_prepend, n_append);
    printf("prepend = \"");
    printall(prepend, n_prepend);
    printf("\"\nappend  = \"");
    printall(append, n_append);
    printf("\"\nx_aug   = \"");
    printall(x_aug, x_aug_len);
    printf("\"\n");
#endif

    /* Generate a random key */
    key = rand_byte(BLOCK_SIZE);

    /* Flip a coin to choose the algorithm to use */
    heads = RAND_RANGE(0,1);

    if (heads) {
#ifdef LOGSTATUS
        LOG("Encrypting in ECB mode");
#endif
        /* Use ECB mode */
        aes_128_ecb_cipher(y, y_len, x_aug, x_aug_len, key, 1);

    } else {
#ifdef LOGSTATUS
        LOG("Encrypting in ECB mode");
#endif
        /* Generate random IV */
        iv = rand_byte(BLOCK_SIZE);
        /* Use CBC mode */
        aes_128_cbc_encrypt(y, y_len, x_aug, x_aug_len, key, iv);
        free(iv);
    }

#ifdef VERBOSE
    LOG("Ciphertext is:");
    BIO_dump_fp(stdout, (const char *)*y, y_len);
#endif

    /* Clean-up */
    free(prepend);
    free(append);
    free(key);
    free(x_aug);

    return 0;
}

/*==============================================================================
 *============================================================================*/
