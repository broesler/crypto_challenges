/*==============================================================================
 *     File: cbc_bit_flip.c
 *  Created: 07/31/2017, 23:11
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 16: CBC bit-flipping attack
 *
 *============================================================================*/
#include <stdio.h>
#include <string.h>

#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "crypto2.h"

#define SRAND_INIT 56

/* Global key used in encryption_oracle */
static BYTE *global_key = NULL;
static BYTE *global_iv  = NULL;

/* Take input of the form (your-string||unknown-string, random-key), and decrypt
 * the unknown string */
size_t encryption_oracle(BYTE **y, BYTE *x, size_t x_len);

/* Decrypt and parse for ';admin=true;' */
int isadmin(BYTE *y, size_t y_len);

/*------------------------------------------------------------------------------
 *         Main function
 *----------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    /* initialize PRNG */
    srand(SRAND_INIT);

    /* Encrypt our string */
    BYTE *y = NULL;
    size_t y_len = encryption_oracle(&y, NULL, 0);

    /* See if we have an admin */
    int test = isadmin(y, y_len);
    if (test) { printf("Found admin!\n"); }

    free(y);
    return 0;
}

/*------------------------------------------------------------------------------
 *          Encryption oracle
 *----------------------------------------------------------------------------*/
size_t encryption_oracle(BYTE **y, BYTE *x, size_t x_len)
{
    size_t xa_len = 0,
           x_aug_len = 0,
           y_len = 0;
    static size_t n_prepend = 0,
                  n_append = 0;

    /* Prepend this string */
    static char prepend[] = "comment1=cooking%20MCs;userdata=";
    n_prepend = strlen(prepend);

    /* Append this string */
    static char append[] = ";comment2=%20like%20a%20pound%20of%20bacon";
    n_append = strlen(append);

    /* Build actual input to oracle */
    xa_len = n_prepend + x_len + n_append;
    char *xa = init_str(xa_len); /* STRING HERE FOR ESCAPING CHARS */

    /* Move pointer along each chunk of bytes */
    memcpy(xa,                     prepend, n_prepend);
    memcpy(xa + n_prepend,               x,     x_len);
    memcpy(xa + n_prepend + x_len,  append,  n_append);

    /* Escape ';' and '=' before encrypting */
    char *x_aug = strhtmlesc((char *)xa, ";=");
    x_aug_len = strlen(x_aug);

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
    }

    /* Generate a random IV ONCE */
    if (!global_iv) {
        global_iv = rand_byte(BLOCK_SIZE);
    }

    /* Encrypt using ECB mode */
    y_len = aes_128_cbc_encrypt(y, (BYTE *)x_aug, x_aug_len, global_key, global_iv);

    /* Clean-up */
    free(xa);
    free(x_aug);
    return y_len;
}


/*------------------------------------------------------------------------------
 *         Decrypt and find ';admin=true;' 
 *----------------------------------------------------------------------------*/
int isadmin(BYTE *y, size_t y_len) 
{
    /* Decrypt ciphertext */ 
    BYTE *x = NULL;
    size_t x_len = aes_128_cbc_decrypt(&x, y, y_len, global_key, global_iv);

    /* Parse for ';admin=true;' */
    char *test = strnstr((char *)x, ";admin=true;", x_len);

    free(x);
    return test ? 1 : 0;
}

/*==============================================================================
 *============================================================================*/
