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
int encryption_oracle(BYTE **y, size_t *y_len, BYTE *x, size_t x_len);

/* Decrypt and parse for ';admin=true;' */
int decrypt_and_checkadmin(BYTE *y, size_t y_len);

/*------------------------------------------------------------------------------
 *         Main function
 *----------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    /* initialize PRNG */
    srand(SRAND_INIT);

    /* NOTE Known prepended input is exactly 2 blocks long */
    /* Define string to be two blocks: 1 throw-away, 1 actual info */
    BYTE k = 0x05;
    size_t x_len = 2*BLOCK_SIZE;
    BYTE x[x_len+1];
    BYTE *p = x;
    /* Fill one full block with garbage so we don't worry about garbling it */
    for (size_t i = 0; i < BLOCK_SIZE; i++) { *p++ = 'X'; }
    /* Add k to "escaped" bytes so they don't get escaped */
    *p++ = ';' ^ k;
    memcpy(p, "admin", 5);
    p += 5;
    *p++ = '=' ^ k;
    memcpy(p, "true", 4);
    p += 4;
    *p++ = ';' ^ k;
    *p = '\0';


#ifdef LOGSTATUS
    printf("x  = \"%s\"\n", x);
    /* x == "XXXXXXXXXXXXXXXX>admin8true>", for k = 0x05 */
#endif

    /* Encrypt our string */
    BYTE *y = NULL;
    size_t y_len = 0;
    if (0 != encryption_oracle(&y, &y_len, x, x_len)) {
        ERROR("Incorrect padding!");
    }

    /* Flip bits in FIRST (junk) block of our ciphertext, so that when this
     * block is XOR'd with the SECOND (data) block, we get the ";=" chars!
     * x  : XXXXXXXXXXXXXXXX >admin8true>
     * y  : YYYYYYYYYYYYYYYY YYYYYYYYYYYY\x04\x04\x04\x04
     * Flip bits to get:
     * y  : pYYYYYpYYYYpYYYY YYYYYYYYYYYY\x04\x04\x04\x04
     * x' : GARBAGEDECRYPTED ;admin=true;
     */
    y[x_len]    ^= k;
    y[x_len+6]  ^= k; /* len("admin")+1 */
    y[x_len+11] ^= k; /* len("true")+1 */

    /* Decrypt y to see if we have an admin */
    int test = decrypt_and_checkadmin(y, y_len); /* bash convention 0 == ok */

#ifdef LOGSTATUS
    if (!test) { printf("Found admin!\n"); }
#endif

    free(y);
    return test;
}

/*------------------------------------------------------------------------------
 *          Encryption oracle
 *----------------------------------------------------------------------------*/
int encryption_oracle(BYTE **y, size_t *y_len, BYTE *x, size_t x_len)
{
    size_t xc_len = 0,
           xa_len = 0;
    static size_t n_prepend = 0,
                  n_append = 0;

    *y_len = 0;

    /* Escape ';' and '=' before encrypting */
    char *x_clean = strhtmlesc((char *)x, ";=");
    xc_len = strlen(x_clean);

    /* Prepend this string */
    static char prepend[] = "comment1=cooking%20MCs;userdata=";
    n_prepend = strlen(prepend);

    /* Append this string */
    static char append[] = ";comment2=%20like%20a%20pound%20of%20bacon";
    n_append = strlen(append);

    /* Build actual input to oracle */
    xa_len = n_prepend + xc_len + n_append;
    char *xa = init_str(xa_len); /* STRING HERE FOR ESCAPING CHARS */

    /* Move pointer along each chunk of bytes */
    memcpy(xa,                      prepend, n_prepend);
    memcpy(xa + n_prepend,          x_clean,    xc_len);
    memcpy(xa + n_prepend + xc_len,  append,  n_append);

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
    }

    /* Generate a random IV ONCE */
    if (!global_iv) {
        global_iv = rand_byte(BLOCK_SIZE);
    }

    /* Encrypt using CBC mode */
    aes_128_cbc_encrypt(y, y_len, (BYTE *)xa, xa_len, global_key, global_iv);

    /* Clean-up */
    free(xa);
    free(x_clean);

    return 0;
}

/*------------------------------------------------------------------------------
 *         Decrypt and find ';admin=true;'
 *----------------------------------------------------------------------------*/
int decrypt_and_checkadmin(BYTE *y, size_t y_len)
{
    /* Decrypt ciphertext */
    BYTE *x = NULL;
    size_t x_len = 0;
    
    /* Check if padding is valid */
    if (0 > aes_128_cbc_decrypt(&x, &x_len, y, y_len, global_key, global_iv)) {
        return -1;
    }

    /* Parse for ';admin=true;' */
#ifdef LOGSTATUS
    printf("x' = \"");
    printall(x, x_len);
    printf("\"\n");
#endif

    /* WARNING Will not work if output has NULL before our admin check!! */
    char *test = strnstr((char *)x, ";admin=true;", x_len);

    free(x);
    return test ? 0 : 1; /* bash convention 0 == true */
}

/*==============================================================================
 *============================================================================*/
