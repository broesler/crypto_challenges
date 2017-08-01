/*==============================================================================
 *     File: one_byte_ecb_hard.c
 *  Created: 07/28/2017, 21:22
 *   Author: Bernie Roesler
 *
 *  Description: One byte ECB, but with additional random text prepended
 *
 *============================================================================*/
#include <stdio.h>

#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "crypto2.h"
#include "dictionary.h"

#define SRAND_INIT 56

/* Mode of operation (easy or hard) */
static int mode = 0;

/* Global key used in encryption_oracle12 */
static BYTE *global_key = NULL;
static BYTE *global_prepend = NULL;
static BYTE *global_append = NULL;

/* Take input of the form (your-string||unknown-string, random-key), and decrypt
 * the unknown string */
int encryption_oracle(BYTE **y, size_t *y_len, BYTE *x, size_t x_len);

// Get next byte from one-byte-at-a-time ECB decryption
BYTE decodeNextByte(int (*encrypt)(BYTE**, size_t*, BYTE*, size_t), const BYTE *y, 
        size_t y_len, size_t block_size, size_t n_prepend);

/* String to append to the plaintext (for decryption!) */
static const char append_b64[] = 
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
    "YnkK";

/*------------------------------------------------------------------------------
 *         Main function
 *----------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    size_t block_size = 0,
           i = 0,
           count = 0,
           n = 0,
           unk_len = sizeof(append_b64)*3/4, /* == 138 */
           y_len = 0; /* length of unknown string (== n_append) */
    BYTE y[1024];
    BYTE *p = y;

    if (argc < 1) {
        printf("Usage: %s [easy|hard]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* choose mode of operation */
    mode = strncmp(argv[1], "easy", 4) ? 1 : 0;

    /* initialize PRNG */
    srand(SRAND_INIT);

    /* Detect block size */
    block_size = getBlockSize(encryption_oracle, &count, &n);
    size_t n_prepend = n*block_size - unk_len - count;

    /* Confirm function is using ECB */
    MY_ASSERT(isECB(encryption_oracle, block_size));

    /* Decrypt unknown bytes */
    for (i = 0; i < unk_len; i++){
        if (!(*p++ = decodeNextByte(encryption_oracle, 
                        (const BYTE *)y, y_len, block_size, n_prepend))) {
            break; 
        }
        y_len++;
    }

    /* Print decrypted string! */
    printall(y, y_len);

    free(global_key);
    free(global_append);
    if (mode) { free(global_prepend); }
    return 0;
}

/*------------------------------------------------------------------------------
 *          Encryption oracle
 *----------------------------------------------------------------------------*/
int encryption_oracle(BYTE **y, size_t *y_len, BYTE *x, size_t x_len)
{
    size_t x_aug_len = 0;
    static size_t n_prepend = 0, /* only compute ONCE */
                  n_append = 0;
    BYTE *x_aug;

    *y_len = 0;

    /* Convert to byte array */
    if (!global_append) {
        n_append = b642byte(&global_append, append_b64);
    }

    /* Prepend random bytes */
    /* only prepend in "hard" mode */
    if (mode && !global_prepend) {
        /* n_prepend = RAND_RANGE(1, BLOCK_SIZE-1); */
        n_prepend = 3;
        global_prepend = rand_byte(n_prepend); 
    }

    /* Build actual input to oracle */
    x_aug_len = n_prepend + x_len + n_append;
    x_aug = init_byte(x_aug_len);

    /* Move pointer along each chunk of bytes */
    memcpy(x_aug,                     global_prepend, n_prepend);
    memcpy(x_aug + n_prepend,                      x,     x_len);
    memcpy(x_aug + n_prepend + x_len,  global_append,  n_append);

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
    }

    /* Encrypt using ECB mode */
    aes_128_ecb_cipher(y, y_len, x_aug, x_aug_len, global_key, 1);

    /* Clean-up */
    free(x_aug);
    return 0;
}

/*------------------------------------------------------------------------------
 *          Get single byte of unknown string
 *----------------------------------------------------------------------------*/
BYTE decodeNextByte(int (*encrypt)(BYTE**, size_t*, BYTE*, size_t), const BYTE *y, 
        size_t y_len, size_t block_size, size_t n_prepend)
{
    DICTIONARY *dict = NULL;
    size_t i = 0,
           x_len = 0,
           t_len = 0,
           in_len = 0;
    static size_t p_len = 0;
    BYTE *c = NULL,
         *t = NULL,
         *in = NULL;

    /* Build input byte base (n-bytes short)
     * Input is (block_size-1) known bytes + 1 unknown */
    p_len = block_size - (n_prepend % block_size); /* virtual block size */
    x_len = block_size - (y_len     % block_size) - 1;
    in_len = x_len + p_len + y_len + 1;  /* == n*block_size */

    in = init_byte(in_len);
    for (i = 0; i < (x_len + p_len); i++) { *(in+i) = 'A'; }
    memcpy(in + x_len + p_len, y, y_len);   /* include all known bytes */

    /* Build dictionary of ECB output for each byte of input */
    if (!(dict = initDictionary())) { ERROR("initDictionary failed!"); }

    for (i = 0; i < 0x100; i++) {
        /* Concatenate single unknown char onto input */
        *(in + in_len - 1) = (BYTE)i;

        /* Encrypt input with one "guess" byte */
        encrypt(&t, &t_len, in, in_len);

        /* Store encrypted "guess" */
        /* NOTE need to malloc "data" for dictionary because it is free'd */
        c = init_byte(1);
        *c = (BYTE)i;
        dAdd(dict, t, in_len, (void *)c);

        free(t);
    }

    /* Encrypt just our one-byte-short string */ 
    encrypt(&t, &t_len, in, x_len + p_len);

    /* cast (void *) to desired byte value */
    BYTE b = *(BYTE *)dLookup(dict, t, in_len);

    /* Clean-up */
    free(t);
    free(in);
    freeDictionary(dict);

    return b;
}

/*==============================================================================
 *============================================================================*/
