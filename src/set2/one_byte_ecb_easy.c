/*==============================================================================
 *     File: one_byte_ecb_easy.c
 *  Created: 07/28/2017, 16:56
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 12: One byte at a time ECB decryption
 *
 *============================================================================*/
#include <stdio.h>

#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "crypto2.h"
#include "dictionary.h"

#define SRAND_INIT 0

/* Global key used in encryption_oracle12 */
static BYTE *global_key = NULL;

/* Take input of the form (your-string||unknown-string, random-key), and decrypt
 * the unknown string */
size_t encryption_oracle(BYTE **y, BYTE *x, size_t x_len);

// Get next byte from one-byte-at-a-time ECB decryption
BYTE decodeNextByte(size_t (*encrypt)(BYTE**, BYTE*, size_t), const BYTE *y, 
        size_t y_len, size_t block_size);

/* String to append to the plaintext (for decryption!) */
static const char append_b64[] = 
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
    "YnkK";

/*------------------------------------------------------------------------------
 *         Main function
 *----------------------------------------------------------------------------*/
int main(void)
{
    size_t block_size = 0,
           i = 0,
           cnt = 0,
           np1 = 0,
           unk_len = sizeof(append_b64)*3/4, /* == 138 */
           y_len = 0; /* length of unknown string (== n_append) */
    BYTE y[1024];
    BYTE *p = y;

    /* initialize PRNG */
    srand(SRAND_INIT);

    /* Detect block size */
    block_size = getBlockSize(encryption_oracle, &cnt, &np1);

    /* Confirm function is using ECB */
    MY_ASSERT(isECB(encryption_oracle, block_size));

    /* Decrypt unknown bytes */
    for (i = 0; i < unk_len; i++){
        if (!(*p++ = decodeNextByte(encryption_oracle, 
                        (const BYTE *)y, y_len, block_size))) {
            break; 
        }
        y_len++;
    }

    /* Print decrypted string! */
    printall(y, y_len);

    free(global_key);
    return 0;
}

/*------------------------------------------------------------------------------
 *          Encryption oracle
 *----------------------------------------------------------------------------*/
size_t encryption_oracle(BYTE **y, BYTE *x, size_t x_len)
{
    size_t x_aug_len = 0,
           y_len = 0;
    BYTE *x_aug;

    /* Convert to byte array */
    static BYTE *append = NULL;
    size_t n_append = b642byte(&append, append_b64);

    /* Build actual input to oracle */
    x_aug_len = x_len + n_append;
    x_aug = init_byte(x_aug_len);

    /* Move pointer along each chunk of bytes */
    memcpy(x_aug,       x,      x_len);
    memcpy(x_aug+x_len, append, n_append);

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
    }

    /* Encrypt using ECB mode */
    y_len = aes_128_ecb_cipher(y, x_aug, x_aug_len, global_key, 1);

    /* Clean-up */
    free(append);
    free(x_aug);

    return y_len;
}

/*------------------------------------------------------------------------------
 *          Get single byte of unknown string
 *----------------------------------------------------------------------------*/
BYTE decodeNextByte(size_t (*encrypt)(BYTE**, BYTE*, size_t), const BYTE *y, 
        size_t y_len, size_t block_size)
{
    DICTIONARY *dict = NULL;
    size_t i = 0,
           x_len = 0,
           in_len = 0;
    BYTE *c = NULL,
         *t = NULL,
         *in = NULL;

    /* Build input byte base (n-bytes short)
     * Input is (block_size-1) known bytes + 1 unknown */
    x_len = block_size - (y_len % block_size) - 1;
    in_len = x_len + y_len + 1;  /* == n_block*block_size */

    /* x_len goes 15-0, y_len counts up, in_len goes up by chunks of 16 */
    /* printf("x_len = %zu\ty_len = %zu\tin_len = %zu\n", x_len, y_len, in_len); */

    in = init_byte(in_len);
    for (i = 0; i < x_len; i++) { *(in+i) = '0'; }
    /* Also include all known bytes */
    memcpy(in + x_len, y, y_len);

    /* Build dictionary of ECB output for each byte of input */
    if (!(dict = initDictionary())) { ERROR("initDictionary failed!"); }

    for (i = 0; i < 0x100; i++) {
        /* Concatenate single unknown char onto input */
        *(in + in_len - 1) = (BYTE)i;

        /* Encrypt single-block input */
        encrypt(&t, in, in_len);

        /* Dictionary key is t, value is i */
        /* NOTE need to malloc "data" for dictionary because it is free'd */
        c = init_byte(1);
        *c = (BYTE)i;
        dAdd(dict, t, in_len, (void *)c);

        free(t);
    }

    /* Encrypt just our one-byte-short string */ 
    /* x_len = in_len - y_len - 1 */
    encrypt(&t, in, x_len);

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
