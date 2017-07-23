/*==============================================================================
 *     File: crypto2.c
 *  Created: 07/22/2017, 00:47
 *   Author: Bernie Roesler
 *
 *  Description: Solutions to Set 2 of Matasano Crypto Challenges
 *
 *============================================================================*/
#include "aes_openssl.h"
#include "header.h"
#include "crypto1.h"
#include "crypto2.h"

/*------------------------------------------------------------------------------
 *         PKCS#7 padding to block size 
 *----------------------------------------------------------------------------*/
BYTE *pkcs7(const BYTE *byte, size_t nbyte, size_t block_size)
{
    if (nbyte > block_size) { ERROR("Input > block size!"); }

    BYTE *out = init_byte(block_size);
    memcpy(out, byte, nbyte);
    BYTE *p = out+nbyte; /* start at end of original byte array */

    /* Add N-bytes of char N */
    BYTE n_pad = block_size - nbyte;

    for (int i = 0; i < n_pad; i++) {
        *p++ = n_pad;
    }

    return out;
}

/*------------------------------------------------------------------------------
 *         Encrypt AES 128-bit cipher in CBC mode 
 *----------------------------------------------------------------------------*/
size_t aes_128_cbc_encrypt(BYTE **y, BYTE *x, size_t x_len, BYTE *key, BYTE *iv)
{
    size_t y_len = 0,      /* output length */
           len = 0;     /* intermediate length */
    BYTE *xp = NULL,    /* intermediate value of xor'd bytes */
         *xi = NULL,    /* one block plaintext input */
         *yi = NULL,    /* one block output of AES encryption */
         *yim1 = NULL;  /* "previous" ciphertext block */

    /* possibly succinct mathematical way other than ternary statement? */
    int n_pad = (x_len % BLOCK_SIZE) ? (BLOCK_SIZE - (x_len % BLOCK_SIZE)) : 0;
    size_t n_blocks = (x_len + n_pad) / BLOCK_SIZE;
    printf("n_pad =    %d\nn_blocks = %zu\n", n_pad, n_blocks);

    /* initialize output byte array with one extra block */
    *y = init_byte(BLOCK_SIZE*(n_blocks+1));

    OpenSSL_init();

    /* Encrypt blocks of plaintext using Chain Block Cipher (CBC) mode */
    for (size_t i = 0; i < n_blocks; i++) {
        /* Input blocks */
        xi = x+i*BLOCK_SIZE;
        yim1 = (i == 0) ? iv : yi;

        /* Pad last block */
        if (i == (n_blocks - 1)) {
            xi = pkcs7(xi, (BLOCK_SIZE - n_pad), BLOCK_SIZE);
        }

        /* XOR plaintext block with previous ciphertext block */
        xp = fixedXOR(xi, yim1, BLOCK_SIZE);

        /* Encrypt single block using key and AES cipher */
        len = aes_128_ecb_cipher(&yi, xp, BLOCK_SIZE, key, 1);

        /* Append encrypted text to output array */
        memcpy(*y+y_len, yi, len);
        y_len += len; /* len == BLOCK_SIZE? */

        /* Clean-up */
        free(xp);
    }

    free(xi);
    free(yi);
    OpenSSL_cleanup();
    return y_len;
}

/*==============================================================================
 *============================================================================*/
