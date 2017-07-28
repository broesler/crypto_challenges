/*==============================================================================
 *     File: aes_ecb.c
 *  Created: 07/28/2017, 13:49
 *   Author: Bernie Roesler
 *
 *  Description: AES ECB encryption function
 *
 *============================================================================*/
#include "aes_openssl.h"
#include "crypto_util.h"
#include "crypto1.h"

/*------------------------------------------------------------------------------
 *         Challenge 7: Encrypt AES in ECB mode
 *----------------------------------------------------------------------------*/
size_t aes_128_ecb_cipher(BYTE **y, BYTE *x, size_t x_len, BYTE *key, int enc)
{
    size_t y_len = 0,      /* output length */
           len = 0;     /* intermediate length */
    BYTE *xi = NULL,    /* one block plaintext input */
         *yi = NULL;    /* one block output of AES encryption */

    /* Number of blocks needed */
    size_t n_blocks = x_len / BLOCK_SIZE;
    if (x_len % BLOCK_SIZE) { n_blocks++; }
    size_t tot_len = BLOCK_SIZE * n_blocks;

    /* initialize output byte array with one extra block */
    *y = init_byte(tot_len + BLOCK_SIZE);

    /* Pad the input (n_pad only non-zero for last block) */
    BYTE *x_pad = pkcs7_pad(x, x_len, BLOCK_SIZE);

    /* Encrypt blocks of plaintext using Chain Block Cipher (CBC) mode */
    for (size_t i = 0; i < n_blocks; i++) {
        /* Input blocks */
        xi = x_pad + i*BLOCK_SIZE;

        /* Encrypt single block using key and AES cipher */
        len = aes_128_ecb_block(&yi, xi, BLOCK_SIZE, key, enc);

        /* Append encrypted text to output array */
        memcpy(*y + y_len, yi, len);
        y_len += len;
        free(yi);
    }

    if (!enc) {
        int n_pad = pkcs7_rmpad(*y, y_len, BLOCK_SIZE); 
        y_len -= n_pad;
    }

    /* Clean-up */
    free(x_pad);
    return y_len;
}

/*==============================================================================
 *============================================================================*/
