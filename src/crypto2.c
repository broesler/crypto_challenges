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
BYTE *pkcs7_pad(const BYTE *byte, size_t nbyte, size_t block_size)
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
 *         Remove PKCS#7 padding bytes 
 *----------------------------------------------------------------------------*/
int pkcs7_rmpad(BYTE *byte, size_t nbyte, size_t block_size)
{
    int n_pad = byte[nbyte-1];      /* last byte is number of pads */
    if (n_pad <= block_size) {
        for (int i = 0; i < n_pad; i++) {
            /* If a byte isn't the same as the pad byte, throw warning */
            if (byte[nbyte-1-i] != n_pad) {
#ifdef LOGSTATUS
                printf("byte = \"");
                printall(byte, nbyte);
                printf("\"\n");
                WARNING("Padding is invalid!");
#endif
                return 0;
            }
        }
        /* Otherwise we've reached the end of the string, add a NULL */
        byte[nbyte-n_pad] = '\0';
        return n_pad;
    } else {
        return 0;
    }        
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

    /* Number of blocks needed */
    size_t n_blocks = x_len / BLOCK_SIZE;
    if (x_len % BLOCK_SIZE) { n_blocks++; }
    size_t tot_len = BLOCK_SIZE * n_blocks;

    /* initialize output byte array with one extra block */
    *y = init_byte(tot_len + BLOCK_SIZE);

    OpenSSL_init();

    /* Encrypt blocks of plaintext using Chain Block Cipher (CBC) mode */
    for (size_t i = 0; i < n_blocks; i++) {
        /* Input blocks */
        xi = x + i*BLOCK_SIZE;
        yim1 = (i == 0) ? iv : yi; /* chain the last ciphertext into the next */

        /* Pad the input (n_pad only non-zero for last block) */
        size_t xi_len = (i == n_blocks-1) ? (x_len - i*BLOCK_SIZE) : BLOCK_SIZE;
        BYTE *xi_pad = pkcs7_pad(xi, xi_len, BLOCK_SIZE);

        /* XOR plaintext block with previous ciphertext block */
        xp = fixedXOR(xi_pad, yim1, BLOCK_SIZE);

        /* Encrypt single block using key and AES cipher */
        len = aes_128_ecb_block(&yi, xp, BLOCK_SIZE, key, 1);

        /* Append encrypted text to output array */
        memcpy(*y + y_len, yi, len);
        y_len += len;

        free(xp);
        free(xi_pad);
    }

    /* Clean-up */
    free(yi);
    OpenSSL_cleanup();
    return y_len;
}

/*------------------------------------------------------------------------------
 *         Decrypt AES 128-bit cipher in CBC mode 
 *----------------------------------------------------------------------------*/
size_t aes_128_cbc_decrypt(BYTE **x, BYTE *y, size_t y_len, BYTE *key, BYTE *iv)
{
    size_t x_len = 0,   /* output length */
           len = 0;     /* intermediate length */
    BYTE *yp = NULL,    /* intermediate value of xor'd bytes */
         *xi = NULL,    /* one block plaintext input */
         *yi = NULL,    /* one block output of AES encryption */
         *yim1 = NULL;  /* "previous" ciphertext block */

    /* Number of blocks needed */
    size_t n_blocks = y_len / BLOCK_SIZE;
    if (x_len % BLOCK_SIZE) { n_blocks++; }

    /* initialize output byte array with one extra block */
    *x = init_byte(BLOCK_SIZE*(n_blocks+1));

    OpenSSL_init();

    /* Encrypt blocks of plaintext using Chain Block Cipher (CBC) mode */
    for (size_t i = 0; i < n_blocks; i++) {
        /* Input blocks */
        yim1 = (i == 0) ? iv : yi;
        yi = y + i*BLOCK_SIZE;

        /* Decrypt single block using key and AES cipher */
        len = aes_128_ecb_block(&yp, yi, BLOCK_SIZE, key, 0);

        /* XOR decrypted ciphertext block with previous ciphertext block */
        xi = fixedXOR(yp, yim1, BLOCK_SIZE);

        /* Remove any padding from output */
        int n_pad = pkcs7_rmpad(xi, len, BLOCK_SIZE); 
        len -= n_pad;

        /* Append decrypted text to output array */
        memcpy(*x + x_len, xi, len);
        x_len += len;

        free(yp);
        free(xi); /* could parallelize because x doesn't depend on xi */
    }

    /* Clean-up */
    OpenSSL_cleanup();
    return x_len;
}
/*==============================================================================
 *============================================================================*/
