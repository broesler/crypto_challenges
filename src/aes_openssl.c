/*==============================================================================
 *     File: aes_openssl.c
 *  Created: 07/20/2017, 16:52
 *   Author: Bernie Roesler
 *
 *  Description: AES encryption functions using OpenSSL library
 *
 *============================================================================*/
#include "aes_openssl.h"
#include "crypto2.h"

/*------------------------------------------------------------------------------
 *         Helpers for OpenSSL Libs
 *----------------------------------------------------------------------------*/
void OpenSSL_init(void)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void OpenSSL_cleanup(void)
{
    EVP_cleanup();
    ERR_free_strings();
}

void handleErrors(void)
{
    /* Just dump to stderr */
    ERR_print_errors_fp(stderr);
    ERROR("AES encountered an error.");
}

/*------------------------------------------------------------------------------
 *          General encryption/decryption function for one block
 *----------------------------------------------------------------------------*/
/* Set enc to 1 for encryption, 0 for decryption */
size_t aes_128_ecb_block(BYTE **out, BYTE *in, size_t in_len, BYTE *key, int enc)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = -1;
    int out_len = -1;

    if (in_len != BLOCK_SIZE) { ERROR("Input must be multiple of BLOCK_SIZE!"); }

    /* Initialize output buffer -- save room for null-termination */
    *out = init_byte(in_len + BLOCK_SIZE + 1);

    /* IMPORTANT - ensure you use a key and IV size appropriate for your cipher */
    if (BLOCK_SIZE != strlen((char *)key)) {
        ERROR("Key must be 16 bytes long for AES-128-ECB!");
    }

    /* Initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) { handleErrors(); }

    /* Initialise the en/decryption operation. No IV needed for ECB */
    if (1 != EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, enc)) { 
        handleErrors(); 
    }

    /* Turn off automatic padding always */
    if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) { handleErrors(); }

    /* Provide the message, and obtain the output.
     * EVP_CipherUpdate can be called multiple times if necessary */
    if (1 != EVP_CipherUpdate(ctx, *out, &len, in, in_len)) {
        handleErrors(); 
    }
    out_len = len;

    /* Finalise the operation. Further out bytes may be written. Provide pointer
     * to end of output array (out+len) */
    if (1 != EVP_CipherFinal_ex(ctx, *out + len, &len)) { handleErrors(); }
    out_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

/*------------------------------------------------------------------------------
 *         Encrypt AES in ECB mode
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

    OpenSSL_init();

    /* Encrypt blocks of plaintext using Chain Block Cipher (CBC) mode */
    for (size_t i = 0; i < n_blocks; i++) {
        /* Input blocks */
        xi = x + i*BLOCK_SIZE;

        /* Pad the input (n_pad only non-zero for last block) */
        size_t xi_len = (i == n_blocks-1) ? (x_len - i*BLOCK_SIZE) : BLOCK_SIZE;
        BYTE *xi_pad = pkcs7_pad(xi, xi_len, BLOCK_SIZE);

        /* Encrypt single block using key and AES cipher */
        len = aes_128_ecb_block(&yi, xi_pad, BLOCK_SIZE, key, enc);

        /* Remove any padding from last block of output */
        if (!enc && (i == n_blocks-1)) {
            int n_pad = pkcs7_rmpad(yi, len, BLOCK_SIZE); 
            len -= n_pad;
        }

        /* Append encrypted text to output array */
        memcpy(*y + y_len, yi, len);
        y_len += len;

        free(xi_pad);
    }

    /* Clean-up */
    free(yi);
    OpenSSL_cleanup();
    return y_len;
}

/*==============================================================================
 *============================================================================*/
