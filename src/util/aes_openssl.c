/*==============================================================================
 *     File: aes_openssl.c
 *  Created: 07/20/2017, 16:52
 *   Author: Bernie Roesler
 *
 *  Description: AES encryption functions using OpenSSL library
 *
 *============================================================================*/
#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"

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
int aes_128_ecb_block(BYTE **out, size_t *out_len, BYTE *in, size_t in_len, 
        BYTE *key, int enc)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = -1;
    *out_len = 0;

    if (in_len != BLOCK_SIZE) { ERROR("Input must be multiple of BLOCK_SIZE!"); }

    /* Initialize output buffer -- save room for null-termination */
    *out = init_byte(in_len + BLOCK_SIZE + 1);

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
    *out_len = len;

    /* Finalise the operation. Further out bytes may be written. Provide pointer
     * to end of output array (out+len) */
    if (1 != EVP_CipherFinal_ex(ctx, *out + len, &len)) { handleErrors(); }
    *out_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/*------------------------------------------------------------------------------
 *         Challenge 9: PKCS#7 padding to block size 
 *----------------------------------------------------------------------------*/
BYTE *pkcs7_pad(const BYTE *byte, size_t nbyte, size_t block_size)
{
    BYTE n_pad = block_size - (nbyte % block_size);

    BYTE *out = init_byte(nbyte + n_pad);
    memcpy(out, byte, nbyte);
    BYTE *p = out + nbyte;      /* start at end of original byte array */

    /* Add N-bytes of char N */
    for (int i = 0; i < n_pad; i++) {
        *p++ = n_pad;
    }

    return out;
}

/*------------------------------------------------------------------------------
 *         Challenge 15: Remove PKCS#7 padding bytes 
 *----------------------------------------------------------------------------*/
int pkcs7_rmpad(const BYTE *byte, size_t nbyte, size_t block_size)
{
    int n_pad = byte[nbyte-1];      /* last byte is number of pads */
    if (n_pad <= block_size) {
        for (int i = 0; i < n_pad; i++) {
            /* If a byte isn't the same as the pad byte, return error code */
            if (byte[nbyte-1-i] != n_pad) {
                return -1;
            }
        }

        /* Otherwise we've reached the end of the bytes, mark end with NULL */
        /* byte[nbyte-n_pad] = '\0'; */
        return n_pad;
    }

    return 0;
}

/*==============================================================================
 *============================================================================*/
