/*==============================================================================
 *     File: aes_openssl.c
 *  Created: 07/20/2017, 16:52
 *   Author: Bernie Roesler
 *
 *  Description: AES encryption functions using OpenSSL library
 *
 *============================================================================*/
#include "aes_openssl.h"

/*------------------------------------------------------------------------------
 *          General encryption/decryption function
 *----------------------------------------------------------------------------*/
/* Set enc to 1 for encryption, 0 for decryption */
int aes_128_ecb_cipher(unsigned char **out, unsigned char *in, size_t in_len, 
        unsigned char *key, int enc)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = -1;
    int out_len = -1;

    /* Initialize output buffer -- save room for null-termination */
    *out = (unsigned char *)init_byte(in_len + EVP_MAX_BLOCK_LENGTH + 1);

    /* IMPORTANT - ensure you use a key and IV size appropriate for your cipher */
    if (16 != strlen((char *)key)) {
        ERROR("Key must be 16 bytes long for AES-128-ECB!");
    }

    /* Initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) { handleErrors(); }

    /* Initialise the en/decryption operation. No IV needed for ECB */
    if (1 != EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL, enc)) { 
        handleErrors(); 
    }

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

/*==============================================================================
 *============================================================================*/
