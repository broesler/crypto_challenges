/*==============================================================================
 *     File: aes_test.c
 *  Created: 07/19/2017, 22:51
 *   Author: Bernie Roesler
 *
 *  Description: Test out example AES encryption/decryption, found here:
 *  <https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption>
 *  See $ man evp for more info
 *
 *  Build using: 
 *  $ mygcc -I/usr/local/opt/openssl/include -o aes_test aes_test.c -lcrypto -lssl
 *============================================================================*/
#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

/*------------------------------------------------------------------------------
 *         Function declarations 
 *----------------------------------------------------------------------------*/
void handleErrors(void);

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
        unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
        unsigned char *iv, unsigned char *plaintext);

/*------------------------------------------------------------------------------
 *          Main Encryption/Decryption Function
 *----------------------------------------------------------------------------*/
int main (void)
{
    /* Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-) */

    /* A 256 bit key */
    /* unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; */

    /* A 128 bit key */
    unsigned char *key = (unsigned char *)"YELLOW SUBMARINE";

    /* A 128 bit IV */
    /* unsigned char *iv = (unsigned char *)"0123456789012345"; */

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    printf("Original plaintext:\n%s\n", plaintext);

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, NULL,
            ciphertext);

    printf("plaintext_len  = %lu\n", strlen((char *)plaintext));
    printf("ciphertext_len = %d\n", ciphertext_len);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, NULL,
            decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);
    if (!strcmp((const char *)plaintext, (const char *)decryptedtext))
        printf("Success!\n");

    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

/*------------------------------------------------------------------------------
 *         Error handling
 *----------------------------------------------------------------------------*/
void handleErrors(void)
{
    /* Just dump to stderr */
    ERR_print_errors_fp(stderr);
    abort();
}

/*------------------------------------------------------------------------------
 *         Encryption function 
 *----------------------------------------------------------------------------*/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
        unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    /* if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) */
    /*     handleErrors(); */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written. */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/*------------------------------------------------------------------------------
 *         Decryption function 
 *----------------------------------------------------------------------------*/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
        unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    /* if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) */
    /*     handleErrors(); */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written. */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/*==============================================================================
 *============================================================================*/
