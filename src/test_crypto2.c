/*==============================================================================
 *     File: test2.c
 *  Created: 07/22/2017, 00:54
 *   Author: Bernie Roesler
 *
 *  Description: Tests of cryptography functions in crypto challenges set 2
 *
 *============================================================================*/
/* User-defined headers */
#include "aes_openssl.h"
#include "header.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "crypto2.h"
#include "unit_test.h"

/* Meta test functions */
int CBCencrypt_test(BYTE *ptext);

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* Test PKCS#7 padding */
int PKCS71()
{
    START_TEST_CASE;
    int n_pad = 4;
    BYTE byte[] = "YELLOW SUBMARINE";
    size_t nbyte = strlen((char *)byte);
    BYTE *block = pkcs7_pad(byte, nbyte, nbyte+n_pad);
    size_t nblock = strlen((char *)block);
    SHOULD_BE(nblock == nbyte+n_pad);
    for (int i = 0; i < n_pad; i++) { SHOULD_BE(*(block+nbyte+i) == n_pad); }
#ifdef LOGSTATUS
    printf("Padded string: '");
    printall(block, nblock);
    printf("'\n");
#endif
    /* Remove padding */
    int npout = pkcs7_rmpad(block, nblock, nbyte+n_pad);
    SHOULD_BE(npout == n_pad);
#ifdef LOGSTATUS
    printf("Removed pad:   '");
    printall(block, nbyte);
    printf("'\n");
#endif
    free(block);
    END_TEST_CASE;
}

/* Test PKCS#7 padding */
int PKCS72()
{
    START_TEST_CASE;
    int n_pad = 0;
    BYTE byte[] = "Bathroom passes.";
    size_t nbyte = strlen((char *)byte);
    BYTE *block = pkcs7_pad(byte, nbyte, nbyte+n_pad);
    size_t nblock = strlen((char *)block);
    SHOULD_BE(nblock == nbyte+n_pad);
    for (int i = 0; i < n_pad; i++) { SHOULD_BE(*(block+nbyte+i) == n_pad); }
#ifdef LOGSTATUS
    printf("Padded string: '");
    printall(block, nblock);
    printf("'\n");
#endif
    /* Remove padding */
    int npout = pkcs7_rmpad(block, nblock, nbyte+n_pad);
    SHOULD_BE(npout == n_pad);
#ifdef LOGSTATUS
    printf("Removed pad:   '");
    printall(block, nbyte);
    printf("'\n");
#endif
    free(block);
    END_TEST_CASE;
}

int CBCencrypt1()
{
    /* NOTE Memory leak occurs out output string (ctext) for BOTH of these
     * cases... so it doesn't have to do with padding removal. */
    START_TEST_CASE;
    BYTE ptext1[] = "I was a terror since the public school era.";
    rs += CBCencrypt_test(ptext1);
    BYTE ptext2[] = "Bathroom passes, cuttin classes, squeezin asses.";
    rs += CBCencrypt_test(ptext2);
    END_TEST_CASE;
}

/* Test CBC mode encryption */
int CBCencrypt_test(BYTE *ptext)
{
    START_TEST_CASE;
    size_t ptext_len = strlen((char *)ptext);
    BYTE key[] = "YELLOW SUBMARINE";
    BYTE iv[BLOCK_SIZE] = "";   /* BLOCK_SIZE-length array of '\0' chars */
    /* Encrypt the text */
    BYTE *ctext = NULL;
    size_t ctext_len = aes_128_cbc_encrypt(&ctext, ptext, ptext_len, key, iv);
    SHOULD_BE((ctext_len % BLOCK_SIZE) == 0);
    /*---------- Decrypt the ciphertext ----------*/
    BYTE *dtext = NULL;
    size_t dtext_len = aes_128_cbc_decrypt(&dtext, ctext, ctext_len, key, iv);
    /* Compare with expected result */
    SHOULD_BE(dtext_len == ptext_len);
    SHOULD_BE(!memcmp(ptext, dtext, ptext_len));
#ifdef LOGSTATUS
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ctext, ctext_len);
    printf("ptext_len = %zu\nctext_len = %zu\ndtext_len = %zu\n", 
            ptext_len, ctext_len, dtext_len);
    printf("ptext: '");
    printall(ptext, ptext_len);
    printf("'\ndtext: '");
    printall(dtext, dtext_len);
    printf("'\n");
#endif
    free(ctext);
    free(dtext);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    /* RUN_TEST(PKCS71,       "Challenge 1: pkcs7() 1               "); */
    /* RUN_TEST(PKCS72,       "             pkcs7() 2               "); */
    RUN_TEST(CBCencrypt1,  "Challenge 2: aes_128_cbc_encrypt() 1 ");

    /* Count errors */
    if (!fails) {
        printf("\033[0;32mAll %d tests passed!\033[0m\n", total); 
        return 0;
    } else {
        printf("\033[0;31m%d/%d tests failed!\033[0m\n", fails, total);
        return 1;
    }
}



/*==============================================================================
 *============================================================================*/
