/*==============================================================================
 *     File: test_util_aes.c
 *  Created: 07/10/2017, 09:59
 *   Author: Bernie Roesler
 *
 *  Description: Unit tests on utility functions
 *
 *============================================================================*/
/* System headers */
#include <math.h>

/* User-defined headers */
#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"
#include "unit_test.h"

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* Test AES in ECB mode decryption for single block */
int AESDecrypt1()
{
    START_TEST_CASE;
    BYTE ptext[] = "Firetruck races!"; /* 16 bytes */
    size_t ptext_len = strlen((char *)ptext);
    /* OpenSSL_init(); */
    BYTE key[] = "YELLOW SUBMARINE"; /* 16-bit key */
    /*---------- Encrypt the plaintext ----------*/
    BYTE *ctext = NULL;
    size_t ctext_len = 0;
    int out = aes_128_ecb_block(&ctext, &ctext_len, ptext, ptext_len, key, 1);
    SHOULD_BE(out == 0);
    SHOULD_BE(ctext_len == BLOCK_SIZE);
    /*---------- Decrypt the ciphertext ----------*/
    BYTE *dtext = NULL;
    size_t dtext_len = 0;
    out = aes_128_ecb_block(&dtext, &dtext_len, ctext, ctext_len, key, 0);
    /* Compare with expected result */
    SHOULD_BE(out == 0);
    SHOULD_BE(dtext_len == ptext_len);
    SHOULD_BE(!memcmp(ptext, dtext, ptext_len));
#ifdef LOGSTATUS
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, (const char *)ctext, ctext_len);
    printf("ptext_len = %zu\nctext_len = %zu\ndtext_len = %zu\n", 
            ptext_len, ctext_len, dtext_len);
    printf("ptext: '");
    printall(ptext, ptext_len);
    printf("'\ndtext: '");
    printall(dtext, dtext_len);
    printf("'\n");
#endif
    /* Clean up */
    /* OpenSSL_cleanup(); */
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

    RUN_TEST(AESDecrypt1,    "aes_128_ecb_block() ");

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
