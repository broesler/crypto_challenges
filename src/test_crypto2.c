/*==============================================================================
 *     File: test2.c
 *  Created: 07/22/2017, 00:54
 *   Author: Bernie Roesler
 *
 *  Description: Tests of cryptography functions in crypto challenges set 2
 *
 *============================================================================*/
/* User-defined headers */
#include "header.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "crypto2.h"
#include "unit_test.h"

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* Test PKCS#7 padding */
int PKCS71()
{
    START_TEST_CASE;
    BYTE byte[] = "YELLOW SUBMARINE";
    size_t nbyte = strlen((char *)byte);
    BYTE *block = pkcs7(byte, nbyte, 20);
    size_t nblock = strlen((char *)block);
    SHOULD_BE(nblock == 20);
    for (int i = 0; i < 4; i++) { SHOULD_BE(*(block+nbyte+i) == 4); }
#ifdef LOGSTATUS
    printf("Padded string: '");
    printall(block, nblock);
    printf("'\n");
#endif
    free(block);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(PKCS71,       "Challenge 1: pkcs7() 1           ");
    /* RUN_TEST(PKCS72,       "             pkcs7() 2           "); */

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
