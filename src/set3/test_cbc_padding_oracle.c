/*==============================================================================
 *     File: test_cbc_padding_oracle.c
 *  Created: 04/29/2018, 14:05
 *   Author: Bernie Roesler
 *
 *  Description: Unit tests for cbc_padding_oracle functions
 *
 *============================================================================*/
/* User-defined headers */
#include "unit_test.h"
#include "header.h"
#include "crypto_util.h"
#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"
#include "cbc_padding_oracle.h"

/* Manually set global key, iv used in tests -- BLOCK_SIZE = 16 */
static BYTE global_key[] = "BUSINESS CASUAL";
static BYTE global_iv[] = "\x99\x99\x99\x99\x99\x99\x99\x99\
                           \x99\x99\x99\x99\x99\x99\x99\x99";

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* Test padding oracle */
int PORACLE1()
{
    START_TEST_CASE;
    BYTE x[] = "FIRETRUCK RACES!YELLOW SUBMARINE"; /* 2 blocks */
    size_t x_len = strlen((char *)x);
    BYTE *y = NULL;
    size_t y_len = 0;
    SHOULD_BE(aes_128_cbc_encrypt(&y, &y_len, x, x_len, global_key, global_iv) == 0);
    printf("y  = \"");
    print_blocks(y, y_len, BLOCK_SIZE, 0);
    printf("\"\n");
    /* Choose a correct padding for FIRST of 2 blocks */
    int n_pad = 1;
    for (size_t i = 0; i < n_pad; i++) {
        y[BLOCK_SIZE - n_pad + i] ^= n_pad;
    }
    printf("y  = \"");
    print_blocks(y, y_len, BLOCK_SIZE, 0);
    printf("\"\n");
    /* Decrypt and test value */
    BYTE *xp = NULL;
    size_t xp_len = 0;
    SHOULD_BE(aes_128_cbc_decrypt(&xp, &xp_len, y, y_len, global_key, global_iv) == 0);
    printf("xp = \"");
    print_blocks(xp, xp_len, BLOCK_SIZE, 1);
    printf("\"\n");
    for (size_t i = 0; i < n_pad; i++) {
        xp[2*BLOCK_SIZE - n_pad + i] ^= n_pad;
    }
    printf("xp = \"");
    print_blocks(xp, xp_len, BLOCK_SIZE, 1);
    printf("\"\n");
    END_TEST_CASE;
}


/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    /* Run OpenSSL lines here for speed */
    RUN_TEST(PORACLE1, "padding_oracle() 1 ");

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
