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

/* OVERWRITE externs?? */
BYTE *global_key = (BYTE *)"BUSINESS CASUAL";
BYTE *global_iv  = (BYTE *)"\x99\x99\x99\x99\x99\x99\x99\x99" \
                           "\x99\x99\x99\x99\x99\x99\x99\x99";

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
#ifdef LOGSTATUS
    printf("y  = \"");
    print_blocks(y, y_len, BLOCK_SIZE, 0);
    printf("\"\n");
#endif
    /* Choose random byte for last position of first block. */
    BYTE i = 0x44; /* 0x44 == 'E' ^ 1 == i in last_byte */
    SHOULD_BE(x[2*BLOCK_SIZE-1] == (i ^ 1)); /* by definition */
    y[BLOCK_SIZE-1] ^= i;
#ifdef LOGSTATUS
    printf("y  = \"");
    print_blocks(y, y_len, BLOCK_SIZE, 0);
    printf("\"\n");
#endif
    /* Decrypt and test value */
    BYTE *xp = NULL;
    size_t xp_len = 0;
    SHOULD_BE(aes_128_cbc_decrypt(&xp, &xp_len, y, y_len, global_key, global_iv) == 1);
#ifdef LOGSTATUS
    printf("xp = \"");
    print_blocks(xp, 2*BLOCK_SIZE, BLOCK_SIZE, 1); /* inclue padding */
    printf("\"\n");
#endif
    SHOULD_BE(*(xp + 2*BLOCK_SIZE-1) == 0x01);  /* last byte of xp is \x01 */
    SHOULD_BE(xp_len == y_len-1); /* valid padding of \x01 gets stripped. */
    /* Last blocks should be equal, first block of xp is garbage */
    SHOULD_BE(!memcmp(xp + BLOCK_SIZE, x + BLOCK_SIZE, xp_len - BLOCK_SIZE));
    free(y);
    free(xp);
    END_TEST_CASE;
}

/* Test last_byte algorithm */
int PORACLE2()
{
    START_TEST_CASE;
    BYTE x[] = "FIRETRUCK RACES!YELLOW SUBMARINE"; /* 2 blocks */
    size_t x_len = strlen((char *)x);
    BYTE *y = NULL;
    size_t y_len = 0;
    SHOULD_BE(aes_128_cbc_encrypt(&y, &y_len, x, x_len, global_key, global_iv) == 0);
    /* Encryption intercepted! Get last byte */
    BYTE *xp = NULL;
    size_t xp_len = 0;
    /* Want last byte of 2nd block */
    SHOULD_BE(last_byte(&xp, &xp_len, y+BLOCK_SIZE) == 0);
    SHOULD_BE(xp_len == 1);
    BYTE xg = xp[0] ^ y[BLOCK_SIZE-1];
    SHOULD_BE(xg == 'E');
#ifdef LOGSTATUS
    printf("xp = \"");
    printall(xp, xp_len);
    printf("\" == \\x%.2X\n", *xp);
#endif
    free(y);
    free(xp);
    END_TEST_CASE;
}

/* Test block_decrypt algorithm */
int PORACLE3()
{
    START_TEST_CASE;
    BYTE x[] = "FIRETRUCK RACES!YELLOW SUBMARINE"; /* 2 blocks */
    size_t x_len = strlen((char *)x);
    BYTE *y = NULL;
    size_t y_len = 0;
    SHOULD_BE(aes_128_cbc_encrypt(&y, &y_len, x, x_len, global_key, global_iv) == 0);
    BYTE *xp = NULL;
    SHOULD_BE(block_decrypt(&xp, y+BLOCK_SIZE) == 0);
    BYTE *xg = fixedXOR(xp, y, BLOCK_SIZE);
    SHOULD_BE(!memcmp(xg, x + BLOCK_SIZE, BLOCK_SIZE));
#ifdef LOGSTATUS
    printf("xg = \"");
    print_blocks(xg, 2*BLOCK_SIZE, BLOCK_SIZE, 1);
    printf("\"\n");
#endif
    free(y);
    free(xp);
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
    RUN_TEST(PORACLE1, "padding_oracle() ");
    RUN_TEST(PORACLE2, "last_byte()      ");
    RUN_TEST(PORACLE3, "block_decrypt()  ");

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