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
    BYTE *Dy = NULL;
    size_t xp_len = 0;
    SHOULD_BE(aes_128_cbc_decrypt(&Dy, &xp_len, y, y_len, global_key, global_iv) == 1);
#ifdef LOGSTATUS
    printf("Dy = \"");
    print_blocks(Dy, 2*BLOCK_SIZE, BLOCK_SIZE, 1); /* inclue padding */
    printf("\"\n");
#endif
    SHOULD_BE(*(Dy + 2*BLOCK_SIZE-1) == 0x01);  /* last byte of Dy is \x01 */
    SHOULD_BE(xp_len == y_len-1); /* valid padding of \x01 gets stripped. */
    /* Last blocks should be equal, first block of Dy is garbage */
    SHOULD_BE(!memcmp(Dy + BLOCK_SIZE, x + BLOCK_SIZE, xp_len - BLOCK_SIZE));
    free(y);
    free(Dy);
    END_TEST_CASE;
}

/* Test last_byte algorithm */
int LASTBYTE1()
{
    START_TEST_CASE;
    BYTE x[] = "FIRETRUCK RACES!YELLOW SUBMARINE"; /* 2 blocks */
    size_t x_len = strlen((char *)x);
    BYTE *y = NULL;
    size_t y_len = 0;
    SHOULD_BE(aes_128_cbc_encrypt(&y, &y_len, x, x_len, global_key, global_iv) == 0);
    /* Encryption intercepted! Get last byte */
    BYTE *Dy = NULL;
    size_t xp_len = 0;
    /* Get last byte of 2nd block */
    SHOULD_BE(last_byte(&Dy, &xp_len, y+BLOCK_SIZE) == 0);
    SHOULD_BE(xp_len == 1);
    BYTE xg = Dy[0] ^ y[BLOCK_SIZE-1];
    SHOULD_BE(xg == 'E');
#ifdef LOGSTATUS
    printf("Dy = \"");
    printall(Dy, xp_len);
    printf("\" == \\x%.2X\n", *Dy);
#endif
    free(y);
    free(Dy);
    END_TEST_CASE;
}

/* Test last_byte algorithm */
int LASTBYTE2()
{
    START_TEST_CASE;
    /* Gives trouble when checking for valid padding that is NOT \x01 */
    char x_b64[] = "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="; 
    BYTE *x = NULL;
    size_t x_len = b642byte(&x, x_b64);
#ifdef LOGSTATUS
    printf("x = \"");
    print_blocks(x, x_len, BLOCK_SIZE, 1);
    printf("\"\n");
#endif
    BYTE *y = NULL;
    size_t y_len = 0;
    SHOULD_BE(aes_128_cbc_encrypt(&y, &y_len, x, x_len, global_key, global_iv) == 0);
    /* Encryption intercepted! Get last byte */
    BYTE *Dy = NULL;
    size_t xp_len = 0;
    /* Want last byte of 2nd block */
    SHOULD_BE(last_byte(&Dy, &xp_len, y+BLOCK_SIZE) == 0);
    SHOULD_BE(xp_len == 1);
    BYTE xg = Dy[0] ^ y[BLOCK_SIZE-1];
    SHOULD_BE(xg == 't');
#ifdef LOGSTATUS
    printf("xg = \\x%.2X = '%c'\n", xg, xg);
#endif
    free(x);
    free(y);
    free(Dy);
    END_TEST_CASE;
}

/* Test block_decrypt algorithm */
int BLOCKDECR1()
{
    START_TEST_CASE;
    BYTE x[] = "FIRETRUCK RACES!YELLOW SUBMARINE"; /* 2 blocks */
    size_t x_len = strlen((char *)x);
    BYTE *y = NULL;
    size_t y_len = 0;
    SHOULD_BE(aes_128_cbc_encrypt(&y, &y_len, x, x_len, global_key, global_iv) == 0);
    BYTE *Dy = NULL;
    SHOULD_BE(block_decrypt(&Dy, y + BLOCK_SIZE) == 0);
    BYTE *xg = fixedXOR(Dy, y, BLOCK_SIZE);
    SHOULD_BE(!memcmp(xg, x + BLOCK_SIZE, BLOCK_SIZE));
#ifdef LOGSTATUS
    printf("xg = \"");
    print_blocks(xg, BLOCK_SIZE, BLOCK_SIZE, 1);
    printf("\"\n");
#endif
    free(xg);
    free(y);
    free(Dy);
    END_TEST_CASE;
}

/* Test last_byte algorithm */
int BLOCKDECR2()
{
    START_TEST_CASE;
    /* Gives trouble when checking for valid padding that is NOT \x01 */
    char x_b64[] = "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=";  /* 7 */
    BYTE *x = NULL;
    size_t x_len = b642byte(&x, x_b64);
#ifdef LOGSTATUS
    printf("x = \"");
    print_blocks(x, x_len, BLOCK_SIZE, 1);
    printf("\"\n");
#endif
    BYTE *y = NULL;
    size_t y_len = 0;
    SHOULD_BE(aes_128_cbc_encrypt(&y, &y_len, x, x_len, global_key, global_iv) == 0);
    /* Encryption intercepted! Get 2nd block */
    BYTE *Dy = NULL;
    int i = 1; /* decrypt ith block */
    SHOULD_BE(block_decrypt(&Dy, y + i*BLOCK_SIZE) == 0);
    BYTE *xg = fixedXOR(Dy, y + (i-1)*BLOCK_SIZE, BLOCK_SIZE); /* XOR with first block */
    SHOULD_BE(!memcmp(xg, "oll, it's time t", BLOCK_SIZE)); /* 7 */
#ifdef LOGSTATUS
    printf("xg = \"");
    print_blocks(xg, BLOCK_SIZE, BLOCK_SIZE, 1);
    printf("\"\n");
#endif
    free(x);
    free(y);
    free(Dy);
    free(xg);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    /* Initialize PRNG for last_byte and block_decrypt random bytes */
    srand(SRAND_INIT);

    /* Run OpenSSL lines here for speed */
    RUN_TEST(PORACLE1,   "padding_oracle()  ");
    RUN_TEST(LASTBYTE1,  "last_byte() 1     ");
    RUN_TEST(LASTBYTE2,  "last_byte() 2     ");
    RUN_TEST(BLOCKDECR1, "block_decrypt() 1 ");
    RUN_TEST(BLOCKDECR2, "block_decrypt() 2 ");

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
