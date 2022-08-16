/*==============================================================================
 *     File: test_crypto3.c
 *  Created: 05/02/2018, 10:31
 *   Author: Bernie Roesler
 *
 *  Description: Unit tests for Set 3 crypto challenges
 *
 *============================================================================*/

/* User-defined headers */
#include "header.h"
#include "fmemopen.h" /* allow string as file stream */
#include "unit_test.h"
#include "crypto_util.h"
#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"
#include "crypto3.h"

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* Test inc64le() little endian incrementer */
int INCLE1()
{
    START_TEST_CASE;
    BYTE *counter = init_byte(BLOCK_SIZE/2);
    inc64le(counter);
    SHOULD_BE(counter[0] == 0x01);
#ifdef LOGSTATUS
    printf("counter = ");
    print_blocks(counter, BLOCK_SIZE/2, BLOCK_SIZE, 0);
    printf("\n");
#endif
    free(counter);
    END_TEST_CASE;
}


/* Test inc64le() little endian incrementer for overflow error */
int INCLE2()
{
    START_TEST_CASE;
    BYTE *counter = bytenrepeat((BYTE *)"\xFF", 1, BLOCK_SIZE/2);
    counter[0] = '\xFE';
    SHOULD_BE(counter[0] == 0xFE);
    SHOULD_BE(counter[BLOCK_SIZE/2 - 1] == 0xFF);
    for (size_t i = 0; i < 3; i++) {
#ifdef LOGSTATUS
        printf("counter = ");
        print_blocks(counter, BLOCK_SIZE/2, BLOCK_SIZE, 0);
        printf("\n");
#endif
        inc64le(counter); /* should wrap to 0, then to 1 (little endian) */
    }
#ifdef LOGSTATUS
        printf("counter = ");
        print_blocks(counter, BLOCK_SIZE/2, BLOCK_SIZE, 0);
        printf("\n");
#endif
    SHOULD_BE(counter[0] == 0x01);
    SHOULD_BE(counter[BLOCK_SIZE/2-1] == 0x00);
    free(counter);
    END_TEST_CASE;
}


/* Test Challenge 18 */
int CTRDEC1()
{
    START_TEST_CASE;
    /* NOTE the function aes_128_ctr() is designed to handle file streams,
     * regardless of their origins. We use fmemopen() to create I/O 'streams' in
     * memory for the purposes of this test. */
    char y_b64[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/" \
                   "2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    BYTE *y = NULL;
    size_t y_len = b642byte(&y, y_b64);
    FILE *ys = fmemopen(y, y_len, "r");
    FILE *xs = tmpfile();
    BYTE *key = (BYTE *)"YELLOW SUBMARINE";
    BYTE *nonce = init_byte(BLOCK_SIZE/2); /* leave at 0's */
    SHOULD_BE(aes_128_ctr(xs, ys, key, nonce) == EXIT_SUCCESS);
    BYTE *xb = init_byte(y_len);
    SHOULD_BE(fread(xb, 1, y_len, xs) > 0);
    SHOULD_BE(!memcmp(xb, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", y_len));
#ifdef LOGSTATUS
    printf("xb = ");
    printall(xb, y_len);
    printf("\n");
#endif
    free(y);
    free(nonce);
    free(xb);
    fclose(ys);
    fclose(xs);
    END_TEST_CASE;
}


/* Encryption identical to decryption */
int CTRENC1()
{
    START_TEST_CASE;
    BYTE *x = (BYTE *)"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";
    size_t x_len = strlen((char *)x);
    FILE *xs = fmemopen(x, x_len, "r");
    FILE *ys = tmpfile();
    BYTE *key = (BYTE *)"YELLOW SUBMARINE";
    BYTE *nonce = init_byte(BLOCK_SIZE/2); /* leave at 0's */
    SHOULD_BE(aes_128_ctr(ys, xs, key, nonce) == EXIT_SUCCESS);
    BYTE *yb = init_byte(x_len);
    SHOULD_BE(fread(yb, 1, x_len, ys) > 0);
    char y_b64[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/" \
                   "2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    BYTE *y = NULL;
    size_t y_len = b642byte(&y, y_b64);
    SHOULD_BE(!memcmp(yb, y, y_len));
    free(y);
    free(yb);
    free(nonce);
    fclose(xs);
    fclose(ys);
    END_TEST_CASE;
}


/* Test Challenge 24 Mersenne CTR */
int MT_CTR1()
{
    START_TEST_CASE;
    srand(565656);
    short seed = (short)565656;
    char *known = "AAAAAAAAAAAAAA";  /* 14 A's */
    size_t k_len = strlen(known);
    /* Add a random number of random padding characters */
    int n_pad = RAND_RANGE(1, 16);
    int x_len = n_pad + k_len;
    BYTE *x = rand_byte(x_len);
    strlcpy((char *)x + n_pad, known, k_len); 
    /* Create filestreams for encryption */
    FILE *xs = fmemopen(x, x_len, "r");
    FILE *ys = tmpfile();
    /* Encrypt xs -> ys */
    SHOULD_BE(mersenne_ctr(ys, xs, seed) == EXIT_SUCCESS);
    BYTE *yb = init_byte(x_len);
    SHOULD_BE(fread(yb, 1, x_len, ys) > 0);
    /* Decrypt ys -> xs */
    SHOULD_BE(mersenne_ctr(xs, ys, seed) == EXIT_SUCCESS);
    BYTE *xb = init_byte(x_len);
    SHOULD_BE(fread(xb, 1, x_len, xs) > 0);
    SHOULD_BE(!memcmp(xb, x, x_len));
#ifdef LOGSTATUS
    printf("x_len = %d, n_pad = %d\n", x_len, n_pad);
    printf("xb = ");
    printall(xb, x_len);
    printf("\n");
    printf("x  = ");
    printall(x, x_len);
    printf("\n");
#endif
    free(x);
    free(xb);
    free(yb);
    fclose(xs);
    fclose(ys);
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
    RUN_TEST(INCLE1,  "inc64le() 1     ");
    RUN_TEST(INCLE2,  "inc64le() 2     ");
    RUN_TEST(CTRDEC1, "aes_128_ctr() 1 ");
    RUN_TEST(CTRENC1, "aes_128_ctr() 2 ");
    RUN_TEST(MT_CTR1, "mersenne_ctr()  ");

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
