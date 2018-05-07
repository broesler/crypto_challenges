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
/* Test fmemopen stream function */
int FMEM1()
{
    START_TEST_CASE;
    char *x = (char *)"Hello, friends!";
    size_t x_len = strlen(x);
    FILE *xs = fmemopen(x, x_len, "r");  /* create stream from byte array */
    FILE *ys = tmpfile();
    int c;
    while ((c = fgetc(xs)) != EOF) {
        fputc(c, ys);
    }
    /* Rewind output stream */
    REWIND_CHECK(ys);
    BYTE *yb = init_byte(x_len);
    if (fread(yb, 1, x_len, ys)) {
#ifdef LOGSTATUS
        printf("ys = \"%s\"\n", yb);
#endif
    }
    SHOULD_BE(!memcmp(yb, x, x_len));
    free(yb);
    fclose(xs);
    fclose(ys);
    END_TEST_CASE;
}

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
    SHOULD_BE(aes_128_ctr(xs, ys, key, nonce) == 0);
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
    SHOULD_BE(aes_128_ctr(ys, xs, key, nonce) == 0);
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

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    /* Run OpenSSL lines here for speed */
    RUN_TEST(FMEM1,   "fmemopen()      ");
    RUN_TEST(INCLE1,  "inc64le() 1       ");
    RUN_TEST(INCLE2,  "inc64le() 2       ");
    RUN_TEST(CTRDEC1, "aes_128_ctr() 1 ");
    RUN_TEST(CTRENC1, "aes_128_ctr() 2 ");

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
