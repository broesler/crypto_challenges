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
    /* if (fseek(ys, 0L, SEEK_SET)) { ERROR("Rewind failed!"); } */
    REWIND_CHECK(ys);
    BYTE *yb = init_byte(x_len);
    if (fread(yb, 1, x_len, ys)) {
#ifdef LOGSTATUS
        printf("ys = \"%s\"\n", yb);
#endif
    }
    SHOULD_BE(!memcmp(yb, x, x_len));
    fclose(xs);
    fclose(ys);
    END_TEST_CASE;
}

int CTRENC1()
{
    START_TEST_CASE;
    /* NOTE the function aes_128_ctr() is designed to handle file streams,
     * regardless of their origins. We use fmemopen() to create I/O 'streams' in
     * memory for the purposes of this test. */
    char x_b64[] = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/" \
                   "2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    BYTE *x = NULL;
    size_t x_len = b642byte(&x, x_b64);
    FILE *xs = fmemopen(x, x_len, "r");
    FILE *ys = tmpfile();
    BYTE *key = (BYTE *)"YELLOW SUBMARINE";
    BYTE *nonce = bytenrepeat((BYTE *)"\x00", 1, BLOCK_SIZE/2);
    SHOULD_BE(aes_128_ctr(ys, xs, key, nonce) == 0);
    BYTE *yb = init_byte(x_len);
    if (fread(yb, 1, x_len, ys)) {
#ifdef LOGSTATUS
        printf("ys = \"%s\"\n", yb);
#endif
    }
    /* SHOULD_BE(!memcmp(yb, xs, x_len)); */
    free(x);
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
    RUN_TEST(CTRENC1, "aes_128_ctr() 1 ");

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
