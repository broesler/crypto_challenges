/*==============================================================================
 *     File: test_util_twister.c
 *  Created: 2018-11-18 13:24
 *   Author: Bernie Roesler
 *
 *  Description: Test PRNG utilities
 *
 *============================================================================*/

#include <time.h>

#include "header.h"
#include "crypto_util.h"
#include "unit_test.h"

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
int SeedMT1()
{
    START_TEST_CASE;
    unsigned long seed = 0;
    srand_mt(seed);
    END_TEST_CASE;
}


int SeedMT2()
{
    START_TEST_CASE;
    unsigned long seed = 0;
    unsigned long *state;
    state = srand_mt_(seed);
    SHOULD_BE(state[0] == seed); /* convert in-place */
#ifdef LOGSTATUS
    printf("Got:    %ld\nExpect: %ld\n", state[0], seed);
#endif
    seed = 56;
    state = srand_mt_(seed);
    SHOULD_BE(state[0] == seed); /* convert in-place */
#ifdef LOGSTATUS
    printf("Got:    %ld\nExpect: %ld\n", state[0], seed);
#endif
    /* Print entire state (N = 624 as implemented) */
    /* printf("\n"); */
    /* for (size_t i = 0; i < 624; i++) { */
    /*     printf("state[%3ld] = %10ld\n", i, state[i]); */
    /* } */
    END_TEST_CASE;
}


/* Test against itself */
int GenRand1()
{
    START_TEST_CASE;
    unsigned long seed = 56;
    unsigned long x[2][10];
    /* Populate each array, with reseeding */
    for (int i = 0; i < 2; i++) {
        srand_mt(seed);
        for (int j = 0; j < 10; j++) {
            x[i][j] = rand_int32();
        }
    }
    /* Check that arrays are the same */
    for (int i = 0; i < 10; i++) {
        SHOULD_BE(x[0][i] == x[1][i]);
#ifdef LOGSTATUS
        printf("%2d: %10ld  %10ld\n", i, x[0][i], x[1][i]);
#endif
    }
    END_TEST_CASE;
}


/* Test against built-in `rand()` */
int GenRand2()
{
    START_TEST_CASE;
    /* unsigned long seed = 56; */
    /* srand_mt(seed); */
    for (int i = 0; i < 10; i++) {
#ifdef LOGSTATUS
        double r = rand_real();
        printf("%2d: %10f\n", i, r);
#else
        rand_real();
#endif
    }
    END_TEST_CASE;
}


int GenRand3()
{
    START_TEST_CASE;
    srand_mt((unsigned)time(NULL));
    for (int i = 0; i < 10; i++) {
#ifdef LOGSTATUS
        double r = rand_real();
        printf("%2d: %10f\n", i, r);
#else
        rand_real();
#endif
    }
    END_TEST_CASE;
}


int GenRange1()
{
    START_TEST_CASE;
    unsigned long r;
    srand_mt(56);
    for (int i = 0; i < 10; i++) {
        r = rand_rangec_int32(1, 10);
        SHOULD_BE((r >= 1) && (r <= 10));
#ifdef LOGSTATUS
        printf("%2d: %3ld\n", i, r);
#endif
    }
    END_TEST_CASE;
}


int GenRange2()
{
    START_TEST_CASE;
    double r;
    srand_mt(56);
    for (int i = 0; i < 10; i++) {
        r = rand_rangec_real(1.0, 10.0);
        SHOULD_BE((r >= 1.0) && (r <= 10.0));
#ifdef LOGSTATUS
        printf("%2d: %10f\n", i, r);
#endif
    }
    END_TEST_CASE;
}


int UndoRshift1()
{
    START_TEST_CASE;
    unsigned long x = 0,
                  mask = 0xFFFFFFFF;  /* mask of all 1's is no mask at all */
    for (int shift = 0; shift < UINT_SIZE; shift++) {
        SHOULD_BE(undo_Rshift_xor(x ^ (x >> shift), shift, mask) == x);
    }
    END_TEST_CASE;
}


int UndoRshift2()
{
    START_TEST_CASE;
    unsigned long x = 0xFFFFFFFF,
                  mask = 0xFFFFFFFF;
    for (int shift = 1; shift < UINT_SIZE; shift++) {
        SHOULD_BE(undo_Rshift_xor(x ^ (x >> shift), shift, mask) == x);
    }
    END_TEST_CASE;
}


/* Test arbitrary x, no mask */
int UndoRshift3()
{
    START_TEST_CASE;
    unsigned long x = 0xB75E7E72,
                  mask = 0xFFFFFFFF;
    for (int shift = 1; shift < UINT_SIZE; shift += 1) {
        unsigned long res = undo_Rshift_xor(x ^ (x >> shift), shift, mask);
        SHOULD_BE(res == x);
#ifdef LOGSTATUS
        printf("shift = %d\n", shift);
        if (res == x) {
            printf("passed!\n");
        } else {
            printf("got:      %08lX\n", res);
            printf("expected: %08lX\n", x);
        }
#endif
    }
    END_TEST_CASE;
}


/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(SeedMT1,     "srand_mt()            ");
    RUN_TEST(SeedMT2,     "srand_mt_()           ");
    RUN_TEST(GenRand1,    "rand_int32()          ");
    RUN_TEST(GenRand2,    "rand_real()           ");
    RUN_TEST(GenRand3,    "rand_real()           ");
    RUN_TEST(GenRange1,   "rand_rangec_int32()   ");
    RUN_TEST(GenRange2,   "rand_rangec_real()    ");
    RUN_TEST(UndoRshift1, "undo_Rshift_xor()     ");
    /* RUN_TEST(UndoRshift2, "undo_Rshift_xor()     "); */
    RUN_TEST(UndoRshift3, "undo_Rshift_xor()     ");

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
