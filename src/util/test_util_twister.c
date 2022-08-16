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

int GenRand1()
{
    START_TEST_CASE;
    unsigned long seed = 56,
                  r;
    srand_mt(seed);
    for (int i = 0; i < 10; i++) {
        r = rand_int32();
        printf("%2d: %10ld\n", i, r);
    }
    END_TEST_CASE;
}

int GenRand2()
{
    START_TEST_CASE;
    double r;
    /* unsigned long seed = 56; */
    /* srand_mt(seed); */
    for (int i = 0; i < 10; i++) {
        r = rand_real();
        printf("%2d: %10f\n", i, r);
    }
    END_TEST_CASE;
}

int GenRand3()
{
    START_TEST_CASE;
    double r;
    srand_mt((unsigned)time(NULL));
    for (int i = 0; i < 10; i++) {
        r = rand_real();
        printf("%2d: %10f\n", i, r);
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

    RUN_TEST(SeedMT1,    "srand_mt()    ");
    RUN_TEST(SeedMT2,    "srand_mt_()   ");
    RUN_TEST(GenRand1,   "rand_int32() ");
    RUN_TEST(GenRand2,   "rand_real()  ");
    RUN_TEST(GenRand3,   "rand_real()  ");

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
