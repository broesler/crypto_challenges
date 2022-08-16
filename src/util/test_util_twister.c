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
    RNG_MT *rng = init_rng_mt();
    srand_mt(rng, 0);
    free(rng);
    END_TEST_CASE;
}


int SeedMT2()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long seed = 0;
    unsigned long *state;
    state = srand_mt_(rng, seed);
    SHOULD_BE(state[0] == seed); /* convert in-place */
#ifdef LOGSTATUS
    printf("Got:    %ld\nExpect: %ld\n", state[0], seed);
#endif
    seed = 56;
    state = srand_mt_(rng, seed);
    SHOULD_BE(state[0] == seed); /* convert in-place */
#ifdef LOGSTATUS
    printf("Got:    %ld\nExpect: %ld\n", state[0], seed);
#endif
    /* Print entire state (N = 624 as implemented) */
    /* printf("\n"); */
    /* for (size_t i = 0; i < 624; i++) { */
    /*     printf("state[%3ld] = %10ld\n", i, state[i]); */
    /* } */
    free(rng);
    END_TEST_CASE;
}


/* Test against itself */
int GenRand1()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long seed = 56;
    unsigned long x[2][10];
    /* Populate each array, with reseeding */
    for (int i = 0; i < 2; i++) {
        srand_mt(rng, seed);
        for (int j = 0; j < 10; j++) {
            x[i][j] = rand_int32(rng);
        }
    }
    /* Check that arrays are the same */
    for (int i = 0; i < 10; i++) {
        SHOULD_BE(x[0][i] == x[1][i]);
#ifdef LOGSTATUS
        printf("%2d: %10ld  %10ld\n", i, x[0][i], x[1][i]);
#endif
    }
    free(rng);
    END_TEST_CASE;
}


/* Test against built-in `rand()` */
int GenRand2()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    /* unsigned long seed = 56; */
    /* srand_mt(rng, seed); */
    for (int i = 0; i < 10; i++) {
#ifdef LOGSTATUS
        double r = rand_real(rng);
        printf("%2d: %10f\n", i, r);
#else
        rand_real(rng);
#endif
    }
    free(rng);
    END_TEST_CASE;
}


int GenRand3()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    srand_mt(rng, (unsigned)time(NULL));
    for (int i = 0; i < 10; i++) {
#ifdef LOGSTATUS
        double r = rand_real(rng);
        printf("%2d: %10f\n", i, r);
#else
        rand_real(rng);
#endif
    }
    free(rng);
    END_TEST_CASE;
}


int GenRange1()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long r;
    srand_mt(rng, 56);
    for (int i = 0; i < 10; i++) {
        r = rand_rangec_int32(rng, 1, 10);
        SHOULD_BE((r >= 1) && (r <= 10));
#ifdef LOGSTATUS
        printf("%2d: %3ld\n", i, r);
#endif
    }
    free(rng);
    END_TEST_CASE;
}


int GenRange2()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    double r;
    srand_mt(rng, 56);
    for (int i = 0; i < 10; i++) {
        r = rand_rangec_real(rng, 1.0, 10.0);
        SHOULD_BE((r >= 1.0) && (r <= 10.0));
#ifdef LOGSTATUS
        printf("%2d: %10f\n", i, r);
#endif
    }
    free(rng);
    END_TEST_CASE;
}


/* x always 0 */
int UndoRshift0()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long x = 0,
                  mask = 0xFFFFFFFF;  /* mask of all 1's is no mask at all */
    for (int shift = 0; shift < UINT_SIZE; shift++) {
        SHOULD_BE(undo_Rshift_xor(x ^ (x >> shift), shift, mask) == x);
    }
    free(rng);
    END_TEST_CASE;
}


/* x all 1's */
int UndoRshift1()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long x = 0xFFFFFFFF,
                  mask = 0xFFFFFFFF;
    for (int shift = 1; shift < UINT_SIZE; shift++) {
        SHOULD_BE(undo_Rshift_xor(x ^ (x >> shift), shift, mask) == x);
    }
    free(rng);
    END_TEST_CASE;
}


/* Test arbitrary x, no mask */
int UndoRshift2()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long x = 0xB75E7E72,
                  mask = 0xFFFFFFFF;
    for (int shift = 1; shift < UINT_SIZE; shift += 1) {
        unsigned long res = undo_Rshift_xor(x ^ (x >> shift), shift, mask);
        SHOULD_BE(res == x);
    }
    free(rng);
    END_TEST_CASE;
}


/* Test arbitrary x, arbitrary mask */
int UndoRshift3()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long x = 0xB75E7E72,
                  mask = 0x9D2C5680;
    for (int shift = 1; shift < UINT_SIZE; shift += 1) {
        unsigned long y = x ^ ((x >> shift) & mask);
        unsigned long res = undo_Rshift_xor(y, shift, mask);
        SHOULD_BE(res == x);
    }
    free(rng);
    END_TEST_CASE;
}


/* x always 0 */
int UndoLshift0()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long x = 0,
                  mask = 0xFFFFFFFF;  /* mask of all 1's is no mask at all */
    for (int shift = 0; shift < UINT_SIZE; shift++) {
        SHOULD_BE(undo_Lshift_xor(x ^ (x << shift), shift, mask) == x);
    }
    free(rng);
    END_TEST_CASE;
}


/* x all 1's */
int UndoLshift1()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long x = 0xFFFFFFFF,
                  mask = 0xFFFFFFFF;
    for (int shift = 1; shift < UINT_SIZE; shift++) {
        SHOULD_BE(undo_Lshift_xor(x ^ (x << shift), shift, mask) == x);
    }
    free(rng);
    END_TEST_CASE;
}


/* Test arbitrary x, no mask */
int UndoLshift2()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long x = 0xB75E7E72,
                  mask = 0xFFFFFFFF;
    for (int shift = 1; shift < UINT_SIZE; shift += 1) {
        unsigned long res = undo_Lshift_xor(x ^ (x << shift), shift, mask);
        SHOULD_BE(res == x);
#ifdef LOGSTATUS
        printf("shift = %d ", shift);
        if (res == x) {
            printf("passed!\n");
        } else {
            printf("got:      %08lX\n", res);
            printf("expected: %08lX\n", x);
        }
#endif
    }
    free(rng);
    END_TEST_CASE;
}


/* Test arbitrary x, arbitrary mask */
int UndoLshift3()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long x = 0xB75E7E72,
                  mask = 0x9D2C5680;
    for (int shift = 1; shift < UINT_SIZE; shift += 1) {
        unsigned long y = x ^ ((x << shift) & mask);
        unsigned long res = undo_Lshift_xor(y, shift, mask);
        SHOULD_BE(res == x);
    }
    free(rng);
    END_TEST_CASE;
}


/* Test arbitrary input */
int Untemper0()
{
    START_TEST_CASE;
    RNG_MT *rng = init_rng_mt();
    unsigned long y = 0xB75E7E72;
    SHOULD_BE(untemper(temper(y)) == y);
    SHOULD_BE(temper(untemper(y)) == y);
    free(rng);
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
    RUN_TEST(UndoRshift0, "undo_Rshift_xor() 0   ");
    RUN_TEST(UndoRshift1, "undo_Rshift_xor() 1   ");
    RUN_TEST(UndoRshift2, "undo_Rshift_xor() 2   ");
    RUN_TEST(UndoRshift3, "undo_Rshift_xor() 3   ");
    RUN_TEST(UndoLshift0, "undo_Lshift_xor() 0   ");
    RUN_TEST(UndoLshift1, "undo_Lshift_xor() 1   ");
    RUN_TEST(UndoLshift2, "undo_Lshift_xor() 2   ");
    RUN_TEST(UndoLshift3, "undo_Lshift_xor() 3   ");
    RUN_TEST(Untemper0,   "untemper() 0          ");

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
