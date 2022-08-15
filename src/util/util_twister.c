/*==============================================================================
 *     File: util_twister.c
 *  Created: 2018-11-15 23:05
 *   Author: Bernie Roesler
 *
 *  Description: Implement the Mersenne Twister PRNG algorithm
 *============================================================================*/

#include <limits.h>

#include "util_twister.h"


/* TODO for Challenge 23, figure out how to create multiple instances */
/* Create a length N array to store the state of the generator */
/* static unsigned long mt[N]; */
/* static int idx = N + 1;  /1* global state index *1/ */


/*------------------------------------------------------------------------------
 *          Private API
 *----------------------------------------------------------------------------*/
unsigned long *srand_mt_(RNG_MT *rng, unsigned long seed) {
    rng->idx = N;  /* set idx to flag that generator is initialized */
    rng->state[0] = seed & MASK32;
    for (size_t i = 1; i < N; i++) {
        rng->state[i] = F * (rng->state[i-1] ^ (rng->state[i-1] >> (W-2))) + i;
        rng->state[i] &= MASK32;  /* get lower 32 bits */
    }
    return rng->state;  /* return state for testing */
}


/* Update the state */
void twist(RNG_MT *rng) {
    unsigned long x, xA;

    /* Generate the next N values from the series x_i  */
    for (size_t i = 0; i < N; i++) {
        x =  (rng->state[i]         & UPPER_MASK) 
           + (rng->state[(i+1) % N] & LOWER_MASK);
        xA = x >> 1;
        if (x % 2) {  /* lowest bit of x is 1 */
            xA ^= 0x9908B0DFUL;
        }
        rng->state[i] = rng->state[(i + M) % N] ^ xA;
    }
    rng->idx = 0;  /* reset the index */
}


/* Temper the value for output */
unsigned long temper(unsigned long y) {
    /* MT19937 values */
    y ^= (y >> 11) & MASK32;
    y ^= (y <<  7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= y >> 18;
    return y;
}


/* Reverse the temper operation */
unsigned long untemper(unsigned long y) {
    /* MT19937 values */
    y = undo_Rshift_xor(y, 18, MASK32);
    y = undo_Lshift_xor(y, 15, 0xEFC60000UL);
    y = undo_Lshift_xor(y,  7, 0x9D2C5680UL);
    y = undo_Rshift_xor(y, 11, MASK32);
    return y;
}


/* Recover y from the operation x = y ^ ((y >> s) & mask) 
 * See also:
 * <https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html>
 * NOTE that the `partMask` used therein DOES NOT work in C, since 
 *  a) a negative uint is machine-dependent to be two's complement
 *  b) left-shifting outside of `sizeof(unsigned long)` is undefined behavior,
 *     so the right-shift back may still have the data that was shifted "off" to
 *     the left.
 *  Instead, need an additional max of UINT_MAX to ensure we only use 32 bits.
 */
/* TODO
 *   - deal with `shift < 0`.
 *   - pass flag to determine left or right shift?
 */
unsigned long undo_Rshift_xor(unsigned long x, const int shift, 
                              const unsigned long mask)
{
    if (shift == 0) return 0;
    unsigned long y = 0;
    for (int i = 0; i < UINT_SIZE; i += shift) {
        /* Shift mask from left to right as we go */
        unsigned long part_mask = ((UINT_MAX << (UINT_SIZE - shift)) & UINT_MAX) >> i;
        unsigned long part = x & part_mask;
        x ^= (part >> shift) & mask;  /* reverse XOR and mask for next pass */
        y |= part;                    /* add part to the result */
    }
    return y;
}


unsigned long undo_Lshift_xor(unsigned long x, const int shift, 
                              const unsigned long mask)
{
    if (shift == 0) return 0;
    unsigned long y = 0;
    for (int i = 0; i < UINT_SIZE; i += shift) {
        /* Shift block from right to left as we go */
        unsigned long part_mask = (((1 << shift) - 1) << i) & UINT_MAX;
        unsigned long part = x & part_mask;
        x ^= (part << shift) & mask;  /* reverse XOR and mask for next pass */
        y |= part;                    /* add part to the result */
    }
    return y;
}


/*------------------------------------------------------------------------------
 *         Public API 
 *----------------------------------------------------------------------------*/
/* Initialize an RNG instance */
RNG_MT *init_rng_mt(void) {
    RNG_MT *rng = NULL;
    rng = NEW(RNG_MT);
    MALLOC_CHECK(rng);
    BZERO(rng, sizeof(RNG_MT));
    BZERO(rng->state, sizeof(rng->state));
    rng->idx = N + 1;
    return rng;
}


/* Seed the RNG. Does not return state. */
void srand_mt(RNG_MT *rng, unsigned long seed) {
    (void)srand_mt_(rng, seed);
}


/* Generate random number in the interval [0, 0xFFFFFFFF] */
unsigned long rand_int32(RNG_MT *rng) {
    if (rng->idx == N+1) {
        /* Seed with constant value; 5489 is used in reference C code */
        srand_mt(rng, 5489UL);
    }

    /* Update the state once N numbers have been generated */
    if (rng->idx >= N) {
        twist(rng);
    }

    return temper(rng->state[rng->idx++]);
}


/* Generate random number in the semi-open interval [0, 1) */
double rand_real(RNG_MT *rng) {
    return rand_int32(rng) * (1.0 / 0x80000000p1);  /* div by 2^32 */
}


/* Generate random number in the closed interval [0, 1] */
double rand_realc(RNG_MT *rng) {
    return rand_int32(rng) * (1.0 / 0x7FFFFFFFp1);  /* div by 2^32 - 1 */
}


/* Generate random integer in the closed interval [a, b] */
unsigned long rand_rangec_int32(RNG_MT *rng, unsigned long a, unsigned long b) {
    return (rand_int32(rng) % (b - a + 1)) + a;
}

/* Generate random float in the closed interval [a, b] */
double rand_rangec_real(RNG_MT *rng, double a, double b) {
    /* Convert range [0, 1] to [a, b] */
    return (rand_realc(rng) * (b - a)) + a;
}

/*==============================================================================
*============================================================================*/
