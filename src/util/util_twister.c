/*==============================================================================
 *     File: util_twister.c
 *  Created: 2018-11-15 23:05
 *   Author: Bernie Roesler
 *
 *  Description: Implement the Mersenne Twister PRNG algorithm
 *============================================================================*/

#include "util_twister.h"

/* Declare constants */
#define W  32   /* [bits] word size */
#define N  624  /* degree of recurrence */
#define M  397  /* middle word (offset in recurrence relation) */

#define UPPER_MASK  0x80000000UL  /* most significant W-R bits == 2^31 */
#define LOWER_MASK  0x7FFFFFFFUL  /* least significant    bits == 2^31 - 1 */

#define MASK32  0xFFFFFFFFUL  /* for > 32-bit machines */
#define F  1812433253UL  /* parameter for initialization */

/* Create a length N array to store the state of the generator */
static unsigned long mt[N];
static int idx = N + 1;  /* global state index */

/*------------------------------------------------------------------------------
 *          Private API
 *----------------------------------------------------------------------------*/
unsigned long *srand_mt_(unsigned long seed) {
    idx = N;  /* set idx to flag that generator is initialized */
    mt[0] = seed & MASK32;
    for (size_t i = 1; i < N; i++) {
        mt[i] = F * (mt[i-1] ^ (mt[i-1] >> (W-2))) + i;
        mt[i] &= MASK32;  /* get lower 32 bits */
    }
    return mt;  /* return state for testing */
}

/* Update the state */
void twist() {
    unsigned long x, xA;

    /* Generate the next N values from the series x_i  */
    for (size_t i = 0; i < N; i++) {
        x =  (mt[i]         & UPPER_MASK) 
           + (mt[(i+1) % N] & LOWER_MASK);
        xA = x >> 1;
        if (x % 2) {  /* lowest bit of x is 1 */
            xA ^= 0x9908B0DFUL;
        }
        mt[i] = mt[(i + M) % N] ^ xA;
    }
    idx = 0;  /* reset the index */
}

/* Temper the value for output */
unsigned long temper(unsigned long y) {
    /* MT19937 values */
    y ^= (y >> 11) & 0xFFFFFFFFUL;
    y ^= (y <<  7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= y >> 18;
    return y;
}

/*------------------------------------------------------------------------------
 *         Public API 
 *----------------------------------------------------------------------------*/
/* does not return state */
void srand_mt(unsigned long seed) {
    (void)srand_mt_(seed);
}

/* Generate random number in the interval [0, 0xFFFFFFFF] */
unsigned long rand_int32() {
    if (idx == N+1) {
        /* Seed with constant value; 5489 is used in reference C code */
        srand_mt(5489UL);
    }

    /* Update the state once N numbers have been generated */
    if (idx >= N) {
        twist();
    }

    return temper(mt[idx++]);
}

/* Generate random number in the semi-open interval [0, 1) */
double rand_real() {
    return rand_int32() * (1.0 / 0x80000000p1);  /* div by 2^32 */
}

/* Generate random number in the closed interval [0, 1] */
double rand_realc() {
    return rand_int32() * (1.0 / 0x7FFFFFFFp1);  /* div by 2^32 - 1 */
}

/* Generate random integer in the closed interval [a, b] */
unsigned long rand_rangec_int32(unsigned long a, unsigned long b) {
    return (rand_int32() % (b - a + 1)) + a;
}

/* Generate random float in the closed interval [a, b] */
double rand_rangec_real(double a, double b) {
    /* Convert range [0, 1] to [a, b] */
    return (rand_realc() * (b - a)) + a;
}

/*==============================================================================
*============================================================================*/
