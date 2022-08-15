//==============================================================================
//     File: include/util_twister.h
//  Created: 2018-11-15 23:17
//   Author: Bernie Roesler
//
//  Description: Utility functions for Mersenne Twister algorithm
//=============================================================================
#ifndef _UTIL_TWISTER_H_
#define _UTIL_TWISTER_H_

#include "header.h"
#include "crypto_util.h"

#define UINT_SIZE (8*sizeof(unsigned int))

/* Declare constants */
#define W  32   /* [bits] word size */
#define N  624  /* degree of recurrence */
#define M  397  /* middle word (offset in recurrence relation) */

#define UPPER_MASK  0x80000000UL  /* most significant W-R bits == 2^31 */
#define LOWER_MASK  0x7FFFFFFFUL  /* least significant    bits == 2^31 - 1 */

#define MASK32  0xFFFFFFFFUL  /* for > 32-bit machines */
#define F  1812433253UL  /* parameter for initialization */


// The random number generator object
typedef struct _RNG_MT {
    unsigned long state[N];  /* state vector */
    int idx;                 /* state index */
} __RNG_MT;

typedef struct _RNG_MT RNG_MT;

// Initialize a generator object
RNG_MT *init_rng_mt(void);

// Initialize the generator from a seed
unsigned long *srand_mt_(RNG_MT *rng, unsigned long seed);

// Initialize the generator from a seed, no return value
void srand_mt(RNG_MT *rng, unsigned long seed);

// Generate random number in the interval [0, 0xFFFFFFFF]
unsigned long rand_int32(RNG_MT *rng);

// Generate random number in the semi-open interval [0, 1)
double rand_real(RNG_MT *rng);

// Generate random number in the closed interval [0, 1]
double rand_realc(RNG_MT *rng);

// Generate random integer in the closed interval [a, b]
unsigned long rand_rangec_int32(RNG_MT *rng, unsigned long a, unsigned long b);

// Generate random double in the closed interval [a, b]
double rand_rangec_real(RNG_MT *rng, double a, double b);

// Reverse the tempering operation of the Mersenne Twister
unsigned long temper(unsigned long y);
unsigned long untemper(unsigned long y);

// Reverse a single right-shift operation
unsigned long undo_Rshift_xor(unsigned long x, const int shift, 
                              const unsigned long mask);

unsigned long undo_Lshift_xor(unsigned long x, const int shift,
                              const unsigned long mask);

#endif
//==============================================================================
//==============================================================================
