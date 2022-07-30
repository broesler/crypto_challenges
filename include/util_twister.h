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

// Initialize the generator from a seed
unsigned long *srand_mt_(unsigned long);

// Initialize the generator from a seed, no return value
void srand_mt(unsigned long);

// Generate random number in the interval [0, 0xFFFFFFFF]
unsigned long rand_int32();

// Generate random number in the semi-open interval [0, 1)
double rand_real();

// Generate random number in the closed interval [0, 1]
double rand_realc();

// Generate random integer in the closed interval [a, b]
unsigned long rand_rangec_int32(unsigned long, unsigned long);

// Generate random double in the closed interval [a, b]
double rand_rangec_real(double a, double b);

#endif
//==============================================================================
//==============================================================================
