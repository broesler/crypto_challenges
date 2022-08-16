//==============================================================================
//     File: crypto3.h
//  Created: 05/02/2018, 10:42
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//==============================================================================
#ifndef _CRYPTO3_H_
#define _CRYPTO3_H_

#include "header.h"
#include "crypto_util.h"

//-------------------------------------------------------------------------------
//      Function Prototypes
//-------------------------------------------------------------------------------
// AES 128-bit CTR mode streamcipher (encrypt or decrypt)
int aes_128_ctr(FILE *y, FILE *x, BYTE *key, BYTE *nonce);

// Encrypt (nonce||counter) using key in AES 128-bit ECB block
BYTE *get_keystream_block(BYTE *key, BYTE *nonce, BYTE *counter);

// Increment little endian counter
int inc64le(BYTE *counter);

// Use a Mersenne Twister MT19937 PRNG as a keystream
int mersenne_ctr(FILE *y, FILE *x, short seed);

#endif
//==============================================================================
//==============================================================================
