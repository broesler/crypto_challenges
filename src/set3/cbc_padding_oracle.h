//==============================================================================
//     File: cbc_padding_oracle.c
//  Created: 08/01/2017, 22:51
//   Author: Bernie Roesler
//
//  Description: Challenge 17: CBC decryption with padding oracle
//
//============================================================================
#ifndef _CBC_PADDING_ORACLE_H_
#define _CBC_PADDING_ORACLE_H_

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "header.h"
#include "crypto_util.h"
#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"

// Global key, iv used in tests
extern BYTE *global_key;
extern BYTE *global_iv;

//------------------------------------------------------------------------------ 
//       Macros and Constnats
//------------------------------------------------------------------------------
// Define PRNG seed for consistency
#define SRAND_INIT 56

// String to be encrypted 
static const char * const POSSIBLE_X[10] = 
{ 
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", 
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", 
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", 
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", 
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", 
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", 
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", 
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", 
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", 
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" 
};

//------------------------------------------------------------------------------ 
//       Function Definitions
//------------------------------------------------------------------------------
// Encrypt randomly one of the above strings, return ciphertext and set IV 
int encryption_oracle(BYTE **y, size_t *y_len);

// Decrypt ciphertext and return 0 for valid padding or -1 for invalid 
int padding_oracle(BYTE *y, size_t y_len);

// Decrypt last word of single block 
int last_byte(BYTE **xb, size_t *xb_len, BYTE *y);

// Decrypt entire block 
int block_decrypt(BYTE **x, BYTE *y);

#endif
//==============================================================================
//==============================================================================
