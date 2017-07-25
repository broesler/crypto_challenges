//==============================================================================
//     File: crypto2.h
//  Created: 07/22/2017, 01:00
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//==============================================================================
#ifndef _CRYPTO2_H_
#define _CRYPTO2_H_

#include <ctype.h>

#include "header.h"
#include "crypto_util.h"

//------------------------------------------------------------------------------
//      Function Definitions
//------------------------------------------------------------------------------
// PKCS#7 padding to block size 
BYTE *pkcs7_pad(const BYTE *byte, size_t nbyte, size_t block_size);

// Remove PKCS#7 padding
int pkcs7_rmpad(BYTE *byte, size_t nbyte, size_t block_size);

// Encrypt using AES 128-bit CBC mode
size_t aes_128_cbc_encrypt(BYTE **y, BYTE *x, size_t x_len, BYTE *key, BYTE *iv);

// Decrypt using AES 128-bit CBC mode
size_t aes_128_cbc_decrypt(BYTE **x, BYTE *y, size_t y_len, BYTE *key, BYTE *iv);

// Generate random AES key 
BYTE *rand_byte(size_t len);

// Encryption oracle: randomly encrypt with ECB or CBC
size_t encryption_oracle(BYTE **y, BYTE *x, size_t x_len);

// Detect if oracle is in ECB mode or not (depends on strategic input)
int is_oracle_ecb(BYTE *x, size_t x_len);

#endif
//==============================================================================
//==============================================================================
