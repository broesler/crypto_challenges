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
size_t aes_128_cbc_encrypt(BYTE **y, BYTE *x, size_t nx, BYTE *key, BYTE *iv);

#endif
//==============================================================================
//==============================================================================
