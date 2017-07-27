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
//      Macros
//------------------------------------------------------------------------------
// maximum bytes to feed into getBlockSize
#define IMAX 32

// Random number in range (inclusive)
// Good enough for government work... or is it? not truly "uniform"
#define RAND_RANGE(A,B) ((rand() % ((B) - (A) + 1)) + (A))

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
size_t encryption_oracle11(BYTE **y, BYTE *x, size_t x_len);

// Encryption with random appended string 
size_t encryption_oracle12(BYTE **y, BYTE *x, size_t x_len);

// Get block size given function pointer
size_t getBlockSize(size_t (*encrypt)(BYTE**, BYTE*, size_t));

// Test if oracle is ECB
size_t isECB(size_t (*encrypt)(BYTE**, BYTE*, size_t), size_t block_size);

// Detect if oracle is in ECB mode or not (depends on strategic input)
int is_oracle_ecb11(BYTE *x, size_t x_len);

// Decrypt unknown string one byte at a time
// size_t simple_ECB_decrypt(BYTE **y);
size_t simple_ECB_decrypt(BYTE y[]);

// Get next byte from one-byte-at-a-time ECB decryption
BYTE decodeNextByte(size_t (*encrypt)(BYTE**, BYTE*, size_t), const BYTE *y, 
        size_t y_len, size_t block_size);

// Parse key=value pairs (reverse of encode)
char *kv_parse(const char *str);

// Encode key=value object as '&'-delimited string (reverse of parse)
char *kv_encode(const char *str);

#endif
//==============================================================================
//==============================================================================
