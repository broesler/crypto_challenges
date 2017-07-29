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
#define IMAX 48

// Random number in range (inclusive)
// Good enough for government work... or is it? not truly "uniform"
#define RAND_RANGE(A,B) ((rand() % ((B) - (A) + 1)) + (A))

//------------------------------------------------------------------------------
//      Function Definitions
//------------------------------------------------------------------------------
// Challenge 10: Encrypt using AES 128-bit CBC mode
size_t aes_128_cbc_encrypt(BYTE **y, BYTE *x, size_t x_len, BYTE *key, BYTE *iv);

// Decrypt using AES 128-bit CBC mode
size_t aes_128_cbc_decrypt(BYTE **x, BYTE *y, size_t y_len, BYTE *key, BYTE *iv);

// Generate random AES key 
BYTE *rand_byte(size_t len);

// Get block size given function pointer
size_t getBlockSize(size_t (*encrypt)(BYTE**, BYTE*, size_t), size_t *cnt, size_t *n);

// Test if oracle is ECB
size_t isECB(size_t (*encrypt)(BYTE**, BYTE*, size_t), size_t block_size);

// Parse key=value pairs (reverse of encode)
char *kv_parse(const char *str);

// Encode key=value object as '&'-delimited string (reverse of parse)
char *kv_encode(const char *str);

// Create profile given email address
char *profile_for(const char *email);

// Encrypt profile with random key
size_t encrypt_profile(BYTE **y, BYTE **key, char *profile);

// Decrypt and parse profile
char *decrypt_profile(BYTE *x, size_t x_len, BYTE *key);

// Challenge 13: ECB cut-and-paste
char *make_admin_profile(void);

#endif
//==============================================================================
//==============================================================================
