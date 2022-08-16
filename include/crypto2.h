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
// maximum bytes to feed into get_block_size
#define IMAX 48

//------------------------------------------------------------------------------
//      Function Definitions
//------------------------------------------------------------------------------
// Challenge 10: Encrypt using AES 128-bit CBC mode
int aes_128_cbc_encrypt(BYTE **y, size_t *y_len, BYTE *x, size_t x_len, BYTE *key, BYTE *iv);

// Decrypt using AES 128-bit CBC mode
int aes_128_cbc_decrypt(BYTE **x, size_t *x_len, BYTE *y, size_t y_len, BYTE *key, BYTE *iv);

// Get block size given function pointer
size_t get_block_size(int (*encrypt)(BYTE**, size_t*, BYTE*, size_t), size_t *count, size_t *n);

// Test if oracle is ECB
size_t isECB(int (*encrypt)(BYTE**, size_t*, BYTE*, size_t), size_t block_size);

// Parse key=value pairs (reverse of encode)
char *kv_parse(const char *str);

// Encode key=value object as '&'-delimited string (reverse of parse)
char *kv_encode(const char *str);

// Create profile given email address
char *profile_for(const char *email);

// Encrypt profile with random key
int encrypt_profile(BYTE **y, size_t *y_len, BYTE **key, char *profile);

// Decrypt and parse profile
char *decrypt_profile(BYTE *x, size_t x_len, BYTE *key);

// Challenge 13: ECB cut-and-paste
char *make_admin_profile(void);

#endif
//==============================================================================
//==============================================================================
