//==============================================================================
//     File: include/aes_openssl.h
//  Created: 07/20/2017, 16:53
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//==============================================================================
#ifndef _AES_OPENSSL_H_
#define _AES_OPENSSL_H_

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include "header.h"
#include "crypto_util.h"

//------------------------------------------------------------------------------
//      Constants
//------------------------------------------------------------------------------
#define BLOCK_SIZE 16   // 16 bytes == 128-bit

//------------------------------------------------------------------------------
//      Function declarations
//------------------------------------------------------------------------------
// OpenSSL helper functions
void OpenSSL_init(void);
void OpenSSL_cleanup(void);
void handleErrors(void);

// AES 128-bit ECB-mode encrypt/decrypt single block
size_t aes_128_ecb_block(BYTE **out, BYTE *in, size_t in_len, BYTE *key, int enc);

#endif
//==============================================================================
//==============================================================================
