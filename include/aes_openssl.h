//==============================================================================
//     File: ../include/aes_openssl.h
//  Created: 07/20/2017, 16:53
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//=============================================================================
#ifndef _AES_OPENSSL_H_
#define _AES_OPENSSL_H_

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include "header.h"
#include "crypto_util.h"

// OpenSSL helper functions
void OpenSSL_init(void);
void OpenSSL_cleanup(void);
void handleErrors(void);

// AES 128-bit ECB-mode encrypt/decrypt
int aes_128_ecb_cipher(unsigned char **out, unsigned char *in, size_t in_len, 
        unsigned char *key, int enc);

#endif
//==============================================================================
//==============================================================================

