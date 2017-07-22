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
BYTE *pkcs7(const BYTE *byte, size_t nbyte, size_t block_size);

#endif
//==============================================================================
//==============================================================================
