//==============================================================================
//     File: include/crypto_util.h
//  Created: 07/06/2017, 15:38
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//=============================================================================
#ifndef _CRYPTO_UTIL_H_
#define _CRYPTO_UTIL_H_

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//------------------------------------------------------------------------------
//      Macros
//------------------------------------------------------------------------------
// Random number in range (inclusive)
// Good enough for government work... or is it? not truly "uniform"
#define RAND_RANGE(A,B) ((rand() % ((B) - (A) + 1)) + (A))

//------------------------------------------------------------------------------
//      Type Definitions
//------------------------------------------------------------------------------
// Use raw bytes as the key
// WARNING BYTE arrays are NOT guaranteed to be NULL terminated like C-strings!!
#ifndef byte_DEFINED
#define byte_DEFINED
typedef unsigned char BYTE;
#endif

#include "util_convert.h"
#include "util_print.h"
#include "util_file.h"
#include "util_init.h"
#include "util_str.h"

#endif
//==============================================================================
//==============================================================================
