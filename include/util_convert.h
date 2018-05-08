//==============================================================================
//     File: include/util_convert.h
//  Created: 05/07/2018, 16:29
//   Author: Bernie Roesler
//
//  Description: Utility functions for converting between array types
//=============================================================================
#ifndef _UTIL_CONVERT_H_
#define _UTIL_CONVERT_H_

#include "header.h" 
#include "crypto_util.h"

//------------------------------------------------------------------------------
//      Function Definitions
//------------------------------------------------------------------------------
// Uppercase entire string
char *strtoupper(char *s);

// Lowercase entire string
char *strtolower(char *s);

// Get single hex byte from a string
BYTE get_hex_byte(const char *hex);

// Print byte array as hexadecimal string
char *byte2hex(const BYTE *byte, size_t nbyte);

// Decode hexadecimal string to raw bytes 
size_t hex2byte(BYTE **byte, const char *hex);

// Convert hex string to ASCII string
char *htoa(const char *hex);

// Copy byte array to proper C-string
char *byte2str(const BYTE *byte, size_t nbyte);

#endif
//==============================================================================
//==============================================================================
