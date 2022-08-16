//==============================================================================
//     File: include/util_init.h
//  Created: 05/07/2018, 16:36
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//=============================================================================
#ifndef _UTIL_INIT_H_
#define _UTIL_INIT_H_

#include "header.h"
#include "crypto_util.h"

// Initialize string (char array)
char *init_str(const size_t len);

// Allocate memory for array of strings of given length
char **init_str_arr(size_t nstr, size_t len);

// Free string array 
void free_str_arr(char **str_arr, size_t nstr);

// Initialize byte array (same as init_str, but don't include extra NULL byte)
BYTE *init_byte(size_t len);

// Generate random sequence of bytes
BYTE *rand_byte(size_t len);

// Initialize integer array
int *init_int(const size_t len);

// Repeat byte N times
BYTE *bytenrepeat(const BYTE *src, size_t src_len, size_t nbyte);

#endif
//==============================================================================
//==============================================================================
