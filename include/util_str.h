//==============================================================================
//     File: include/util_str.h
//  Created: 05/07/2018, 16:45
//   Author: Bernie Roesler
//
//  Description: Utility functions for manipulating strings
//=============================================================================
#ifndef _UTIL_STR_H_
#define _UTIL_STR_H_

#include "header.h"
#include "crypto_util.h"

#define NUM_LETTERS 27      // include space!!

// Get index of character in string 
size_t indexof(const char *str, char c);

// Character frequency list
int *count_chars(const BYTE *s, size_t nbyte);

// Hamming weight of hex string 
size_t hamming_weight(const BYTE *byte, size_t nbyte);

// Remove chars in set from string
char *strrmchr(const char *src, const char *charset);

// Escape chars in set
char *strescchr(const char *src, const char *charset, const int html_flag);

// Count occurrences of character in string
size_t cntchr(const char *str, const char c);

#endif
//==============================================================================
//==============================================================================

