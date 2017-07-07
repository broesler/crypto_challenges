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
//      Constants
//------------------------------------------------------------------------------
#define MAX_STR_LEN 4096

//------------------------------------------------------------------------------
//      Function Definitions
//------------------------------------------------------------------------------
// Uppercase entire string
char *strtoupper(char *s);

// Lowercase entire string
char *strtolower(char *s);

// Get single hex byte from a string
int getHexByte(char *hex);

// Encode ASCII string as hexadecimal
char *atoh(char *str);

// Decode hexadecimal string to ASCII 
char *htoa(char *str);

// Decode hexadecimal string to integer array
int *htoi(char *hex);

// Determine if string has non-printable characters
int isprintable(const char *s);

// Initialize string (char array)
char *init_str(size_t len);

// Initialize integer array
int *init_int(size_t len);

// Comparison function for sorting
int compare_int(const void *a, const void *b);

#endif
//==============================================================================
//==============================================================================
