//==============================================================================
//     File: include/util_print.h
//  Created: 05/07/2018, 16:34
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//=============================================================================
#ifndef _UTIL_PRINT_H_
#define _UTIL_PRINT_H_

#include "header.h"
#include "crypto_util.h"

// Determine if string has non-printable characters
int isprintable(const BYTE *s, size_t nbyte);

// Check for any ascii character, space, tab, and newline
int ispchar(const char c);

// Print all bytes from array 
void printall(const BYTE *s, size_t nbyte);

// Print block separators
void print_blocks(const BYTE *s, size_t nbyte, size_t block_size, int pchar);

#endif
//==============================================================================
//==============================================================================
