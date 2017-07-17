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
#define NUM_LETTERS 27      // include space!!

//------------------------------------------------------------------------------
//      Function Definitions
//------------------------------------------------------------------------------
// Uppercase entire string
char *strtoupper(char *s);

// Lowercase entire string
char *strtolower(char *s);

// Get single hex byte from a string
int getHexByte(const char *hex);

// Print byte array as hexadecimal string
char *byte2hex(const char *byte, size_t nbyte);

// Decode hexadecimal string to raw bytes 
size_t hex2byte(char **byte, const char *hex);

// Convert hex string to ASCII string
char *htoa(const char *hex);

// Copy byte array to proper C-string
char *byte2str(const char *byte, size_t nbyte);

// Determine if string has non-printable characters
int isprintable(const char *s);

// Initialize string (char array)
char *init_str(const size_t len);

// Allocate memory for array of strings of given length
char **init_str_arr(size_t nstr, size_t len);

// Free string array 
void free_str_arr(char **str_arr, size_t nstr);

// Initialize byte array (same as init_str, but don't include extra NULL byte)
char *init_byte(size_t len);

// Initialize integer array
int *init_int(const size_t len);

// Repeat byte N times
char *bytenrepeat(const char *src, size_t src_len, size_t nbyte);

// Get index of character in string 
size_t indexof(const char *str, char c);

// Character frequency list
int *countChars(const char *s, size_t nbyte);

// Hamming weight of hex string 
size_t hamming_weight(const char *byte, size_t nbyte);

// Read file as single string 
unsigned long fileToString(char **buffer, const char *filename);

#endif
//==============================================================================
//==============================================================================
