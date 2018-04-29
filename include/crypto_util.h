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
//      Type Definitions
//------------------------------------------------------------------------------
// Use raw bytes as the key
#ifndef byte_DEFINED
    #define byte_DEFINED
    typedef unsigned char BYTE;
#endif

//------------------------------------------------------------------------------
//      Function Definitions
//------------------------------------------------------------------------------
// Uppercase entire string
char *strtoupper(char *s);

// Lowercase entire string
char *strtolower(char *s);

// Get single hex byte from a string
BYTE getHexByte(const char *hex);

// Print byte array as hexadecimal string
char *byte2hex(const BYTE *byte, size_t nbyte);

// Decode hexadecimal string to raw bytes 
size_t hex2byte(BYTE **byte, const char *hex);

// Convert hex string to ASCII string
char *htoa(const char *hex);

// Copy byte array to proper C-string
char *byte2str(const BYTE *byte, size_t nbyte);

// Determine if string has non-printable characters
int isprintable(const BYTE *s, size_t nbyte);

// Check for any ascii character, space, tab, and newline
int ispchar(const char c);

// Print all bytes from array 
void printall(const BYTE *s, size_t nbyte);

// Print block separators
void print_blocks(const BYTE *s, size_t nbyte, size_t block_size, int pchar);

// Initialize string (char array)
char *init_str(const size_t len);

// Allocate memory for array of strings of given length
char **init_str_arr(size_t nstr, size_t len);

// Free string array 
void free_str_arr(char **str_arr, size_t nstr);

// Initialize byte array (same as init_str, but don't include extra NULL byte)
BYTE *init_byte(size_t len);

// Initialize integer array
int *init_int(const size_t len);

// Repeat byte N times
BYTE *bytenrepeat(const BYTE *src, size_t src_len, size_t nbyte);

// Get index of character in string 
size_t indexof(const char *str, char c);

// Character frequency list
int *countChars(const BYTE *s, size_t nbyte);

// Hamming weight of hex string 
size_t hamming_weight(const BYTE *byte, size_t nbyte);

// Read file as single string 
unsigned long fileToString(char **buffer, const char *filename);

// Remove chars in set from string
char *strrmchr(const char *src, const char *charset);

// Escape chars in set
char *strescchr(const char *src, const char *charset);

// HTML %-escape chars
char *strhtmlesc(const char *src, const char *charset);

// Count occurrences of character in string
size_t cntchr(const char *str, const char c);

#endif
//==============================================================================
//==============================================================================
