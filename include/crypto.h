//==============================================================================
//     File: crypto.h
//  Created: 10/19/2016, 23:24
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//=============================================================================
#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//------------------------------------------------------------------------------
//      Constants
//------------------------------------------------------------------------------
#define MAX_STR_LEN 4096
#define NUM_LETTERS 26

//------------------------------------------------------------------------------
//      Structures
//------------------------------------------------------------------------------
// The character frequency structure contains the letter and its frequency
typedef struct _CHARFREQ {
    char letter;
    int count;
} CHARFREQ;

//------------------------------------------------------------------------------
//      Function Definitions
//------------------------------------------------------------------------------
// Uppercase entire string
char *strtoupper(char *s);

// Uppercase entire string
char *strtolower(char *s);

// Get single hex byte from a string
int getHexByte(char *hex);

// Encode ASCII string as hexadecimal
char *atoh(char *str);

// Decode hexadecimal string to ASCII 
char *htoa(char *str);

// Decode hexadecimal string to integer array
int *htoi(char *hex);

// Convert hex string to base-64 string
char *hex2b64_str(char *hex_str);

// XOR two strings
char *fixedXOR(char *str1, char *str2);

// Character frequency list
CHARFREQ *findFrequency(char *s);

// Compare counts
int compare_counts(const void *a, const void *b);

// Character frequency score
int charFreqScore(char *str, const int N);

// Single byte XOR decode
char *singleByteXORDecode(char *hex, const int N);

#endif
//==============================================================================
//==============================================================================
