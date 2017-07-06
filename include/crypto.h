//==============================================================================
//     File: crypto.h
//  Created: 10/19/2016, 23:24
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//=============================================================================
#ifndef _CRYPTO_H_
#define _CRYPTO_H_

//------------------------------------------------------------------------------
//      Constants
//------------------------------------------------------------------------------
#define NUM_LETTERS 0xFF

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
// Convert hex string to base-64 string
char *hex2b64_str(char *hex_str);

// Convert base-64 string to hex string??
// char *b642hex_str(char *b64_str);

// XOR two strings
char *fixedXOR(char *str1, char *str2);

// Character frequency list
CHARFREQ *countChars(char *s);

// Character frequency score
float charFreqScore(char *str);

// Single byte XOR encode
char *singleByteXOREncode(char *hex, int key);

// Single byte XOR decode
char *singleByteXORDecode(char *hex);

#endif
//==============================================================================
//==============================================================================
