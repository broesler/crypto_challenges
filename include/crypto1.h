//==============================================================================
//     File: crypto1.h
//  Created: 10/19/2016, 23:24
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//=============================================================================
#ifndef _CRYPTO1_H_
#define _CRYPTO1_H_

//------------------------------------------------------------------------------
//      Constants
//------------------------------------------------------------------------------
#define NUM_LETTERS 26
#define MAX_PAGE_NUM 1000
#define MAX_WORD_LEN 10000

// Global array
extern const float ENGLISH_FREQ[];


//------------------------------------------------------------------------------
//      Structures
//------------------------------------------------------------------------------


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
int *countChars(const char *s);

// Character frequency score
float charFreqScore(char *str);

// Single byte XOR encode
char *singleByteXOREncode(char *hex, int key);

// Single byte XOR decode
char *singleByteXORDecode(char *hex);

// Search file for single byte XOR'd string
char *findSingleByteXOR(char *filename);

#endif
//==============================================================================
//==============================================================================
