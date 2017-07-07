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
#define NUM_LETTERS 27      // include space!!
#define MAX_PAGE_NUM 1000
#define MAX_WORD_LEN 10000

// Global array
extern const float ENGLISH_FREQ[];

//------------------------------------------------------------------------------
//      Structures
//------------------------------------------------------------------------------
// The character frequency structure contains the letter and its frequency
typedef struct _XOR_NODE {
    int key;
    char plaintext[MAX_WORD_LEN];
    float score;
    int file_line;
} __XOR_NODE;

typedef struct _XOR_NODE XOR_NODE;

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
char *singleByteXOREncode(char *hex, char *key);

// Single byte XOR decode
XOR_NODE *singleByteXORDecode(char *hex);

// Search file for single byte XOR'd string
XOR_NODE *findSingleByteXOR(char *filename);

// Encode hex string using repeating-key XOR
char *repeatingKeyXOR(char *input_hex, char *key_hex);

#endif
//==============================================================================
//==============================================================================
