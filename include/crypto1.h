//==============================================================================
//     File: crypto1.h
//  Created: 10/19/2016, 23:24
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//=============================================================================
#ifndef _CRYPTO1_H_
#define _CRYPTO1_H_

#include <ctype.h>

#include "crypto_util.h"

//------------------------------------------------------------------------------
//      Constants
//------------------------------------------------------------------------------
#define NUM_LETTERS 27      // include space!!
#define MAX_KEY_LEN 100
#define MAX_PAGE_NUM 1000
#define MAX_WORD_LEN 10000

// Take minimum, but don't bother with type checking
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

//------------------------------------------------------------------------------
//      Structures
//------------------------------------------------------------------------------
// The character frequency structure contains the letter and its frequency
typedef struct _XOR_NODE {
    BYTE key[MAX_KEY_LEN];
    BYTE plaintext[MAX_WORD_LEN];
    size_t key_byte;
    float score;
    int file_line;
} __XOR_NODE;

typedef struct _XOR_NODE XOR_NODE;

//------------------------------------------------------------------------------
//      Function Definitions
//------------------------------------------------------------------------------
// Convert hex string to base-64 string
char *hex2b64(const char *hex);

// Convert base-64 string to hex string
char *b642hex(const char *b64);

// Encode byte array as b64 string
char *byte2b64(const BYTE *byte, size_t nbyte);

// Decode base64 string to byte array
size_t b642byte(BYTE **byte, const char *b64);

// XOR two fixed-length byte arrays
BYTE *fixedXOR(const BYTE *a, const BYTE *b, size_t nbyte);

// Character frequency score
float charFreqScore(const BYTE *byte, size_t nbyte);

// Allocate memory and initialize an XOR_NODE
XOR_NODE *init_xor_node(void);

// Single byte XOR decode
XOR_NODE *singleByteXORDecode(const BYTE *byte, size_t nbyte);

// Search file for single byte XOR'd string
XOR_NODE *findSingleByteXOR(const char *filename);

// Encode byte array using repeating-key XOR
BYTE *repeatingKeyXOR(const BYTE *byte, const BYTE *key_byte, size_t nbyte, size_t key_len);

// Compute Hamming distance between strings 
size_t hamming_dist(const BYTE *a, const BYTE *b, size_t nbyte);

// Get the normalized mean Hamming distance between chunks of a byte array
float normMeanHamming(const BYTE *byte, size_t nbyte, size_t k);

// Get most probable key length of repeating XOR 
size_t getKeyLength(const BYTE *byte, size_t nbyte);

//  Break repeating key XOR cipher 
XOR_NODE *breakRepeatingXOR(const BYTE *byte, size_t nbyte);

// Same as normMeanHamming except return logical value
int hasIdenticalBlocks(const BYTE *byte, size_t nbyte, size_t block_size);

// Detect AES in ECB mode 
int find_AES_ECB(BYTE **out, const char *hex_filename);

#endif
//==============================================================================
//==============================================================================
