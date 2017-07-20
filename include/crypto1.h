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
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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
    char key[MAX_KEY_LEN];
    char plaintext[MAX_WORD_LEN];
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
char *byte2b64(const char *byte, size_t nbyte);

// Decode base64 string to byte array
size_t b642byte(char **byte, const char *b64);

// XOR two fixed-length byte arrays
char *fixedXOR(const char *a, const char *b, size_t nbyte);

// Character frequency score
float charFreqScore(const char *str, size_t nbyte);

// Allocate memory and initialize an XOR_NODE
XOR_NODE *init_xor_node(void);

// Single byte XOR decode
XOR_NODE *singleByteXORDecode(const char *byte, size_t nbyte);

// Search file for single byte XOR'd string
XOR_NODE *findSingleByteXOR(const char *filename);

// Encode hex string using repeating-key XOR
// char *repeatingKeyXOR(const char *input_hex, const char *key_hex);
char *repeatingKeyXOR(const char *byte, const char *key_byte, size_t nbyte, size_t key_len);

// Compute Hamming distance between strings 
size_t hamming_dist(const char *a, const char *b, size_t nbyte);

// Get most probable key length of repeating XOR 
size_t getKeyLength(const char *byte, size_t nbyte);

//  Break repeating key XOR cipher 
XOR_NODE *breakRepeatingXOR(const char *byte, size_t nbyte);

// OpenSSL helper functions
void OpenSSL_init(void);
void OpenSSL_cleanup(void);
void handleErrors(void);

// AES 128-bit ECB-mode encrypt/decrypt
int aes_128_ecb_encrypt(unsigned char *plaintext, int plaintext_len,
        unsigned char *key, unsigned char *ciphertext);
int aes_128_ecb_decrypt(unsigned char *ciphertext, int ciphertext_len, 
        unsigned char *key, unsigned char *plaintext);

int aes_128_ecb_cipher(unsigned char *in, size_t in_len, unsigned char *key,
        unsigned char *out, int enc);

#endif
//==============================================================================
//==============================================================================
