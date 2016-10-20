//==============================================================================
//     File: crypto.h
//  Created: 10/19/2016, 23:24
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//
//=============================================================================

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

// Convert hex string to base-64 string
char *hex2b64_str(char *hex_str);

#endif
//==============================================================================
//==============================================================================
