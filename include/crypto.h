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

// Encode ASCII string as hexadecimal
char *atoh(const char *str);

// Decode hexadecimal string to ASCII 
char *htoa(const char *str);

#endif
//==============================================================================
//==============================================================================
