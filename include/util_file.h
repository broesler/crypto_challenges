//==============================================================================
//     File: include/util_file.h
//  Created: 05/07/2018, 16:39
//   Author: Bernie Roesler
//
//  Description: Utility functions for cryptography challenges
//=============================================================================
#ifndef _UTIL_FILE_H_
#define _UTIL_FILE_H_

#include "header.h"
#include "crypto_util.h"

// Read file as single string 
unsigned long fileToString(char **buffer, const char *filename);

// Count lines in file
size_t lines_in_file(const char *filename);


#endif
//==============================================================================
//==============================================================================

