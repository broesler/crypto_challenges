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

//-------------------------------------------------------------------------------
//      Macros
//-------------------------------------------------------------------------------
#define MAX_LINE_LEN 1024

#define REWIND_CHECK(x) if (fseek((x), 0L, SEEK_SET)) { ERROR("Rewind failed!"); }

//------------------------------------------------------------------------------ 
//      Function Definitions
//------------------------------------------------------------------------------
// Read file as single string 
unsigned long file2str(char **buffer, const char *filename);

// Count lines in file
size_t lines_in_file(const char *filename);

#endif
//==============================================================================
//==============================================================================

