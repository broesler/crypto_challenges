/*==============================================================================
 *     File: util_init.c
 *  Created: 05/07/2018, 16:36
 *   Author: Bernie Roesler
 *
 *  Description: Utilities for initializing arrays
 *
 *============================================================================*/

#include "util_init.h"

/*------------------------------------------------------------------------------
 *         Allocate memory for string
 *----------------------------------------------------------------------------*/
char *init_str(size_t len)
{
    char *buffer = calloc(len+1, sizeof(char));
    MALLOC_CHECK(buffer);
    return buffer;
}

/*------------------------------------------------------------------------------
 *         Allocate memory for array of strings of given length
 *----------------------------------------------------------------------------*/
char **init_str_arr(size_t nstr, size_t len)
{
    char **str_arr = malloc(nstr*sizeof(char *));
    MALLOC_CHECK(str_arr);

    for (size_t i = 0; i < nstr; i++) {
        *(str_arr+i) = init_str(len);
    }
    return str_arr;
}

/*------------------------------------------------------------------------------
 *         Free string array 
 *----------------------------------------------------------------------------*/
void free_str_arr(char **str_arr, size_t nstr)
{
    for (size_t i = 0; i < nstr; i++) { 
        if (*(str_arr+i)) { free(*(str_arr+i)); }
    }
    free(str_arr);
}

/*------------------------------------------------------------------------------
 *         Allocate memory for string
 *----------------------------------------------------------------------------*/
BYTE *init_byte(size_t len)
{
    BYTE *buffer = calloc(len+1, sizeof(BYTE));
    MALLOC_CHECK(buffer);
    return buffer;
}

/*------------------------------------------------------------------------------
 *         Generate random sequence of bytes (i.e. AES key) 
 *----------------------------------------------------------------------------*/
BYTE *rand_byte(size_t len)
{
    BYTE *key = init_byte(len);
    for (size_t i = 0; i < len; i++) {
        key[i] = rand() % 0x100;     /* generate random byte [0x00,0xFF] */ 
    }
    return key;
}

/*------------------------------------------------------------------------------
 *         Allocate memory for int
 *----------------------------------------------------------------------------*/
int *init_int(size_t len)
{
    int *buffer = calloc(len, sizeof(int));
    MALLOC_CHECK(buffer);
    return buffer;
}

/*------------------------------------------------------------------------------
 *         Repeat byte array to fill nbyte array
 *----------------------------------------------------------------------------*/
BYTE *bytenrepeat(const BYTE *src, size_t src_byte, size_t nbyte)
{
    BYTE *dest = init_byte(nbyte);
    BYTE *p = dest;
    for (size_t i = 0; i < nbyte; i++) {
        *p++ = *(src + (i % src_byte));
    }
    return dest;
}

/*==============================================================================
 *============================================================================*/
