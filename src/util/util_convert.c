/*==============================================================================
 *     File: util_convert.c
 *  Created: 05/07/2018, 16:28
 *   Author: Bernie Roesler
 *
 *  Description: Utilities for converting between array types
 *
 *============================================================================*/

#include "util_convert.h"

static const char *HEX_LUT = "0123456789ABCDEF";

/*------------------------------------------------------------------------------ 
 *          Convert string to uppercase (in-place)
 *----------------------------------------------------------------------------*/
char *strtoupper(char *s)
{
    size_t i = 0;
    while (*(s+i)) {
        if (*(s+i) >= 'a' && *(s+i) <= 'z') {
            *(s+i) -= 32;
        }
        i++;
    }
    return s;
}

/*------------------------------------------------------------------------------ 
 *          Convert string to lowercase (in-place)
 *----------------------------------------------------------------------------*/
char *strtolower(char *s)
{
    size_t i = 0;
    while (*(s+i)) {
        if (*(s+i) >= 'A' && *(s+i) <= 'Z') {
            *(s+i) += 32;
        }
        i++;
    }
    return s;
}

/*------------------------------------------------------------------------------
*         Get an integer from 2 hex characters in a string
*-----------------------------------------------------------------------------*/
BYTE get_hex_byte(const char *hex)
{
    BYTE u = 0;
    int c = 0;
    char p;

    /* Take 1 or 2 chars, error if input is length 0 */
    int nmax = (strlen(hex) > 1) ? 2 : 1;

    for (int i = 0; i < nmax; i++)
    {
        p = *hex;
        if      (p >= '0' && p <= '9') { c = p - '0'; }
        else if (p >= 'a' && p <= 'f') { c = p - 'a' + 10; } 
        else if (p >= 'A' && p <= 'F') { c = p - 'A' + 10; } 
        else { 
            ERROR("Invalid hex character! Got char: \\x%d.\n", p); 
        } 

        u <<= 4;
        u += c;
        hex++;
    }
    return u;
}

/*------------------------------------------------------------------------------ 
 *          Encode byte array into hex string
 *----------------------------------------------------------------------------*/
/* Input:
 *      byte  = pointer to byte array-to-be-converted
 *      nbyte = number of bytes in byte array (NOT null-terminated)
 * Output:
 *      pointer to hex string
 */
char *byte2hex(const BYTE *byte, size_t nbyte)
{
    char *hex = init_str(2*nbyte); /* include NULL termination for STRING */
    char *p = hex;
    const BYTE *c = byte;

    /* One byte --> 2 hex chars */
    for (size_t i = 0; i < nbyte; i++)
    {
        *p++ = HEX_LUT[*c   >> 0x04]; /* take first nibble (4 bits) */
        *p++ = HEX_LUT[*c++  & 0x0F]; /* take next  nibble */
    }

    return hex;
}

/*------------------------------------------------------------------------------ 
 *          Decode hex string into byte array
 *----------------------------------------------------------------------------*/
/* Input:
 *      byte = pointer to char* that will hold output array
 *      hex  = pointer to hex string-to-be-converted
 * Output:
 *      number of bytes in byte array (NOT null-terminated)
 */
size_t hex2byte(BYTE **byte, const char *hex)
{
    size_t nchar = strlen(hex);
    if (nchar & 1) { ERROR("Input string is not a valid hex string!"); }
    size_t nbyte = nchar/2;

    *byte = init_byte(nbyte);     /* allocate memory */
    BYTE *p = *byte;

    /* Take every 2 hex characters and combine bytes to make 1 ASCII char */
    for (size_t i = 0; i < nbyte; i++)
    {
        *p++ = get_hex_byte(hex+2*i);
    }

    return nbyte;
}

/*------------------------------------------------------------------------------
 *          Convert hex string to ASCII string
 *----------------------------------------------------------------------------*/
char *htoa(const char *hex)
{
    BYTE *byte = NULL;
    size_t nbyte = hex2byte(&byte, hex);
    char *ascii = byte2str(byte, nbyte);
    free(byte);
    return ascii;
}

/*------------------------------------------------------------------------------
 *         Convert byte array to ASCII string 
 *----------------------------------------------------------------------------*/
char *byte2str(const BYTE *byte, size_t nbyte)
{
    char *str = init_str(nbyte); /* same as nbyte, but add null-terminator */
    memcpy(str, byte, nbyte); /* probably optimized over a loop */
    return str;
}


/*==============================================================================
 *============================================================================*/
