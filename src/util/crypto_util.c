/*==============================================================================
 *     File: crypto_util.c
 *  Created: 07/06/2017, 15:37
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for cryptography challenges
 *
 *============================================================================*/
#include "crypto_util.h"
#include "header.h"

/*------------------------------------------------------------------------------ 
 *          Convert string to uppercase (in-place)
 *----------------------------------------------------------------------------*/
char *strtoupper(char *s)
{
    int i = 0;
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
    int i = 0;
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
int getHexByte(const char *hex)
{
    int u = 0,
        c = 0;

    int nmax = (strlen(hex) > 1) ? 2 : 1;

    for (int i = 0; i < nmax; i++)
    {
        c = *hex;
        if      (c >= 'a' && c <= 'f') { c = c - 'a' + 10; } 
        else if (c >= 'A' && c <= 'F') { c = c - 'A' + 10; } 
        else if (c >= '0' && c <= '9') { c = c - '0'; }
        else { ERROR("Invalid hex character!"); } 

        u <<= 4;
        u += (int)c;
        hex++;
    }
    return u;
}

/*------------------------------------------------------------------------------ 
 *          Encode ASCII string into hex string
 *----------------------------------------------------------------------------*/
/* Take each 8-bit character and convert it to 2, 4-bit characters */
char *atoh(char *str)
{
    static const char *lut = "0123456789ABCDEF";
    size_t len = strlen(str);

    char *hex = init_str(2*len); /* allocate memory */
    char *p = hex;               /* moveable pointer */

    for (char *c = str; *c; c++)
    {
        *p++ = lut[*c >> 0x04]; /* take first nibble (4 bits) */
        *p++ = lut[*c  & 0x0F]; /* take next  nibble */
    }
    return hex;
}

/*------------------------------------------------------------------------------ 
 *          Decode hex-encoded string into ASCII string
 *----------------------------------------------------------------------------*/
char *htoa(const char *hex)
{
    size_t len = strlen(hex);

    /* Check for odd-length inputs */
    if (len & 1) { ERROR("Input string is not a valid hex string!"); }

    size_t nbyte = len/2;
    char *str = init_str(nbyte); /* allocate memory */
    char *str_t = init_str(nbyte); /* allocate memory */
    char *p = str_t;

    char ascii[2];
    BZERO(ascii, 2);

    /* Take every 2 hex characters and combine bytes to make 1 ASCII char */
    for (size_t i = 0; i < nbyte; i++)
    {
        /* *(str+i) = (char)getHexByte(hex+2*i); */
        *p++ = getHexByte(hex+2*i);
        int u = getHexByte(hex+2*i);        /* get integer value of byte */
        snprintf(ascii, 2, "%c", u);        /* convert to ascii character */
        strncat(str, ascii, 1);             /* append to output string */
    }

    return str_t;
}

/*------------------------------------------------------------------------------
 *          Determine if string is printable
 *----------------------------------------------------------------------------*/
int isprintable(const char *s)
{
    while (*s && (isprint((unsigned char)*s) || isspace((unsigned char)*s))) s++;
    return (*s == '\0'); /* non-zero if true, zero if false */
}


/*------------------------------------------------------------------------------
 *         Allocate memory for string
 *----------------------------------------------------------------------------*/
char *init_str(size_t len)
{
    size_t nbyte = len+1;
    char *buffer = calloc(nbyte, sizeof(char));
    MALLOC_CHECK(buffer);
    return buffer;
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
 *         Repeat hex string 
 *----------------------------------------------------------------------------*/
char *strnrepeat_hex(const char *src, size_t src_len, size_t len)
{
    char *dest = init_str(len);

    /* Assumes strings are hex-encoded, so 2 chars == 1 byte */
    for (int i = 0; i < len/2; i++) {
        strncat(dest, &src[2*(i % (src_len/2))], 2);
    }

    return dest;
}

/*------------------------------------------------------------------------------
 *         Get index of character in string 
 *----------------------------------------------------------------------------*/
size_t indexof(const char *str, char c)
{
    char *s = strchr(str, c);
    return (s ? (s - str) : -1);
}

/*------------------------------------------------------------------------------
 *         Hamming weight of hex string 
 *----------------------------------------------------------------------------*/
size_t hamming_weight(const char *a)
{
    size_t weight = 0;
    int x = 0,
        count = 0;

    /* Wegner (1960), x & x-1 zeros LSB, so repeat until convergence
     * <https://en.wikipedia.org/wiki/Hamming_weight> */
    /* For each byte in string, sum the weights */
    for (size_t i = 0; i < strlen(a); i+=2) { 
        x = getHexByte(a+i); 
        for (count = 0; x; count++) {
            x &= x - 1;
        }
        weight += count;
    }

    return weight;
}

/*------------------------------------------------------------------------------
 *         Convert hex to binary string 
 *----------------------------------------------------------------------------*/

/*==============================================================================
 *============================================================================*/
