/*==============================================================================
 *     File: crypto.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for cryptography challenges
 *
 *============================================================================*/

#include "crypto.h"
#include "header.h"

/*------------------------------------------------------------------------------ 
 *      Encode ASCII string into hex string
 *----------------------------------------------------------------------------*/
/* Take each 8-bit character and convert it to 2, 4-bit characters */
char *atoh(const char *str)
{
    static const char *lut = "0123456789ABCDEF";
    size_t len = strlen(str);
    char *hex = calloc(2*len, sizeof(char));   /* 4 bits for hex, 8 for char */

    /* zero out string */
    BZERO(hex, sizeof(*hex));

    for (size_t i = 0; i < len; i++)
    {
        char c = str[i];
        strncat(hex, &lut[c >> 0x04], 1);
        strncat(hex, &lut[c  & 0x0F], 1);
    }
    return hex;
}

/*------------------------------------------------------------------------------ 
 *      Decode hex-encoded string into ASCII string
 *----------------------------------------------------------------------------*/
/* char *htoa(const char *hex) */
/* { */
/*     static const char *lut = "0123456789ABCDEF"; */
/*     size_t len = strlen(hex); */
/*     if (len & 1) { ERROR("String is odd input length!"); } */
/*  */
/*     char *str = calloc(len/2, sizeof(char));   #<{(| 4 bits for hex, 8 for char |)}># */
/*  */
/*     #<{(| zero out string |)}># */
/*     BZERO(str, sizeof(*str)); */
/*  */
/*     for (size_t i = 0; i < len; i+=2) */
/*     { */
/*         char c = hex[i]; */
/*         strncat(hex, &lut[c >> 0x04], 1); */
/*         strncat(hex, &lut[c  & 0x0F], 1); */
/*     } */
/*     return hex; */
/* } */

/* #<{(|------------------------------------------------------------------------------ */
/*  *      Convert hexadecimal string to base64 string */
/*  *----------------------------------------------------------------------------|)}># */
/* char *hex2b64_str(char *hex_str); */
/*     #<{(| Convert hex string to base64 string. |)}># */
/*     int nchr_in = strlen(hex_str);      #<{(| Number of chars in encoded string |)}># */
/*     int nbyte = nchr_in / 2;            #<{(| 2 hex chars == 1 byte |)}># */
/*     #<{(| nchr_out = nchr_in * 2/3;           #<{(| Number of chars in output |)}># |)}># */
/*     #<{(| TODO allocate memory for output string that is 2/3 length of input */
/*      * string. We need to account for non-integer answers... (i.e. = padding) |)}># */
/*  */
/*     #<{(| Byte array (2 hex chars == 1 byte) |)}># */
/*     #<{(| hex_byte = [int(hex_str[i:i+2], 16) for i in range(0, nchr_in, 2)] |)}># */
/*     #<{(| hex string IS a byte array in C... |)}># */
/*  */
/*     b64_str = '' */
/*     #<{(| Operate in chunks of 3 bytes  in ==> 4 bytes out |)}># */
/*     for i in range(0, nbyte, 3): */
/*         #<{(| Add first character using first 6 bits of first byte |)}># */
/*         #<{(| Need 2 chars of hex to get 1 byte |)}># */
/*         b64_int = (hex_byte[i] & 0xFC) >> 2 */
/*         b64_str += b64_lut[b64_int] */
/*  */
/*         #<{(| get last 2 bits of first byte |)}># */
/*         b64_int = (hex_byte[i] & 0x03) << 4 */
/*  */
/*         #<{(| if we have more bytes to go |)}># */
/*         if i+1 < nbyte: */
/*             #<{(| Add second character using first 4 bits of second byte and */
/*              * combine with 2 from above |)}># */
/*             b64_int |= (hex_byte[i+1] & 0xF0) >> 4 */
/*             b64_str += b64_lut[b64_int] */
/*  */
/*             #<{(| get last 4 bits of second byte |)}># */
/*             b64_int = (hex_byte[i+1] & 0x0F) << 2 */
/*  */
/*             #<{(| if we have more bytes to go |)}># */
/*             if i+2 < nbyte: */
/*                 #<{(| Add third character |)}># */
/*                 #<{(| get first 2 bits of third byte and combine with 4 from above |)}># */
/*                 b64_int |= (hex_byte[i+2] & 0xC0) >> 6 */
/*                 b64_str += b64_lut[b64_int] */
/*  */
/*                 #<{(| Add fourth character using last 6 bits of third byte |)}># */
/*                 b64_int = (hex_byte[i+2] & 0x3F) */
/*                 b64_str += b64_lut[b64_int] */
/*  */
/*             #<{(| There are only 2 bytes of input, so interpret 3rd character with */
/*              * a "0x00" byte appended, and pad with an '=' character |)}># */
/*             else: */
/*                 b64_str += b64_lut[b64_int] */
/*                 b64_str += '=' */
/*  */
/*         #<{(| There is only 1 byte of input, so interpret 2nd character with two */
/*          * "0x00" bytes appended, and pad with an '=' character |)}># */
/*         else: */
/*             b64_str += b64_lut[b64_int] */
/*             b64_str += '==' */
/*  */
/*     return b64_str */

/*==============================================================================
 *============================================================================*/
