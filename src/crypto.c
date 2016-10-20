/*==============================================================================
 *     File: crypto.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for cryptography challenges
 *
 *============================================================================*/

#include <ctype.h>

#include "crypto.h"
#include "header.h"

/*------------------------------------------------------------------------------ 
 *      Convert string to uppercase
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
 *      Convert string to lowercase
 *----------------------------------------------------------------------------*/
char *strtolower(char *s)
{
    int i = 0;
    while (s[i]) {
        if (s[i] >= 'A' && s[i] <= 'Z') {
            s[i] += 32;
        }
        i++;
    }
    return s;
}

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
        strncat(hex, &lut[c >> 0x04], 1); /* take first 4 bits */
        strncat(hex, &lut[c  & 0x0F], 1); /* take next 4 bits */
    }
    return hex;
}

/*------------------------------------------------------------------------------ 
 *      Decode hex-encoded string into ASCII string
 *----------------------------------------------------------------------------*/
char *htoa(const char *hex)
{
    /* static const char *lut = "0123456789ABCDEF"; */
    size_t len = strlen(hex);

    /* Check for bad inputs */
    if (len & 1) { ERROR("String is odd input length!"); }

    /* Proceed with conversion */
    unsigned int u; 
    char substr[2]; /* store 2 chars of hex string at a time */
    char ascii[2];  /* store 1 ascii character */

    /* Create uppercase copy of input string */
    char *hex_upper = calloc(len, sizeof(char));
    BZERO(hex_upper, sizeof(*hex_upper));
    strncpy(hex_upper, hex, len);   /* copy string in as-is */
    strtoupper(hex_upper);          /* make string uppercase */

    /* Allocate memory */
    char *str = calloc(len/2, sizeof(char));
    BZERO(str, sizeof(*str));

    /* Take every 2 hex characters and combine bytes to make 1 ASCII char */
    for (size_t i = 0; i < len; i+=2)
    {
        /* clear memory */
        BZERO(substr, sizeof(substr));
        BZERO(ascii, sizeof(ascii));

        strncpy(substr, hex_upper+i, 2);        /* take 2 chars */
        if (sscanf(substr, "%2X", &u)) {        /* convert to integer */
            snprintf(ascii, 2, "%c", u);        /* convert to ascii character */
            strncat(str, ascii, 1);             /* append to output string */
        }
    }
    return str;
}

/* #<{(|------------------------------------------------------------------------------ */
/*  *      Convert hexadecimal string to base64 string */
/*  *----------------------------------------------------------------------------|)}># */
/* char *hex2b64_str(char *hex_str) */
/* { */
/*     int nchr_in, */
/*         nbyte, */
/*         nchr_out; */
/*  */
/*     nchr_in = strlen(hex_str);      #<{(| Number of chars in encoded string |)}># */
/*  */
/*     if (nchr_in % 2 == 0) { */
/*         nbyte = nchr_in / 2;            #<{(| 2 hex chars == 1 byte |)}># */
/*     } else { */
/*         ERROR("Input string it not a valid hex string!"); */
/*     } */
/*  */
/*     nchr_out = nchr_in * 2/3;           #<{(| Number of chars in output |)}># */
/*     #<{(| TODO allocate memory for output string that is 2/3 length of input */
/*      * string. We need to account for non-integer answers... (i.e. = padding) |)}># */
/*  */
/*     #<{(| #<{(| Operate in chunks of 3 bytes in ==> 4 bytes out |)}># |)}># */
/*     #<{(| for i in range(0, nbyte, 3): |)}># */
/*     #<{(|     #<{(| Add first character using first 6 bits of first byte |)}># |)}># */
/*     #<{(|     #<{(| Need 2 chars of hex to get 1 byte |)}># |)}># */
/*     #<{(|     b64_int = (hex_byte[i] & 0xFC) >> 2 |)}># */
/*     #<{(|     b64_str += b64_lut[b64_int] |)}># */
/*     #<{(|  |)}># */
/*     #<{(|     #<{(| get last 2 bits of first byte |)}># |)}># */
/*     #<{(|     b64_int = (hex_byte[i] & 0x03) << 4 |)}># */
/*     #<{(|  |)}># */
/*     #<{(|     #<{(| if we have more bytes to go |)}># |)}># */
/*     #<{(|     if i+1 < nbyte: |)}># */
/*     #<{(|         #<{(| Add second character using first 4 bits of second byte and |)}># */
/*     #<{(|          * combine with 2 from above |)}># |)}># */
/*     #<{(|         b64_int |= (hex_byte[i+1] & 0xF0) >> 4 |)}># */
/*     #<{(|         b64_str += b64_lut[b64_int] |)}># */
/*     #<{(|  |)}># */
/*     #<{(|         #<{(| get last 4 bits of second byte |)}># |)}># */
/*     #<{(|         b64_int = (hex_byte[i+1] & 0x0F) << 2 |)}># */
/*     #<{(|  |)}># */
/*     #<{(|         #<{(| if we have more bytes to go |)}># |)}># */
/*     #<{(|         if i+2 < nbyte: |)}># */
/*     #<{(|             #<{(| Add third character |)}># |)}># */
/*     #<{(|             #<{(| get first 2 bits of third byte and combine with 4 from above |)}># |)}># */
/*     #<{(|             b64_int |= (hex_byte[i+2] & 0xC0) >> 6 |)}># */
/*     #<{(|             b64_str += b64_lut[b64_int] |)}># */
/*     #<{(|  |)}># */
/*     #<{(|             #<{(| Add fourth character using last 6 bits of third byte |)}># |)}># */
/*     #<{(|             b64_int = (hex_byte[i+2] & 0x3F) |)}># */
/*     #<{(|             b64_str += b64_lut[b64_int] |)}># */
/*     #<{(|  |)}># */
/*     #<{(|         #<{(| There are only 2 bytes of input, so interpret 3rd character with |)}># */
/*     #<{(|          * a "0x00" byte appended, and pad with an '=' character |)}># |)}># */
/*     #<{(|         else: |)}># */
/*     #<{(|             b64_str += b64_lut[b64_int] |)}># */
/*     #<{(|             b64_str += '=' |)}># */
/*     #<{(|  |)}># */
/*     #<{(|     #<{(| There is only 1 byte of input, so interpret 2nd character with two |)}># */
/*     #<{(|      * "0x00" bytes appended, and pad with an '=' character |)}># |)}># */
/*     #<{(|     else: |)}># */
/*     #<{(|         b64_str += b64_lut[b64_int] |)}># */
/*     #<{(|         b64_str += '==' |)}># */
/*  */
/*     return b64_str */
/* } */

/*==============================================================================
 *============================================================================*/
