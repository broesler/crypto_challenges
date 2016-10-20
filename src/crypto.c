/*==============================================================================
 *     File: crypto.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for cryptography challenges
 *
 *============================================================================*/

#include "crypto.h"
/*------------------------------------------------------------------------------ 
 *      Print the hex values of the characters in the input string.
 *----------------------------------------------------------------------------*/
/* Should really be a function to return the hex string (no need for built-in
 * functions, just use bit-shifts to take chunks of 4 from each ASCII character
 * to make each hex character */
void print_hex(const char *s)
{
    printf("0x");
    while(*s) {
        printf("%02x", (unsigned int)*s++);
    }
    printf("\n");
}

/*------------------------------------------------------------------------------
 *      Convert hexadecimal string to base64 string
 *----------------------------------------------------------------------------*/
char *hex2b64_str(char *hex_str);
    /* Convert hex string to base64 string. */

    nchr_in = len(hex_str)      /* Number of chars in encoded string */
    nbyte = nchr_in / 2         /* 2 hex chars == 1 byte */
    /* nchr_out = nbyte * 4/3      #<{(| Number of chars in output |)}># */

    /* Byte array (2 hex chars == 1 byte) */
    hex_byte = [int(hex_str[i:i+2], 16) for i in range(0, nchr_in, 2)]

    b64_str = ''
    /* Operate in chunks of 3 bytes  in ==> 4 bytes out */
    for i in range(0, nbyte, 3):
        /* Add first character using first 6 bits of first byte */
        /* Need 2 chars of hex to get 1 byte */
        b64_int = (hex_byte[i] & 0xFC) >> 2
        b64_str += b64_lut[b64_int]

        /* get last 2 bits of first byte */
        b64_int = (hex_byte[i] & 0x03) << 4

        /* if we have more bytes to go */
        if i+1 < nbyte:
            /* Add second character using first 4 bits of second byte and
             * combine with 2 from above */
            b64_int |= (hex_byte[i+1] & 0xF0) >> 4
            b64_str += b64_lut[b64_int]

            /* get last 4 bits of second byte */
            b64_int = (hex_byte[i+1] & 0x0F) << 2

            /* if we have more bytes to go */
            if i+2 < nbyte:
                /* Add third character */
                /* get first 2 bits of third byte and combine with 4 from above */
                b64_int |= (hex_byte[i+2] & 0xC0) >> 6
                b64_str += b64_lut[b64_int]

                /* Add fourth character using last 6 bits of third byte */
                b64_int = (hex_byte[i+2] & 0x3F)
                b64_str += b64_lut[b64_int]

            /* There are only 2 bytes of input, so interpret 3rd character with
             * a "0x00" byte appended, and pad with an '=' character */
            else:
                b64_str += b64_lut[b64_int]
                b64_str += '='

        /* There is only 1 byte of input, so interpret 2nd character with two
         * "0x00" bytes appended, and pad with an '=' character */
        else:
            b64_str += b64_lut[b64_int]
            b64_str += '=='

    return b64_str

/*==============================================================================
 *============================================================================*/
