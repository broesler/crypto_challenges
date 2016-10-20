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
 *      Get an integer from 2 hex characters in a string
 *----------------------------------------------------------------------------*/
int getHexByte(char *hex) 
{
    int u = 0; 
    char substr[2];
    strncpy(substr, hex, 2);                /* take 2 chars */
    strtoupper(substr);                     /* convert to uppercase only */
    if (sscanf(substr, "%2X", &u)) {        /* convert to integer */
        return u;
    } else {
        ERROR("Invalid hex character!");
    }
}

/*------------------------------------------------------------------------------ 
 *      Encode ASCII string into hex string
 *----------------------------------------------------------------------------*/
/* Take each 8-bit character and convert it to 2, 4-bit characters */
char *atoh(char *str)
{
    static const char *lut = "0123456789ABCDEF";
    size_t len = strlen(str);

    /* allocate memory */
    char *hex = (char *)calloc(2*len, sizeof(char));
    MALLOC_CHECK(hex);
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
char *htoa(char *hex)
{
    size_t len = strlen(hex);

    /* Check for bad inputs */
    if (len & 1) { ERROR("Input string is not a valid hex string!"); }

    /* Proceed with conversion */
    unsigned int u; 
    char ascii[2];  /* store 1 ascii character */

    /* Create uppercase copy of input string */
    char hex_upper[len];
    strncpy(hex_upper, hex, len);   /* copy string in as-is */
    strtoupper(hex_upper);          /* make string uppercase */

    /* Allocate memory */
    char *str = malloc(len/2 * sizeof(char));
    MALLOC_CHECK(str);
    BZERO(str, sizeof(*str));

    /* Take every 2 hex characters and combine bytes to make 1 ASCII char */
    for (size_t i = 0; i < len; i+=2)
    {
        u = getHexByte(hex_upper+i);        /* get integer value of byte */
        snprintf(ascii, 2, "%c", u);        /* convert to ascii character */
        strncat(str, ascii, 1);             /* append to output string */
    }

    return str;
}

/*------------------------------------------------------------------------------ 
 *      Decode hex-encoded string into int array
 *----------------------------------------------------------------------------*/
int *htoi(char *hex)
{
    size_t len = strlen(hex);

    /* Check for bad inputs */
    if (len & 1) { ERROR("Input string is not a valid hex string!"); }

    /* Proceed with conversion */
    size_t nbyte = len/2;

    /* Create uppercase copy of input string */
    char hex_upper[len];
    strncpy(hex_upper, hex, len);   /* copy string in as-is */
    strtoupper(hex_upper);          /* make function case insensitive */

    /* Allocate memory */
    int *out = malloc(nbyte * sizeof(int));
    MALLOC_CHECK(out);
    BZERO(out, nbyte);

    /* Take every 2 hex characters and combine bytes to make 1 integer */
    for (size_t i = 0; i < nbyte; i++)
    {
        out[i] = getHexByte(hex_upper+2*i); /* get integer value of byte */
    }

    return out;
}

/*------------------------------------------------------------------------------
 *      Convert hexadecimal string to base64 string
 *----------------------------------------------------------------------------*/
char *hex2b64_str(char *hex_str)
{
    const char *b64_lut = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    int nchr_in,
        nbyte_in,
        nbyte_out,
        nchr_out,
        b64_int;
    int hex_int;

    if (hex_str) {
        nchr_in = strlen(hex_str);      /* Number of chars in encoded string */
    } else {
        return NULL;
    }

    if (nchr_in & 1) {
        ERROR("Input string it not a valid hex string!");
    } else {
        nbyte_in = nchr_in / 2;            /* 2 hex chars == 1 byte */
    }

    /* round nbyte up to multiple of 3 (need 3 bytes for even base64 output) */
    nbyte_out = nbyte_in + 3 - (nbyte_in % 3);
    nchr_out = nbyte_out * 4/3;  /* Number of chars in output */

    /* allocate memory for output */
    char *b64_str = malloc(nchr_out * sizeof(char));
    MALLOC_CHECK(b64_str);
    BZERO(b64_str, nchr_out);

    /* Operate in chunks of 3 bytes in ==> 4 bytes out */
    for (int i = 0; i < nbyte_in; i+=3) {
        int j = 0;
        hex_int = getHexByte(hex_str+2*i+2*j);

        /* Add first character using first 6 bits of first byte */
        b64_int = (hex_int & 0xFC) >> 2;
        strncat(b64_str, &b64_lut[b64_int], 1);

        /* get last 2 bits of first byte */
        b64_int = (hex_int & 0x03) << 4;

        /* if we have more bytes to go */
        if (j+1 < nbyte_in) {
            j++;
            hex_int = getHexByte(hex_str+2*i+2*j);

            /* Add second character using first 4 bits of second byte and
             * combine with 2 from above */
            b64_int |= (hex_int & 0xF0) >> 4;
            strncat(b64_str, &b64_lut[b64_int], 1);

            /* get last 4 bits of second byte */
            b64_int = (hex_int & 0x0F) << 2;

            /* if we have more bytes to go */
            if (j+1 < nbyte_in) {
                j++;
                hex_int = getHexByte(hex_str+2*i+2*j);
                /* Add third character */
                /* get first 2 bits of third byte and combine with 4 from above */
                b64_int |= (hex_int & 0xC0) >> 6;
                strncat(b64_str, &b64_lut[b64_int], 1);

                /* Add fourth character using last 6 bits of third byte */
                b64_int = (hex_int & 0x3F);
                strncat(b64_str, &b64_lut[b64_int], 1);

            /* There are only 2 bytes of input, so interpret 3rd character with
             * a "0x00" byte appended, and pad with an '=' character */
            } else {
                strncat(b64_str, &b64_lut[b64_int], 1);
                strncat(b64_str, "=", 1);
            }

        /* There is only 1 byte of input, so interpret 2nd character with two
         * "0x00" bytes appended, and pad with an '=' character */
        } else {
            strncat(b64_str, &b64_lut[b64_int], 1);
            strncat(b64_str, "==", 2);
        }
    }

    return b64_str;
}

/*------------------------------------------------------------------------------
 *      XOR two equal-length buffers
 *----------------------------------------------------------------------------*/
char *fixedXOR(char *str1, char *str2)
{
    size_t len1 = strlen(str1),
           len2 = strlen(str2);
    char *hex_str;
    int hex_xor, hex_int1, hex_int2;
    char hex_chars[3];

    if (len1 != len2) { ERROR("Input strings must be the same length!"); }

    int nbyte = len1/2;

    /* allocate memory for string output */
    hex_str = malloc(len1 * sizeof(char));
    MALLOC_CHECK(hex_str);
    BZERO(hex_str, len1);

    /* XOR each byte in the input string */
    for (int i = 0; i < nbyte; i++) {
        hex_int1 = getHexByte(str1+2*i); /* 2 chars per byte */
        hex_int2 = getHexByte(str2+2*i);
        hex_xor = hex_int1 ^ hex_int2;
        snprintf(hex_chars, 3, "%0.2X", hex_xor);  /* convert to hex chars */
        strncat(hex_str, hex_chars, 2);            /* append to output string */
    }

    return hex_str;
}


/*------------------------------------------------------------------------------
 *         Get character frequency score of string
 *----------------------------------------------------------------------------*/
/* int charFreqScore(char *str) */
/* { */
/*     #<{(| most common English letters (include spaces!) |)}># */
/*     const char etaoin = " etaoinshrdlcumwfgypbvkjxqz"; */
/*  */
/*     #<{(| Get ordered string of letters |)}># */
/* } */

/* #<{(|------------------------------------------------------------------------------ */
/*  *         Decode a string XOR'd against a single character */
/*  *----------------------------------------------------------------------------|)}># */
/* char *singleByteXORDecode(char *hex) */
/* { */
/*     size_t len = strlen(hex); */
/*  */
/*     if (len & 1) { ERROR("Input string is not a valid hex string!"); } */
/*  */
/*     int nbyte = len/2; */
/*  */
/*     char key[3];            #<{(| i.e. 0x01 --> '01' |)}># */
/*     BZERO(key, 3); */
/*  */
/*     char key_str[len];      #<{(| i.e. if hex == "4D616E", key_str = "010101" |)}># */
/*     BZERO(key_str, len); */
/*  */
/*     #<{(| Allocate memory for the output |)}># */
/*     char *plaintext = malloc(nbyte * sizeof(char)); */
/*     MALLOC_CHECK(plaintext); */
/*     BZERO(plaintext, nbyte); */
/*  */
/*     #<{(| Initialize variables |)}># */
/*     int cfreq_score_max = 0; */
/*     #<{(| char true_key; |)}># */
/*     #<{(| char plaintext_decrypt[nbyte];  #<{(| ascii is half the length of hex |)}># |)}># */
/*  */
/*     #<{(| test each possible character byte |)}># */
/*     #<{(| for (int i = 0; i < 0x100; i++) { |)}># */
/*     int i = 0x56; */
/*         #<{(| repeat key for each byte of input, to speed up XOR |)}># */
/*         snprintf(key, 3, "%0.2X", i); */
/*         for (int j = 0; j < nbyte; j++) { */
/*             strncat(key_str, key, 2); */
/*         } */
/*  */
/*         #<{(| XOR each byte in the ciphertext with the key |)}># */
/*         char *xor = fixedXOR(hex, key_str); */
/*  */
/*         #<{(| Calculate character frequency score |)}># */
/*         int cfreq_score = charFreqScore(xor); */
/*          */
/*  */
/*         #<{(| Track maximum score and actual key |)}># */
/*     #<{(| } |)}># */
/*         printf("%s\n", key_str); */
/*  */
/*     #<{(| Return the decoded plaintext! |)}># */
/*     return plaintext; */
/* } */
/*==============================================================================
 *============================================================================*/
