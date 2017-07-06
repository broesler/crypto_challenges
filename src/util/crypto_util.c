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
 *          Convert string to uppercase
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
 *          Convert string to lowercase
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
 *          Get an integer from 2 hex characters in a string
 *----------------------------------------------------------------------------*/
int getHexByte(char *hex) 
{
    int u = 0; 
    char substr[3];
    BZERO(substr, 3);
    strncpy(substr, hex, 2);                /* take 2 chars */
    strtoupper(substr);                     /* convert to uppercase only */
    if (sscanf(substr, "%2X", &u)) {        /* convert to integer */
        return u;
    } else {
        ERROR("Invalid hex character!");
    }
}

/*------------------------------------------------------------------------------ 
 *          Encode ASCII string into hex string
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
 *          Decode hex-encoded string into ASCII string
 *----------------------------------------------------------------------------*/
char *htoa(char *hex)
{
    size_t len = strlen(hex);

    /* Check for odd-length inputs */
    if (len & 1) { ERROR("Input string is not a valid hex string!"); }

    /* Proceed with conversion */
    unsigned int u; 
    char ascii[2];  /* store 1 ascii character */

    /* Create uppercase copy of input string */
    char hex_upper[len];
    BZERO(hex_upper, len);
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
 *          Decode hex-encoded string into int array
 *----------------------------------------------------------------------------*/
int *htoi(char *hex)
{
    size_t len = strlen(hex);

    /* Check for odd-length inputs */
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
 *          Determine if string is printable
 *----------------------------------------------------------------------------*/
int isValid(const char *s)
{
    while (*s && isprint((unsigned char)*s)) s++;
    return (*s != '\0');

    /*     int i = 0; */
    /*     while (*s) */
    /*     { */
    /*         if (isprint((unsigned char)*s)) */
    /*         { */
    /*             s++; */
    /*             i++; */
    /*         } else { */
    /* #ifdef LOGSTATUS */
    /*             printf("Found non-printable at %d\n", i); */
    /* #endif */
    /*             return i; */
    /*         } */
    /*     } */
    /*     return (*s != '\0'); */
}

/*==============================================================================
 *============================================================================*/
