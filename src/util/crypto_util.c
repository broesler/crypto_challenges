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

static const char *HEX_LUT = "0123456789ABCDEF";

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
    char p;

    /* Take 1 or 2 chars, error if input is length 0 */
    int nmax = (strlen(hex) > 1) ? 2 : 1;

    for (int i = 0; i < nmax; i++)
    {
        p = *hex;
        if      (p >= 'a' && p <= 'f') { c = p - 'a' + 10; } 
        else if (p >= 'A' && p <= 'F') { c = p - 'A' + 10; } 
        else if (p >= '0' && p <= '9') { c = p - '0'; }
        else { 
            errno = ERANGE; 
            ERROR("Invalid hex character!"); 
        } 

        u <<= 4;
        u += c;
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
    size_t len = strlen(str);

    char *hex = init_str(2*len); /* allocate memory */
    char *p = hex;               /* moveable pointer */

    for (char *c = str; *c; c++)
    {
        *p++ = HEX_LUT[*c >> 0x04]; /* take first nibble (4 bits) */
        *p++ = HEX_LUT[*c  & 0x0F]; /* take next  nibble */
    }
    return hex;
}

/*------------------------------------------------------------------------------ 
 *          Decode hex-encoded string into ASCII string
 *----------------------------------------------------------------------------*/
char *htoa(const char *hex)
{
    size_t nchar = strlen(hex);

    /* Check for odd-length inputs */
    if (nchar & 1) { ERROR("Input string is not a valid hex string!"); }

    size_t nbyte = nchar/2;

    char *str_t = init_str(nbyte); /* allocate memory */
    char *p = str_t;

    /* Take every 2 hex characters and combine bytes to make 1 ASCII char */
    for (size_t i = 0; i < nbyte; i++) /*use hex+2*i in assignment */
    {
        *p++ = (char)getHexByte(hex+2*i);
    }

    return str_t;
}

/*------------------------------------------------------------------------------
 *         Convert hex to binary string??
 *----------------------------------------------------------------------------*/
/* char *htob(const char *hex) */
/* { return NULL; } */

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
 *         Allocate memory for array of strings of given length
 *----------------------------------------------------------------------------*/
char **init_str_arr(size_t nstr, size_t len)
{
    char **str_arr = malloc(nstr*sizeof(char *));
    MALLOC_CHECK(str_arr);
    BZERO(str_arr, nstr*sizeof(char *));

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
        /* if (str_arr[i]) free(str_arr[i]); */
    }
    free(str_arr);
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
char *strnrepeat_hex(const char *src, size_t src_len, size_t nchar)
{
    char *dest = init_str(nchar);
    /* Assumes strings are hex-encoded, so 2 chars == 1 byte */
    for (int i = 0; i < nchar/2; i++) {
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
size_t hamming_weight(const char *hex)
{
    size_t nchar = strlen(hex);
    if (nchar & 1) { ERROR("Input string is not a valid hex string!"); }

    size_t nbyte = nchar/2;
    size_t weight = 0;
    int x = 0,
        count = 0;

    /* Wegner (1960), x & x-1 zeros LSB, so repeat until x = 0
     * <https://en.wikipedia.org/wiki/Hamming_weight> */
    /* For each byte in string, sum the weights */
    for (size_t i = 0; i < nbyte; i++) { 
        x = getHexByte(hex+2*i);
        for (count = 0; x; count++) {
            x &= x - 1;
        }
        weight += count;
    }

    return weight;
}

/*------------------------------------------------------------------------------
 *         Read file as single string 
 *----------------------------------------------------------------------------*/
char *fileToString(char *filename, long *file_length)
{
    FILE *fp = NULL;
    char *buffer = NULL;
    int result = 0;
    char message[2*MAX_STR_LEN];

    /*------ Determine length of temp file -------------*/
    fp = fopen(filename, "r");
    if (!fp) {
        snprintf(message, 2*MAX_STR_LEN, "File %s could not be read!", filename);
        LOG(message);
        exit(-1);
    }

    fseek(fp, 0, SEEK_END);   /* move pointer to end of file */
    *file_length = ftell(fp);
    rewind(fp);               /* reset to top of file */

    /*------ malloc buffer to file_length+1 ------------*/
    buffer = malloc(*file_length*sizeof(char) + 1);
    MALLOC_CHECK(buffer);
    BZERO(buffer, *file_length*sizeof(char));

    /*------ read temp into buffer ------*/
    result = fread(buffer, sizeof(char), *file_length, fp);

    if (result != *file_length) {
        WARNING("File read error!");
        free(buffer);
        return NULL;
    }

    /* free file pointer */
    fclose(fp);
    return buffer;
}

/*==============================================================================
 *============================================================================*/
