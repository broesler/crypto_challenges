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
        if      (p >= '0' && p <= '9') { c = p - '0'; }
        else if (p >= 'a' && p <= 'f') { c = p - 'a' + 10; } 
        else if (p >= 'A' && p <= 'F') { c = p - 'A' + 10; } 
        else { 
            printf("Got char: \\x%d.\n", p);
            ERROR("Invalid hex character!"); 
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
char *byte2hex(const char *byte, size_t nbyte)
{
    char *hex = init_str(2*nbyte); /* include NULL termination for STRING */
    char *p = hex;
    const char *c = byte;

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
size_t hex2byte(char **byte, const char *hex)
{
    size_t nchar = strlen(hex);
    if (nchar & 1) { ERROR("Input string is not a valid hex string!"); }
    size_t nbyte = nchar/2;

    *byte = init_byte(nbyte);     /* allocate memory */
    char *p = *byte;

    /* Take every 2 hex characters and combine bytes to make 1 ASCII char */
    for (size_t i = 0; i < nbyte; i++)
    {
        *p++ = (char)getHexByte(hex+2*i);
    }

    return nbyte;
}

/*------------------------------------------------------------------------------
 *         Convert hex to binary string??
 *----------------------------------------------------------------------------*/
/* char *htob(const char *hex) */
/* { return NULL; } */

/*------------------------------------------------------------------------------
 *          Convert hex string to ASCII string
 *----------------------------------------------------------------------------*/
char *htoa(const char *hex)
{
    char *byte = NULL;
    size_t nbyte = hex2byte(&byte, hex);
    char *ascii = byte2str(byte, nbyte);
    free(byte);
    return ascii;
}

/*------------------------------------------------------------------------------
 *         Convert byte array to ASCII string 
 *----------------------------------------------------------------------------*/
char *byte2str(const char *byte, size_t nbyte)
{
    char *str = init_str(nbyte); /* same as nbyte, but add null-terminator */
    memcpy(str, byte, nbyte); /* probably optimized over a loop */
    return str;
}

/*------------------------------------------------------------------------------
 *          Determine if string is printable
 *----------------------------------------------------------------------------*/
int isprintable(const char *s)
{
    /* Accept "printable" characters, single space, or newline, but NOT carriage
     * return, tab, or vertical tab (odd in normal text) */
    while (*s && (isprint(*s) || (*s == '\t') || (*s == '\n'))) { s++; }
    return (*s == '\0'); /* non-zero if true, zero if false */
}

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
    }
    free(str_arr);
}

/*------------------------------------------------------------------------------
 *         Allocate memory for string
 *----------------------------------------------------------------------------*/
char *init_byte(size_t len)
{
    char *buffer = calloc(len, sizeof(char));
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
 *         Repeat byte array to fill nbyte array
 *----------------------------------------------------------------------------*/
char *bytenrepeat(const char *src, size_t src_byte, size_t nbyte)
{
    char *dest = init_byte(nbyte);
    char *p = dest;
    for (size_t i = 0; i < nbyte; i++) {
        *p++ = *(src + (i % src_byte));
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
 *         Find character frequency in byte array
 *----------------------------------------------------------------------------*/
int *countChars(const char *s, size_t nbyte)
{
    int *cf = init_int(NUM_LETTERS);

    /* Count occurrences letters in the string, index by letter */
    for (size_t i = 0; i < nbyte; i++)
    {
        if      (*s >= 'A' && *s <= 'Z') { cf[*s-'A']++; }
        else if (*s >= 'a' && *s <= 'z') { cf[*s-'a']++; }
        else if (*s == 32) { cf[NUM_LETTERS-1]++; } /* count spaces */
        s++;
    }
    return cf;
}

/*------------------------------------------------------------------------------
 *         Hamming weight of hex string 
 *----------------------------------------------------------------------------*/
size_t hamming_weight(const char *byte, size_t nbyte)
{
    size_t weight = 0,
           count = 0;
    int x = 0;

    /* Wegner (1960), x & x-1 zeros LSB, so repeat until x = 0
     * <https://en.wikipedia.org/wiki/Hamming_weight> */
    /* For each byte in string, sum the weights */
    for (size_t i = 0; i < nbyte; i++) { 
        x = *(byte+i);
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
unsigned long fileToString(char **buffer, const char *filename)
{
    FILE *fp = NULL;
    int result = 0;
    char message[2*MAX_STR_LEN];
    unsigned long file_length = -1;

    /* Determine length of temp file */
    fp = fopen(filename, "r");
    if (!fp) {
        snprintf(message, 2*MAX_STR_LEN, "File %s could not be read!", filename);
        LOG(message);
        exit(-1);
    }

    fseek(fp, 0, SEEK_END);   /* move pointer to end of file */
    file_length = ftell(fp);
    rewind(fp);               /* reset to top of file */

    /* malloc buffer to file_length+1 */
    *buffer = init_str(file_length);

    /* read temp into buffer */
    result = fread(*buffer, sizeof(char), file_length, fp);

    if (result != file_length) {
        WARNING("File read error!");
        free(*buffer);
        return -1;
    }

    fclose(fp);
    return file_length;
}

/*==============================================================================
 *============================================================================*/
