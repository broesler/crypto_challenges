/*==============================================================================
 *     File: util_str.c
 *  Created: 07/06/2017, 15:37
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for cryptography challenges
 *
 *============================================================================*/

#include "util_str.h"

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
int *count_chars(const BYTE *s, size_t nbyte)
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
 *         Hamming weight of byte array 
 *----------------------------------------------------------------------------*/
size_t hamming_weight(const BYTE *byte, size_t nbyte)
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
 *        Remove chars in set from string
 *----------------------------------------------------------------------------*/
char *strrmchr(const char *src, const char *charset)
{
    const char *s = src;
    const char *c = charset;

    /* This "lookup table" makes our algorithm O(N+n). We don't have to scan
     * through the charset for ever char in src ==> worst-case O(N*(n+1)) */
    /* boolean of which chars in charset are in src */
    static const int totchars = 256;
    int rmchar[totchars];
    for (size_t i = 0; i < totchars; i++) { rmchar[i] = 0; }

    /* Step through charset and mark which chars are there */
    while (*c) {
        rmchar[(size_t)*c++] = 1; 
    }

    /* malloc more than necessary, fine unless we have a very "sparse" string */
    char *dest = init_str(strlen(src));
    char *d = dest;

    /* Step through string and copy characters not in charset to dest */
    while (*s) {
        if (!rmchar[(size_t)*s]) {
            *d++ = *s;
        }
        s++;
    }

    return dest; 
}

/* TODO combind strescchr and strhtmlesc into one function that takes a "mode"
 * argument i.e. mode='std' or mode='html'. Only 3 lines differ. */
/*------------------------------------------------------------------------------
 *        Escape chars in set occuring in string
 *----------------------------------------------------------------------------*/
char *strescchr(const char *src, const char *charset)
{
    const char *s = src;
    const char *c = charset;

    /* boolean of which chars in charset are in src */
    static const int totchars = 256;
    int escchar[totchars];
    for (size_t i = 0; i < totchars; i++) { escchar[i] = 0; }

    /* Step through charset and mark which chars are there */
    while (*c) {
        escchar[(size_t)*c++] = 1; 
    }

    /* malloc double the length in case we have to escape all chars in string */
    char *dest = init_str(2*strlen(src));
    char *d = dest;

    /* Step through string and copy characters not in charset to dest */
    while (*s) {
        if (escchar[(size_t)*s]) {
            *d++ = '\\';
            *d++ = *s;
        } else {
            *d++ = *s;
        }
        s++;
    }

    return dest; 
}

/*------------------------------------------------------------------------------
 *        HTML escape chars in set occuring in string
 *----------------------------------------------------------------------------*/
char *strhtmlesc(const char *src, const char *charset)
{
    const char *s = src;
    const char *c = charset;

    /* boolean of which chars in charset are in src */
    static const int totchars = 256;
    int escchar[totchars];
    for (size_t i = 0; i < totchars; i++) { escchar[i] = 0; }

    /* Step through charset and mark which chars are there */
    while (*c) {
        escchar[(size_t)*c++] = 1; 
    }

    /* For HTML escape, use '%' with hex value of character */
    char *dest = init_str(3*strlen(src));
    char *d = dest;

    /* Step through string and copy characters not in charset to dest */
    while (*s) {
        if (escchar[(size_t)*s]) {
            *d++ = '%';   /* html escape character */
            snprintf(d, 3, "%.2X", (unsigned int)*s);  /* hex value */
            d += 2;
        } else {
            *d++ = *s;
        }
        s++;
    }

    return dest; 
}

/*------------------------------------------------------------------------------
 *          Count occurrences of character in string
 *----------------------------------------------------------------------------*/
size_t cntchr(const char *str, const char c)
{
    size_t i;
    for (i = 0; *(str+i); *(str+i) == c ? i++ : *str++);
    return i;
}

/*==============================================================================
 *============================================================================*/
