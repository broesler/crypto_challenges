/*==============================================================================
 *     File: util_print.c
 *  Created: 05/07/2018, 16:33
 *   Author: Bernie Roesler
 *
 *  Description: Utilities to print arrays
 *
 *============================================================================*/

#include "util_print.h"

/*------------------------------------------------------------------------------
 *          Determine if string is printable
 *----------------------------------------------------------------------------*/
int isprintable(const BYTE *s, size_t nbyte)
{
    /* Accept "printable" characters, single space, or newline, but NOT carriage
     * return, tab, or vertical tab (odd in normal text) */
    /* while (*s && (ispchar(*s))) { s++; } */
    size_t i;
    for (i = 0; i < nbyte; i++) {
        if ((*s) && (ispchar(*s))) {
            s++;
        } else { 
            break; 
        }
    }
    return (i == nbyte); /* non-zero if true, zero if false */
}

int ispchar(const char c)
{
    /* Check for any ascii character, space, tab, and newline */
    return (isprint(c) || (c == '\t') || (c == '\n'));
}

/*------------------------------------------------------------------------------
 *         Print all bytes from array 
 *----------------------------------------------------------------------------*/
void printall(const BYTE *s, size_t nbyte)
{
    for (size_t i = 0; i < nbyte; i++) {
        char c = *(s+i);
        if (ispchar(c)) {
            printf("%c", c);
        } else {
            printf("\\x%.2X", c);
        }
    }
}

/*------------------------------------------------------------------------------
 *         Print all bytes from array in blocks
 *----------------------------------------------------------------------------*/
void print_blocks(const BYTE *s, size_t nbyte, size_t block_size, int pchar)
{
    /* *s         : pointer to byte array for printing
     * nbyte      : number of bytes in *s
     * block_size : number of bytes per block
     * pchar      : if true, print 'printable' chars instead of hex codes
     */

    int all_pchar = 1;
    for (size_t i = 0; i < nbyte; i++) {
        if (!isprint(*(s+i))) {
            all_pchar = 0;
            break;
        }
    }
    /* If all are printable, no need to space out to matching hex blocks */
    char *cfmt = (all_pchar == 1) ? "%c" : "  %c ";

    /* Number of blocks needed */
    size_t n_blocks = nbyte / block_size;
    if (nbyte % block_size) { n_blocks++; }

    for (size_t n = 0; n < n_blocks; n++) {
        size_t i = 0,
               idx = n*block_size;
        do {
            char c = *(s + idx);
            if (pchar && isprint(c)) {
                printf(cfmt, c); /* keep same spaceing as \x01, i.e. */
            } else {
                printf("\\x%.2X", c);
            }
            i++;
            idx++;
        } while ((i < block_size) && (idx < nbyte));

        if (idx < nbyte) {
            printf("||");
        }
    }
}



/*==============================================================================
 *============================================================================*/
