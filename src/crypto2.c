/*==============================================================================
 *     File: crypto2.c
 *  Created: 07/22/2017, 00:47
 *   Author: Bernie Roesler
 *
 *  Description: Solutions to Set 2 of Matasano Crypto Challenges
 *
 *============================================================================*/
#include "header.h"
#include "crypto2.h"

/*------------------------------------------------------------------------------
 *         PKCS#7 padding to block size 
 *----------------------------------------------------------------------------*/
BYTE *pkcs7(const BYTE *byte, size_t nbyte, size_t block_size)
{
    if (nbyte > block_size) { ERROR("Input > block size!"); }

    BYTE *out = init_byte(block_size);
    memcpy(out, byte, nbyte);
    BYTE *p = out+nbyte; /* start at end of original byte array */

    /* Add N-bytes of char N */
    BYTE n_pad = block_size - nbyte;
    for (int i = 0; i < n_pad; i++) {
        *p++ = n_pad;
    }

    return out;
}


/*==============================================================================
 *============================================================================*/
