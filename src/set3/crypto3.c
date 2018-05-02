/*==============================================================================
 *     File: crypto3.c
 *  Created: 05/02/2018, 10:08
 *   Author: Bernie Roesler
 *
 *  Description: Functions for solutions to cryto challenges Set 3
 *
 *============================================================================*/

#include "header.h"
#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"
#include "crypto3.h"

int aes_128_ctr(FILE *y, FILE *x, BYTE *key, BYTE *nonce)
{
    /* Block -> Stream Cipher implementation
     * y : output stream
     * x : input stream
     * key: 128-bit AES key
     * nonce: 64-bit unsigned little endian
     *
     * returns : integer 0 on success, non-zero on failure
     */
    BYTE *counter = bytenrepeat((BYTE *)"\x00", 1, BLOCK_SIZE/2);
    int c;

    /* While x stream not EOF */
    do {
        BYTE *keystream = get_keystream(key, nonce, counter);

        /* Write x ^ keystream to y */
        int n = 0;
        while ((n < BLOCK_SIZE) && ((c = fgetc(x)) != EOF))
        {
            fputc(c ^ keystream[n++], y);
        }
    } while (!feof(x));

    /* Rewind output stream before returning */
    REWIND_CHECK(y);
    return 0;
}

BYTE *get_keystream(BYTE *key, BYTE *nonce, BYTE *counter)
{
    BYTE *keystream = (BYTE *)"HELLO, FRIENDS! JIM NANTZ HERE.";

    /* Create (nonce || counter) */

    /* Encrypt single block to get keystream */
    /* if (0 != aes_128_ecb_block(&keystream, &len, nc, BLOCK_SIZE, key, 1)) { */
    /*     ERROR("Encryption failed!"); */
    /* } */

    return keystream;
}
/*==============================================================================
 *============================================================================*/
