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


/* Challenge 18: Implement AES CTR Mode */
int aes_128_ctr(FILE *y, FILE *x, BYTE *key, BYTE *nonce)
{
    /* Block -> Stream Cipher implementation
     * NOTE encryption and decryption are the same operation!!
     * y     : output stream
     * x     : input stream
     * key   : 128-bit AES key
     * nonce : 64-bit unsigned little endian
     *
     * returns : integer 0 on success, non-zero on failure
     */
    int c;
    BYTE *counter = init_byte(BLOCK_SIZE/2);

    do {
        BYTE *keystream = get_keystream_block(key, nonce, counter);

        /* Write x ^ keystream to y */
        int n = 0;
        while ((n < BLOCK_SIZE) && ((c = fgetc(x)) != EOF))
        {
            fputc(c ^ keystream[n++], y);
        }

        if (ferror(x)) { ERROR("Read error in input stream!"); }

        /* Increment counter for next block */
        assert(inc64le(counter) == 0);
        free(keystream);
    } while (!feof(x));

    /* Rewind output stream before returning */
    REWIND_CHECK(y);
    free(counter);
    return 0;
}

BYTE *get_keystream_block(BYTE *key, BYTE *nonce, BYTE *counter)
{
    /* Create one block of the keystream
     * key     : 128-bit AES key
     * nonce   : 64-bit unsigned little endian
     * counter : 64-bit unsigned little endian 
     *
     * returns : pointer to keystream
     */
    BYTE *keystream = NULL;
    BYTE *nc = init_byte(BLOCK_SIZE);
    size_t len = 0;

    /* Create (nonce || counter) */
    memcpy(nc, nonce, BLOCK_SIZE/2);
    memcpy(nc+BLOCK_SIZE/2, counter, BLOCK_SIZE/2);

    /* Encrypt single block to get keystream */
    if (0 != aes_128_ecb_block(&keystream, &len, nc, BLOCK_SIZE, key, 1)) {
        ERROR("Encryption failed!");
    }

    free(nc);
    return keystream;
}

int inc64le(BYTE *counter)
{
    /* Increment little-endian counter
     * counter : 64-bit unsigned little endian counter
     *
     * returns : 0 on success, -1 on overflow
     */
    /* NOTE this function assumes counter is 64-bit, AND the machine on which we
     * are operating is LITTLE-endian!! See notes/endian.sh */
    int out = 0;
    uint32_t hi, lo;
    memcpy(&lo, counter, sizeof(uint32_t));
    memcpy(&hi, counter + sizeof(uint32_t), sizeof(uint32_t));

    /* Check for overflow */
    if (++lo == 0) {
        WARNING("Counter overflow!!"); 
        out = -1;
        hi++;
    }

    /* Copy back into counter */
    memcpy(counter, &lo, sizeof(uint32_t));
    memcpy(counter + sizeof(uint32_t), &hi, sizeof(uint32_t));
    return out;
}

/*==============================================================================
 *============================================================================*/
