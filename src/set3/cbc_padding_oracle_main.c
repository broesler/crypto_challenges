/*==============================================================================
 *     File: cbc_padding_oracle_main.c
 *  Created: 08/01/2017, 22:51
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 17: CBC decryption with padding oracle
 *
 *============================================================================*/

#include "cbc_padding_oracle.h"

// Global key, iv used in tests
BYTE *global_key = NULL;
BYTE *global_iv  = NULL;

int main(int argc, char **argv)
{
    BYTE *y = NULL;
    size_t y_len = 0;

    /* initialize PRNG */
    /* srand(SRAND_INIT); */
    srand(time(NULL));

    /* Encrypt random string */
    encryption_oracle(&y, &y_len);

    size_t Nb = y_len / BLOCK_SIZE;
    BYTE *x = init_byte(y_len);

    /* start at 1 because we don't have IV */
    for (size_t i = 1; i < Nb; i++) {
    /* for (size_t i = 1; i < 2; i++) { */
        size_t idx = i*BLOCK_SIZE,
               im1 = (i-1)*BLOCK_SIZE;
        /* Decrypt block to get D(y) */
        BYTE *xp = NULL;
        block_decrypt(&xp, y+idx);
        /* x = D(y) ^ y_{n-1} */
        BYTE *xg = fixedXOR(xp, y+im1, BLOCK_SIZE);
        /* Store in output array */
        memcpy(x+idx, xg, BLOCK_SIZE);
        free(xp);
        free(xg);
    }

    /* print result */
    printf("\nx = \"");
    print_blocks(x, y_len, BLOCK_SIZE, 1);
    printf("\"\n");

    free(x);
    free(y);
    free(global_key);
    free(global_iv);
    return 0;
}

/*==============================================================================
 *============================================================================*/
