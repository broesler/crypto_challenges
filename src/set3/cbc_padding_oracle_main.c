/*==============================================================================
 *     File: cbc_padding_oracle_main.c
 *  Created: 08/01/2017, 22:51
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 17: CBC decryption with padding oracle
 *
 *============================================================================*/

#include "cbc_padding_oracle.h"

/* Global key, iv used in tests */
/* BYTE *global_key = NULL; */
/* BYTE *global_iv  = NULL; */
BYTE *global_key = (BYTE *)"BUSINESS CASUAL";
BYTE *global_iv  = (BYTE *)"\x99\x99\x99\x99\x99\x99\x99\x99" \
                           "\x99\x99\x99\x99\x99\x99\x99\x99";

int main(int argc, char **argv)
{
    BYTE *y = NULL;
    size_t y_len = 0;
    int n_pad = 0;

    /* initialize PRNG */
    srand(SRAND_INIT);
    /* srand(time(NULL)); */

    for (size_t j = 5; j < 10; j++) {
        /* Encrypt each string */
        encryption_oracle(&y, &y_len, j);

        size_t Nb = y_len / BLOCK_SIZE;
        BYTE *x = init_byte(y_len);

        /* Decrypt all blocks */
        for (size_t i = 0; i < Nb; i++) {
            size_t idx = i*BLOCK_SIZE,
                   im1 = (i-1)*BLOCK_SIZE;

            /* Decrypt block to get D(y) */
            BYTE *Dy = NULL;
            block_decrypt(&Dy, y + idx);

            /* IV assumed known */
            BYTE *yim1 = (i == 0) ? global_iv : (y + im1);

            /* x = D(y) ^ y_{n-1} */
            BYTE *xg = fixedXOR(Dy, yim1, BLOCK_SIZE);
            n_pad = pkcs7_rmpad(xg, BLOCK_SIZE, BLOCK_SIZE);

            /* Store in output array */
            memcpy(x + idx, xg, BLOCK_SIZE);
            free(Dy);
            free(xg);
        }

        /* print result */
        printall(x, y_len - n_pad);
        printf("\n");
        free(x);
        free(y);
    }

    /* free(global_key); */
    /* free(global_iv); */
    return 0;
}

/*==============================================================================
 *============================================================================*/
