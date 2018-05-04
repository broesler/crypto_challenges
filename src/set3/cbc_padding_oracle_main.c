/*==============================================================================
 *     File: cbc_padding_oracle_main.c
 *  Created: 08/01/2017, 22:51
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 17: CBC decryption with padding oracle
 *
 *      NOTE this code is purposefully set up to reproduce an odd bug that
 *      occurs when j = [5,10) ONLY. Seems to have something to do with how Dy
 *      is calculated or initialized within block_decrypt()? We get the
 *      initialization vector for the first block of the 8th string decrypted...
 *
 *============================================================================*/

#include <time.h>

#include "cbc_padding_oracle.h"

/* Global key, iv used in tests */
/* NOTE Uncomment to allow encryption_oracle() to set these values randomly. Doing so
 * will MOST LIKELY produce a bug in decryption... but sometimes it will produce
 * the correct result. Need to experiment further to see which random values
 * produce the bug and why. My guess is NULLs somewhere... but not sure. */
/* BYTE *global_key = NULL; */
/* BYTE *global_iv  = NULL; */
/* BYTE *global_key = (BYTE *)"BUSINESS CASUAL"; */
/* BYTE *global_iv  = (BYTE *)"\x99\x99\x99\x99\x99\x99\x99\x99" \ */
/*                            "\x99\x99\x99\x99\x99\x99\x99\x99"; */
/* Pseudo-random bytes spit out by RNG when using srand(SRAND_INIT); */
BYTE *global_key = (BYTE *)"\x88\xBF\xA2\x49\x8D\xCC\x42\xB6"\
                           "\xCE\x0C\x55\xB5\xCE\x71\x2A\xA5";
BYTE *global_iv  = (BYTE *)"\x2D\xB8\x55\x63\x5F\xDE\xF8\x4C"\
                           "\x6F\xB5\x6D\xF4\xD7\xAF\xAA\x1A";

int main(int argc, char **argv)
{
    BYTE *y = NULL;
    size_t y_len = 0;
    int n_pad = 0;

    /* FUCK MY DREAMS this bug has to do with the random bytes used in either
     * the global_(key|iv), or the rfs use in block_decrypt() or last_byte(). */
    /* initialize PRNG */
    srand(SRAND_INIT);
    /* srand(time(NULL)); */

    for (size_t j = 0; j < 10; j++) {
        /* Encrypt each string */
        encryption_oracle(&y, &y_len, j); /* maybe reset y to NULL here?? */

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
        /* NOTE valgrind gives "4,096 bytes in 1 block still reachable" for this
         * printall() statement when using random global_(key|iv) */
        printall(x, y_len - n_pad);
        /* print_blocks(x, y_len - n_pad, BLOCK_SIZE, 1); */
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
