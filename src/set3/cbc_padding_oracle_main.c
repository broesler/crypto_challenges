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
/* Try these "random" values that gave the following results */
BYTE *global_key = (BYTE *)"\x43\x4F\x84\xFD\x14\x36\xD1\x2F"\
                           "\x83\x3B\xF1\xE0\xF1\xF6\xFB\x68";
BYTE *global_iv  = (BYTE *)"\x53\x35\xF6\x4C\x1F\x7D\x2B\xA0"\
                           "\x7C\x91\x7D\x27\x5B\x0A\x80\xCA";

/* In the following case, the 2nd block of string 6 finds a "valid" padding of
 * \x02, so we find 2 bytes of Dy */
/* Output:
 * global_key set to: \x43\x4F\x84\xFD\x14\x36\xD1\x2F\x83\x3B\xF1\xE0\xF1\xF6\xFB\x68
 * global_iv  set to: \x53\x35\xF6\x4C\x1F\x7D\x2B\xA0\x7C\x91\x7D\x27\x5B\x0A\x80\xCA
 * 000000Now that t||he party is jump||ing
 * 000001With the b||ass kicked in an||d the Vega's are pumpin'
 * 000002Quick to t||he point, to the|| point, no faking
 * 000003Cooking MC||'s like a pound ||of bacon
 * 000004Burning 'e||m, if you ain't ||quick and nimble
 * 000005I go crazy|| when I hear a c||ymbal
 * 000006And a high||0\x87\xFA'\xBD\x1D\xBF\xB8\xEF;l\xBC\xF9\x86uT||ed up tempo
 * 000007I'm on a r||oll, it's time t||o go solo
 * 000008ollin' in ||my five point oh||
 * 000009ith my rag||-top down so my ||hair can blow
 */

int main(int argc, char **argv)
{
    BYTE *y = NULL;
    size_t y_len = 0;
    int n_pad = 0;

    /* initialize PRNG */
    /* srand(SRAND_INIT); */
    srand(time(NULL));

    for (size_t j = 6; j < 7; j++) {
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
