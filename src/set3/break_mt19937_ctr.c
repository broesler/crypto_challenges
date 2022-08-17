/*==============================================================================
 *     File: break_mt19937_ctr.c
 *  Created: 2022-08-16 20:45
 *   Author: Bernie Roesler
 *
 * Challenge 24: Break MT19937 CTR stream cipher.
 *
 *============================================================================*/

#include "header.h"
#include "fmemopen.h" /* allow string as file stream */
#include "crypto_util.h"
#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"
#include "crypto3.h"

int main(void)
{
    srand(565656);  /* seed the built-in RNG */
    short seed = (short)565656;  /* the "key" */
    char *known = "AAAAAAAAAAAAAA";  /* 14 A's */
    size_t k_len = strlen(known);

    /* Add a random number of random padding characters */
    int n_pad = RAND_RANGE(1, 16);
    int x_len = n_pad + k_len;
    BYTE *x = rand_byte(x_len);
    strlcpy((char *)x + n_pad, known, k_len); 

    /* Encrypt the known string as a stream */
    FILE *xs = fmemopen(x, x_len, "r");
    FILE *ys = tmpfile();
    assert(mersenne_ctr(ys, xs, seed) == EXIT_SUCCESS);  /* encrypt x -> y */

    free(x);
    fclose(xs);
    fclose(ys);
    return EXIT_SUCCESS;
}

/*==============================================================================
 *============================================================================*/
