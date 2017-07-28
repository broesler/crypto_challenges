/*==============================================================================
 *     File: make_admin_profile.c
 *  Created: 07/28/2017, 17:46
 *   Author: Bernie Roesler
 *
 *  Description: 
 *
 *============================================================================*/
#include <stdio.h>

#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "crypto2.h"

#define SRAND_INIT 0

/*------------------------------------------------------------------------------
 *          Challenge 13: ECB cut-and-paste
 *----------------------------------------------------------------------------*/
/* Make a "role=admin" profile but using only user input to profile_for() to
 * generate valid ciphertexts, then swap ciphertexts to get "role: 'admin'" */
int main(void)
{
    char *profile1 = NULL,
         *profile2 = NULL,
         *profile = NULL;
    static BYTE *key = NULL;   /* random key, save for decryption */
    BYTE *y1 = NULL,
         *y2 = NULL,
         *y = NULL;

    /* Strategy: Create block with just "admin" and block with profile up to
     * "role=", then combine the two ciphertexts to get the entire profile */
    /*              #1               #2             #3
     * (a)    |email=bernie@me.|admin\x0B...\x0B|&uid=...   |     #2
     * (b)  + |email=bernie@me.|com&uid=56&role=|user\x0C...|     #1-2
     *      ------------------------------------------------------
     * (c)    |email=bernie@me.|com&uid=56&role=|admin\x0B...\x0B|  */

    /* Need email long enough to push "user" into third block, so second block
     * ends with "role=". */
    /* total string will be: "email=bernie@me.|com&uid=56&role=|user\x0C..." */
    char email1[] = "bernie@me.com";

    /* Need "admin" at the start of a ciphertext block */
    /* total string will be "email=bernie@me.|admin\x0B...\x0B|&uid=..." */
    char email2[] = "bernie@me.admin";
    size_t faux_block = 2*BLOCK_SIZE - strlen("email=");
    BYTE *email2_pad = pkcs7_pad((BYTE *)email2, strlen(email2), faux_block);

    /* Make profiles */
    profile1 = profile_for(email1);
    profile2 = profile_for((char *)email2_pad);

    /* Encrypt each email and swap blocks */
    encrypt_profile(&y1, &key, profile1);
    encrypt_profile(&y2, &key, profile2);

    /* Build faux ciphertext */
    size_t y_len = 3*BLOCK_SIZE;
    y = init_byte(y_len);
    memcpy(y,                y1,              2*BLOCK_SIZE); /* #1-2 */
    memcpy(y + 2*BLOCK_SIZE, y2 + BLOCK_SIZE,   BLOCK_SIZE); /* #2 */

    /* Decrypt substituted ciphertext */
    profile = decrypt_profile(y, y_len, key);

    printf("%s", profile);

    /* Clean-up */
    free(profile1);
    free(profile2);
    free(profile);
    free(key);
    free(y1);
    free(y2);
    free(y);
    free(email2_pad);

    return 0;
}


/*==============================================================================
 *============================================================================*/
