/*==============================================================================
 *     File: create_rng_seed.c
 *  Created: 2018-11-18 20:25
 *   Author: Bernie Roesler
 *
 *  Description: Create an MT19937 seed from a random timestamp.
 *
 *============================================================================*/

#include <time.h>
#include "header.h"
#include "util_twister.h"

unsigned long wait_and_seed() {
    /* Wait a random number of seconds between, I don't know, 40 and 1000. */
    sleep(rand_rangec_int32(40, 1000));

    /* Seeds the RNG with the current Unix timestamp */
    srand_mt(time(NULL));

    /* Wait a random number of seconds again. */
    sleep(rand_rangec_int32(40, 1000));

    /* Return the first 32 bit output of the RNG. */
    return rand_int32();
}

int main(void) {
    /* Record start/end times, and first output of RNG */
    time_t start_time = time(NULL);
    unsigned long out = wait_and_seed();
    time_t end_time = time(NULL);
    printf("Start: %ld\n", start_time);
    printf("%ld\n", out);
    printf("End: %ld\n", end_time);
    return 0;
}

/*==============================================================================
 *============================================================================*/
