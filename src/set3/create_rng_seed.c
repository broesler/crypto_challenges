/*==============================================================================
 *     File: create_rng_seed.c
 *  Created: 2018-11-18 20:25
 *   Author: Bernie Roesler
 *
 *  Challenge 22: Create an MT19937 seed from a random timestamp.
 *
 *============================================================================*/

#include <stdlib.h>
#include <time.h>
#include "header.h"
#include "util_twister.h"

/* TODO combine this function into a single script with crack_rng_seed.c */
/* Generate a random number in a range *not* using the MT */
unsigned long rand_integer(int lo, int hi) {
    return rand() % (hi + 1 - lo) + lo;
}

unsigned long wait_and_seed() {
    sleep(rand_integer(1, 20));  /* wait a random number of seconds */
    srand_mt(time(NULL));        /* seed with the current Unix timestamp */
    sleep(rand_integer(1, 20));  /* wait a random number of seconds again */
    return rand_int32();         /* return the first output of the RNG */
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
