/*==============================================================================
 *     File: crack_rng_seed.c
 *  Created: 2018-11-29 22:03
 *   Author: Bernie Roesler
 *
 *  Challenge 22: Determine an RNG seed knowing it was seeded between two times.
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
    sleep(rand_integer(1, 10));  /* wait a random number of seconds */
    srand_mt(time(NULL));        /* seed with the current Unix timestamp */
    sleep(rand_integer(1, 10));  /* wait a random number of seconds again */
    return rand_int32();         /* return the first output of the RNG */
}

int main(int argc, char *argv[]) {
    time_t start_time, end_time;
    unsigned long x, y, test_seed;

    /* Wait a random amount of time before and after seeding the rng. */
    start_time = time(NULL);
    x = wait_and_seed();
    end_time = time(NULL);
    printf("Start: %ld\n", start_time);
    printf("x = %ld\n", x);
    printf("End: %ld\n", end_time);

    /* Crack RNG seed given first value output */
    for (int i = 0; i < (end_time - start_time + 1); i++) {
        test_seed = end_time - i;
        srand_mt(test_seed);        /* seed the RNG with a fake "time" */
        y = rand_int32();           /* generate the first random number */
        if (y == x) {
            printf("seed = %lu\ny = %lu\n", test_seed, y);
            break;
        }
    }

    return 0;
}


/*==============================================================================
 *============================================================================*/
