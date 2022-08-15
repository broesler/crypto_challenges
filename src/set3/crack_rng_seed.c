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


/* Generate a random number in a range *not* using the MT */
unsigned long rand_integer(int lo, int hi) {
    return rand() % (hi + 1 - lo) + lo;
}


/* Use the Mersenne Twister RNG object */
unsigned long wait_and_seed(RNG_MT *rng) {
    sleep(rand_integer(1, 10));  /* wait a random number of seconds */
    srand_mt(rng, time(NULL));   /* seed with the current Unix timestamp */
    sleep(rand_integer(1, 10));  /* wait a random number of seconds again */
    return rand_int32(rng);      /* return the first output of the RNG */
}


int main(int argc, char *argv[]) {
    time_t start_time, end_time;
    unsigned long x, y, test_seed;

    /* Wait a random amount of time before and after seeding the rng. */
    RNG_MT *rng = init_rng_mt();
    start_time = time(NULL);
    x = wait_and_seed(rng);
    end_time = time(NULL);
    printf("Start: %ld\n", start_time);
    printf("End: %ld\n", end_time);
    printf("x = %ld\n", x);

    /* Crack RNG seed given first value output */
    for (int i = 0; i < (end_time - start_time + 1); i++) {
        test_seed = end_time - i;
        srand_mt(rng, test_seed);  /* seed the RNG with a fake "time" */
        y = rand_int32(rng);       /* generate the first random number */
        if (y == x) {
            printf("y = %lu\nseed found! seed = %lu\n", y, test_seed);
            break;
        }
    }

    free(rng);
    return 0;
}


/*==============================================================================
 *============================================================================*/
