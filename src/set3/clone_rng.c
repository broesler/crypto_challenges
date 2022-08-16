/*==============================================================================
 *     File: clone_rng.c
 *  Created: 2022-08-14 22:56
 *   Author: Bernie Roesler
 *
 * Challenge 23: Clone an RNG from its output.
 *
 *============================================================================*/

#include <time.h>
#include "util_twister.h"


int main(void) {
    /* Create 2 MT19337 instances */
    RNG_MT *rng = init_rng_mt();
    RNG_MT *clone = init_rng_mt();
    assert(rng != clone);

    /* Generate 624 numbers from the original rng */
    for (int i = 0; i < _N; i++) {
        unsigned long x = rand_int32(rng);
        unsigned long y = untemper(x);
        clone->state[i] = y;
        clone->idx++;
        assert(rng->state[i] == clone->state[i]);
    }

    /* Print the next 10 numbers from each RNG */
    for (int i = 0; i < 10; i++) {
        unsigned long x = rand_int32(rng);
        unsigned long y = rand_int32(clone);
        assert(x == y);
#ifdef LOGSTATUS
        printf("%3d: %10lu, %10lu\n", i, x, y);
#endif
    }

    free(rng);
    free(clone);
    return EXIT_SUCCESS;
}

/*==============================================================================
 *============================================================================*/
