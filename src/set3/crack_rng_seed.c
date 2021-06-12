/*==============================================================================
 *     File: crack_rng_seed.c
 *  Created: 2018-11-29 22:03
 *   Author: Bernie Roesler
 *
 *  Description: Determine an RNG seed knowing it was seeded between two times.
 *
 *============================================================================*/

#include <time.h>
#include "header.h"
#include "util_twister.h"

int main(int argc, char *argv[]) {
    char *filename; 
    char buf[MAX_CHAR];
    FILE *fp;
    time_t start_time, end_time;
    unsigned long rng_1;

    if (argc < 2) {
        filename = "rng.out";
    } else {
        filename = argv[1];
    }

    /* Open the file */
    if (!(fp = fopen(filename, "r"))) {
        ERROR("Could not open file: '%s'", filename);
    }
    
    /* Read 3 lines */
    for (int i = 0; i < 3; i++) {
        if (fgets(buf, MAX_CHAR - 1, fp)) {
            switch (i) {
                case 0:
                    sscanf(buf, "Start: %ld", &start_time);
                    /* printf("Start: %ld\n", start_time); */
                    break;
                case 1:
                    sscanf(buf, "%lu", &rng_1);
                    /* printf("%ld\n", rng_1); */
                    break;
                case 2:
                    sscanf(buf, "End: %ld", &end_time);
                    /* printf("End: %ld\n", end_time); */
                    break;
            }
        } else {
            if (ferror(fp)) { ERROR("Read error in input stream!"); }
        }
    }

    /* Crack RNG seed given first value output */
    /* for (int  */



    return 0;
}


/*==============================================================================
 *============================================================================*/
