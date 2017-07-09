/*==============================================================================
 *     File: strassign_test.c
 *  Created: 07/08/2017, 22:13
 *   Author: Bernie Roesler
 *
 *  Description: Test apparent string assignment anomaly
 *
 *============================================================================*/
#include <ctype.h>

#include "header.h"
#include "unit_test.h"

/*******************************************************************************
 * NOTE on string assignment:
 * Method 1: words as expected for assigning to ascii_str
 * Method 2: ascii_str has values shifted by 5 relative to pointer assignment
 ******************************************************************************/

/* Test getHexByte function */
int StrassignTest()
{
    START_TEST_CASE;
    /* Method 1: Single char */
    /* char ascii; */

    /* Method 2: String of length 1 */
    char ascii[2];
    BZERO(ascii, 2*sizeof(char));

    /* String initializations are identical functionally */
    /* full string of ascii chars */
    /* char ascii_str[0x100]; */
    char *ascii_str = malloc(0x100*sizeof(char));
    MALLOC_CHECK(ascii_str);
    BZERO(ascii_str, 0x100*sizeof(char));

    /* Method 3: pointer for assignment */
    /* full string of ascii chars */
    /* char test_str[0x100]; */
    char *test_str = malloc(0x100*sizeof(char));
    MALLOC_CHECK(test_str);
    BZERO(test_str, 0x100*sizeof(char));

    char *p = test_str;   /* pointer to start of string */

    /* loop over all possible ascii chars */
    for (size_t i = 0x00; i < 0x100; i++)
    {
        /* Method 1: */
        /* ascii = (char)i; */
        /* strncat(ascii_str, &ascii, 1); */

        /* Method 2: */
        snprintf(ascii, 2, "%c", (char)i);
        strncat(ascii_str, ascii, 1);

        /* Assignment method 3: */
        *p++ = (char)i;

        /* Print character table */
        if (isprint(i)) {
            /* Method 1: */
            /* printf("%0.2zX\t%0.3zu\t'%c'\t'%c'\n", i, i, ascii, *(p-1)); */
            /* Method 2: */
            printf("%0.2zX\t%0.3zu\t'%c'\t'%c'\n", i, i, ascii[i], *(p-1));
            /* Method 3: */
            /* This line prints NOTHING for last char */
            /* printf("%0.2X\t%0.3d\t'%c'\t'%c'\n", i, i, ascii, *(test_str+i)); */
        /* } else { */
        /*     #<{(| funky double cast otherwise we'll get \\xfffffff instead of right value |)}># */
        /*     unsigned int c1 = (unsigned int)(unsigned char)ascii[i]; */
        /*     unsigned int c2 = (unsigned int)(unsigned char)*(p-1); */
        /*     printf("%0.2zX\t%0.3zu\t\\x%02x\t\\x%02x\n", i, i, c1, c2); */
        }
    }

    /* Print entire strings to make sure assignment happened */
    printf("ascii: %s\n", ascii_str);
    printf(" test: %s\n", test_str);
    SHOULD_BE(!strcmp(ascii_str, test_str));
    printf("strcmp =  %d\n", strcmp(ascii_str, test_str));
    /* Clean-up if using [cm]alloc */
    /* free(ascii_str); */
    /* free(test_str); */
    END_TEST_CASE;
}

int main(void)
{
    int fails = 0;
    int total = 0;
    RUN_TEST(StrassignTest, "string assignment");

    /* Count errors */
    if (!fails) {
        printf("\033[0;32mAll %d tests passed!\033[0m\n", total); 
        return 0;
    } else {
        printf("\033[0;31m%d/%d tests failed!\033[0m\n", fails, total);
        return 1;
    }
}
/*==============================================================================
 *============================================================================*/
