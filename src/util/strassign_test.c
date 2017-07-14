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
 * Method 2: identical to method 1
 * Mehtod 3: 
 ******************************************************************************/

/* Test getHexByte function */
int StrassignTest()
{
    START_TEST_CASE;
    /* Method 1: Single char */
    char ascii;

    /* Method 2: String of length 1 */
    /* char ascii[2]; */
    /* BZERO(ascii, 2*sizeof(char)); */

    /* String initializations are identical functionally */
    /* full string of ascii chars */
    char ascii_str[0x101];
    BZERO(ascii_str, 0x101*sizeof(char));

    /* Method 3: pointer for assignment */
    /* full string of ascii chars */
    char test_str[0x101];
    BZERO(test_str, 0x101*sizeof(char));

    char *p = test_str;   /* pointer to start of string */

    /* NOTE Need to start at '0x01'!!! If we start at 0x00, the strncat method
     * finds the end of ascii_str at ascii_str[0], because it's NULL (== 0x00),
     * and concatenates another NULL, which effectively does nothing because we
     * BZERO'd the string. At i = 0x01, everything proceeds as normal, and
     * since we can't print a NULL, it looks as if we've perfectly gotten every
     * character. 
     *
     * For the pointer method, on the other hand, when we set and move the
     * pointer to the next memory location (*p++ = ...), we just skip over the
     * slot we assigned to NULL == 0x00, so the string test_str APPEARS to end
     * at test_str[0] with the NULL we left there!
     *
     * So, in regards to crypto code, the pointer method does more faithfully
     * copy character-by-character into the memory slots alotted; however, we
     * should build in a check that strlen(xor) == strlen(inputs) before
     * accepting a string as valid output */
    /* loop over all possible ascii chars (except 0x00 == NULL) */
    for (size_t i = 0x01; i < 0x100; i++)
    {
        /* Method 1: */
        ascii = (char)i;
        strncat(ascii_str, &ascii, 1);

        /* Method 2: */
        /* snprintf(ascii, 2, "%c", (char)i); */
        /* strncat(ascii_str, ascii, 1); */

        /* Assignment method 3: */
        *p++ = (char)i;

        /* Print character table */
        if (isprint(i)) {
            /* Method 1: */
            printf("%0.2zX\t%0.3zu\t'%c'\t'%c'\n", i, i, ascii, *(p-1));
            /* Method 2: */
            /* printf("%0.2zX\t%0.3zu\t'%c'\t'%c'\n", i, i, ascii[0], *(p-1)); */
            /* Method 3: */
            /* printf("%0.2zX\t%0.3zu\t'%c'\t'%c'\n", i, i, ascii, *(test_str+(i-1))); */
        /* } else { */
        /*     #<{(| funky double cast otherwise we'll get \\xfffffff instead of right value |)}># */
        /*     unsigned int c1 = (unsigned int)(unsigned char)ascii[i]; */
        /*     unsigned int c2 = (unsigned int)(unsigned char)*(p-1); */
        /*     printf("%0.2zX\t%0.3zu\t\\x%02x\t\\x%02x\n", i, i, c1, c2); */
        }
    }

    /* Print entire strings to make sure assignment happened */
    printf("ascii: |||%s|||\n", ascii_str);
    printf("test: |||%s|||\n", test_str);
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
