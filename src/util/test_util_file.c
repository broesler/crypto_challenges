/*==============================================================================
 *     File: test_utiL_file.c
 *  Created: 05/07/2018, 17:18
 *   Author: Bernie Roesler
 *
 *  Description: 
 *
 *============================================================================*/

/* User-defined headers */
#include "header.h"
#include "crypto_util.h"
#include "unit_test.h"

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* Test lines_in_file() */
int LineInFile1()
{
    START_TEST_CASE;
    char filename[] = "../../data/19.txt";
    size_t Nl = lines_in_file(filename);
    SHOULD_BE(Nl == 40);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(LineInFile1,    "lines_in_file()     ");

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
