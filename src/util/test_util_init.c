/*==============================================================================
 *     File: test_util_init.c
 *  Created: 05/07/2018, 17:15
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
int StrArray1()
{
    START_TEST_CASE;
    size_t nstr = 3;
    size_t len = 30;
    char **str_arr = init_str_arr(nstr, len);
    strncpy(*(str_arr)  , "Hello, ",   len);
    strncpy(*(str_arr+1), "World!",    len);
    strncpy(*(str_arr+2), " Goodbye.", len);
#ifdef LOGSTATUS
    for (size_t i = 0; i < nstr; i++) {
        printf("%s", *(str_arr+i));
    }
    printf("\n");
#endif
    SHOULD_BE(!strncmp(*(str_arr)  , "Hello, ",  len));
    SHOULD_BE(!strncmp(*(str_arr+1), "World!",   len));
    SHOULD_BE(!strncmp(*(str_arr+2), " Goodbye.", len));
    free_str_arr(str_arr, nstr);
    END_TEST_CASE;
}

/* Test the string repeat function */
int Strnrepeat1()
{
    START_TEST_CASE;
    BYTE key[] = "ICE";
    BYTE *key_arr = bytenrepeat(key, 3, 8);
    BYTE expect[] = "ICEICEIC";
    SHOULD_BE(!memcmp(key_arr, expect, 8));
#ifdef LOGSTATUS
    char *ascii = byte2str(key_arr, 8);
    printf("Got:    %s\nExpect: %.*s\n", ascii, 8, expect);
    free(ascii);
#endif
    free(key_arr);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(StrArray1,      "init_str_arr()      ");
    RUN_TEST(Strnrepeat1,    "strnrepeat_hex()    ");

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
