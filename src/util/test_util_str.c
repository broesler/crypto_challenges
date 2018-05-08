/*==============================================================================
 *     File: test_util_str.c
 *  Created: 05/07/2018, 17:11
 *   Author: Bernie Roesler
 *
 *  Description: Test util_str.c functions.
 *
 *============================================================================*/

/* User-defined headers */
#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"
#include "unit_test.h"

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* TODO test indexof */

/* This function tests the function to find character frequency in a string */
int FindFreq1()
{
    START_TEST_CASE;
    BYTE str1[] = "HelLo, World!";
    int *cf = countChars(str1, strlen((char *)str1));
    SHOULD_BE(cf['H'-'A'] == 1);
    SHOULD_BE(cf['e'-'a'] == 1);
    SHOULD_BE(cf['L'-'A'] == 3);
    SHOULD_BE(cf['o'-'a'] == 2);
    SHOULD_BE(cf['W'-'A'] == 1);
    SHOULD_BE(cf['r'-'a'] == 1);
    SHOULD_BE(cf['d'-'a'] == 1);
    free(cf);
    END_TEST_CASE;
}

/* Test Hamming weight function */
int HammingWeight1()
{
    START_TEST_CASE;
    BYTE str[] = "this is a test";
    size_t dist = hamming_weight(str, strlen((char *)str));
    SHOULD_BE(dist == 48);
#ifdef LOGSTATUS
    printf("Got:    %zu\nExpect: %d\n", dist, 48);
#endif
    END_TEST_CASE;
}

/* Test strrmchr function */
int Strrmchr1()
{
    START_TEST_CASE;
    char str[] = "Hello, World!";
    char *dest = strrmchr(str, "l!");
    SHOULD_BE(!strcmp(dest, "Heo, Word"));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", dest, "Heo, Word");
#endif
    free(dest);
    END_TEST_CASE;
}

/* Test strescchr function */
int Strescchr1()
{
    START_TEST_CASE;
    char str[] = "Hello, World!";
    char *dest = strescchr(str, "l!");
    char expect[] = "He\\l\\lo, Wor\\ld\\!";
    SHOULD_BE(!strcmp(dest,expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", dest, expect);
#endif
    free(dest);
    END_TEST_CASE;
}

/* Test strescchr function */
int StrHTMLesc1()
{
    START_TEST_CASE;
    char str[] = "Hello, World!";
    char *dest = strhtmlesc(str, "l!");
    char expect[] = "He%6C%6Co, Wor%6Cd%21";
    SHOULD_BE(!strcmp(dest,expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", dest, expect);
#endif
    free(dest);
    END_TEST_CASE;
}

/* Test count chars */
int CntChr1()
{
    START_TEST_CASE;
    char str[] = "this is a test.";
    size_t cnt = cntchr(str, 'i');
    SHOULD_BE(cnt == 2);
    END_TEST_CASE;
}


/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(FindFreq1,      "countChars()        ");
    RUN_TEST(HammingWeight1, "hamming_dist()      ");
    RUN_TEST(Strrmchr1,      "strrmchr()          ");
    RUN_TEST(Strescchr1,     "strescchr()         ");
    RUN_TEST(StrHTMLesc1,    "strhtmlesc()        ");
    RUN_TEST(CntChr1,        "cntchr()            ");

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
