/*==============================================================================
 *     File: test_util.c
 *  Created: 07/10/2017, 09:59
 *   Author: Bernie Roesler
 *
 *  Description: Unit tests on utility functions
 *
 *============================================================================*/
/* System headers */
#include <math.h>

/* User-defined headers */
#include "header.h"
#include "crypto_util.h"
#include "unit_test.h"

/* TODO split into "test_util" and "test_crypto1" for better maintenance */

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
int StrToUpper1()
{
    START_TEST_CASE;
    char str1[] = "test!";
    SHOULD_BE(!strcmp(strtoupper(str1), "TEST!")); /* convert in-place */
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", strtoupper(str1), "TEST!");
#endif
    SHOULD_BE(!strcmp(strtolower(str1), "test!"));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", strtolower(str1), "test!");
#endif
    END_TEST_CASE;
}

int StrArray1()
{
    START_TEST_CASE;
    size_t nstr = 3;
    size_t len = 30;
    char **str_arr = init_str_arr(nstr, len);
    strncpy(*(str_arr)  , "Hello, ",  len);
    strncpy(*(str_arr+1), "World!",   len);
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

/* This function tests the validity of printable characters */
int IsPrintable1()
{
    START_TEST_CASE;
    /* everything prints */
    char str1[] = "Anything less than the best is a felony.";
    int test = isprintable(str1);
    int expect = 1;
    SHOULD_BE(test == expect); 
#ifdef LOGSTATUS
    printf("Got:    %d\nExpect: %d\n", test, expect);
    printf("Sizeof: %lu\nStrlen: %lu\n", sizeof(str1)/sizeof(char), strlen(str1));
#endif
    /* include non-printing char */
    char str2[] = "Anything \u1801less than the best is a felony.";
    test = isprintable(str2);
    expect = 0;
    SHOULD_BE(test == expect); 
#ifdef LOGSTATUS
    printf("Got:    %d\nExpect: %d\n", test, expect);
#endif
    END_TEST_CASE;
}

/* This function tests the function to find character frequency in a string */
int FindFreq1()
{
    START_TEST_CASE;
    char str1[] = "HelLo, World!";
    int *cf = countChars(str1);
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

/* Test getHexByte function */
int GetHexByte1()
{
    START_TEST_CASE;
    char hex1[] = "A";
    int hex_int = getHexByte(hex1);
    SHOULD_BE(hex_int == 10);
    char hex2[] = "4D";
    hex_int = getHexByte(hex2);
    SHOULD_BE(hex_int == 77);
    char hex3[] = "4d616e";
    hex_int = getHexByte(hex3);
    SHOULD_BE(hex_int == 77);
    END_TEST_CASE;
}

/* This tests conversion of a byte string to a hex string, and vice versa */
int HexConvert1()
{
    START_TEST_CASE;
    char str1[] = "Man";
    char *hex = atoh(str1);
    SHOULD_BE(!strcasecmp(hex,"4d616e"));
    char *str2 = hex2byte(hex);
    SHOULD_BE(!strcmp(str2,str1));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", str2, str1);
#endif
    /* Test ERROR() macro by giving odd-length hex string: */
    /* char hex1[] = "4D616E7"; */
    /* char *byte1 = hex2byte(hex1); */
    /* printf("byte1: %s\n", byte1); */
    free(hex);
    free(str2);
    END_TEST_CASE;
}

/* Test the string repeat function */
int Strnrepeat1()
{
    START_TEST_CASE;
    char *key_hex = atoh("ICE");
    char *key_str = strnrepeat_hex(key_hex, strlen(key_hex), 16);
    char *expect = atoh("ICEICEIC");
    SHOULD_BE(!strcasecmp(key_str, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", key_str, expect);
#endif
    free(expect);
    free(key_hex);
    free(key_str);
    END_TEST_CASE;
}

/* Test Hamming weight function */
int HammingWeight1()
{
    START_TEST_CASE;
    char *a = atoh("this is a test");
    size_t dist = hamming_weight(a);
    SHOULD_BE(dist == 48);
#ifdef LOGSTATUS
    printf("Got:    %zu\nExpect: %d\n", dist, 48);
#endif
    free(a);
    END_TEST_CASE;
}


/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    /* RUN_TEST(StrToUpper1,    "strtoupper()     "); */
    /* RUN_TEST(StrArray1,      "init_str_arr()   "); */
    /* RUN_TEST(IsPrintable1,   "isprintable()    "); */
    RUN_TEST(FindFreq1,      "countChars()     ");
    RUN_TEST(GetHexByte1,    "getHexByte()     ");
    RUN_TEST(HexConvert1,    "atoh(),htoa()    ");
    RUN_TEST(Strnrepeat1,    "strnrepeat_hex() ");
    RUN_TEST(HammingWeight1, "hamming_dist()   ");

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
