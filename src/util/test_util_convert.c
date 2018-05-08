/*==============================================================================
 *     File: test_utiL_convert.c
 *  Created: 05/07/2018, 17:04
 *   Author: Bernie Roesler
 *
 *  Description: Test conversion utilities
 *
 *============================================================================*/

/* User-defined headers */
#include "header.h"
#include "crypto_util.h"
#include "unit_test.h"

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

/* Test getHexByte function */
int GetHexByte1()
{
    START_TEST_CASE;
    char hex1[] = "A";
    BYTE hex_int = getHexByte(hex1);
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
    BYTE byte1[] = "Man";
    char *hex = byte2hex(byte1, 3);
    SHOULD_BE(!strcasecmp(hex, "4d616e"));
    BYTE *byte2 = NULL;
    size_t nbyte = hex2byte(&byte2, hex);
    SHOULD_BE(nbyte == 3);
    SHOULD_BE(!memcmp(byte2, byte1, nbyte));
#ifdef LOGSTATUS
    printf("Got:    %.*s\nExpect: %.*s\n", (int)nbyte, byte2, (int)nbyte, byte1);
#endif
    free(hex);
    free(byte2);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(StrToUpper1,    "strtoupper()        ");
    RUN_TEST(GetHexByte1,    "getHexByte()        ");
    RUN_TEST(HexConvert1,    "atoh(),htoa()       ");

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
