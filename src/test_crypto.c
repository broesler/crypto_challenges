/*==============================================================================
 *     File: test_crypto.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: 
 *
 *============================================================================*/
#include <string.h>

/* User-defined headers */
#include "header.h"
#include "crypto.h"
#include "unit_test.h"

    /* print '---- hex2b64_str ----' */
    /* # Simple ASCII string to base64 string */
    /* test(crp.hex2b64_str('Man'.encode('hex')), 'TWFu') */
    /* test(crp.hex2b64_str('Ma'.encode('hex')), 'TWE=') */
    /* test(crp.hex2b64_str('M'.encode('hex')), 'TQ==') */
    /*  */
    /* # Hex string to base64 string */
    /* # I/O test taken from <http://cryptopals.com/sets/1/challenges/1> */
    /* string = '49276d206b696c6c696e6720796f75722'\ */
    /*          '0627261696e206c696b65206120706f69'\ */
    /*          '736f6e6f7573206d757368726f6f6d' */
    /* expect = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa'\ */
    /*          'WtlIGEgcG9pc29ub3VzIG11c2hyb29t' */
    /*  */
    /* # Input already a hex-encoded string */
    /* test(crp.hex2b64_str(string), expect) */
    /* print '    |\tascii:  \'%s\'' % string.decode('hex') */
/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* This tests conversion of a hex string to a base64 string */
int HexConvert1() {
    START_TEST_CASE;
    char *str1 = "Man";
    /* unsigned int hex_str = 0x4d616e; // == "Man" */
    int hex_str = 0x4d;
    printf("%c\n", hex_str);
    /* char *b64_str = hex2b64(hex_str); */
    /* SHOULDBE( */
    print_hex(str1);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void) {
    int fails = 0;
    int total = 0;

    RUN_TEST(HexConvert1, "push() test case 1");

    /* Count errors */
    if (!fails) {
        printf("All %d tests passed!\n", total); 
        return 0;
    } else {
        printf("\033[0;31m%d/%d tests failed!\033[0m\n", fails, total);
        return 1;
    }
}

/*==============================================================================
 *============================================================================*/
