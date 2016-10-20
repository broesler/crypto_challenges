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
int StrToUpper1() {
    START_TEST_CASE;
    char *str1 = NEW("test");
    strcpy(str1,"test");
    SHOULD_BE(!strcmp(strtoupper(str1), "TEST")); /* convert in-place */
    SHOULD_BE(!strcmp(strtolower(str1), "test"));
    free(str1);
    END_TEST_CASE;
}

/* This tests conversion of an ASCII string to a hex string, and vice versa */
int HexConvert1() {
    START_TEST_CASE;
    char *str1 = "Man";
    char *hex = atoh(str1);  /* any atoh call must be free'd! */
    SHOULD_BE(!strcmp(hex,"4D616E"));    /* convert to hex */
    char *str2 = htoa(hex);
    SHOULD_BE(!strcmp(str2,str1));       /* convert back to ascii */
    free(hex);
    free(str2);
    END_TEST_CASE;
}

/* This tests conversion of a hex string to a base64 string */
int HexConvert2() {
    START_TEST_CASE;
    char *str1 = "Man";
    char *hex1 = atoh(str1);  /* any atoh call must be free'd! */
    char *b641 = hex2b64_str(hex1);
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str1, hex1, b641);
#endif
    SHOULD_BE(!strcmp(b641, "TWFu"));
    char *str2 = "Ma";
    char *hex2 = atoh(str2);  /* any atoh call must be free'd! */
    char *b642 = hex2b64_str(hex2);
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str2, hex2, b642);
#endif
    SHOULD_BE(!strcmp(b642, "TWE="));
    char *str3 = "M";
    char *hex3 = atoh(str3);  /* any atoh call must be free'd! */
    char *b643 = hex2b64_str(hex3);
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str3, hex3, b643);
#endif
    SHOULD_BE(!strcmp(b643, "TQ=="));
    free(hex1); 
    free(hex2); 
    free(hex3); 
    free(b641);
    free(b642);
    free(b643);
    END_TEST_CASE;
}

/* This tests conversion of a hex string to a base64 string */
int HexConvert3() {
    START_TEST_CASE;
    char *hex1 = "49276d206b696c6c696e6720796f75722" \
                 "0627261696e206c696b65206120706f69" \
                 "736f6e6f7573206d757368726f6f6d";
    char *b641 = hex2b64_str(hex1);
    char *expect = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa" \
                   "WtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    SHOULD_BE(!strcmp(b641, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", b641, expect);
#endif
    free(b641);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void) {
    int fails = 0;
    int total = 0;

    RUN_TEST(StrToUpper1, "strtoupper() test case 1");
    RUN_TEST(HexConvert1, "atoh(),htoa()  test case 1");
    RUN_TEST(HexConvert2, "hex2b64_str()  test case 1");
    RUN_TEST(HexConvert3, "hex2b64_str()  test case 1");

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
