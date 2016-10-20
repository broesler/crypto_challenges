/*==============================================================================
 *     File: test_crypto.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Tests of cryptography functions in crypto challenges
 *
 *============================================================================*/
#include <string.h>

/* User-defined headers */
#include "header.h"
#include "crypto.h"
#include "unit_test.h"

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
    SHOULD_BE(!strcmp(b641, "TWFu"));
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str1, hex1, b641);
#endif
    char *str2 = "Ma";
    char *hex2 = atoh(str2);  /* any atoh call must be free'd! */
    char *b642 = hex2b64_str(hex2);
    SHOULD_BE(!strcmp(b642, "TWE="));
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str2, hex2, b642);
#endif
    char *str3 = "M";
    char *hex3 = atoh(str3);  /* any atoh call must be free'd! */
    char *b643 = hex2b64_str(hex3);
    SHOULD_BE(!strcmp(b643, "TQ=="));
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str3, hex3, b643);
#endif
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

/* This tests the XOR of two hex-encoded strings */
int FixedXOR1() {
    START_TEST_CASE;
    char hex1[]   = "1c0111001f010100061a024b53535009181c";
    char hex2[]   = "686974207468652062756c6c277320657965";
    char expect[] = "746865206b696420646f6e277420706c6179";
    strtoupper(expect);  /* always use uppercase */
    char *xor = fixedXOR(hex1, hex2);
    SHOULD_BE(!strcmp(xor, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", xor, expect);
#endif
    free(xor);
    END_TEST_CASE;
}

/* This function tests the decoding of a single byte XOR cipher */
int GetFreq1() {
    START_TEST_CASE;
    char *str1 = "Hello";
    int count[26] = {0};
    findFreqOrder(str1, count);
    for (int i = 0; i < 26; i++) {
        printf("%c  %d\n", i+'a', count[i]);
    }
    /* SHOULD_BE(!strcmp(plaintext, expect)); */
    free(plaintext);
    END_TEST_CASE;
}

/* #<{(| This function tests the decoding of a single byte XOR cipher |)}># */
/* int SingleByte1() { */
/*     START_TEST_CASE; */
/*     #<{(| char hex1[]   = "1b37373331363f78151b7f2b783431333d78" \ |)}># */
/*     #<{(|                  "397828372d363c78373e783a393b3736"; |)}># */
/*     char expect[] = "Cooking MC's like a pound of bacon"; */
/*     char hex1[] = "4D616E"; */
/*     char *plaintext = singleByteXORDecode(hex1); */
/*     SHOULD_BE(!strcmp(plaintext, expect)); */
/* #ifdef LOGSTATUS */
/*     printf("Got:    %s\nExpect: %s\n", plaintext, expect); */
/* #endif */
/*     free(plaintext); */
/*     END_TEST_CASE; */
/* } */
/*  */
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
    RUN_TEST(FixedXOR1, "fixedXOR()  test case 1");
    RUN_TEST(SingleByte1, "singleByteXORDecode()  test case 1");

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
