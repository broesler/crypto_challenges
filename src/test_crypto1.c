/*==============================================================================
 *     File: test_crypto1.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Tests of cryptography functions in crypto challenges
 *
 *============================================================================*/
/* System headers */
#include <math.h>
#include <string.h>

/* User-defined headers */
#include "header.h"
#include "crypto_util.h"
#include "crypto1.h"
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

/* This tests conversion of an ASCII string to a hex string, and vice versa */
int HexConvert1()
{
    START_TEST_CASE;
    char str1[] = "Man";
    char *hex = atoh(str1);  /* any atoh call must be free'd! */
    SHOULD_BE(!strcmp(hex,"4D616E"));    /* convert to hex */
    char *str2 = htoa(hex);
    SHOULD_BE(!strcmp(str2,str1));       /* convert back to ascii */
    free(hex);
    free(str2);
    END_TEST_CASE;
}

/* This tests conversion of a hex string to a base64 string */
int HexConvert2()
{
    START_TEST_CASE;
    char str1[] = "Man";
    char *hex1 = atoh(str1);  /* any atoh call must be free'd! */
    char *b641 = hex2b64_str(hex1);
    SHOULD_BE(!strcmp(b641, "TWFu"));
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str1, hex1, b641);
#endif
    char str2[] = "Ma";
    char *hex2 = atoh(str2);  /* any atoh call must be free'd! */
    char *b642 = hex2b64_str(hex2);
    SHOULD_BE(!strcmp(b642, "TWE="));
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str2, hex2, b642);
#endif
    char str3[] = "M";
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
int HexConvert3()
{
    START_TEST_CASE;
    char hex1[] = "49276d206b696c6c696e6720796f75722" \
                  "0627261696e206c696b65206120706f69" \
                  "736f6e6f7573206d757368726f6f6d";
    char *b641 = hex2b64_str(hex1);
    char expect[] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa" \
                    "WtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    SHOULD_BE(!strcmp(b641, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", b641, expect);
#endif
    free(b641);
    END_TEST_CASE;
}

/* This tests the XOR of two hex-encoded strings, as well as printing their
 * ASCII conversions */
int FixedXOR1()
{
    START_TEST_CASE;
    char hex1[]   = "1c0111001f010100061a024b53535009181c";
    char hex2[]   = "686974207468652062756c6c277320657965";
    char expect[] = "746865206b696420646f6e277420706c6179";
    strtoupper(expect);  /* always use uppercase */
    char *xor = fixedXOR(hex1, hex2);
    char *ascii1 = htoa(hex1);
    char *ascii2 = htoa(hex2);
    char *ascii3 = htoa(xor);
    SHOULD_BE(!strcmp(xor, expect));
    /* SHOULD_BE(!strcmp(ascii1, "KSSP")); // sketchy, non-printables */
    SHOULD_BE(!strcmp(ascii2, "hit the bull's eye"));
    SHOULD_BE(!strcmp(ascii3, "the kid don't play"));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", xor, expect);
    printf("ascii:\n1: %s\n2: %s\n3: %s\n", ascii1, ascii2, ascii3);
#endif
    free(xor);
    free(ascii1);
    free(ascii2);
    free(ascii3);
    END_TEST_CASE;
}

/* Test the string repeat function */
int Strnrepeat1()
{
    START_TEST_CASE;
    char *key_hex = atoh("ICE");
    char *key_str = strnrepeat_hex(key_hex, strlen(key_hex), 16);
    char *expect = atoh("ICEICEIC");
    SHOULD_BE(!strcmp(key_str, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", key_str, expect);
#endif
    free(expect);
    free(key_hex);
    free(key_str);
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

/* This function tests the character frequency score*/
int CharFreqScore1()
{
    START_TEST_CASE;
    char str1[] = "Anything less than the best is a felony.";
    float test = charFreqScore(str1);
    float tol = 1e-10;
    float expect = 16.430251917634155; /* new score according to <char_test.m> */
    /* float expect = 15.6190082292009702; #<{(| length == all chars |)}># */
    /* float expect = 17.5239402865012082; #<{(| length == just letters |)}># */
    SHOULD_BE(fabsf(test - expect) < tol); 
#ifdef LOGSTATUS
    printf("Got:    %10.4f\nExpect: %10.4f\n", test, expect);
#endif
    END_TEST_CASE;
}

/* This function tests the decoding of a single byte XOR cipher */
int SingleByte1()
{
    START_TEST_CASE;
    char hex1[]   = "1b37373331363f78151b7f2b783431333d78" \
                    "397828372d363c78373e783a393b3736";
    char expect[] = "Cooking MC's like a pound of bacon";
    XOR_NODE *out = singleByteXORDecode(hex1);
    SHOULD_BE(!strcmp(out->plaintext, expect));
#ifdef LOGSTATUS
    printf("key   = 0x%0.2X\n",        out->key);
    printf("score = %8.4f\n",          out->score);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
#endif
    free(out);
    END_TEST_CASE;
}

/* This function tests the decoding of multiple strings in a file */
int FileSingleByte1()
{
    START_TEST_CASE;
    char filename[] = "../data/4.txt";
    /* char filename[] = "../data/4_test.txt"; */
    char expect[] = "Now that the party is jumping";
    XOR_NODE *out = findSingleByteXOR(filename);
    size_t len1 = strlen(out->plaintext);
    size_t len2 = strlen(expect);
    size_t min_str_len = (len1 < len2) ? len1 : len2;
    SHOULD_BE(!strncmp(out->plaintext, expect, min_str_len));
#ifdef LOGSTATUS
    printf("line  = %3d\n",            out->file_line);
    printf("key   = 0x%0.2X\n",        out->key);
    printf("score = %8.4f\n",          out->score);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
#endif
    free(out);
    END_TEST_CASE;
}

/* This function tests the implementation of repeating-key XOR */
int RepeatingKeyXOR1()
{
    START_TEST_CASE;
    char input[]  = "Burning 'em, if you ain't quick and nimble\n" \
                    "I go crazy when I hear a cymbal";
    char key[] = "ICE";
    char *input_hex = atoh(input);
    char *key_hex = atoh(key);
    char expect[] = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d" \
                    "63343c2a26226324272765272a282b2f20430a652e2c652a31" \
                    "24333a653e2b2027630c692b20283165286326302e27282f";
    char *xor = repeatingKeyXOR(input_hex, key_hex);
    SHOULD_BE(!strcmp(xor, strtoupper(expect)));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", xor, expect);
#endif
    free(input_hex);
    free(key_hex);
    free(xor);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(StrToUpper1, "strtoupper() test case 1");
    RUN_TEST(HexConvert1, "atoh(),htoa() test case 1");
    RUN_TEST(HexConvert2, "hex2b64_str() test case 1");
    RUN_TEST(HexConvert3, "hex2b64_str() test case 2");
    RUN_TEST(FixedXOR1, "fixedXOR() test case 1");
    RUN_TEST(Strnrepeat1, "strnrepeat_hex() test case 1");
    RUN_TEST(FindFreq1, "countChars() test case 1");
    RUN_TEST(IsPrintable1, "isprintable() test case 1");
    RUN_TEST(CharFreqScore1, "charFreqScore() test case 1");
    RUN_TEST(SingleByte1, "singleByteXORDecode() test case 1");
    /* Don't always run this file test, it's a bit slow */
    RUN_TEST(FileSingleByte1, "findSingleByteXOR() test case 1");
    RUN_TEST(RepeatingKeyXOR1, "repeatingKeyXOR() test case 1");

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
