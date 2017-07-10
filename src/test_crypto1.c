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

/* User-defined headers */
#include "header.h"
#include "crypto_util.h"
#include "crypto1.h"
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
    char hex3[] = "4d616E";
    hex_int = getHexByte(hex3);
    SHOULD_BE(hex_int == 77);
    END_TEST_CASE;
}

/* This tests conversion of an ASCII string to a hex string, and vice versa */
int HexConvert1()
{
    START_TEST_CASE;
    char str1[] = "Man";
    char *hex = atoh(str1);               /* any atoh call must be free'd! */
    SHOULD_BE(!strcasecmp(hex,"4d616e")); /* convert to hex */
    char *str2 = htoa(hex);               /* convert back to ascii */
    SHOULD_BE(!strcmp(str2,str1));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", str2, str1);
#endif
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

/* This tests conversion of a hex string to a base64 string */
int HexConvert4()
{
    START_TEST_CASE;
    char hex1[] = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d" \
                   "63343c2a26226324272765272a282b2f20430a652e2c652a31" \
                   "24333a653e2b2027630c692b20283165286326302e27282f";
    char *b641 = hex2b64_str(hex1);
    char expect[] = "CzY3JyorLmNiLC5paSojaToqPGMkIC1iPWM0PComImMkJydlJy" \
                    "ooKy8gQwplLixlKjEkMzplPisgJ2MMaSsgKDFlKGMmMC4nKC8=";
    /* char ascii[] = "Burning 'em, if you ain't quick and nimble\n" \ */
    /*                "I go crazy when I hear a cymbal"; */
    SHOULD_BE(!strcmp(b641, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", b641, expect);
#endif
    free(b641);
    END_TEST_CASE;
}

/* This tests conversion of a base64 string to a hex string */
int B64Convert1()
{
    START_TEST_CASE;
    char b641[] = "TWFu";
    char *hex1 = b642hex_str(b641);
    char *str1 = htoa(hex1);
    SHOULD_BE(!strcmp(str1, "Man"));
#ifdef LOGSTATUS
    printf("%-5s => %-7s => %-4s\n", b641, hex1, str1);
#endif
    char b642[] = "TWE=";
    char *hex2 = b642hex_str(b642);
    char *str2 = htoa(hex2);
    SHOULD_BE(!strcmp(str2, "Ma"));
#ifdef LOGSTATUS
    printf("%-5s => %-7s => %-4s\n", b642, hex2, str2);
#endif
    char b643[] = "TQ==";
    char *hex3 = b642hex_str(b643);
    char *str3 = htoa(hex3);
    SHOULD_BE(!strcmp(str3, "M"));
#ifdef LOGSTATUS
    printf("%-5s => %-7s => %-4s\n", b643, hex3, str3);
#endif
    free(hex1); 
    free(hex2); 
    free(hex3); 
    free(str1);
    free(str2);
    free(str3);
    END_TEST_CASE;
}

/* This tests conversion of a base64 string to a hex string */
int B64Convert2()
{
    START_TEST_CASE;
    char b641[] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa" \
                  "WtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    char *hex1 = b642hex_str(b641);
    char expect[] = "49276d206b696c6c696e6720796f75722" \
                    "0627261696e206c696b65206120706f69" \
                    "736f6e6f7573206d757368726f6f6d";
    SHOULD_BE(!strncasecmp(hex1, expect, strlen(expect)));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", hex1, expect);
    char *ascii = htoa(expect);
    printf("ascii: %s\n", ascii);
    free(ascii);
#endif
    free(hex1);
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
    SHOULD_BE(!strcasecmp(xor, expect));
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
    SHOULD_BE(!strcasecmp(key_str, expect));
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
    float tol = 1e-4;
    float score_expect = 34.2697034515381986;
    XOR_NODE *out = singleByteXORDecode(hex1);
    SHOULD_BE(!strcmp(out->key, "58"));
    SHOULD_BE(!strcmp(out->plaintext, expect));
    SHOULD_BE(fabsf(out->score - score_expect) < tol);
    SHOULD_BE(out->file_line == 0);
#ifdef LOGSTATUS
    printf("key   = 0x%s\n",           out->key);
    printf("score = %20.16f\n",        out->score);
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
    printf("key   = 0x%s\n",           out->key);
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
    SHOULD_BE(!strcasecmp(xor, expect)); /* hex strings don't care about case */
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", xor, expect);
#endif
    free(input_hex);
    free(key_hex);
    free(xor);
    END_TEST_CASE;
}

/* Test Hamming distance function */
int HammingDist1()
{
    START_TEST_CASE;
    char *a = atoh("this is a test");
    char *b = atoh("wokka wokka!!!");
    unsigned long dist = hamming_dist(a,b);
    SHOULD_BE(dist == 37);
#ifdef LOGSTATUS
    printf("Got:    %zu\nExpect: %d\n", dist, 37);
#endif
    free(a);
    free(b);
    END_TEST_CASE;
}

/* Test break repeating key XOR */
int BreakRepeatingXOR1()
{
    START_TEST_CASE;
    char input_hex[] = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d" \
                       "63343c2a26226324272765272a282b2f20430a652e2c652a31" \
                       "24333a653e2b2027630c692b20283165286326302e27282f";
    char *input_b64 = hex2b64_str(input_hex);
    char key[] = "ICE";
    char *key_hex = atoh(key);
    char expect[] = "Burning 'em, if you ain't quick and nimble\n" \
                    "I go crazy when I hear a cymbal";
    XOR_NODE *out = breakRepeatingXOR(input_b64);
    SHOULD_BE(!strcmp(out->key, "494345"));
    SHOULD_BE(!strcmp(out->plaintext, expect));
    /* SHOULD_BE(fabsf(out->score - score_expect) < tol); */
    SHOULD_BE(out->file_line == 0);
#ifdef LOGSTATUS
    printf("key   = 0x%s\n",           out->key);
    printf("score = %8.4f\n",          out->score);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
#endif
    free(input_b64);
    free(key_hex);
    free(out);
    END_TEST_CASE;
}

/* Test break repeating key XOR */
int BreakRepeatingXOR2()
{
    START_TEST_CASE;
    char message[2*MAX_STR_LEN];
    char doc[] = "../data/6.txt";
    long file_length = 0;
    /* load document as string */
    char *page = fileToString(doc, &file_length);
    if (page == NULL) {
        snprintf(message, 2*MAX_STR_LEN, "File %s not read correctly.", doc);
        ERROR(message);
    }
    /* printf("%s\nlength: %ld\n", page, file_length); */
    SHOULD_BE(file_length == 3900);
    XOR_NODE *out = breakRepeatingXOR(page);
    free(page);
    free(out);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    /* RUN_TEST(StrToUpper1,      "strtoupper()          "); */
    /* RUN_TEST(GetHexByte1,      "getHexByte()          "); */
    /* RUN_TEST(HexConvert1,      "atoh(),htoa()         "); */
    /* RUN_TEST(HexConvert2,      "hex2b64_str() 1       "); */
    /* RUN_TEST(HexConvert3,      "hex2b64_str() 2       "); */
    /* RUN_TEST(HexConvert4,      "hex2b64_str() 3       "); */
    /* RUN_TEST(B64Convert1,      "b642hex_str() 1       "); */
    /* RUN_TEST(B64Convert2,      "b642hex_str() 2       "); */
    /* RUN_TEST(FixedXOR1,        "fixedXOR()            "); */
    /* RUN_TEST(Strnrepeat1,      "strnrepeat_hex()      "); */
    /* RUN_TEST(FindFreq1,        "countChars()          "); */
    /* RUN_TEST(IsPrintable1,     "isprintable()         "); */
    /* RUN_TEST(CharFreqScore1,   "charFreqScore()       "); */
    /* RUN_TEST(SingleByte1,      "singleByteXORDecode() "); */
    /* Don't always run this file test, it's a bit slow */
    /* RUN_TEST(FileSingleByte1,  "findSingleByteXOR()   "); */
    /* RUN_TEST(RepeatingKeyXOR1, "repeatingKeyXOR()     "); */
    /* RUN_TEST(HammingDist1,      "hamming_dist()        "); */
    RUN_TEST(BreakRepeatingXOR1,"breakRepeatingXOR() 1 ");
    /* RUN_TEST(BreakRepeatingXOR2,"breakRepeatingXOR() 2 "); */

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
