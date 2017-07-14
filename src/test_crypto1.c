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
#include <float.h>

/* User-defined headers */
#include "header.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "unit_test.h"

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
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
    char key[] = "ICE";
    char *key_hex = atoh(key);
    char expect[] = "Burning 'em, if you ain't quick and nimble\n" \
                    "I go crazy when I hear a cymbal";
    XOR_NODE *out = breakRepeatingXOR(input_hex);
    /* NOTE First byte of key is wrong... getting 0x4E4335 == "NCE" hmmm... */
    SHOULD_BE(!strcmp(out->key, key_hex));
    SHOULD_BE(!strcmp(out->plaintext, expect));
    SHOULD_BE(out->score == FLT_MAX); /* unchanged */
    SHOULD_BE(out->file_line == 0);   /* unchanged */
#ifdef LOGSTATUS
    char *out_key_ascii = htoa(out->key);
    printf("key   = 0x%s = %s\n",           out->key, out_key_ascii);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
    free(out_key_ascii);
#endif
    free(key_hex);
    free(out);
    END_TEST_CASE;
}

/* Test break repeating key XOR */
int BreakRepeatingXOR2()
{
    START_TEST_CASE;
    /* char b64_file[] = "../data/6.b64_str"; */
    char b64_file[] = "../data/6.txt";
    long file_length = 0;
    char *page = fileToString(b64_file, &file_length);
    SHOULD_BE(file_length == 3900);
    char *hex = b642hex_str(page);
    /* char hex_file[] = "../data/6.hexxd"; */
    /* char *page_hex = fileToString(hex_file, &file_length); */
    /* printf("hex translated from 6.txt:\n%s\n", hex); */
    /* printf("hex translated from 6.char:\n%s\n", page_hex); */
    /* SHOULD_BE(!strcasecmp(hex, page_hex)); */
    XOR_NODE *out = breakRepeatingXOR(hex);
    char expect[] = "???";
    SHOULD_BE(!strcmp(out->key, "test"));
    SHOULD_BE(out->score == FLT_MAX); /* unchanged */
    SHOULD_BE(out->file_line == 0);   /* unchanged */
    SHOULD_BE(!strcmp(out->plaintext, expect));
#ifdef LOGSTATUS
    printf("key   = 0x%s\n",           out->key);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
#endif
    free(page);
    free(hex);
    /* free(page_hex); */
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

    /* RUN_TEST(HexConvert2,       "hex2b64_str() 1       "); */
    /* RUN_TEST(HexConvert3,       "hex2b64_str() 2       "); */
    /* RUN_TEST(HexConvert4,       "hex2b64_str() 3       "); */
    /* RUN_TEST(B64Convert1,       "b642hex_str() 1       "); */
    /* RUN_TEST(B64Convert2,       "b642hex_str() 2       "); */
    /* RUN_TEST(FixedXOR1,         "fixedXOR()            "); */
    /* RUN_TEST(CharFreqScore1,    "charFreqScore()       "); */
    /* RUN_TEST(SingleByte1,       "singleByteXORDecode() "); */
    /* RUN_TEST(FileSingleByte1,   "findSingleByteXOR()   "); #<{(| SLOW |)}># */
    /* RUN_TEST(RepeatingKeyXOR1,  "repeatingKeyXOR()     "); */
    /* RUN_TEST(HammingDist1,      "hamming_dist()        "); */
    /* RUN_TEST(BreakRepeatingXOR1,"breakRepeatingXOR() 1 "); */
    RUN_TEST(BreakRepeatingXOR2,"breakRepeatingXOR() 2 ");

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
