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
    char *hex1 = byte2hex(str1, strlen(str1));
    char *b641 = hex2b64(hex1);
    SHOULD_BE(!strcmp(b641, "TWFu"));
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str1, hex1, b641);
#endif
    char str2[] = "Ma";
    char *hex2 = byte2hex(str2, strlen(str2));
    char *b642 = hex2b64(hex2);
    SHOULD_BE(!strcmp(b642, "TWE="));
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str2, hex2, b642);
#endif
    char str3[] = "M";
    char *hex3 = byte2hex(str3, strlen(str3));
    char *b643 = hex2b64(hex3);
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
    char *b641 = hex2b64(hex1);
    char expect[] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa" \
                    "WtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    SHOULD_BE(!strcmp(b641, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", b641, expect);
    char *ascii = htoa(hex1);
    printf("ascii: %s\n", ascii);
    free(ascii);
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
    char *b641 = hex2b64(hex1);
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
    char *hex1 = b642hex(b641);
    char *str1 = NULL;
    size_t nbyte = hex2byte(&str1, hex1);
    SHOULD_BE(!memcmp(str1, "Man", nbyte));
#ifdef LOGSTATUS
    printf("%-5s => %-7s => %-4s\n", b641, hex1, str1);
#endif
    char b642[] = "TWE=";
    char *hex2 = b642hex(b642);
    char *str2 = NULL;
    nbyte = hex2byte(&str2, hex2);
    SHOULD_BE(!memcmp(str2, "Ma", nbyte));
#ifdef LOGSTATUS
    printf("%-5s => %-7s => %-4s\n", b642, hex2, str2);
#endif
    char b643[] = "TQ==";
    char *hex3 = b642hex(b643);
    char *str3 = NULL;
    nbyte = hex2byte(&str3, hex3);
    SHOULD_BE(!memcmp(str3, "M", nbyte));
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
    char *hex1 = b642hex(b641);
    char expect[] = "49276d206b696c6c696e6720796f75722" \
                    "0627261696e206c696b65206120706f69" \
                    "736f6e6f7573206d757368726f6f6d";
    SHOULD_BE(!strncasecmp(hex1, expect, strlen(expect)));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", hex1, expect);
    char *ascii = htoa(hex1);
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
    char hexpect[] = "746865206b696420646f6e277420706c6179";
    char *a, *b, *expect;
    size_t nbyte1 = hex2byte(&a, hex1);
    size_t nbyte2 = hex2byte(&b, hex2);
    SHOULD_BE(nbyte1 == nbyte2);
    size_t nbyte3 = hex2byte(&expect, hexpect);
    SHOULD_BE(nbyte1 == nbyte3);
    char *xor = fixedXOR(a, b, nbyte1);
    char *asciia = byte2str(a, nbyte1);
    char *asciib = byte2str(b, nbyte2);
    char *asciix = byte2str(xor, nbyte3);
    SHOULD_BE(!memcmp(xor, expect, nbyte3));
    /* SHOULD_BE(!memcmp(asciia, "KSSP", nbyte1)); // sketchy, non-printables */
    SHOULD_BE(!memcmp(asciib, "hit the bull's eye", nbyte2));
    SHOULD_BE(!memcmp(asciix, "the kid don't play", nbyte3));
#ifdef LOGSTATUS
    char *hexx = byte2hex(xor, nbyte3);
    printf("Got:    %s\nExpect: %s\n", hexx, hexpect);
    printf("ascii:\n1: %s\n2: %s\n3: %s\n", asciia, asciib, asciix);
    free(hexx);
#endif
    free(a);
    free(b);
    free(expect);
    free(xor);
    free(asciia);
    free(asciib);
    free(asciix);
    END_TEST_CASE;
}

/* This function tests the character frequency score*/
int CharFreqScore1()
{
    START_TEST_CASE;
    char str1[] = "Anything less than the best is a felony.";
    float test = charFreqScore(str1, strlen(str1));
    float tol = 1e-10;
    float expect = 16.430251917634155; /* new score according to <char_test.m> */
    /* float expect = 15.6190082292009702; // length == all chars */
    /* float expect = 17.5239402865012082; // length == just letters */
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
    char *byte = NULL;
    size_t nbyte = hex2byte(&byte, hex1);
    XOR_NODE *out = singleByteXORDecode(byte, nbyte);
    SHOULD_BE(*out->key == 0x58);
    SHOULD_BE(!strcmp(out->plaintext, expect));
    SHOULD_BE(fabsf(out->score - score_expect) < tol);
    SHOULD_BE(out->file_line == 0);
#ifdef LOGSTATUS
    printf("key   =  0x%0.2X\n",       *out->key);
    printf("score = %20.16f\n",        out->score);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
#endif
    free(out);
    free(byte);
    END_TEST_CASE;
}

/* This function tests the decoding of multiple strings in a file */
int FileSingleByte1()
{
    START_TEST_CASE;
    char filename[] = "../data/4.txt";
    char expect[] = "Now that the party is jumping\n";
    XOR_NODE *out = findSingleByteXOR(filename);
    SHOULD_BE(!strcmp(out->plaintext, expect));
#ifdef LOGSTATUS
    printf("line  = %3d\n",            out->file_line);
    printf("key   =  0x%0.2X\n",       *out->key);
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
    char hexpect[] = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d" \
                     "63343c2a26226324272765272a282b2f20430a652e2c652a31" \
                     "24333a653e2b2027630c692b20283165286326302e27282f";
    char *expect = NULL;
    size_t nbyte = hex2byte(&expect, hexpect);
    char *xor = repeatingKeyXOR(input, key, strlen(input), strlen(key));
    SHOULD_BE(!memcmp(xor, expect, nbyte));
#ifdef LOGSTATUS
    char *hexor = byte2hex(xor, nbyte);
    printf("Got:    %s\nExpect: %s\n", hexor, hexpect);
    free(hexor);
#endif
    free(expect);
    free(xor);
    END_TEST_CASE;
}

/* Test Hamming distance function */
int HammingDist1()
{
    START_TEST_CASE;
    char a[] = "this is a test";
    char b[] = "wokka wokka!!!";
    unsigned long dist = hamming_dist(a,b, strlen(a));
    SHOULD_BE(dist == 37);
#ifdef LOGSTATUS
    printf("Got:    %zu\nExpect: %d\n", dist, 37);
#endif
    END_TEST_CASE;
}

/* Test break repeating key XOR by reversing the above test */
int BreakRepeatingXOR1()
{
    START_TEST_CASE;
    char input_hex[] = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d" \
                       "63343c2a26226324272765272a282b2f20430a652e2c652a31" \
                       "24333a653e2b2027630c692b20283165286326302e27282f";
    char *input_byte = NULL;
    size_t nbyte = hex2byte(&input_byte, input_hex);
    char key[] = "ICE";
    char expect[] = "Burning 'em, if you ain't quick and nimble\n" \
                    "I go crazy when I hear a cymbal";
    XOR_NODE *out = breakRepeatingXOR(input_byte, nbyte);
    SHOULD_BE(!strcmp(out->key, key));
    SHOULD_BE(!strcmp(out->plaintext, expect));
    SHOULD_BE(out->score == FLT_MAX); /* unchanged */
    SHOULD_BE(out->file_line == 0);   /* unchanged */
#ifdef LOGSTATUS
    char *key_hex = byte2hex(out->key, strlen(out->key));
    printf("key   = 0x%s = %s\n", key_hex, out->key);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
    free(key_hex);
#endif
    free(input_byte);
    free(out);
    END_TEST_CASE;
}

/* Test break repeating key XOR */
int BreakRepeatingXOR2()
{
    START_TEST_CASE;
    /*---------- Read in b64 from file and convert to byte array ----------*/
    /* TODO check for newline characters in the input string and remove them
     * could do the same for hex, etc. char *s = cleanstr(const char *src); */
    char b64_file[] = "../data/6.txt_oneline";
    char *b64 = NULL;
    unsigned long file_length = fileToString(&b64, b64_file);
    SHOULD_BE(file_length == 3836); /* 3836 * 3/4 = 2877-1 (one equals sign) */

    /* File with newlines */
    char file[] = "../data/6.txt";
    char *page = NULL;
    (void)fileToString(&page, file);
    char *page_nonl = strrmchr(page, "\n");
    SHOULD_BE(!strcmp(page_nonl, b64));

    char *byte = NULL;
    size_t nbyte = b642byte(&byte, b64);      /* This line fails at b64[96:99] */
    /*---------- Break the code! ----------*/
    XOR_NODE *out = breakRepeatingXOR(byte, nbyte);
    SHOULD_BE(!strcmp(out->key, "Terminator X: Bring the noise"));
    /* Long output... maybe store in file for future testing? */
    /* SHOULD_BE(!strcmp(out->plaintext, expect)); */
    SHOULD_BE(out->score == FLT_MAX);
    SHOULD_BE(out->file_line == 0);
#ifdef LOGSTATUS
    char *key_hex = byte2hex(out->key, strlen(out->key));
    printf("key   = 0x%s\n      = %s\n", key_hex, out->key);
    /* printf("Got:\n%s\n", out->plaintext); */
    free(key_hex);
#endif
    free(b64);
    free(byte);
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

    /* RUN_TEST(HexConvert2,       "Challenge 1: hex2b64() 1       "); */
    /* RUN_TEST(HexConvert3,       "             hex2b64() 2       "); */
    /* RUN_TEST(HexConvert4,       "             hex2b64() 3       "); */
    /* RUN_TEST(B64Convert1,       "             b642hex() 1       "); */
    /* RUN_TEST(B64Convert2,       "             b642hex() 2       "); */
    /* RUN_TEST(FixedXOR1,         "Challenge 2: fixedXOR()            "); */
    /* RUN_TEST(CharFreqScore1,    "Challenge 3: charFreqScore()       "); */
    /* RUN_TEST(SingleByte1,       "             singleByteXORDecode() "); */
    /* RUN_TEST(FileSingleByte1,   "Challenge 4: findSingleByteXOR()   "); #<{(| SLOW |)}># */
    /* RUN_TEST(RepeatingKeyXOR1,  "Challenge 5: repeatingKeyXOR()     "); */
    /* RUN_TEST(HammingDist1,      "Challenge 6: hamming_dist()        "); */
    /* RUN_TEST(BreakRepeatingXOR1,"             breakRepeatingXOR() 1 "); */
    RUN_TEST(BreakRepeatingXOR2,"             breakRepeatingXOR() 2 ");

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
