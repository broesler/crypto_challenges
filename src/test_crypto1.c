/*==============================================================================
 *     File: test_crypto1.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Tests of cryptography functions in crypto challenges set 1
 *
 *============================================================================*/
/* System headers */
#include <math.h>
#include <float.h>

/* User-defined headers */
#include "aes_openssl.h"
#include "header.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "unit_test.h"

int AESDecrypt_test(BYTE *ptext);

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* Challenge 1: This tests conversion of a hex string to a base64 string */
int HexConvert2()
{
    START_TEST_CASE;
    BYTE str1[] = "Man";
    char *hex1 = byte2hex(str1, 3);
    char *b641 = hex2b64(hex1);
    SHOULD_BE(!strcmp(b641, "TWFu"));
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str1, hex1, b641);
#endif
    BYTE str2[] = "Ma";
    char *hex2 = byte2hex(str2, 2);
    char *b642 = hex2b64(hex2);
    SHOULD_BE(!strcmp(b642, "TWE="));
#ifdef LOGSTATUS
    printf("%-4s => %-7s => %-5s\n", str2, hex2, b642);
#endif
    BYTE str3[] = "M";
    char *hex3 = byte2hex(str3, 1);
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
    BYTE *str1 = NULL;
    size_t nbyte = hex2byte(&str1, hex1);
    SHOULD_BE(!memcmp(str1, "Man", nbyte));
#ifdef LOGSTATUS
    printf("%-5s => %-7s => %-4s\n", b641, hex1, str1);
#endif
    char b642[] = "TWE=";
    char *hex2 = b642hex(b642);
    BYTE *str2 = NULL;
    nbyte = hex2byte(&str2, hex2);
    SHOULD_BE(!memcmp(str2, "Ma", nbyte));
#ifdef LOGSTATUS
    printf("%-5s => %-7s => %-4s\n", b642, hex2, str2);
#endif
    char b643[] = "TQ==";
    char *hex3 = b642hex(b643);
    BYTE *str3 = NULL;
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

/* Challenge 2: This tests the XOR of two hex-encoded strings, as well as printing their
 * ASCII conversions */
int FixedXOR1()
{
    START_TEST_CASE;
    char hex1[]   = "1c0111001f010100061a024b53535009181c";
    char hex2[]   = "686974207468652062756c6c277320657965";
    char hexpect[] = "746865206b696420646f6e277420706c6179";
    BYTE *a, *b, *expect;
    size_t nbyte1 = hex2byte(&a, hex1);
    size_t nbyte2 = hex2byte(&b, hex2);
    SHOULD_BE(nbyte1 == nbyte2);
    size_t nbyte3 = hex2byte(&expect, hexpect);
    SHOULD_BE(nbyte1 == nbyte3);
    BYTE *xor = fixedXOR(a, b, nbyte1);
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
    BYTE str1[] = "Anything less than the best is a felony.";
    float test = charFreqScore(str1, strlen((char *)str1));
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

/* Challenge 3: This function tests the decoding of a single byte XOR cipher */
int SingleByte1()
{
    START_TEST_CASE;
    char hex1[]   = "1b37373331363f78151b7f2b783431333d78" \
                    "397828372d363c78373e783a393b3736";
    char expect[] = "Cooking MC's like a pound of bacon";
    float tol = 1e-4;
    float score_expect = 34.2697034515381986;
    BYTE *byte = NULL;
    size_t nbyte = hex2byte(&byte, hex1);
    XOR_NODE *out = singleByteXORDecode(byte, nbyte);
    SHOULD_BE(*out->key == 0x58);
    SHOULD_BE(!memcmp(out->plaintext, expect, nbyte));
    SHOULD_BE(fabsf(out->score - score_expect) < tol);
    SHOULD_BE(out->file_line == 0);
#ifdef LOGSTATUS
    printf("key   =  0x%.2X\n",       *out->key);
    printf("score = %20.16f\n",        out->score);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
#endif
    free(out);
    free(byte);
    END_TEST_CASE;
}

/* Challenge 4: This function tests the decoding of multiple strings in a file */
int FileSingleByte1()
{
    START_TEST_CASE;
    char filename[] = "../data/4.txt";
    char expect[] = "Now that the party is jumping\n";
    XOR_NODE *out = findSingleByteXOR(filename);
    SHOULD_BE(!memcmp(out->plaintext, expect, strlen(expect)));
#ifdef LOGSTATUS
    printf("line  = %3d\n",            out->file_line);
    printf("key   =  0x%.2X\n",       *out->key);
    printf("score = %8.4f\n",          out->score);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
#endif
    free(out);
    END_TEST_CASE;
}

/* Challenge 5: This function tests the implementation of repeating-key XOR */
int RepeatingKeyXOR1()
{
    START_TEST_CASE;
    BYTE input[]  = "Burning 'em, if you ain't quick and nimble\n" \
                    "I go crazy when I hear a cymbal";
    BYTE key[] = "ICE";
    char hexpect[] = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d" \
                     "63343c2a26226324272765272a282b2f20430a652e2c652a31" \
                     "24333a653e2b2027630c692b20283165286326302e27282f";
    BYTE *expect = NULL;
    size_t nbyte = hex2byte(&expect, hexpect);
    BYTE *xor = repeatingKeyXOR(input, key, strlen((char *)input), strlen((char *)key));
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
    BYTE a[] = "this is a test";
    BYTE b[] = "wokka wokka!!!";
    unsigned long dist = hamming_dist(a,b, strlen((char *)a));
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
    BYTE *input_byte = NULL;
    size_t nbyte = hex2byte(&input_byte, input_hex);
    BYTE key[] = "ICE";
    char expect[] = "Burning 'em, if you ain't quick and nimble\n" \
                    "I go crazy when I hear a cymbal";
    XOR_NODE *out = breakRepeatingXOR(input_byte, nbyte);
    SHOULD_BE(!memcmp(out->key, key, out->key_byte));
    SHOULD_BE(!memcmp(out->plaintext, expect, nbyte));
    SHOULD_BE(out->score == FLT_MAX); /* unchanged */
    SHOULD_BE(out->file_line == 0);   /* unchanged */
#ifdef LOGSTATUS
    char *key_hex = byte2hex(out->key, out->key_byte);
    printf("key   = 0x%s = %s\n", key_hex, out->key);
    printf("Got:    %s\nExpect: %s\n", out->plaintext, expect);
    free(key_hex);
#endif
    free(input_byte);
    free(out);
    END_TEST_CASE;
}

/* Challenge 6: Test break repeating key XOR */
int BreakRepeatingXOR2()
{
    START_TEST_CASE;
    /*---------- Read in b64 from file and convert to byte array ----------*/
    char b64_file[] = "../data/6.txt";
    char *b64 = NULL;
    unsigned long file_length = fileToString(&b64, b64_file);
    SHOULD_BE(file_length == 3900);
    char *b64_clean = strrmchr(b64, "\n"); /* strip newlines */
    SHOULD_BE(strlen(b64_clean) == 3836);
    BYTE *byte = NULL;
    size_t nbyte = b642byte(&byte, b64_clean);
    /* Read in expected file (hand-checked before) */
    char *expect = NULL;
    (void)fileToString(&expect, "../data/play_that_funky_music.txt");
    char key_expect[] = "Terminator X: Bring the noise";
    /*---------- Break the code! ----------*/
    XOR_NODE *out = breakRepeatingXOR(byte, nbyte);
    SHOULD_BE(!memcmp(out->key, key_expect, out->key_byte));
    SHOULD_BE(!memcmp(out->plaintext, expect, nbyte));
    SHOULD_BE(out->score == FLT_MAX);
    SHOULD_BE(out->file_line == 0);
#ifdef LOGSTATUS
    char *key_hex = byte2hex(out->key, out->key_byte);
    printf("----------------------------------------\n");
    printf("key   = 0x%s\n      = %s\n", key_hex, out->key);
    printf("Got:\n%s\n", out->plaintext);
    free(key_hex);
#endif
    free(b64);
    free(b64_clean);
    free(byte);
    free(out);
    free(expect);
    END_TEST_CASE;
}

/* Test all AES en/decrypt cases */
int AESDecrypt1()
{
    START_TEST_CASE;
    /* BLOCK_SIZE multiple: */
    BYTE ptext1[] = "Bathroom passes, cuttin classes, squeezin asses.";
    rs += AESDecrypt_test(ptext1);
    /* non-BLOCK_SIZE multiple: */
    BYTE ptext2[] = "I was a terror since the public school era.";
    rs += AESDecrypt_test(ptext2);
    /* BLOCK_SIZE multiple with newline at end of block:
     * NOTE this test fails because pkcs7_rmpad strips 10*'\n' = '\x10' from the
     * output! Also strips other odd characters if a block ends in a newline. */
    BYTE ptext3[] = "Bathroom passes, cuttin classes, squeezin asses\n";
    rs += AESDecrypt_test(ptext3);
    END_TEST_CASE;
}

/* Test AES in ECB mode decryption */
int AESDecrypt_test(BYTE *ptext)
{
    START_TEST_CASE;
    size_t ptext_len = strlen((char *)ptext);
    OpenSSL_init();
    BYTE key[] = "YELLOW SUBMARINE"; /* 16-bit key */
    /*---------- Encrypt the plaintext ----------*/
    BYTE *ctext = NULL;
    size_t ctext_len = aes_128_ecb_cipher(&ctext, ptext, ptext_len, key, 1);
    SHOULD_BE((ctext_len % BLOCK_SIZE) == 0);
    /*---------- Decrypt the ciphertext ----------*/
    BYTE *dtext = NULL;
    size_t dtext_len = aes_128_ecb_cipher(&dtext, ctext, ctext_len, key, 0);
    /* Compare with expected result */
    SHOULD_BE(dtext_len == ptext_len);
    SHOULD_BE(!memcmp(ptext, dtext, ptext_len));
#ifdef LOGSTATUS
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, (const char *)ctext, ctext_len);
    printf("ptext_len = %zu\nctext_len = %zu\ndtext_len = %zu\n", 
            ptext_len, ctext_len, dtext_len);
    printf("ptext: '");
    printall(ptext, ptext_len);
    printf("'\ndtext: '");
    printall(dtext, dtext_len);
    printf("'\n");
#endif
    /* Clean up */
    OpenSSL_cleanup();
    free(ctext);
    free(dtext);
    END_TEST_CASE;
}

/* Challenge 7: Test AES in ECB mode decryption */
int AESDecrypt2()
{
    START_TEST_CASE;
    /*---------- Read in b64 from file and convert to byte array ----------*/
    char *b64 = NULL;
    unsigned long file_length = fileToString(&b64, "../data/7.txt");
    SHOULD_BE(file_length = 3904);
    char *b64_clean = strrmchr(b64, "\n"); /* strip newlines */
    SHOULD_BE(strlen(b64_clean) == 3840);
    BYTE *byte = NULL;
    size_t nbyte = b642byte(&byte, b64_clean);
    /* Initialize the OpenSSL library */
    OpenSSL_init();
    /* Define the key -- 16 byte == 128 bit key */
    BYTE key[] = "YELLOW SUBMARINE";
    BYTE *plaintext = NULL;
    /*---------- Break the code! ----------*/
    int plaintext_len = aes_128_ecb_cipher(&plaintext, byte, nbyte, key, 0);
    /* Compare with expected result */
    char *expect = NULL;
    unsigned long expect_len = fileToString(&expect, "../data/play_that_funky_music.txt");
    SHOULD_BE(expect_len == plaintext_len);
    SHOULD_BE(!memcmp(plaintext, expect, plaintext_len));
#ifdef LOGSTATUS
    printf("----------------------------------------\n");
    printf("plaintext_len = %d\nexpect_len = %zu\n", plaintext_len, expect_len);
    /*---------- Print all bytes */
    printf("Got:\n\"");
    printall(plaintext, plaintext_len);
    printf("\"\n");
    printf("----------------------------------------\n");
    printf("Expected:\n\"");
    printall((BYTE *)expect, expect_len);
    printf("\"\n");
#endif
    /* Clean up */
    OpenSSL_cleanup();
    free(b64);
    free(b64_clean);
    free(byte);
    free(plaintext);
    free(expect);
    END_TEST_CASE;
}

/* Test ECB mode detection */
int ECBDetect1()
{
    START_TEST_CASE;
    BYTE byte[] = "YELLOW SUBMARINEthis is a test!!YELLOW SUBMARINE";
    SHOULD_BE(1 == hasIdenticalBlocks(byte, strlen((char *)byte), 16));
    END_TEST_CASE;
}

/* Challenge 8: Test ECB mode detection */
int ECBDetect2()
{
    START_TEST_CASE;
    BYTE *ciphertext = NULL;
    int file_line = find_AES_ECB(&ciphertext, "../data/8.txt");
    if (file_line < 0) { WARNING("ECB encryption not found!"); }
    /* 133 on average Hamming, AND identical blocks! */
    SHOULD_BE(file_line == 133);
#ifdef LOGSTATUS
    printf("line  = %3d\n", file_line);
#endif
    free(ciphertext);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(HexConvert2,       "Challenge  1: hex2b64() 1            ");
    RUN_TEST(HexConvert3,       "              hex2b64() 2            ");
    RUN_TEST(HexConvert4,       "              hex2b64() 3            ");
    RUN_TEST(B64Convert1,       "              b642hex() 1            ");
    RUN_TEST(B64Convert2,       "              b642hex() 2            ");
    RUN_TEST(FixedXOR1,         "Challenge  2: fixedXOR()             ");
    RUN_TEST(CharFreqScore1,    "Challenge  3: charFreqScore()        ");
    RUN_TEST(SingleByte1,       "              singleByteXORDecode()  ");
    RUN_TEST(FileSingleByte1,   "Challenge  4: findSingleByteXOR()    ");
    RUN_TEST(RepeatingKeyXOR1,  "Challenge  5: repeatingKeyXOR()      ");
    RUN_TEST(HammingDist1,      "Challenge  6: hamming_dist()         ");
    RUN_TEST(BreakRepeatingXOR1,"              breakRepeatingXOR() 1  ");
    RUN_TEST(BreakRepeatingXOR2,"              breakRepeatingXOR() 2  ");
    RUN_TEST(AESDecrypt1,       "Challenge  7: aes_128_ecb_cipher() 1 ");
    RUN_TEST(AESDecrypt2,       "              aes_128_ecb_cipher() 2 ");
    RUN_TEST(ECBDetect1,        "Challenge  8: find_AES_ECB() 1       ");
    RUN_TEST(ECBDetect2,        "              find_AES_ECB() 2       ");

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
