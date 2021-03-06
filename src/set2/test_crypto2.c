/*==============================================================================
 *     File: test_crypto2.c
 *  Created: 07/22/2017, 00:54
 *   Author: Bernie Roesler
 *
 *  Description: Tests of cryptography functions in crypto challenges set 2
 *
 *============================================================================*/
/* User-defined headers */
#include "unit_test.h"
#include "header.h"
#include "crypto_util.h"
#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"

#define SRAND_INIT 0

/* Meta test functions */
int CBCencrypt_test(BYTE *ptext);

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* Test PKCS#7 padding */
int PKCS71()
{
    START_TEST_CASE;
    int n_pad = 4;
    BYTE byte[] = "YELLOW SUBMARINE";
    size_t nbyte = strlen((char *)byte);
    BYTE *block = pkcs7_pad(byte, nbyte, nbyte+n_pad);
    size_t nblock = strlen((char *)block);
    SHOULD_BE(nblock == nbyte+n_pad);
    for (int i = 0; i < n_pad; i++) { SHOULD_BE(*(block+nbyte+i) == n_pad); }
#ifdef LOGSTATUS
    printf("Padded string: '");
    printall(block, nblock);
    printf("'\n");
#endif
    free(block);
    END_TEST_CASE;
}

/* Test PKCS#7 padding */
int PKCS72()
{
    START_TEST_CASE;
    int n_pad = 0;
    BYTE byte[] = "YELLOW SUBMARINE";
    size_t nbyte = strlen((char *)byte);
    BYTE *block = pkcs7_pad(byte, nbyte, nbyte+n_pad);
    for (int i = 0; i < n_pad; i++) { SHOULD_BE(*(block+nbyte+i) == n_pad); }
#ifdef LOGSTATUS
    printf("Padded string: '");
    printall(block, nbyte);
    printf("'\n");
#endif
    free(block);
    END_TEST_CASE;
}

/* Test PKCS#7 padding removal (valid padding) */
int PKCS73()
{
    START_TEST_CASE;
    /* valid padding */
    BYTE byte[] = "ICE ICE BABY\x04\x04\x04\x04";
    size_t nbyte = strlen((char *)byte);
    int npout = pkcs7_rmpad(byte, nbyte, 20);
    SHOULD_BE(npout == 4);
#ifdef LOGSTATUS
    printf("Removed pad:   '");
    printall(byte, nbyte);   /* sets byte[nbyte] = \x00 */
    printf("'\n");
#endif
    END_TEST_CASE;
}

/* Test PKCS#7 padding (invalid 1) */
int PKCS74()
{
    START_TEST_CASE;
    /* valid padding */
    BYTE byte[] = "ICE ICE BABY\x05\x05\x05\x05";
    size_t nbyte = strlen((char *)byte);
    int npout = pkcs7_rmpad(byte, nbyte, 20);
    SHOULD_BE(npout == -1);
    END_TEST_CASE;
}

/* Test PKCS#7 padding (invalid 2) */
int PKCS75()
{
    START_TEST_CASE;
    /* valid padding */
    BYTE byte[] = "ICE ICE BABY\x01\x02\x03\x04";
    size_t nbyte = strlen((char *)byte);
    int npout = pkcs7_rmpad(byte, nbyte, 20);
    SHOULD_BE(npout == -1);
    END_TEST_CASE;
}

int CBCencrypt1()
{
    START_TEST_CASE;
    BYTE ptext1[] = "I was a terror since the public school era.";
    rs += CBCencrypt_test(ptext1);
    BYTE ptext2[] = "Bathroom passes, cuttin classes, squeezin asses.";
    rs += CBCencrypt_test(ptext2);
    END_TEST_CASE;
}

/* Test CBC mode encryption */
int CBCencrypt_test(BYTE *ptext)
{
    START_TEST_CASE;
    size_t ptext_len = strlen((char *)ptext);
    BYTE key[] = "YELLOW SUBMARINE";
    BYTE iv[BLOCK_SIZE] = "";   /* BLOCK_SIZE-length array of '\0' chars */
    /* Encrypt the text */
    BYTE *ctext = NULL;
    size_t ctext_len = 0;
    aes_128_cbc_encrypt(&ctext, &ctext_len, ptext, ptext_len, key, iv);
    SHOULD_BE((ctext_len % BLOCK_SIZE) == 0);
    /*---------- Decrypt the ciphertext ----------*/
    BYTE *dtext = NULL;
    size_t dtext_len = 0;
    aes_128_cbc_decrypt(&dtext, &dtext_len, ctext, ctext_len, key, iv);
    /* Compare with expected result */
    SHOULD_BE(dtext_len == ptext_len);
    SHOULD_BE(!memcmp(ptext, dtext, ptext_len));
#ifdef LOGSTATUS
    printf("ptext_len = %zu\nctext_len = %zu\ndtext_len = %zu\n", 
            ptext_len, ctext_len, dtext_len);
    printf("ptext: '");
    printall(ptext, ptext_len);
    printf("'\ndtext: '");
    printall(dtext, dtext_len);
    printf("'\n");
#endif
    free(ctext);
    free(dtext);
    END_TEST_CASE;
}

/* Generate a random AES key */
int RandByte1()
{
    START_TEST_CASE;
    srand(SRAND_INIT);
    BYTE *key = rand_byte(BLOCK_SIZE);
#ifdef LOGSTATUS
    printf("key: \"");
    printall(key, BLOCK_SIZE);
    printf("\"\n");
#endif
    free(key);
    END_TEST_CASE;
}

/* Test Key=value parser */
int KVParse1()
{
    START_TEST_CASE;
    char in[] = "foo=bar&baz=qux&zap=zazzle&uid=56";
    char *out = kv_parse(in);
    char expect[] = "{\n\tfoo: 'bar',\n\tbaz: 'qux',\n\tzap: 'zazzle',\n\tuid: 56\n}";
    SHOULD_BE(!strcmp(out, expect));
#ifdef LOGSTATUS
    printf("Got:\n%s\nExpect:\n%s\n", out, expect);
#endif
    free(out);
    END_TEST_CASE;
}

/* Test Key=value encoding (reverse of parser) */
int KVEncode1()
{
    START_TEST_CASE;
    char in[] = "email=foo@bar.com&uid=56&role=user";
    char *kv_p = kv_parse(in);
    char *out = kv_encode(kv_p);
    char expect[] = "email=foo@bar.com&uid=56&role=user";
    SHOULD_BE(!strcmp(out, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", out, expect);
#endif
    free(kv_p);
    free(out);
    END_TEST_CASE;
}

/* Test profile creation */
int ProfileFor1()
{
    START_TEST_CASE;
    char in[] = "foo@bar.com";
    char *out = profile_for(in);
    char expect[] = "email=foo@bar.com&uid=56&role=user";
    SHOULD_BE(!strcmp(out, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", out, expect);
#endif
    free(out);
    END_TEST_CASE;
}

/* Test profile creation vs attempted admin hack */
int ProfileFor2()
{
    START_TEST_CASE;
    char in[] = "foo@bar.com&role=admin";
    char *out = profile_for(in);
    char expect[] = "email=foo@bar.com%26role%3Dadmin&uid=56&role=user";
    SHOULD_BE(!strcmp(out, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", out, expect);
#endif
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

    /* Run OpenSSL lines here for speed */
    RUN_TEST(PKCS71,           "Challenge  9: pkcs7() 1                ");
    RUN_TEST(PKCS72,           "              pkcs7() 2                ");
    RUN_TEST(PKCS73,           "              pkcs7() 3                ");
    RUN_TEST(PKCS74,           "              pkcs7() 4                ");
    RUN_TEST(PKCS75,           "              pkcs7() 5                ");
    RUN_TEST(CBCencrypt1,      "Challenge 10: aes_128_cbc_encrypt() 1  ");
    RUN_TEST(RandByte1,        "Challenge 11: randByte() 1             ");
    RUN_TEST(KVParse1,         "Challenge 12: kv_parse()               ");
    RUN_TEST(KVEncode1,        "              kv_encode()              ");
    RUN_TEST(ProfileFor1,      "              profile_for() 1          ");
    RUN_TEST(ProfileFor2,      "              profile_for() 2          ");

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
