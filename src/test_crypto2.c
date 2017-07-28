/*==============================================================================
 *     File: test2.c
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
    SHOULD_BE(npout == 0);
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
    SHOULD_BE(npout == 0);
    END_TEST_CASE;
}

int CBCencrypt1()
{
    /* NOTE Memory leak occurs out output string (ctext) for BOTH of these
     * cases... so it doesn't have to do with padding removal. */
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
    size_t ctext_len = aes_128_cbc_encrypt(&ctext, ptext, ptext_len, key, iv);
    SHOULD_BE((ctext_len % BLOCK_SIZE) == 0);
    /*---------- Decrypt the ciphertext ----------*/
    BYTE *dtext = NULL;
    size_t dtext_len = aes_128_cbc_decrypt(&dtext, ctext, ctext_len, key, iv);
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

/* Test AES in CBC mode decryption */
int CBCdecrypt1()
{
    START_TEST_CASE;
    /*---------- Read in b64 from file and convert to byte array ----------*/
    char *b64 = NULL;
    unsigned long file_length = fileToString(&b64, "../data/10.txt");
    SHOULD_BE(file_length = 3904);
    char *b64_clean = strrmchr(b64, "\n"); /* strip newlines */
    SHOULD_BE(strlen(b64_clean) == 3840);
    BYTE *byte = NULL;
    size_t nbyte = b642byte(&byte, b64_clean);
    /* Define the key -- 16 byte == 128 bit key */
    BYTE key[] = "YELLOW SUBMARINE";
    BYTE *plaintext = NULL;
    BYTE iv[BLOCK_SIZE] = "";   /* BLOCK_SIZE-length array of '\0' chars */
    /*---------- Break the code! ----------*/
    int plaintext_len = aes_128_cbc_decrypt(&plaintext, byte, nbyte, key, iv);
    /* Compare with expected result */
    char *expect = NULL;
    unsigned long expect_len = fileToString(&expect, "../data/play_that_funky_music.txt");
    SHOULD_BE(expect_len == plaintext_len);
    SHOULD_BE(!memcmp(plaintext, expect, plaintext_len));
#ifdef LOGSTATUS
    /* printf("----------------------------------------\n"); */
    printf("plaintext_len = %d\nexpect_len    = %zu\n", plaintext_len, expect_len);
    printf("Got:\n\"");
    printall(plaintext, plaintext_len);
    printf("\"\n");
    /* printf("----------------------------------------\n"); */
    /* printf("Expected:\n\""); */
    /* printall((BYTE *)expect, expect_len); */
    /* printf("\"\n"); */
#endif
    /* Clean up */
    free(b64);
    free(b64_clean);
    free(byte);
    free(plaintext);
    free(expect);
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

/* Randomly encrypt plaintext */
int EncOracle1()
{
    START_TEST_CASE;
    srand(SRAND_INIT);
    BYTE ptext[] = "I was a terror since the public school era.";
    size_t ptext_len = strlen((char *)ptext);
    /* Encrypt the text with randomly-chosen algorithm */
    BYTE *ctext = NULL;
    size_t ctext_len = encryption_oracle11(&ctext, ptext, ptext_len);
    SHOULD_BE((ctext_len % BLOCK_SIZE) == 0);
    free(ctext);
    END_TEST_CASE;
}

/* Test if oracle is in ECB mode */
int EncOracle2()
{
    START_TEST_CASE;
    srand(SRAND_INIT);
    /* Need at least (BLOCK_SIZE % 10) + 2*BLOCK_SIZE+1 bytes == 38 here */
    BYTE ptext[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    int test = is_oracle_ecb11(ptext, 48);
#ifdef LOGSTATUS
    printf("is ecb? %d\n", test);
#endif
    SHOULD_BE(test == 1); /* if srand(0), we get ECB mode guaranteed */
    END_TEST_CASE;
}

/* Test getBlockSize */
int GetBlockSize()
{
    START_TEST_CASE;
    srand(SRAND_INIT);
    size_t block_size = getBlockSize(encryption_oracle12);
    SHOULD_BE(block_size == BLOCK_SIZE);
    END_TEST_CASE;
}

/* Test isECB */
int IsECB()
{
    START_TEST_CASE;
    srand(SRAND_INIT);
    SHOULD_BE(1 == isECB(encryption_oracle12, BLOCK_SIZE));
    END_TEST_CASE;
}

/* Byte-at-a-time decrypt ECB */
int OneByteECB1()
{
    START_TEST_CASE;
    srand(SRAND_INIT);
    BYTE y[1024];
    size_t y_len = simple_ECB_decrypt(y);
    BYTE expect[] = "Rollin' in my 5.0\n" \
                    "With my rag-top down so my hair can blow\n" \
                    "The girlies on standby waving just to say hi\n" \
                    "Did you stop? No, I just drove by\n";
    SHOULD_BE(!memcmp(y, expect, y_len));
#ifdef LOGSTATUS
    printf("y_len = %zu\n", y_len);
    printf("Got: \"");
    printall(y, y_len);
    printf("\"\n");
#endif
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
    /* char kv_p[] = "{\n\temail: 'foo@bar.com',\n\tuid: 56,\n\trole: 'user'\n}"; */
    char *out = kv_encode(kv_p);
    char expect[] = "email=foo@bar.com&uid=56&role=user";
    SHOULD_BE(!strcmp(out, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", out, expect);
#endif
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

/* Test profile creation */
int ProfileFor2()
{
    START_TEST_CASE;
    char in[] = "foo@bar.com&role=admin";
    char *out = profile_for(in);
    char expect[] = "email=foo@bar.comroleadmin&uid=56&role=user";
    SHOULD_BE(!strcmp(out, expect));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", out, expect);
#endif
    free(out);
    END_TEST_CASE;
}

/* Test profile encrypt/decrypt */
int ProfileFor3()
{
    START_TEST_CASE;
    char *out = make_admin_profile();
    char expect[] = "{\n\temail: 'bernie@me.com',\n\tuid: 56,\n\trole: 'user'\n}";
    SHOULD_BE(!strcmp(out, expect));
#ifdef LOGSTATUS
    printf("Got:\n%s\nExpect:\n%s\n", out, expect);
#endif
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
    OpenSSL_init();
    /* RUN_TEST(PKCS71,       "Challenge  9: pkcs7() 1                "); */
    /* RUN_TEST(PKCS72,       "              pkcs7() 2                "); */
    /* RUN_TEST(PKCS73,       "              pkcs7() 3                "); */
    /* RUN_TEST(PKCS74,       "              pkcs7() 4                "); */
    /* RUN_TEST(PKCS75,       "              pkcs7() 5                "); */
    /* RUN_TEST(CBCencrypt1,  "Challenge 10: aes_128_cbc_encrypt() 1  "); */
    /* RUN_TEST(CBCdecrypt1,  "              aes_128_cbc_encrypt() 2  "); */
    /* RUN_TEST(RandByte1,    "Challenge 11: randByte() 1             "); */
    /* RUN_TEST(EncOracle1,   "              encryption_oracle() 1    "); */
    /* RUN_TEST(EncOracle2,   "              encryption_oracle() 2    "); */
    /* RUN_TEST(GetBlockSize, "              getBlockSize()           "); */
    /* RUN_TEST(IsECB,        "              isECB()                  "); */
    /* RUN_TEST(OneByteECB1,  "              simple_ECB_decrypt() 1   "); */
    RUN_TEST(KVParse1,     "Challenge 12: kv_parse()               ");
    RUN_TEST(KVEncode1,    "              kv_encode()              ");
    RUN_TEST(ProfileFor1,  "              profile_for() 1          ");
    RUN_TEST(ProfileFor2,  "              profile_for() 2          ");
    RUN_TEST(ProfileFor3,  "              profile_for() 3          ");
    OpenSSL_cleanup();

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
