/*==============================================================================
 *     File: cbc_padding_oracle.c
 *  Created: 08/01/2017, 22:51
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 17: CBC decryption with padding oracle
 *
 *============================================================================*/
#include <stdio.h>
#include <string.h>

#include "header.h"
#include "aes_openssl.h"
#include "crypto_util.h"
#include "crypto1.h"
#include "crypto2.h"

#define SRAND_INIT 56

/* Global key used in encryption_oracle */
static BYTE *global_key = NULL;
static BYTE *global_iv  = NULL;

/* String to be encrypted */
static const char * const possible_x[10] = 
{ 
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", 
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", 
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", 
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", 
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", 
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", 
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", 
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", 
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", 
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" 
};

/* Encrypt randomly one of the above strings, return ciphertext and set IV */
int encryption_oracle(BYTE **y, size_t *y_len);

/*------------------------------------------------------------------------------
 *         Main function
 *----------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    /* initialize PRNG */
    srand(SRAND_INIT);

    /* Encrypt random string */
    BYTE *y = NULL;
    size_t y_len = 0;
    if (0 != encryption_oracle(&y, &y_len)) {
        ERROR("Incorrect padding!");
    }

    /* Decrypt it and report if padding is valid or not */
    BYTE *x = NULL;
    size_t x_len = 0;
    /* Test == -1 for invalid padding */
    int test = aes_128_cbc_decrypt(&x, &x_len, y, y_len, global_key, global_iv);

    printf("x = %s\ntest = %d\n", x, test);

    free(y);
    free(global_key);
    free(global_iv);
    return 0;
}

/*------------------------------------------------------------------------------
 *          Encryption oracle
 *----------------------------------------------------------------------------*/
int encryption_oracle(BYTE **y, size_t *y_len)
{
    int out = 0,
        choice = 0;
    *y_len = 0;

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
    }

    /* Generate a random IV ONCE */
    if (!global_iv) {
        global_iv = rand_byte(BLOCK_SIZE);
    }

    /* Randomly select one of possible inputs */
    choice = RAND_RANGE(0, 9);
    const char *x = possible_x[choice];
    size_t x_len = strlen(x);

#ifdef LOGSTATUS
    printf("Chose string %d:\n    %s\n", choice, x);
#endif

    /* Encrypt using CBC mode */
    out = aes_128_cbc_encrypt(y, y_len, (BYTE *)x, x_len, global_key, global_iv);

    /* Padding is invalid */
    if (0 != out) { 
        return -1; 
    }

    return 0;
}


/*==============================================================================
 *============================================================================*/
