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
#include <time.h>

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
static const char * const POSSIBLE_X[10] = 
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

/* Decrypt ciphertext and return 0 for valid padding or -1 for invalid */
int decrypt_and_checkpad(BYTE *y, size_t y_len);

/*------------------------------------------------------------------------------
 *         Main function
 *----------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    BYTE *y = NULL;
    size_t y_len = 0;

    /* initialize PRNG */
    srand(SRAND_INIT); /* init for deterministic result */
    /* srand(time(NULL)); */

    /* Encrypt random string */
    encryption_oracle(&y, &y_len);

    /* Create copy of ciphertext */
    BYTE *yp = init_byte(y_len);
    memcpy(yp, y, y_len);
    /* Let last byte yp be 0x01 */
    BYTE pad_byte = 0x01;
    yp[y_len-1] = pad_byte;

    BYTE *pad_arr = init_byte(y_len);
    pad_arr[y_len-1] = pad_byte;

    int test = decrypt_and_checkpad(yp, y_len);

    if (!test) {
       /* Last byte of x is yp ^ pad_byte */
        BYTE *x_blocks = fixedXOR(yp, pad_arr, y_len);
    } /* else { */
    /* } */

#ifdef LOGSTATUS
    /* test == -1 for invalid padding */
    char *status = (test == 0) ? "valid" : "invalid";
    printf("Padding %s!\n", status);
#endif

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
    /* Randomly select one of possible inputs */
    int choice = RAND_RANGE(0, 9);
    const char *x = POSSIBLE_X[choice];
    size_t x_len = strlen(x);

    *y_len = 0;

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
    }

    /* Generate a random IV ONCE */
    if (!global_iv) {
        global_iv = rand_byte(BLOCK_SIZE);
    }

#ifdef LOGSTATUS
    printf("Chose string %d: %s\n", choice, x);
#endif

    /* Encrypt using CBC mode */
    aes_128_cbc_encrypt(y, y_len, (BYTE *)x, x_len, global_key, global_iv);
    return 0;
}


/*------------------------------------------------------------------------------
 *          Decrypt and Check Padding
 *----------------------------------------------------------------------------*/
int decrypt_and_checkpad(BYTE *y, size_t y_len)
{
    /* Decrypt y report if padding is valid or not, but do not return x */
    BYTE *x = NULL;
    size_t x_len = 0;
    int test = aes_128_cbc_decrypt(&x, &x_len, y, y_len, global_key, global_iv);
    free(x);
    return test;
}

/*==============================================================================
 *============================================================================*/
