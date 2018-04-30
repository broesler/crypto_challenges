/*==============================================================================
 *     File: crypto2.c
 *  Created: 07/22/2017, 00:47
 *   Author: Bernie Roesler
 *
 *  Description: Solutions to Set 2 of Matasano Crypto Challenges
 *
 *============================================================================*/
#include "header.h"
#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"

/*------------------------------------------------------------------------------
 *         Challenge 10: Encrypt AES 128-bit cipher in CBC mode 
 *----------------------------------------------------------------------------*/
int aes_128_cbc_encrypt(BYTE **y, size_t *y_len, BYTE *x, size_t x_len, BYTE *key, BYTE *iv)
{
    size_t len = 0;     /* intermediate length */
    BYTE *xp = NULL,    /* intermediate value of xor'd bytes */
         *xi = NULL,    /* one block plaintext input */
         *yi = NULL,    /* one block output of AES encryption */
         *yim1 = NULL;  /* "previous" ciphertext block */
    *y_len = 0;         /* output length */

    /* Number of blocks needed */
    size_t n_blocks = x_len / BLOCK_SIZE;
    if (x_len % BLOCK_SIZE) { n_blocks++; }
    size_t tot_len = BLOCK_SIZE * n_blocks;

    /* initialize output byte array with one extra block */
    *y = init_byte(tot_len + BLOCK_SIZE);

    /* pad byte array to multiple of BLOCK_SIZE */
    BYTE *x_pad = pkcs7_pad(x, x_len, BLOCK_SIZE);

    /* Encrypt blocks of plaintext using Chain Block Cipher (CBC) mode */
    for (size_t i = 0; i < n_blocks; i++) {
        /* Input blocks */
        xi = x_pad + i*BLOCK_SIZE;
        yim1 = (i == 0) ? iv : yi; /* chain the last ciphertext into the next */

        /* XOR plaintext block with previous ciphertext block */
        xp = fixedXOR(xi, yim1, BLOCK_SIZE);
        free(yi); /* a new yi is malloc'd during ECB, so free the old one */

        /* Encrypt single block using key and AES cipher */
        if (0 != aes_128_ecb_block(&yi, &len, xp, BLOCK_SIZE, key, 1)) {
            ERROR("Encryption failed!");
        }

        /* Append encrypted text to output array */
        memcpy(*y + *y_len, yi, len);
        *y_len += len;

        free(xp);
    }

    /* Clean-up */
    free(yi);
    free(x_pad);

    return 0;
}

/*------------------------------------------------------------------------------
 *         Decrypt AES 128-bit cipher in CBC mode 
 *----------------------------------------------------------------------------*/
int aes_128_cbc_decrypt(BYTE **x, size_t *x_len, BYTE *y, size_t y_len, BYTE *key, BYTE *iv)
{
    size_t len = 0;     /* intermediate length */
    BYTE *yp = NULL,    /* intermediate value of xor'd bytes */
         *xi = NULL,    /* one block plaintext input */
         *yi = NULL,    /* one block output of AES encryption */
         *yim1 = NULL;  /* "previous" ciphertext block */
    int n_pad = 0;

    *x_len = 0;         /* output length */

    /* Number of blocks needed */
    size_t n_blocks = y_len / BLOCK_SIZE;
    if (*x_len % BLOCK_SIZE) { n_blocks++; }

    /* initialize output byte array with one extra block */
    *x = init_byte(BLOCK_SIZE*(n_blocks+1));

    /* Encrypt blocks of plaintext using Chain Block Cipher (CBC) mode */
    for (size_t i = 0; i < n_blocks; i++) {
        /* Input blocks */
        yim1 = (i == 0) ? iv : yi;
        yi = y + i*BLOCK_SIZE;

        /* Decrypt single block using key and AES cipher */
        if (0 != aes_128_ecb_block(&yp, &len, yi, BLOCK_SIZE, key, 0)) {
            ERROR("Decryption failed!");
        }

        /* XOR decrypted ciphertext block with previous ciphertext block */
        xi = fixedXOR(yp, yim1, BLOCK_SIZE);

        /* Append decrypted text to output array */
        memcpy(*x + *x_len, xi, len);
        *x_len += len;

        free(yp);
        free(xi); /* could parallelize because x doesn't depend on xi */
    }

    /* Remove any padding from output, or error code if invalid */
    if ((n_pad = pkcs7_rmpad(*x, *x_len, BLOCK_SIZE)) < 0) {
        return -1;
    }

    *x_len -= n_pad;
    return n_pad;
}

/*------------------------------------------------------------------------------
 *         Generate random sequence of bytes (i.e. AES key) 
 *----------------------------------------------------------------------------*/
BYTE *rand_byte(size_t len)
{
    BYTE *key = init_byte(len);
    for (size_t i = 0; i < len; i++) {
        key[i] = rand() % 0x100;     /* generate random byte [0x00,0xFF] */ 
    }
    return key;
}

/*------------------------------------------------------------------------------
 *          Test if we're encrypting in ECB mode or not
 *----------------------------------------------------------------------------*/
/* Accepts function pointer to encryption oracle and block size */
size_t isECB(int (*encrypt)(BYTE**, size_t*, BYTE*, size_t), size_t block_size)
{
    /* Encrypt 3 identical blocks, guarantees we will get 2 consecutive */
    size_t x_len = 3*block_size;
    BYTE x[x_len];
    for (size_t i = 0; i < x_len; i++) { *(x+i) = 'A'; }

    /* Encrypt and check for identical blocks */
    BYTE *y = NULL;
    size_t y_len = 0;
    encrypt(&y, &y_len, x, x_len);

    int test = hasIdenticalBlocks(y, y_len, block_size);

    /* clean up */
    free(y);
    return test;
}

/*------------------------------------------------------------------------------
 *          Get block size of cipher 
 *----------------------------------------------------------------------------*/
/* Accepts function pointer to encryption oracle */
size_t getBlockSize(int (*encrypt)(BYTE**, size_t*, BYTE*, size_t), size_t *count, size_t *n)
{
    BYTE *y = NULL;
    *count = 0;
    *n = 0;
    BYTE x[IMAX];
    for (size_t i = 0; i < IMAX; i++) { x[i] = 'A'; } /* arbitrary byte */

    /* Unknown string will be padded to N*block_size */
    size_t Nblock = 0; 
    encrypt(&y, &Nblock, x, 0);
    free(y); /* unused */

    for (size_t i = 1; i < IMAX; i++) {
        /* Keep adding bytes to input until we "overflow" to next block */
        size_t Np1block = 0; 
        encrypt(&y, &Np1block, x, i);
        free(y); /* unused */

        if (Np1block != Nblock) {
            size_t block_size = Np1block - Nblock;
            *count = i-1; /* one less than overflow */
            *n = Nblock / block_size;
            return block_size;
        }
    }

    return 0;
}

/*------------------------------------------------------------------------------
 *          Key=value parser
 *----------------------------------------------------------------------------*/
char *kv_parse(const char *str)
{
    char *kv_obj = NULL,
         *brk,
         *buf,
         *pair,
         *sep = "&";        /* token character */
    char key[MAX_KEY_LEN+1],
         val[MAX_KEY_LEN+1];
    int val_int = 0;
    size_t kv_obj_len,
           line_len;

    /* format string == i.e. "%127[^=]=%127s" */
    char fmt_key[] = "%" XSTR(MAX_KEY_LEN) "[^=]=",
         fmt_val_str[] = "%*[^=]=%" XSTR(MAX_KEY_LEN) "s";

    /* Get number of pairs and total output length (incl extra chars) */
    kv_obj_len = 3*strlen(str) + 1;

    /* Copy input into buffer so we don't destroy it with strtok */
    buf = init_str(strlen(str));
    strlcpy(buf, str, strlen(str)+1);

    /* Initialize output string */
    kv_obj = init_str(kv_obj_len);
    strlcpy(kv_obj, "{\n", kv_obj_len);
    line_len = 2;   /* 2 chars just appended */

    /* Tokenize string on '&' */
    for (pair = strtok_r(buf, sep, &brk);
         pair;
         pair = strtok_r(NULL, sep, &brk))
    {
        /* clear buffers */
        BZERO(key, MAX_KEY_LEN);
        BZERO(val, MAX_KEY_LEN);

        /* Read in key */
        sscanf(pair, fmt_key, key);

        /* if key is "uid", val is int, otherwise val is string */
        if (!strcmp(key, "uid")) {
            sscanf(pair, "%*[^=]=%d", &val_int);  /* ignore key */
            line_len += snprintf(kv_obj + line_len, kv_obj_len - line_len,
                                 "\t%s: %d", key, val_int);
        } else {
            sscanf(pair, fmt_val_str, val);
            line_len += snprintf(kv_obj + line_len, kv_obj_len - line_len,
                                 "\t%s: '%s'", key, val);
        }

        /* if we're on last pair, no comma */
        char *out_end = brk ? ",\n" : "\n";
        line_len += strlcpy(kv_obj + line_len, out_end, kv_obj_len - line_len);
    }

    /* Final brace */
    strlcpy(kv_obj + line_len, "}", kv_obj_len - line_len);

    free(buf);
    return kv_obj;
}

/*------------------------------------------------------------------------------
 *          Key=value encoder (reverse of parser)
 *----------------------------------------------------------------------------*/
char *kv_encode(const char *str)
{
    char *kv_enc = NULL,
         *brk,
         *buf,
         *pair,
         *sep = ",";        /* token character */
    char key[MAX_KEY_LEN+1],
         val[MAX_KEY_LEN+1];
    size_t kv_enc_len,
           line_len;

    /* format string == i.e. "%127[^=]=%127s" */
    char fmt_key[] = " %" XSTR(MAX_KEY_LEN) "[^:]:",
         fmt_val_str[] = "%*[^']\'%" XSTR(MAX_KEY_LEN) "[^\']s\',";

    /* Get number of pairs and total output length (incl extra chars) */
    kv_enc_len = strlen(str);

    /* Copy input into buffer so we don't destroy it */
    if (*str != '{') { ERROR("kv pairs not properly formatted!"); }
    buf = init_str(strlen(str));
    strlcpy(buf, str+1, strlen(str)-2); /* skip initial and closing braces */

    /* Initialize output string */
    kv_enc = init_str(kv_enc_len);
    line_len = 0;

    /* Tokenize string on ','
     * ASSUME keys and values do NOT have commas in them... */
    for (pair = strtok_r(buf, sep, &brk);
         pair;
         pair = strtok_r(NULL, sep, &brk))
    {
        /* clear buffers */
        BZERO(key, MAX_KEY_LEN);
        BZERO(val, MAX_KEY_LEN);

        /* Read in key */
        sscanf(pair, fmt_key, key);

        /* if key is "uid", val is int, otherwise val is string */
        if (!strcmp(key, "uid")) {
            sscanf(pair, "%*[^:]: %s", val);  /* no single quotes on int */
        } else {
            sscanf(pair, fmt_val_str, val);   /* yes single quotes on str */
        }

        /* Append key-value pairs to line */
        line_len += snprintf(kv_enc + line_len, kv_enc_len - line_len, "%s=%s", key, val);

        /* unless we're at the end, add an ampersand */
        if (brk) { 
            *(kv_enc + line_len) = '&';
            line_len++;
        }
    }

    free(buf);
    return kv_enc;
}

/*------------------------------------------------------------------------------
 *          Encode a user profile in k=v format
 *----------------------------------------------------------------------------*/
char *profile_for(const char *email)
{
    char email_key[] = "email=";
    char profile_data[] = "&uid=56&role=user"; /* append to email */
    char *email_clean,
         *kv_enc;
    size_t tot_len,
           len = 0;

    /* Escape "metacharacters" from the input */
    email_clean = strhtmlesc(email, "&=");

    /* Initialize output */
    tot_len = sizeof(email_key) + strlen(email_clean)+1 + sizeof(profile_data);
    kv_enc = init_str(tot_len);

    /* Concatenate profile into output buffer */
    len  = strlcpy(kv_enc,     email_key,    tot_len);
    len += strlcpy(kv_enc+len, email_clean,  tot_len - len);
    len += strlcpy(kv_enc+len, profile_data, tot_len - len);

    free(email_clean);
    return kv_enc;
}

/*------------------------------------------------------------------------------
 *          Encrypt encoded profile under random key
 *----------------------------------------------------------------------------*/
int encrypt_profile(BYTE **y, size_t *y_len, BYTE **key, char *profile)
{
    /* Set key once only */
    if (!(*key)) {
        *key = rand_byte(BLOCK_SIZE);
    }
    aes_128_ecb_cipher(y, y_len, (BYTE *)profile, strlen(profile), *key, 1);
    return 0;
}

/*------------------------------------------------------------------------------
 *          Decrypt and parse user profile 
 *----------------------------------------------------------------------------*/
char *decrypt_profile(BYTE *x, size_t x_len, BYTE *key)
{
    BYTE *y = NULL;
    size_t y_len = 0;
    if (0 != aes_128_ecb_cipher(&y, &y_len, x, x_len, key, 0)) {
        ERROR("Invalid padding!");
    }
    char *str = byte2str(y, y_len);
    char *profile = kv_parse(str);
    free(y);
    free(str);
    return profile;
}

/*==============================================================================
 *============================================================================*/
