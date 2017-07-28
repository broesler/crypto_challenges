/*==============================================================================
 *     File: crypto2.c
 *  Created: 07/22/2017, 00:47
 *   Author: Bernie Roesler
 *
 *  Description: Solutions to Set 2 of Matasano Crypto Challenges
 *
 *============================================================================*/

#include "header.h"
#include "dictionary.h"
#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"

/* Global key used in encryption_oracle12 */
static BYTE *global_key = NULL;

/*------------------------------------------------------------------------------
 *         Challenge 9: PKCS#7 padding to block size 
 *----------------------------------------------------------------------------*/
BYTE *pkcs7_pad(const BYTE *byte, size_t nbyte, size_t block_size)
{
    BYTE n_pad = block_size - (nbyte % block_size);

    BYTE *out = init_byte(nbyte + n_pad);
    memcpy(out, byte, nbyte);
    BYTE *p = out + nbyte;      /* start at end of original byte array */

    /* Add N-bytes of char N */
    for (int i = 0; i < n_pad; i++) {
        *p++ = n_pad;
    }

    return out;
}

/*------------------------------------------------------------------------------
 *         Challenge 15: Remove PKCS#7 padding bytes 
 *----------------------------------------------------------------------------*/
int pkcs7_rmpad(BYTE *byte, size_t nbyte, size_t block_size)
{
    int n_pad = byte[nbyte-1];      /* last byte is number of pads */
    if (n_pad <= block_size) {
        for (int i = 0; i < n_pad; i++) {
            /* If a byte isn't the same as the pad byte, throw warning */
            if (byte[nbyte-1-i] != n_pad) {
#ifdef LOGSTATUS
                printf("byte = \"");
                printall(byte, nbyte);
                printf("\"\n");
                WARNING("Padding is invalid!");
#endif
                return 0;
            }
        }
        /* Otherwise we've reached the end of the bytes, add a NULL */
        byte[nbyte-n_pad] = '\0';
        return n_pad;
    } else {
        return 0;
    }        
}

/*------------------------------------------------------------------------------
 *         Challenge 10: Encrypt AES 128-bit cipher in CBC mode 
 *----------------------------------------------------------------------------*/
size_t aes_128_cbc_encrypt(BYTE **y, BYTE *x, size_t x_len, BYTE *key, BYTE *iv)
{
    size_t y_len = 0,      /* output length */
           len = 0;     /* intermediate length */
    BYTE *xp = NULL,    /* intermediate value of xor'd bytes */
         *xi = NULL,    /* one block plaintext input */
         *yi = NULL,    /* one block output of AES encryption */
         *yim1 = NULL;  /* "previous" ciphertext block */

    /* Number of blocks needed */
    size_t n_blocks = x_len / BLOCK_SIZE;
    if (x_len % BLOCK_SIZE) { n_blocks++; }
    size_t tot_len = BLOCK_SIZE * n_blocks;

    /* initialize output byte array with one extra block */
    *y = init_byte(tot_len + BLOCK_SIZE);

    /* pad byte array to multiple of BLOCK_SIZE */
    BYTE *x_pad = pkcs7_pad(x, x_len, BLOCK_SIZE);

    OpenSSL_init();

    /* Encrypt blocks of plaintext using Chain Block Cipher (CBC) mode */
    for (size_t i = 0; i < n_blocks; i++) {
        /* Input blocks */
        xi = x_pad + i*BLOCK_SIZE;
        yim1 = (i == 0) ? iv : yi; /* chain the last ciphertext into the next */

        /* XOR plaintext block with previous ciphertext block */
        xp = fixedXOR(xi, yim1, BLOCK_SIZE);
        free(yi); /* a new yi is malloc'd during ECB, so free the old one */

        /* Encrypt single block using key and AES cipher */
        len = aes_128_ecb_block(&yi, xp, BLOCK_SIZE, key, 1);

        /* Append encrypted text to output array */
        memcpy(*y + y_len, yi, len);
        y_len += len;

        free(xp);
    }

    /* Clean-up */
    free(yi);
    free(x_pad);
    OpenSSL_cleanup();
    return y_len;
}

/*------------------------------------------------------------------------------
 *         Decrypt AES 128-bit cipher in CBC mode 
 *----------------------------------------------------------------------------*/
size_t aes_128_cbc_decrypt(BYTE **x, BYTE *y, size_t y_len, BYTE *key, BYTE *iv)
{
    size_t x_len = 0,   /* output length */
           len = 0;     /* intermediate length */
    BYTE *yp = NULL,    /* intermediate value of xor'd bytes */
         *xi = NULL,    /* one block plaintext input */
         *yi = NULL,    /* one block output of AES encryption */
         *yim1 = NULL;  /* "previous" ciphertext block */

    /* Number of blocks needed */
    size_t n_blocks = y_len / BLOCK_SIZE;
    if (x_len % BLOCK_SIZE) { n_blocks++; }

    /* initialize output byte array with one extra block */
    *x = init_byte(BLOCK_SIZE*(n_blocks+1));

    OpenSSL_init();

    /* Encrypt blocks of plaintext using Chain Block Cipher (CBC) mode */
    for (size_t i = 0; i < n_blocks; i++) {
        /* Input blocks */
        yim1 = (i == 0) ? iv : yi;
        yi = y + i*BLOCK_SIZE;

        /* Decrypt single block using key and AES cipher */
        len = aes_128_ecb_block(&yp, yi, BLOCK_SIZE, key, 0);

        /* XOR decrypted ciphertext block with previous ciphertext block */
        xi = fixedXOR(yp, yim1, BLOCK_SIZE);

        /* Append decrypted text to output array */
        memcpy(*x + x_len, xi, len);
        x_len += len;

        free(yp);
        free(xi); /* could parallelize because x doesn't depend on xi */
    }

    /* Remove any padding from output */
    int n_pad = pkcs7_rmpad(*x, x_len, BLOCK_SIZE); 
    x_len -= n_pad;

    /* Clean-up */
    OpenSSL_cleanup();
    return x_len;
}

/*------------------------------------------------------------------------------
 *         Generate random AES key 
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
 *          randomly encrypt with ECB or CBC
 *----------------------------------------------------------------------------*/
size_t encryption_oracle11(BYTE **y, BYTE *x, size_t x_len)
{
    size_t x_aug_len = 0,
           y_len = 0;
    BYTE *prepend,
         *append,
         *iv,
         *key,
         *x_aug;
    int n_prepend,
        n_append,
        heads;

    /* Randomly generate 5-10 bytes to pre-/append to input */
    n_prepend = RAND_RANGE(5,10);
    n_append  = RAND_RANGE(5,10);
    prepend = rand_byte(n_prepend);
    append  = rand_byte(n_append);

    /* Build actual input to oracle */
    x_aug_len = n_prepend + x_len + n_append;
    x_aug = init_byte(x_aug_len);

    /* Move pointer along each chunk of bytes */
    memcpy(x_aug,                  prepend,  n_prepend);
    memcpy(x_aug+n_prepend,        x,        x_len);
    memcpy(x_aug+n_prepend+x_len,  append,   n_append);

#ifdef VERBOSE
    printf("n_prepend = %d, n_append = %d\n", n_prepend, n_append);
    printf("prepend = \"");
    printall(prepend, n_prepend);
    printf("\"\nappend  = \"");
    printall(append, n_append);
    printf("\"\nx_aug   = \"");
    printall(x_aug, x_aug_len);
    printf("\"\n");
#endif

    /* Generate a random key */
    key = rand_byte(BLOCK_SIZE);

    /* Flip a coin to choose the algorithm to use */
    heads = RAND_RANGE(0,1);

    if (heads) {
#ifdef LOGSTATUS
        printf("[oracle]: Encrypting in ECB mode\n");
#endif
        /* Use ECB mode */
        y_len = aes_128_ecb_cipher(y, x_aug, x_aug_len, key, 1);

    } else {
#ifdef LOGSTATUS
        printf("[oracle]: Encrypting in CBC mode\n");
#endif
        /* Generate random IV */
        iv = rand_byte(BLOCK_SIZE);
        /* Use CBC mode */
        y_len = aes_128_cbc_encrypt(y, x_aug, x_aug_len, key, iv);
        free(iv);
    }

#ifdef VERBOSE
    printf("Oracle ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)*y, y_len);
#endif

    /* Clean-up */
    free(prepend);
    free(append);
    free(key);
    free(x_aug);

    return y_len;
}

/*------------------------------------------------------------------------------
 *          Challenge 11: Detect encryption_oracle mode 
 *----------------------------------------------------------------------------*/
int is_oracle_ecb11(BYTE *x, size_t x_len)
{
    /* Encrypt the input with the oracle, AES in either ECB or CBC mode */
    BYTE *c = NULL;
    size_t c_len = encryption_oracle11(&c, x, x_len);

    /* 1 if in ECB mode, 0 if not (i.e. CBC mode) */
    int test = hasIdenticalBlocks(c, c_len, BLOCK_SIZE);
    free(c);
    return test;
}

/*------------------------------------------------------------------------------
 *          Encryption oracle for Challenge 12 
 *----------------------------------------------------------------------------*/
size_t encryption_oracle12(BYTE **y, BYTE *x, size_t x_len)
{
    size_t x_aug_len = 0,
           y_len = 0;
    BYTE *x_aug;

    /* String to append to the plaintext (for decryption!) */
    static const char *append_b64 = 
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
        "YnkK";

    /* Convert to byte array */
    static BYTE *append = NULL;
    size_t n_append = b642byte(&append, append_b64);

    /* Build actual input to oracle */
    x_aug_len = x_len + n_append;
    x_aug = init_byte(x_aug_len);

    /* Move pointer along each chunk of bytes */
    memcpy(x_aug,       x,      x_len);
    memcpy(x_aug+x_len, append, n_append);

    /* Generate a random key ONCE */
    if (!global_key) {
        global_key = rand_byte(BLOCK_SIZE);
    }

    /* Encrypt using ECB mode */
    y_len = aes_128_ecb_cipher(y, x_aug, x_aug_len, global_key, 1);

    /* Clean-up */
    free(append);
    free(x_aug);

    return y_len;
}

/*------------------------------------------------------------------------------
 *          Get block size of cipher 
 *----------------------------------------------------------------------------*/
/* Accepts function pointer to encryption oracle */
size_t getBlockSize(size_t (*encrypt)(BYTE**, BYTE*, size_t))
{
    BYTE *y = NULL;
    BYTE x[IMAX];
    for (size_t i = 0; i < IMAX; i++) { x[i] = 'A'; } /* arbitrary byte */

    /* Unknown string will be padded to N*block_size */
    size_t Nblock = encrypt(&y, x, 0);
    free(y); /* unused */

    for (size_t i = 1; i < IMAX; i++) {
        /* Keep adding bytes to input until we "overflow" to next block */
        size_t Np1block = encrypt(&y, x, i);
        free(y); /* unused */

        if (Np1block != Nblock) {
            return (Np1block - Nblock);
        }
    }
    return 0;
}

/*------------------------------------------------------------------------------
 *          Get block size of cipher 
 *----------------------------------------------------------------------------*/
/* Accepts function pointer to encryption oracle and block size */
size_t isECB(size_t (*encrypt)(BYTE**, BYTE*, size_t), size_t block_size)
{
    /* Encrypt two identical blocks of block size */
    BYTE *y = NULL;
    size_t x_len = 2*block_size;
    BYTE x[x_len];
    for (size_t i = 0; i < x_len; i++) { *(x+i) = 'A'; }
    size_t y_len = encrypt(&y, x, x_len);
    int test = hasIdenticalBlocks(y, y_len, block_size);
    free(y);
    return test;
}

/*------------------------------------------------------------------------------
 *          Get single byte of unknown string
 *----------------------------------------------------------------------------*/
BYTE decodeNextByte(size_t (*encrypt)(BYTE**, BYTE*, size_t), const BYTE *y, 
        size_t y_len, size_t block_size)
{
    DICTIONARY *dict = NULL;
    size_t i = 0,
           x_len = 0,
           in_len = 0;
    BYTE *c = NULL,
         *t = NULL,
         *in = NULL;

    /* Build input byte base (n-bytes short)
     * Input is (block_size-1) known bytes + 1 unknown */
    x_len = block_size - (y_len % block_size) - 1;
    in_len = x_len + y_len + 1;  /* == n_block*block_size */

    in = init_byte(in_len);
    for (i = 0; i < x_len; i++) { *(in+i) = '0'; }
    memcpy(in + x_len, y, y_len);

    /* Build dictionary of ECB output for each byte of input */
    if (!(dict = initDictionary())) { ERROR("initDictionary failed!"); }

    for (i = 0; i < 0x100; i++) {
        /* Concatenate y + single char onto input */
        *(in + x_len + y_len) = (BYTE)i;

        /* Encrypt single-block input */
        encrypt(&t, in, in_len);

        /* Dictionary key is t, value is i */
        /* NOTE need to malloc "data" for dictionary because it is free'd */
        c = init_byte(1);
        *c = (BYTE)i;
        dAdd(dict, t, in_len, (void *)c);

        free(t);
    }

    /* Encrypt just our one-byte-short string */ 
    encrypt(&t, in, x_len);

    /* cast (void *) to desired byte value */
    BYTE b = *(BYTE *)dLookup(dict, t, in_len);

    /* Clean-up */
    free(t);
    free(in);
    freeDictionary(dict);

    return b;
}

/*------------------------------------------------------------------------------
 *         Challenge 12: Decrypt unknown string encrypted using ECB 
 *----------------------------------------------------------------------------*/
/* Take input of the form (your-string||unknown-string, random-key), and decrypt
 * the unknown string */
/* size_t simple_ECB_decrypt(BYTE **y) */
size_t simple_ECB_decrypt(BYTE y[])
{
    size_t block_size = 0,
           i = 0,
           unk_len = 138,
           y_len = 0; /* length of unknown string (== n_append) */
    BYTE *p = y;

    /* Detect block size */
    block_size = getBlockSize(encryption_oracle12);

    /* Confirm function is using ECB */
    MY_ASSERT(isECB(encryption_oracle12, block_size));

    /* Decrypt unknown bytes */
    for (i = 0; i < unk_len; i++){
        if (!(*p++ = decodeNextByte(encryption_oracle12, (const BYTE *)y, y_len, block_size))) {
            break; 
        }
        y_len++;
    }

    return y_len;
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
            line_len += snprintf(kv_obj + line_len, kv_obj_len - line_len, "\t%s: %d", key, val_int);
        } else {
            sscanf(pair, fmt_val_str, val);
            line_len += snprintf(kv_obj + line_len, kv_obj_len - line_len, "\t%s: '%s'", key, val);
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
    char fmt_key[] = "\t%" XSTR(MAX_KEY_LEN) "[^:]:",
         fmt_val_str[] = "%*[^']\'%" XSTR(MAX_KEY_LEN) "[^\']s\',";

    /* Get number of pairs and total output length (incl extra chars) */
    kv_enc_len = strlen(str);

    /* Copy input into buffer so we don't destroy it */
    if (strncmp("{\n", str, 2)) { ERROR("kv pairs not properly formatted!"); }
    buf = init_str(strlen(str));
    strlcpy(buf, str+2, strlen(str)-3); /* skip initial and closing braces */

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
    email_clean = strescchr(email, "&=");

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
size_t encrypt_profile(BYTE **y, BYTE **key, char *profile)
{
    /* Set key once only */
    if (!(*key)) {
        *key = rand_byte(BLOCK_SIZE);
    }
    return aes_128_ecb_cipher(y, (BYTE *)profile, strlen(profile), *key, 1);
}

/*------------------------------------------------------------------------------
 *          Decrypt and parse user profile 
 *----------------------------------------------------------------------------*/
char *decrypt_profile(BYTE *x, size_t x_len, BYTE *key)
{
    BYTE *y = NULL;
    size_t y_len = aes_128_ecb_cipher(&y, x, x_len, key, 0);
    char *str = byte2str(y, y_len);
    char *profile = kv_parse(str);
    free(y);
    free(str);
    return profile;
}

/*------------------------------------------------------------------------------
 *          Challenge 13: ECB cut-and-paste
 *----------------------------------------------------------------------------*/
/* Make a "role=admin" profile but using only user input to profile_for() to
 * generate valid ciphertexts, then swap ciphertexts to get "role: 'admin'" */
char *make_admin_profile(void)
{
    char *profile1 = NULL,
         *profile2 = NULL,
         *profile = NULL;
    static BYTE *key = NULL;   /* random key, save for decryption */
    BYTE *y1 = NULL,
         *y2 = NULL,
         *y = NULL;

    /* Strategy: Create block with just "admin" and block with profile up to
     * "role=", then combine the two ciphertexts to get the entire profile */

    /* Need "admin" at the start of a ciphertext block */
    /* total string will be "email=bernie@me.|admin\x0B...\x0B|&uid=..." */
    char email1[] = "bernie@me.admin";
    size_t faux_block = 2*BLOCK_SIZE - strlen("email=");
    BYTE *email1_pad = pkcs7_pad((BYTE *)email1, strlen(email1), faux_block);

    /* Need email long enough to push "user" into third block, so second block
     * ends with "role=". Now we combine the first two ciphertext blocks of this
     * email, and the 2nd blocks of the email masking off "admin\x0B...", which
     * will decrypt to "email=bernie@me.|com&uid=56&role=|admin\x0B..." */
    /* total string will be: "email=bernie@me.|com&uid=56&role=|user\x0C..." */
    char email2[] = "bernie@me.com";

    /* Make profiles */
    profile1 = profile_for((char *)email1_pad);
    profile2 = profile_for(email2);

    /* Encrypt each email and swap blocks */
    encrypt_profile(&y1, &key, profile1);
    encrypt_profile(&y2, &key, profile2);

    /* Build faux ciphertext */
    size_t y_len = 3*BLOCK_SIZE;
    y = init_byte(y_len);
    memcpy(y, y2, 2*BLOCK_SIZE);                       /* first two blocks */
    memcpy(y+2*BLOCK_SIZE, y1+BLOCK_SIZE, BLOCK_SIZE); /* 2nd block */
    
    /* Decrypt substituted ciphertext */
    profile = decrypt_profile(y, y_len, key);

    /* Clean-up */
    free(email1_pad);
    free(profile1);
    free(profile2);
    free(y);
    free(y1);
    free(y2);
    free(key);

    return profile;
}

/*==============================================================================
 *============================================================================*/
