/*==============================================================================
 *     File: crypto1.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for cryptography challenges
 *
 *============================================================================*/
#include <float.h>
#include <math.h>

#include "crypto1.h"
#include "crypto_util.h"
#include "header.h"

/* Globals */
/* Used in hex2b64_str() and b642hex_str(): */
static const char B64_LUT[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/*------------------------------------------------------------------------------
 *          Convert hexadecimal string to base64 string
 *----------------------------------------------------------------------------*/
char *hex2b64(const char *hex)
{
    BYTE *byte = NULL;
    size_t nbyte = hex2byte(&byte, hex);
    char *b64 = byte2b64(byte, nbyte);
    free(byte);
    return b64;
}

/*------------------------------------------------------------------------------
 *          Convert base64 string to hex string
 *----------------------------------------------------------------------------*/
char *b642hex(const char *b64)
{
    BYTE *byte = NULL;
    size_t nbyte = b642byte(&byte, b64);
    char *hex = byte2hex(byte, nbyte);
    free(byte);
    return hex;
}

/*------------------------------------------------------------------------------
 *      Encode byte array as base64 string
 *----------------------------------------------------------------------------*/
char *byte2b64(const BYTE *byte, size_t nbyte)
{
    int nbyte_out,
        nchr_out,
        b64_int;
    BYTE this_byte;

    if (!byte) { return NULL; }

    /* round nbyte up to multiple of 3 (need 3 bytes for even base64 output) */
    nbyte_out = nbyte + 3 - (nbyte % 3);
    nchr_out = nbyte_out * 4/3;  /* Number of chars in output */

    /* allocate memory for output */
    char *b64_str = init_str(nchr_out);
    char *p = b64_str; /* moveable pointer for concatenation */

    /* Operate in chunks of 3 bytes in ==> 4 bytes out */
    for (size_t i = 0; i < nbyte; i+=3) {
        int j = 0;
        this_byte = *(byte+i+j);

        /* Add first character using first 6 bits of first byte */
        b64_int = (this_byte & 0xFC) >> 2;
        *p++ = B64_LUT[b64_int];

        /* get last 2 bits of first byte */
        b64_int = (this_byte & 0x03) << 4;

        /* if we have more bytes to go */
        if (i+j+1 < nbyte) {
            j++;
            this_byte = *(byte+i+j);

            /* Add second character using first 4 bits of second byte and
             * combine with 2 from above */
            b64_int |= (this_byte & 0xF0) >> 4;
            *p++ = B64_LUT[b64_int];

            /* get last 4 bits of second byte */
            b64_int = (this_byte & 0x0F) << 2;

            /* if we have more bytes to go */
            if (i+j+1 < nbyte) {
                j++;
                this_byte = *(byte+i+j);

                /* Add third character */
                /* get first 2 bits of third byte and combine with 4 from above */
                b64_int |= (this_byte & 0xC0) >> 6;
                *p++ = B64_LUT[b64_int];

                /* Add fourth character using last 6 bits of third byte */
                b64_int = (this_byte & 0x3F);
                *p++ = B64_LUT[b64_int];

            /* There are only 2 bytes of input, so interpret 3rd character with
             * a "0x00" byte appended, and pad with an '=' character */
            } else {
                *p++ = B64_LUT[b64_int];
                *p++ = '=';
            }

        /* There is only 1 byte of input, so interpret 2nd character with two
         * "0x00" bytes appended, and pad with two '=' characters */
        } else {
            *p++ = B64_LUT[b64_int];
            strncat(b64_str, "==", 2);
        }
    }

    return b64_str;
}

/*------------------------------------------------------------------------------
 *         Decode base64 string to byte array
 *----------------------------------------------------------------------------*/
size_t b642byte(BYTE **byte, const char *b64)
{
    size_t nchar,
           i,
           nbyte;

    /* Input checking */
    if (b64) {
        nchar = strlen(b64);
    } else {
        return 0;
    }

    /* Require padding by '=' signs */
    if (nchar % 4) {
        printf("nchar = %zu\n", nchar);
        ERROR("Input string is not a valid b64 string!");
    } else {
        /* 4 b64 chars * 6 bits/char == 24 bits / 8 bits/byte == 3 bytes */
        /* check for "=" padding in b64 string -- will have 0, 1, or 2 */
        char *s = strchr(b64, '=');
        nbyte = nchar*3/4 - (s ? (nchar - (s - b64)) : 0);
    }

    /* Initialize output */
    *byte = init_byte(nbyte);
    BYTE *p = *byte;

    /* Operate in chunks of 4 bytes in ==> 3 bytes out */
    for (i = 0; i < nchar; i+=4) {
        /* Get 4 bytes of input */
        int b64_int[4];

        for (int j = 0; j < 4; j++) {
            /* Lookup table of b64 indices */
            int b = (int)indexof(B64_LUT, b64[i+j]);

            if (b < 65 && b >= 0) {
                b64_int[j] = b;
            } else {
                printf("got index %d\n", b);
                ERROR("Input string is not a valid b64 string!");
            }
        }

        /* NOTE mask off MSBs for left-shifts so we don't keep large #s 
         * (same as casting to char, but probably faster) */
        *p++ = ((b64_int[0] << 2) & 0xFF) | (b64_int[1] >> 4); /* 1st byte */
        *p++ = ((b64_int[1] << 4) & 0xFF) | (b64_int[2] >> 2); /* 2nd byte */
        *p++ = ((b64_int[2] << 6) & 0xFF) |  b64_int[3];       /* 3rd byte */
    }

    return nbyte;
}

/*------------------------------------------------------------------------------
 *      XOR two equal-length byte arrays
 *----------------------------------------------------------------------------*/
BYTE *fixedXOR(const BYTE *a, const BYTE *b, size_t nbyte)
{
    BYTE *xor = init_byte(nbyte);

    /* XOR each byte in the input array */
    for (int i = 0; i < nbyte; i++) {
       *(xor+i) = *(a+i) ^ *(b+i);
    }
    return xor;
}


/*------------------------------------------------------------------------------
 *         Get character frequency score of string
 *----------------------------------------------------------------------------*/
float charFreqScore(const BYTE *byte, size_t nbyte)
{
    /* <https://en.wikipedia.org/wiki/Letter_frequency> */
    /* Indexed [A-Z] - 'A' == 0 -- 25 */
    static const float ENGLISH_FREQ[] =
        { 0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  \
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  \
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  \
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074 };

    /* ordering by frequency of acceptable chars */
    static const char etaoin[] = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

    float N = 0,
          Nl = 0,
          letter_frac = 1,
          score = FLT_MAX,
          observed = 0.0,
          expected = 0.0,
          chi_sq = 0.0,
          tol = 1e-16;

    /* Count frequency of each letter in string */
    int *cf = countChars(byte, nbyte);

    /* Calculate score via chi-squared test */
    N = (float)nbyte; /* all chars in array */

    /* Count just letters in string */
    for (int j = 0; j < NUM_LETTERS; j++) {
        Nl += (float)cf[j];
    }

    /* Fraction of string that is just letters */
    letter_frac = Nl/N;
    if (letter_frac < tol) {  /* no letters present, just clean up and exit */
        free(cf);
        return score; 
    }

    /* Sum the chi^2 values for each alphabetic character */
    for (int i = 0; i < strlen(etaoin); i++) {
        int ch_ind = etaoin[i];
        observed = cf[ch_ind-'A'];               /* observed count */
        expected = ENGLISH_FREQ[ch_ind-'A'] * N; /* expected in English */

        /* sum actual letter counts, not frequencies */
        chi_sq += (observed - expected)*(observed - expected) / expected;
    }

    /* Weight strings with more letter in them (vs non-letter chars) */
    score = chi_sq / (letter_frac*letter_frac);

    free(cf);
    return score;
}


/*------------------------------------------------------------------------------
 *         Allocate memory and initialize an XOR_NODE
 *----------------------------------------------------------------------------*/
XOR_NODE *init_xor_node(void)
{
    XOR_NODE *out = NULL;

    /* Allocate memory for the output */
    out = NEW(XOR_NODE);
    MALLOC_CHECK(out);
    BZERO(out, sizeof(XOR_NODE));

    /* Initialize fields */
    BZERO(out->key, sizeof(out->key));
    BZERO(out->plaintext, sizeof(out->plaintext));
    out->key_byte  = 0;
    out->score     = FLT_MAX; /* initialize to large number */
    out->file_line = 0;

    return out;
}

/*------------------------------------------------------------------------------
 *         Decode a string XOR'd against a single character
 *----------------------------------------------------------------------------*/
XOR_NODE *singleByteXORDecode(const BYTE *byte, size_t nbyte)
{
    XOR_NODE *out = init_xor_node();
    float cfreq_score = FLT_MAX; /* initialize large value */

    /* test each possible character byte */
    for (int keyi = 0x01; keyi < 0x100; keyi++) {
        BYTE key = (BYTE)keyi;  /* cast to char (char always < 0x100) */

        /* Decode input with single-byte key */
        BYTE *ptext = repeatingKeyXOR(byte, &key, nbyte, 1);

        /* Make sure string does not contain NULL chars, and is printable */
        /* strlen(ptext) could break. BYTE not guaranteed null-terminated */
        if (isprintable(ptext, nbyte)) {
        /* if ((strlen(ptext) == nbyte) && (isprintable(ptext))) { */
            /* calculate string score */
            cfreq_score = charFreqScore(ptext, nbyte);

#ifdef VERBOSE
            printf("%0.2X\t%s\t%10.4e\n", key, ptext, cfreq_score);
#endif
            /* Track minimum chi-squared score and actual key */
            if (cfreq_score < out->score) {
                out->score = cfreq_score;
                /* include null-terminator in output for ease of use */
                BZERO(out->key, 2);
                memcpy(out->key, &key, 1);
                BZERO(out->plaintext, nbyte+1);
                memcpy(out->plaintext, ptext, nbyte);
                out->key_byte = 1;
            }
        }

        free(ptext);
    }

    return out;
}

/*------------------------------------------------------------------------------
 *         Find single byte XOR string in a file
 *----------------------------------------------------------------------------*/
XOR_NODE *findSingleByteXOR(const char *filename)
{
    XOR_NODE *out = NULL;
    FILE *fp = NULL;
    char buffer[MAX_WORD_LEN];
    char message[2*MAX_PAGE_NUM];
    BZERO(buffer, MAX_WORD_LEN);
    BZERO(message, 2*MAX_PAGE_NUM);

    /* initialize output */
    out = init_xor_node();

    /* open file stream */
    fp = fopen(filename, "r");
    if (fp == NULL) {
        snprintf(message, 2*MAX_PAGE_NUM, "File %s could not be read!", filename);
        ERROR(message);
    }

    int file_line = 1;

    /* For each line, run singleByteXORDecode, return {key, string, score} */
    while ( fgets(buffer, sizeof(buffer), fp) ) {
        /* Buffer is hex, so OK to treat as string */
        buffer[strcspn(buffer, "\n")] = '\0';  /* remove trailing '\n' */
        BYTE *byte = NULL;
        size_t nbyte = hex2byte(&byte, buffer);

#ifdef VERBOSE
        printf("---------- Line: %3d\n", file_line);
#endif

        /* Find most likely key for this line */
        XOR_NODE *temp = singleByteXORDecode(byte, nbyte);
        if (*temp->plaintext) {
            /* Track {key, string, score} by lowest score */
            if (temp->score < out->score) {
                BZERO(out->key, sizeof(out->key));
                memcpy(out->key, temp->key, strlen((char *)temp->key));
                BZERO(out->plaintext, sizeof(out->plaintext));
                memcpy(out->plaintext, temp->plaintext, strlen((char *)temp->plaintext));
                out->score = temp->score;
                out->file_line = file_line;
            }
        }
#ifdef VERBOSE
        else { printf("\x1B[A\r"); /* move cursor up and overwrite */ }
#endif
        free(byte);
        free(temp); /* clean-up */
        file_line++;
    }

#ifdef VERBOSE
    printf("\x1B[A\r\n\n"); /* erase last title line */
#endif
    fclose(fp);
    return out;
}

/*------------------------------------------------------------------------------
 *         Encode hex string using repeating-key XOR
 *----------------------------------------------------------------------------*/
BYTE *repeatingKeyXOR(const BYTE *byte, const BYTE *key_byte, size_t nbyte, size_t key_len)
{
    /* XOR each byte in the ciphertext with the key */
    BYTE *key_arr = bytenrepeat(key_byte, key_len, nbyte);
    BYTE *xor = fixedXOR(byte, key_arr, nbyte);
    free(key_arr);
    return xor;
}

/*------------------------------------------------------------------------------
 *         Compute Hamming distance between strings
 *----------------------------------------------------------------------------*/
size_t hamming_dist(const BYTE *a, const BYTE *b, size_t nbyte)
{
    BYTE *xor = fixedXOR(a, b, nbyte); /* XOR returns differing bits */
    size_t weight = hamming_weight(xor, nbyte);
    free(xor);
    return weight;
}


/*------------------------------------------------------------------------------
 *         Get the normalized mean Hamming distance
 *----------------------------------------------------------------------------*/
float normMeanHamming(const BYTE *byte, size_t nbyte, size_t k)
{
    /* Maximum number of pairs of size k */
    size_t n_blocks = (size_t)ceil(nbyte/(2.0*k) + 1);

    unsigned long tot_dist = 0;

    /* Take all combinations of blocks of length k */
    for (int i = 0; i < n_blocks; i++) {
        for (int j = i+1; j < n_blocks; j++) {
            const BYTE *a = byte + k*i;
            const BYTE *b = byte + k*j;
            tot_dist += hamming_dist(a,b,k);
        }
    }

    /* total combinations == n!/((n-k)!k!), but 2! == 2 */
    size_t ncomb = n_blocks*(n_blocks-1)/2;

    /* Average Hamming distances normalized by bytes in key */
    float mean_dist =  (float)tot_dist / ncomb;
    float norm_mean = mean_dist / k;

#ifdef VERBOSE
    printf("%3zu\t%8.4f\t%8.4f\n", k, mean_dist, norm_mean);
#endif

    return norm_mean;
}

/*------------------------------------------------------------------------------
 *         Get most probable key length of repeating XOR 
 *----------------------------------------------------------------------------*/
size_t getKeyLength(const BYTE *byte, size_t nbyte)
{
    size_t min_samples = 10; /* ensure high accuracy */
    size_t key_byte = 0;
    float min_mean_dist = FLT_MAX;

    /* key length in bytes */
    size_t max_key_len = (size_t)min(40.0, (float)nbyte/min_samples);

#ifdef VERBOSE
    printf("%3s\t%8s\t%8s\n", "Key", "Mean", "Norm");
#endif
    for (size_t k = 3; k <= max_key_len; k++) {
        /* Get mean Hamming distance of all samples */
        float norm_mean = normMeanHamming(byte, nbyte, k);

        /* Take key with minimum mean Hamming distance. */
        if (norm_mean < min_mean_dist) {
            min_mean_dist = norm_mean;
            key_byte = k;
        }
    }

#ifdef VERBOSE
    printf("key_byte  = %zu\n",   key_byte);
    printf("min_dist  = %6.4f\n", min_mean_dist);
#endif

    return key_byte;
}


/*------------------------------------------------------------------------------
 *         Break repeating key XOR cipher
 *----------------------------------------------------------------------------*/
XOR_NODE *breakRepeatingXOR(const BYTE *byte, size_t nbyte)
{
    /* Get most probable key length */
    /* TODO return sorted list of possible key sizes */
    size_t key_byte = getKeyLength(byte, nbyte);

    /* Maximum number of bytes in each substring 
     * (may run out of chars on repeated key application) */
    size_t nbyte_t = (nbyte + (key_byte - (nbyte % key_byte))) / key_byte;

    XOR_NODE *out = init_xor_node();

    /* For each byte of the key, transpose input and decode */
    for (size_t k = 0; k < key_byte; k++) {
        /* Transpose input into every kth chunk */
        BYTE *byte_t = init_byte(nbyte_t);
        size_t count_byte = 0;
        for (size_t i = 0; i < nbyte_t; i++) {
            /* Make sure we're not at end of input */
            size_t ind = k+i*key_byte;
            if (ind < nbyte) {
                *(byte_t+i)   = *(byte+ind);
                count_byte++; /* track actual number of bytes used */
            } else { 
                break; 
            }
        }

#ifdef VERBOSE
        printf("---------- k = %zu\n", k);
#endif
        /* Run single byte xor on each chunk */
        XOR_NODE *temp = singleByteXORDecode(byte_t, count_byte);
        *(out->key+k) = *(temp->key);

        free(temp);
        free(byte_t);
    }

    if (*out->key) {
        /* XOR original string with found key! */
        BYTE *ptext = repeatingKeyXOR(byte, out->key, nbyte, key_byte);
        memcpy(out->plaintext, ptext, nbyte);
        out->key_byte = key_byte;
        free(ptext);
    } else {
        WARNING("Key not found!");
    }

    return out;
}

/*------------------------------------------------------------------------------
 *         Look for blocks with 0 Hamming distance
 *----------------------------------------------------------------------------*/
int hasIdenticalBlocks(const BYTE *byte, size_t nbyte, size_t k)
{
    /* Maximum number of pairs of size k */
    size_t n_blocks = (size_t)ceil(nbyte/(2.0*k) + 1);

    /* Take all combinations of blocks of length k */
    for (int i = 0; i < n_blocks; i++) {
        for (int j = i+1; j < n_blocks; j++) {
            const BYTE *a = byte + k*i;
            const BYTE *b = byte + k*j;
            /* If we found identical blocks, break */
            if (0 == hamming_dist(a,b,k)) { return 1; }
        }
    }

    return 0;
}
/*------------------------------------------------------------------------------
 *         Detect AES in ECB mode 
 *----------------------------------------------------------------------------*/
int find_AES_ECB(BYTE **out, const char *hex_filename)
{
    int file_line = -1;
    FILE *fp = NULL;
    char buffer[MAX_WORD_LEN];
    char message[2*MAX_PAGE_NUM];
    BZERO(buffer, MAX_WORD_LEN);
    BZERO(message, 2*MAX_PAGE_NUM);

    /* open file stream */
    fp = fopen(hex_filename, "r");
    if (fp == NULL) {
        snprintf(message, sizeof(message), "File %s could not be read!", hex_filename);
        ERROR(message);
    }

    int fl = 1; /* count file lines */
    BYTE key_byte = 16;
    /* float min_mean_dist = FLT_MAX; */

    while ( fgets(buffer, sizeof(buffer), fp) ) {
        buffer[strcspn(buffer, "\n")] = '\0';  /* remove trailing '\n' */

        /* Convert to byte array */
        BYTE *byte = NULL;
        size_t nbyte = hex2byte(&byte, buffer);

        /* initialize output only for first line */
        if (fl == 1) { *out = init_byte(nbyte); }

        /* AES ECB encrypted line will have identical blocks of ciphertext */
        if (hasIdenticalBlocks(byte, nbyte, key_byte)) {
            memcpy(*out, byte, nbyte);
            file_line = fl;
        }

/*         #<{(| Get mean Hamming distance between key_byte-size chunks of byte |)}># */
/*         float mean_dist = normMeanHamming(byte, nbyte, key_byte); */
/*          */
/* #ifdef LOGSTATUS */
/*         printf("%4d\t%8.4f\n", fl, mean_dist); */
/* #endif */
/*         if (mean_dist < min_mean_dist) { */
/*             min_mean_dist = mean_dist; */
/*             memcpy(*out, byte, nbyte); */
/*             file_line = fl; */
/*         } */

        free(byte);
        fl++;
    }

    fclose(fp);
    return file_line; 
}
/*==============================================================================
 *============================================================================*/
