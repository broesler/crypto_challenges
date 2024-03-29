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

#include "aes_openssl.h"
#include "crypto1.h"
#include "crypto2.h"
#include "crypto_util.h"
#include "header.h"

/* Globals */
/* Used in hex2b64_str() and b642hex_str(): */
static const char B64_LUT[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/*------------------------------------------------------------------------------
 *          Challenge 1: Convert hexadecimal string to base64 string
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
           nbyte;

    /* Input checking */
    if (b64) {
        nchar = strlen(b64);
    } else {
        return 0;
    }

    /* Require padding by '=' signs */
    if (nchar % 4) {
        ERROR("Input string is not a valid b64 string! nchar = %zu\n", nchar);
    } else {
        /* 4 b64 chars * 6 bits/char == 24 bits / 8 bits/byte == 3 bytes */
        /* check for "=" padding in b64 string -- will have 0, 1, or 2 */
        char *s = strchr(b64, '=');
        nbyte = nchar*3/4 - (s ? (nchar - (s - b64)) : 0);
    }

    /* Check that we actually have bytes to convert */
    if (nbyte == 0) { return 0; }

    /* Initialize output */
    *byte = init_byte(nbyte);
    BYTE *p = *byte;

    size_t n = 0;
    /* Operate in chunks of 4 bytes in ==> 3 bytes out */
    for (size_t i = 0; i < nchar; i+=4) {
        /* Get 4 bytes of input */
        int b64_int[4];

        for (int j = 0; j < 4; j++) {
            /* Lookup table of b64 indices */
            int b = (int)indexof(B64_LUT, b64[i+j]);

            if (0 <= b && b < 65) {
                b64_int[j] = b;
            } else {
                ERROR("Input string is not a valid b64 string! got index %d\n", b);
            }
        }

        /* Assign bytes to array -- always */
        *p++ = ((b64_int[0] << 2) & 0xFF) | (b64_int[1] >> 4); /* 1st byte */
        n++;

        if (n++ >= nbyte) { break; }
        *p++ = ((b64_int[1] << 4) & 0xFF) | (b64_int[2] >> 2); /* 2nd byte */

        if (n++ >= nbyte) { break; }
        *p++ = ((b64_int[2] << 6) & 0xFF) |  b64_int[3];       /* 3rd byte */
    }

    return nbyte;
}

/*------------------------------------------------------------------------------
 *          Challenge 2: XOR two equal-length byte arrays
 *----------------------------------------------------------------------------*/
BYTE *fixed_xor(const BYTE *a, const BYTE *b, size_t nbyte)
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
/* TODO include spaces and punctuation! 1st and ~4th in order */
float char_freq_score(const BYTE *byte, size_t nbyte)
{
    /* <https://en.wikipedia.org/wiki/Letter_frequency> */
    /* Indexed [A-Z] - 'A' == 0 -- 25 */
    /* static const float ENGLISH_FREQ[] = */
        /* { 0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  \ */
        /*   0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  \ */
        /*   0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  \ */
        /*   0.00978, 0.02360, 0.00150, 0.01974, 0.00074 */ 
        /* }; */
    /* <http://www.macfreek.nl/memory/Letter_Distribution> */
    /* Includes space as {A: 0, B: 1, ..., Z: 25, SPACE: 26} */
    static const float ENGLISH_FREQ[] =
        { 0.065454, 0.012614, 0.022382, 0.032896, 0.102875, 0.019871, 0.016282,\
          0.049887, 0.056799, 0.000977, 0.005621, 0.033243, 0.020307, 0.057236,\
          0.061721, 0.015074, 0.000838, 0.049980, 0.053278, 0.075322, 0.022804,\
          0.007977, 0.017074, 0.001412, 0.014306, 0.000514, 0.183256,
        };

    /* ordering by frequency of acceptable chars (include space!) */
    static const char etaoin[] = "ETAOINSHRDLCUMWFGYPBVKJXQZ ";

    float N = 0,
          Nl = 0,
          letter_frac = 1,
          score = FLT_MAX,
          observed = 0.0,
          expected = 0.0,
          chi_sq = 0.0;
    const float TOL = 1e-16;

    /* Count frequency of each letter in string */
    int *cf = count_chars(byte, nbyte);

    /* Calculate score via chi-squared test */
    N = (float)nbyte; /* all chars in array */

    /* Count letters and spaces in string */
    for (int j = 0; j < NUM_LETTERS; j++) {
        Nl += (float)cf[j];
    }

    /* Fraction of string that is just letters and spaces */
    if ((letter_frac = Nl/N) < TOL) {  /* no letters present */
        free(cf);
        return score; 
    }

    /* Sum the chi^2 values for each alphabetic character */
    /* NOTE this calculation does not include spaces! */
    for (int i = 0; i < strlen(etaoin); i++) {
        int ch_ind = etaoin[i];
        int ind = 0;
        if ('A' <= ch_ind && ch_ind <= 'Z') {
            ind = ch_ind - 'A';
        } else if (ch_ind == 32) {
            ind = NUM_LETTERS - 1;
        } else {
            ERROR("Invalid character index!");
        }
        observed = cf[ind];               /* observed count */
        expected = ENGLISH_FREQ[ind] * N; /* expected in English */

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
 *         Challenge 3: Decode a string XOR'd against a single character
 *----------------------------------------------------------------------------*/
XOR_NODE *single_byte_xor_decode(const BYTE *byte, size_t nbyte)
{
    XOR_NODE *out = init_xor_node();
    float cfreq_score = FLT_MAX; /* initialize large value */

    /* test each possible character byte */
    for (int keyi = 0x01; keyi < 0x100; keyi++) {
        BYTE key = (BYTE)keyi;  /* cast to char (char always < 0x100) */

        /* Decode input with single-byte key */
        BYTE *ptext = repeating_key_xor(byte, &key, nbyte, 1);

        /* Make sure string does not contain NULL chars, and is printable */
        /* strlen(ptext) could break. BYTE not guaranteed null-terminated */
        if (isprintable(ptext, nbyte)) {
            /* calculate string score */
            cfreq_score = char_freq_score(ptext, nbyte);

#ifdef VERBOSE
            printf("%.2X\t%s\t%10.4e\n", key, ptext, cfreq_score);
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
 *         Challenge 5: Encode hex string using repeating-key XOR
 *----------------------------------------------------------------------------*/
BYTE *repeating_key_xor(const BYTE *byte, const BYTE *key_byte, size_t nbyte, size_t key_len)
{
    /* XOR each byte in the ciphertext with the key */
    BYTE *key_arr = bytenrepeat(key_byte, key_len, nbyte);
    BYTE *xor = fixed_xor(byte, key_arr, nbyte);
    free(key_arr);
    return xor;
}

/*------------------------------------------------------------------------------
 *         Compute Hamming distance between strings
 *----------------------------------------------------------------------------*/
size_t hamming_dist(const BYTE *a, const BYTE *b, size_t nbyte)
{
    BYTE *xor = fixed_xor(a, b, nbyte); /* XOR returns differing bits */
    size_t weight = hamming_weight(xor, nbyte);
    free(xor);
    return weight;
}

/*------------------------------------------------------------------------------
 *         Get the normalized mean Hamming distance
 *----------------------------------------------------------------------------*/
float norm_mean_hamming(const BYTE *byte, size_t nbyte, size_t k)
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
size_t get_key_length(const BYTE *byte, size_t nbyte)
{
    size_t min_samples = 10;  /* ensure high accuracy */
    size_t key_byte = 0;
    float min_mean_dist = FLT_MAX;

    /* key length in bytes */
    size_t max_key_len = (size_t)MIN(40.0, (float)nbyte/min_samples);

#ifdef VERBOSE
    printf("%3s\t%8s\t%8s\n", "Key", "Mean", "Norm");
#endif
    for (size_t k = 3; k <= max_key_len; k++) {
        /* Get mean Hamming distance of all samples */
        float norm_mean = norm_mean_hamming(byte, nbyte, k);

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
 *         Challenge 6: Break repeating key XOR cipher
 *----------------------------------------------------------------------------*/
XOR_NODE *break_repeating_xor(const BYTE *byte, const size_t nbyte, 
                              int key_byte)
{
    if (key_byte < 0) {
        /* Get most probable key length */
        /* TODO return sorted list of possible key sizes */
        key_byte = get_key_length(byte, nbyte);
    }

    /* Maximum number of bytes in each substring 
     * (may run out of chars on repeated key application) */
    size_t nbyte_t = (nbyte + (key_byte - (nbyte % key_byte))) / key_byte;

    XOR_NODE *out = init_xor_node();

    /* For each byte of the key, transpose input and decode */
    for (size_t k = 0; k < key_byte; k++) {
        /* TODO refactor this block into a function */
        /* Transpose input into every kth chunk */
        BYTE *byte_t = init_byte(nbyte_t);
        size_t count_byte = 0, ind = 0;
        for (size_t i = 0; i < nbyte_t; i++) {
            /* Make sure we're not at end of input */
            ind = k + i*key_byte;
            if (ind < nbyte) {
                *(byte_t + i) = *(byte + ind);
                count_byte++; /* track actual number of bytes used */
            } else { 
                break; 
            }
        }

#ifdef VERBOSE
        printf("---------- k = %zu\n", k);
#endif
        /* Run single byte xor on each chunk */
        XOR_NODE *temp = single_byte_xor_decode(byte_t, count_byte);
        *(out->key+k) = *(temp->key);

        free(temp);
        free(byte_t);
    }

    if (*out->key) {
        /* XOR original string with found key! */
        BYTE *ptext = repeating_key_xor(byte, out->key, nbyte, key_byte);
        memcpy(out->plaintext, ptext, nbyte);
        out->key_byte = key_byte;
        free(ptext);
    } else {
        ERROR("Key not found!");
    }

    return out;
}

/*------------------------------------------------------------------------------
 *         Look for blocks with 0 Hamming distance
 *----------------------------------------------------------------------------*/
int has_identical_blocks(const BYTE *byte, size_t nbyte, size_t block_size)
{
    /* Maximum number of pairs of size block_size */
    size_t n_blocks = (size_t)ceil(nbyte/(2.0*block_size) + 1);

    /* Take all combinations of blocks of length block_size */
    for (int i = 0; i < n_blocks; i++) {
        for (int j = i+1; j < n_blocks; j++) {
            const BYTE *a = byte + block_size*i;
            const BYTE *b = byte + block_size*j;
            /* If we found identical blocks, break */
            if (0 == hamming_dist(a,b,block_size)) { 
                return 1; 
            }
        }
    }

    return 0;
}

/*==============================================================================
 *============================================================================*/
