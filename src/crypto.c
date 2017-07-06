/*==============================================================================
 *     File: crypto.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for cryptography challenges
 *
 *============================================================================*/
#include "crypto.h"
#include "crypto_util.h"
#include "header.h"

/*------------------------------------------------------------------------------
 *      Convert hexadecimal string to base64 string
 *----------------------------------------------------------------------------*/
char *hex2b64_str(char *hex_str)
{
    const char *b64_lut = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    int nchr_in,
        nbyte_in,
        nbyte_out,
        nchr_out,
        b64_int;
    int hex_int;

    if (hex_str) {
        nchr_in = strlen(hex_str);      /* Number of chars in encoded string */
    } else {
        return NULL;
    }

    if (nchr_in & 1) {
        ERROR("Input string it not a valid hex string!");
    } else {
        nbyte_in = nchr_in / 2;            /* 2 hex chars == 1 byte */
    }

    /* round nbyte up to multiple of 3 (need 3 bytes for even base64 output) */
    nbyte_out = nbyte_in + 3 - (nbyte_in % 3);
    nchr_out = nbyte_out * 4/3;  /* Number of chars in output */

    /* allocate memory for output */
    char *b64_str = malloc(nchr_out * sizeof(char));
    MALLOC_CHECK(b64_str);
    BZERO(b64_str, nchr_out);

    /* Operate in chunks of 3 bytes in ==> 4 bytes out */
    for (int i = 0; i < nbyte_in; i+=3) {
        int j = 0;
        hex_int = getHexByte(hex_str+2*i+2*j);

        /* Add first character using first 6 bits of first byte */
        b64_int = (hex_int & 0xFC) >> 2;
        strncat(b64_str, &b64_lut[b64_int], 1);

        /* get last 2 bits of first byte */
        b64_int = (hex_int & 0x03) << 4;

        /* if we have more bytes to go */
        if (j+1 < nbyte_in) {
            j++;
            hex_int = getHexByte(hex_str+2*i+2*j);

            /* Add second character using first 4 bits of second byte and
             * combine with 2 from above */
            b64_int |= (hex_int & 0xF0) >> 4;
            strncat(b64_str, &b64_lut[b64_int], 1);

            /* get last 4 bits of second byte */
            b64_int = (hex_int & 0x0F) << 2;

            /* if we have more bytes to go */
            if (j+1 < nbyte_in) {
                j++;
                hex_int = getHexByte(hex_str+2*i+2*j);
                /* Add third character */
                /* get first 2 bits of third byte and combine with 4 from above */
                b64_int |= (hex_int & 0xC0) >> 6;
                strncat(b64_str, &b64_lut[b64_int], 1);

                /* Add fourth character using last 6 bits of third byte */
                b64_int = (hex_int & 0x3F);
                strncat(b64_str, &b64_lut[b64_int], 1);

            /* There are only 2 bytes of input, so interpret 3rd character with
             * a "0x00" byte appended, and pad with an '=' character */
            } else {
                strncat(b64_str, &b64_lut[b64_int], 1);
                strncat(b64_str, "=", 1);
            }

        /* There is only 1 byte of input, so interpret 2nd character with two
         * "0x00" bytes appended, and pad with an '=' character */
        } else {
            strncat(b64_str, &b64_lut[b64_int], 1);
            strncat(b64_str, "==", 2);
        }
    }

    return b64_str;
}

/*------------------------------------------------------------------------------
 *      XOR two equal-length hex-encoded buffers
 *----------------------------------------------------------------------------*/
char *fixedXOR(char *str1, char *str2)
{
    size_t len1 = strlen(str1),
           len2 = strlen(str2);
    char *hex_str;
    int hex_xor, hex_int1, hex_int2;
    char hex_chars[3];

    if (len1 != len2) { ERROR("Input strings must be the same length!"); }

    /* int nbyte = len1/2; */

    /* allocate memory for string output */
    hex_str = malloc(len1 * sizeof(char));
    MALLOC_CHECK(hex_str);
    BZERO(hex_str, len1);

    /* XOR each byte in the input string */
    for (int i = 0; i < len1; i+=2) {
        hex_int1 = getHexByte(str1+i); /* 2 chars per byte */
        hex_int2 = getHexByte(str2+i);
        hex_xor = hex_int1 ^ hex_int2;
        snprintf(hex_chars, 3, "%0.2X", hex_xor);  /* convert to hex chars */
        strncat(hex_str, hex_chars, 2);            /* append to output string */
    }

    /* return hex-encoded string */
    return hex_str;
}

/*------------------------------------------------------------------------------
 *         Find character frequency in string 
 *----------------------------------------------------------------------------*/
CHARFREQ *countChars(char *s)
{
    /* TODO update this function to count other non-alphabetic characters, and
     * penalize strings that have many non-ascii characters */
    CHARFREQ *cf; /* one struct per letter of alphabet */
    int i;

    /* Initialize struct array */
    cf = malloc(NUM_LETTERS * sizeof(CHARFREQ));
    MALLOC_CHECK(cf);
    BZERO(cf, NUM_LETTERS*sizeof(CHARFREQ));

    /* Populate struct array with ALL characters */
    for (i = 0; i < NUM_LETTERS; i++) {
        cf[i].letter = i;
        cf[i].count = 0;
    }

    /* Get frequency of ALL characters in the string */
    i = 0;
    while (s[i]) {
        cf[(size_t)s[i]].count++;
        i++;
    }
    return cf;
}

/*------------------------------------------------------------------------------
 *         Get character frequency score of string
 *----------------------------------------------------------------------------*/
float charFreqScore(char *str)
{
    const char etaoin[] = "ETAOINSHRDLCUMWFGYPBVKJXQZ";  /* acceptable chars */
    int len = strlen(etaoin);
    float observed = 0.0,
          expected = 0.0,
          chi_sq = 0.0;
    int ch_ind;

    /* Get ordered string of letters */
    CHARFREQ *cf = countChars(str);

    /* <https://en.wikipedia.org/wiki/Letter_frequency> */
    const float english_freq[] = 
        { 0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  \
          0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  \
          0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  \
          0.00978, 0.02360, 0.00150, 0.01974, 0.00074 };

    /* Calculate score via chi-squared test */
    float slen = (float)strlen(str);

    /* Sum the chi^2 values for each alphabetic character */
    for (int i = 0; i < len; i++) {
        ch_ind = etaoin[i];
        observed = cf[ch_ind].count;
        expected = english_freq[ch_ind-'A'] * slen;
        chi_sq += (observed - expected)*(observed - expected) / expected;
    }

    free(cf);
    return chi_sq;
}

/*------------------------------------------------------------------------------
 *         Encode a string with a single byte XOR cipher 
 *----------------------------------------------------------------------------*/
char *singleByteXOREncode(char *hex, int key_int)
{
    size_t len = strlen(hex);
    if (len & 1) { ERROR("Input string is not a valid hex string!"); }
    if ((key_int < 0x00) || (key_int >= 0x100)) { ERROR("key is outside of valid range!"); }

    int nbyte = len/2;
    char key[3],            /* i.e. 0x01 --> '01' */
         key_str[len+1];    /* i.e. if hex == "4D616E", key_str = "010101" */
    BZERO(key, 3);
    BZERO(key_str, len+1);

    /* repeat key for each byte of input, so only one XOR is needed */
    snprintf(key, 3, "%0.2X", key_int);
    for (int j = 0; j < nbyte; j++) {
        strncat(key_str, key, 2);
    }

    /* XOR each byte in the ciphertext with the key */
    return fixedXOR(hex, key_str);
}

/*------------------------------------------------------------------------------
 *         Decode a string XOR'd against a single character
 *----------------------------------------------------------------------------*/
char *singleByteXORDecode(char *hex)
{
    size_t len = strlen(hex);
    if (len & 1) { ERROR("Input string is not a valid hex string!"); }

    float cfreq_score_min = 1.0e9; /* initialize to large number */

    /* Allocate memory for the output */
    char *plaintext = malloc(len * sizeof(char));
    MALLOC_CHECK(plaintext);
    BZERO(plaintext, len);

    char *true_key = malloc(3 * sizeof(char));
    MALLOC_CHECK(true_key);
    BZERO(true_key, sizeof(*true_key));

    /* test each possible character byte */
#ifdef LOGSTATUS
        printf("key\tdecoded string\t\t\t\tchi^2\n");
#endif
    /* for (int i = 0x58; i < 0x59; i++) { */
    for (int i = 0x00; i < 0x100; i++) {
        /* Decode hex string */
        char *xor = singleByteXOREncode(hex, i);

        /* Convert to plain ASCII text */
        char *ptext = htoa(xor);

        /* Calculate character frequency score */
        float cfreq_score = charFreqScore(ptext);

#ifdef LOGSTATUS
        /* print each key, decoded string, score */
        if (isValid(ptext) == 0) {
            printf("%0.2X\t%s\t%10.4f\n", i, ptext, cfreq_score);
        } else {
            printf("%0.2X\t%s\t\t%10.5f\n", i, "--------------------", cfreq_score);
        }
#endif

        /* Track minimum chi-squared score and actual key */
        if (cfreq_score < cfreq_score_min) {
            cfreq_score_min = cfreq_score;
            snprintf(true_key, 3, "%0.2X", i);
            strncpy(plaintext, ptext, len);
        }
    }

#ifdef LOGSTATUS
    printf("--------------------\n");
    printf("found key = %s\n", true_key);
    printf("cfreq_score_min = %10.4f\n", cfreq_score_min);
#endif

    /* Return the decoded plaintext! */
    return plaintext;
}
/*==============================================================================
 *============================================================================*/
