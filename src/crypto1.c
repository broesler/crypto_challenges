/*==============================================================================
 *     File: crypto1.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for cryptography challenges
 *
 *============================================================================*/
#include <float.h>

#include "crypto1.h"
#include "crypto_util.h"
#include "header.h"

/* Global variable */
// <https://en.wikipedia.org/wiki/Letter_frequency>
// Indexed [A-Z] - 'A' == 0 -- 25
const float ENGLISH_FREQ[] = 
    { 0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  \
      0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  \
      0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  \
      0.00978, 0.02360, 0.00150, 0.01974, 0.00074 };

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
    char *b64_str = init_str(nchr_out);

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
    int hex_xor, hex_int1, hex_int2;
    char hex_chars[3];

    if (len1 != len2) { ERROR("Input strings must be the same length!"); }

    /* allocate memory for string output */
    char *hex_str = init_str(len1);

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
int *countChars(const char *s)
{
    /* initialize array */
    int *cf = init_int(NUM_LETTERS);

    /* Get frequency of letters in the string */
    while (*s) {
        if      (*s >= 'A' && *s <= 'Z') { cf[*s-'A']++; }
        else if (*s >= 'a' && *s <= 'z') { cf[*s-'a']++; }
        s++;
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

    /* Count frequency of each letter in string */
    int *cf = countChars(str);

    /* Calculate score via chi-squared test */
    float slen = (float)strlen(str); /* all chars in array */

    /* Calculate slen just counting letters -- no difference in result */
    /* float slen = 0; */
    /* for (int j = 0; j < NUM_LETTERS; j++) { slen += (float)cf[j]; } */

    /* Sum the chi^2 values for each alphabetic character */
    for (int i = 0; i < len; i++) {
        int ch_ind = etaoin[i];
        observed = cf[ch_ind-'A'];                  /* observed count */
        expected = ENGLISH_FREQ[ch_ind-'A'] * slen; /* expected in English */

        /* sum actual letter counts, not frequencies */
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
/* char *singleByteXORDecode(char *hex) */
XOR_NODE *singleByteXORDecode(char *hex)
{
    XOR_NODE *out = NULL;
    size_t len = strlen(hex);
    if (len & 1) { ERROR("Input string is not a valid hex string!"); }

    /* Allocate memory for the output */
    out = NEW(XOR_NODE);
    MALLOC_CHECK(out);
    BZERO(out, sizeof(XOR_NODE));

    /* initialize fields */
    out->key = 0;
    BZERO(out->plaintext, sizeof(out->plaintext));
    out->score = FLT_MAX; /* initialize to large number */

    /* test each possible character byte */
    /* for (int i = 0x35; i < 0x36; i++) { #<{(| actual key for 4.txt |)}># */
    for (int i = 0x00; i < 0x100; i++) {
        char *xor = singleByteXOREncode(hex, i); /* Decode hex string */
        char *ptext = htoa(xor);                 /* Convert to ASCII text */
        float cfreq_score = FLT_MAX;             /* initialize to high value */

        /* Make sure string is printable */
        if (isprintable(ptext)) {
            cfreq_score = charFreqScore(ptext);  /* calculate string score */
            ptext[strcspn(ptext, "\n")] = 0;     /* remove trailing '\n' */
#ifdef LOGSTATUS
            printf("%0.2X\t%s\t%10.4e\n", i, ptext, cfreq_score);
#endif
            /* Track minimum chi-squared score and actual key */
            if (cfreq_score < out->score) {
                out->key = i;
                BZERO(out->plaintext, sizeof(out->plaintext));
                strncpy(out->plaintext, ptext, strlen(ptext));
                out->score = cfreq_score;
            }
        }

        /* clean-up */
        free(xor);
        free(ptext);
    }

    return out;
}

/*------------------------------------------------------------------------------
 *         Find single byte XOR string in a file
 *----------------------------------------------------------------------------*/
XOR_NODE *findSingleByteXOR(char *filename)
{
    XOR_NODE *out = NULL;
    FILE *fp = NULL;
    char *buffer = NULL;
    char message[2*MAX_PAGE_NUM];

    /* Allocate memory for the output */
    out = NEW(XOR_NODE);
    MALLOC_CHECK(out);
    BZERO(out, sizeof(XOR_NODE));

    /* Initialize fields */
    out->key = 0;
    BZERO(out->plaintext, sizeof(out->plaintext));
    out->score = FLT_MAX; /* initialize to large number */
    out->file_line = 0;

    /* open file stream */
    fp = fopen(filename, "r");
    if (fp == NULL) {
        snprintf(message, 2*MAX_PAGE_NUM, "File %s could not be read!", filename);
        ERROR(message);
        exit(-1);
    }

    /* Initialize buffer */
    buffer = init_str(MAX_WORD_LEN);

    int file_line = 1;

    /* For each line, run singleByteXORDecode, return {key, string, score} */
    while ( (buffer = fgets(buffer, MAX_WORD_LEN*sizeof(char), fp)) )
    {
        printf("---------- Line: %3d\n", file_line);
        buffer[strcspn(buffer, "\n")] = 0;  /* remove trailing '\n' */

        /* Find most likely key for this line */
        XOR_NODE *temp = singleByteXORDecode(buffer);
        if (*temp->plaintext) {
            /* Track {key, string, score} by lowest score */
            if (temp->score < out->score) {
                out->key = temp->key;
                BZERO(out->plaintext, sizeof(out->plaintext));
                strncpy(out->plaintext, temp->plaintext, strlen(temp->plaintext));
                out->score = temp->score;
                out->file_line = file_line;
            }
        } else { printf("\x1B[A\r"); /* erase title line */ }

        free(temp);
        file_line++;
    }

    printf("\n");
    free(buffer);
    fclose(fp);
    return out;
}
/*==============================================================================
 *============================================================================*/
