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

const char B64_LUT[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/*------------------------------------------------------------------------------
 *      Convert hexadecimal string to base64 string
 *----------------------------------------------------------------------------*/
char *hex2b64_str(char *hex_str)
{
    int nchr_in,
        nbyte_in,
        nbyte_out,
        nchr_out,
        b64_int;
    unsigned long hex_int;

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
    char *p = b64_str; /* moveable pointer for concatenation */

    /* Operate in chunks of 3 bytes in ==> 4 bytes out */
    for (int i = 0; i < nbyte_in; i+=3) {
        int j = 0;
        htoi(hex_str+2*i+2*j, &hex_int);

        /* Add first character using first 6 bits of first byte */
        b64_int = (hex_int & 0xFC) >> 2;
        *p++ = B64_LUT[b64_int];

        /* get last 2 bits of first byte */
        b64_int = (hex_int & 0x03) << 4;

        /* if we have more bytes to go */
        if (j+1 < nbyte_in) {
            j++;
            htoi(hex_str+2*i+2*j, &hex_int);

            /* Add second character using first 4 bits of second byte and
             * combine with 2 from above */
            b64_int |= (hex_int & 0xF0) >> 4;
            *p++ = B64_LUT[b64_int];

            /* get last 4 bits of second byte */
            b64_int = (hex_int & 0x0F) << 2;

            /* if we have more bytes to go */
            if (j+1 < nbyte_in) {
                j++;
                htoi(hex_str+2*i+2*j, &hex_int);
                /* Add third character */
                /* get first 2 bits of third byte and combine with 4 from above */
                b64_int |= (hex_int & 0xC0) >> 6;
                *p++ = B64_LUT[b64_int];

                /* Add fourth character using last 6 bits of third byte */
                b64_int = (hex_int & 0x3F);
                *p++ = B64_LUT[b64_int];

            /* There are only 2 bytes of input, so interpret 3rd character with
             * a "0x00" byte appended, and pad with an '=' character */
            } else {
                *p++ = B64_LUT[b64_int];
                *p++ = '=';
            }

        /* There is only 1 byte of input, so interpret 2nd character with two
         * "0x00" bytes appended, and pad with an '=' character */
        } else {
            *p++ = B64_LUT[b64_int];
            strncat(b64_str, "==", 2);
        }
    }

    return b64_str;
}

/*------------------------------------------------------------------------------
 *         Convert base64 string to hexadecimal 
 *----------------------------------------------------------------------------*/
char *b642hex_str(char *b64_str)
{
    size_t nchr_in,
           nbyte,
           nchr_out;
    unsigned long hex_int;
    char hex_chr[3];
    BZERO(hex_chr, 3);
    char *hex_str = NULL;

    /* Input checking */
    if (b64_str) {
        nchr_in = strlen(b64_str);
    } else {
        return NULL;
    }

    if (nchr_in % 4) {
        ERROR("Input string is not a valid b64 string!");
    } else {
        /* 4 b64 chars --> 3 bytes */
        /* check for "=" padding in b64 string -- if we find one, s will point
         * to the end of the string, or 2nd to last character.   */
        char *s = strchr(b64_str, '=');
        nbyte = nchr_in*3/4 - (s ? (nchr_in - (s - b64_str)) : 0); 
    }

    /* hex output is longer, so we'll have exactly the right bytes */
    nchr_out = 2*nbyte;  /* hex takes 2 chars per byte */

    /* Get integer array from B64_LUT */
    int *b64_int = init_int(nchr_in);         /* byte array */
    for (int i = 0; i < nchr_in; i++) {
        b64_int[i] = indexof(B64_LUT, b64_str[i]);
    }

    hex_str = init_str(nchr_out);     /* character array */

    /* Operate in chunks of 4 bytes in ==> 3 bytes out */
    for (int i = 0; i < nchr_in; i+=4) {
        /* First char of output */
        /* NOTE mask off MSBs for left-shifts so we don't keep large #s */
        hex_int = ((b64_int[i] << 2) & 0xFF) | (b64_int[i+1] >> 4);
        snprintf(hex_chr, 3, "%0.2lX", hex_int);
        strncat(hex_str, hex_chr, 2);

        /* Second char */
        if ((b64_int[i+2] < 64) && (b64_int[i+2] > 0)) {
            hex_int = ((b64_int[i+1] << 4) & 0xFF) | (b64_int[i+2] >> 2);
            snprintf(hex_chr, 3, "%0.2lX", hex_int);
            strncat(hex_str, hex_chr, 2);

            /* Third char */
            if ((b64_int[i+3] < 64) && (b64_int[i+3] > 0)) {
                hex_int = ((b64_int[i+2] << 6) & 0xFF) | b64_int[i+3];
                snprintf(hex_chr, 3, "%0.2lX", hex_int);
                strncat(hex_str, hex_chr, 2);
            }
        }
    }

    free(b64_int);
    return hex_str;
}

/*------------------------------------------------------------------------------
 *      XOR two equal-length hex-encoded buffers
 *----------------------------------------------------------------------------*/
char *fixedXOR(char *str1, char *str2)
{
    size_t len1 = strlen(str1),
           len2 = strlen(str2);
    unsigned long hex_xor, hex_int1, hex_int2;
    char hex_chars[3];
    BZERO(hex_chars, 3);

    if (len1 != len2) { ERROR("Input strings must be the same length!"); }

    /* allocate memory for string output */
    char *hex_str = init_str(len1);

    /* XOR each byte in the input string */
    for (int i = 0; i < len1; i+=2) {
        htoi(str1+i, &hex_int1); /* 2 chars per byte */
        htoi(str2+i, &hex_int2);
        hex_xor = hex_int1 ^ hex_int2;
        snprintf(hex_chars, 3, "%0.2lX", hex_xor);  /* convert to hex chars */
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

    /* Count occurrences letters in the string */
    while (*s) {
        if      (*s >= 'A' && *s <= 'Z') { cf[*s-'A']++; }
        else if (*s >= 'a' && *s <= 'z') { cf[*s-'a']++; }
        else if (*s == 32) { cf[NUM_LETTERS-1]++; } /* count spaces */
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
    float N = 0,
          Nl = 0,
          letter_frac = 1,
          score = 1.0e9,
          observed = 0.0,
          expected = 0.0,
          chi_sq = 0.0;

    /* Count frequency of each letter in string */
    int *cf = countChars(str);

    /* Calculate score via chi-squared test */
    N = (float)strlen(str); /* all chars in array */

    /* Count just letters in string */
    for (int j = 0; j < NUM_LETTERS; j++) { 
        Nl += (float)cf[j]; 
    }

    /* Fraction of string that is just letters */
    letter_frac = Nl/N;

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
 *         Encode a string with a single byte XOR cipher 
 *----------------------------------------------------------------------------*/
char *singleByteXOREncode(char *hex, char *key)
{
    size_t len = strlen(hex);
    size_t key_len = strlen(key);
    if ((len & 1) || (key_len & 1)) { 
        ERROR("Input string is not a valid hex string!"); 
    }

    char *key_str = strnrepeat_hex(key, key_len, len);

    /* XOR each byte in the ciphertext with the key */
    char *xor = fixedXOR(hex, key_str);
    free(key_str);
    return xor;
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

    char key[3];            /* i.e. 0x01 --> '01' */
    BZERO(key, 3);

    /* test each possible character byte */
    for (int i = 0x00; i < 0x100; i++) {
        snprintf(key, 3, "%0.2X", i);
        char *xor = singleByteXOREncode(hex, key); /* Decode hex string */
        char *ptext = htoa(xor);                 /* Convert to ASCII text */
        float cfreq_score = FLT_MAX;             /* initialize to high value */

        /* Make sure string is printable */
        if (isprintable(ptext)) {
            cfreq_score = charFreqScore(ptext);  /* calculate string score */
            ptext[strcspn(ptext, "\n")] = 0;     /* remove any trailing '\n' */
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
    char buffer[MAX_WORD_LEN];
    char message[2*MAX_PAGE_NUM];
    BZERO(buffer, MAX_WORD_LEN);
    BZERO(message, 2*MAX_PAGE_NUM);

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

    int file_line = 1;

    /* For each line, run singleByteXORDecode, return {key, string, score} */
    while ( fgets(buffer, sizeof(buffer), fp) )
    {
        buffer[strcspn(buffer, "\n")] = 0;  /* remove trailing '\n' */
        /* printf("%s\n", buffer); */

#ifdef LOGSTATUS
        printf("---------- Line: %3d\n", file_line);
#endif

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
        } 
#ifdef LOGSTATUS
        else { printf("\x1B[A\r"); /* move cursor up and overwrite */ }
#endif
        free(temp); /* clean-up */
        file_line++;
    }

#ifdef LOGSTATUS
    printf("\x1B[A\r\n\n"); /* erase last title line */ 
#endif
    fclose(fp);
    return out;
}

/*------------------------------------------------------------------------------
 *         Encode hex string using repeating-key XOR 
 *----------------------------------------------------------------------------*/
char *repeatingKeyXOR(char *input_hex, char *key_hex)
{
    size_t len = strlen(input_hex);
    size_t key_len = strlen(key_hex);
    if ((len & 1) || (key_len & 1)) { 
        ERROR("Input string is not a valid hex string!"); 
    }

    char *key_str = strnrepeat_hex(key_hex, key_len, len);

    /* XOR each byte in the ciphertext with the key */
    char *xor = fixedXOR(input_hex, key_str);
    free(key_str);
    return xor;
}

/*------------------------------------------------------------------------------
 *         Compute Hamming distance between strings 
 *----------------------------------------------------------------------------*/
unsigned long hamming_dist(char *a, char *b)
{
    char *xor = fixedXOR(a, b); /* XOR returns differing bits */
    return hamming_weight(xor);
}
/*==============================================================================
 *============================================================================*/
