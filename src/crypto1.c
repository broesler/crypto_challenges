/*==============================================================================
 *     File: crypto1.c
 *  Created: 10/19/2016, 22:17
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for cryptography challenges
 *
 *============================================================================*/
#include <float.h>
/* #include <math.h> */

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
    char *byte = NULL;
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
    char *byte = NULL;
    size_t nbyte = b642byte(&byte, b64);
    char *hex = byte2hex(byte, nbyte);
    free(byte);
    return hex;
}

/*------------------------------------------------------------------------------
 *      Encode byte array as base64 string
 *----------------------------------------------------------------------------*/
char *byte2b64(const char *byte, size_t nbyte)
{
    int nbyte_out,
        nchr_out,
        this_byte,
        b64_int;

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
size_t b642byte(char **byte, const char *b64)
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

    if (nchar % 4) {
        printf("nchar = %zu\n", nchar);
        ERROR("Input string is not a valid b64 string!");
    } else {
        /* 4 b64 chars --> 3 bytes */
        /* check for "=" padding in b64 string -- if we find one, s will point
         * to the end of the string, or 2nd to last character.   */
        char *s = strchr(b64, '=');
        nbyte = nchar*3/4 - (s ? (nchar - (s - b64)) : 0);
    }

    /* Initialize output */
    *byte = init_byte(nbyte);
    char *p = *byte;

    /* Get integer array from B64_LUT */
    int *b64_int = init_int(nchar);         /* byte array */
    for (i = 0; i < nchar; i++) {
        b64_int[i] = indexof(B64_LUT, b64[i]);
    }

    /* Operate in chunks of 4 bytes in ==> 3 bytes out */
    for (i = 0; i < nchar; i+=4) {
        /* First char of output */
        /* NOTE mask off MSBs for left-shifts so we don't keep large #s */
        *p++ = ((b64_int[i] << 2) & 0xFF) | (b64_int[i+1] >> 4);

        /* Second char */
        if ((b64_int[i+2] < 64) && (b64_int[i+2] > 0)) {
            *p++ = ((b64_int[i+1] << 4) & 0xFF) | (b64_int[i+2] >> 2);

            /* Third char */
            if ((b64_int[i+3] < 64) && (b64_int[i+3] > 0)) {
                *p++ = ((b64_int[i+2] << 6) & 0xFF) | b64_int[i+3];
            }
        }
    }

    free(b64_int);
    return nbyte;
}

/*------------------------------------------------------------------------------
 *      XOR two equal-length byte arrays
 *----------------------------------------------------------------------------*/
char *fixedXOR(const char *a, const char *b, size_t nbyte)
{
    char *xor = init_byte(nbyte);

    /* XOR each xor in the input array */
    for (int i = 0; i < nbyte; i++) {
       *(xor+i) = *(a+i) ^ *(b+i);
    }

    return xor;
}


/* #<{(|------------------------------------------------------------------------------ */
/*  *         Get character frequency score of string */
/*  *----------------------------------------------------------------------------|)}># */
/* float charFreqScore(const char *str) */
/* { */
/*     #<{(| <https://en.wikipedia.org/wiki/Letter_frequency> |)}># */
/*     #<{(| Indexed [A-Z] - 'A' == 0 -- 25 |)}># */
/*     static const float ENGLISH_FREQ[] = */
/*         { 0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  \ */
/*         0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  \ */
/*         0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  \ */
/*         0.00978, 0.02360, 0.00150, 0.01974, 0.00074 }; */
/*     #<{(| ordering by frequency of acceptable chars |)}># */
/*     static const char etaoin[] = "ETAOINSHRDLCUMWFGYPBVKJXQZ"; */
/*     float N = 0, */
/*           Nl = 0, */
/*           letter_frac = 1, */
/*           score = FLT_MAX, */
/*           observed = 0.0, */
/*           expected = 0.0, */
/*           chi_sq = 0.0, */
/*           tol = 1e-16; */
/*  */
/*     #<{(| Count frequency of each letter in string |)}># */
/*     int *cf = countChars(str, strlen(str)); */
/*  */
/*     #<{(| Calculate score via chi-squared test |)}># */
/*     N = (float)strlen(str); #<{(| all chars in array |)}># */
/*  */
/*     #<{(| Count just letters in string |)}># */
/*     for (int j = 0; j < NUM_LETTERS; j++) { */
/*         Nl += (float)cf[j]; */
/*     } */
/*  */
/*     #<{(| Fraction of string that is just letters |)}># */
/*     letter_frac = Nl/N; */
/*     if (letter_frac < tol) { return score; } #<{(| no letters present |)}># */
/*  */
/*     #<{(| Sum the chi^2 values for each alphabetic character |)}># */
/*     for (int i = 0; i < strlen(etaoin); i++) { */
/*         int ch_ind = etaoin[i]; */
/*         observed = cf[ch_ind-'A'];               #<{(| observed count |)}># */
/*         expected = ENGLISH_FREQ[ch_ind-'A'] * N; #<{(| expected in English |)}># */
/*  */
/*         #<{(| sum actual letter counts, not frequencies |)}># */
/*         chi_sq += (observed - expected)*(observed - expected) / expected; */
/*     } */
/*  */
/*     #<{(| Weight strings with more letter in them (vs non-letter chars) |)}># */
/*     score = chi_sq / (letter_frac*letter_frac); */
/*  */
/*     free(cf); */
/*     return score; */
/* } */
/*  */
/*  */
/* #<{(|------------------------------------------------------------------------------ */
/*  *         Allocate memory and initialize an XOR_NODE */
/*  *----------------------------------------------------------------------------|)}># */
/* XOR_NODE *init_xor_node(void) */
/* { */
/*     XOR_NODE *out = NULL; */
/*  */
/*     #<{(| Allocate memory for the output |)}># */
/*     out = NEW(XOR_NODE); */
/*     MALLOC_CHECK(out); */
/*     BZERO(out, sizeof(XOR_NODE)); */
/*  */
/*     #<{(| Initialize fields |)}># */
/*     BZERO(out->key, sizeof(out->key)); */
/*     BZERO(out->plaintext, sizeof(out->plaintext)); */
/*     out->score = FLT_MAX; #<{(| initialize to large number |)}># */
/*     out->file_line = 0; */
/*  */
/*     return out; */
/* } */
/*  */
/* #<{(|------------------------------------------------------------------------------ */
/*  *         Decode a string XOR'd against a single character */
/*  *----------------------------------------------------------------------------|)}># */
/* XOR_NODE *singleByteXORDecode(const char *hex) */
/* { */
/*     XOR_NODE *out = NULL; */
/*     size_t nchar = strlen(hex); */
/*     if (nchar & 1) { ERROR("Input string is not a valid hex string!"); } */
/*  */
/*     out = init_xor_node(); */
/*  */
/*     char key[3];            #<{(| i.e. 0x01 --> '01' |)}># */
/*     BZERO(key, 3); */
/*  */
/*     #<{(| test each possible character byte |)}># */
/*     for (int i = 0x01; i < 0x100; i++) { */
/*         snprintf(key, 3, "%0.2X", i); */
/*         char *xor = repeatingKeyXOR(hex, key);  #<{(| Decode hex string |)}># */
/*         char *ptext = htoa(xor);               #<{(| Convert to ASCII text |)}># */
/*         float cfreq_score = FLT_MAX;           #<{(| initialize large value |)}># */
/*  */
/*         #<{(| Make sure string does not contain NULL chars, and is printable |)}># */
/*         #<{(| if (isprintable(ptext)) { |)}># */
/*         if ((strlen(ptext) == nchar/2) && (isprintable(ptext))) { */
/*             cfreq_score = charFreqScore(ptext);  #<{(| calculate string score |)}># */
/*  */
/*             #<{(| TODO organize statements like these that print a LOT of data into */
/*              * a "VVERBOSE" flag for extra output |)}># */
/* #ifdef LOGSTATUS */
/*             printf("%0.2X\t%s\t%10.4e\n", i, ptext, cfreq_score); */
/* #endif */
/*             #<{(| Track minimum chi-squared score and actual key |)}># */
/*             if (cfreq_score < out->score) { */
/*                 out->score = cfreq_score; */
/*                 BZERO(out->key, sizeof(out->key)); */
/*                 strncpy(out->key, key, strlen(key)); */
/*                 BZERO(out->plaintext, sizeof(out->plaintext)); */
/*                 strncpy(out->plaintext, ptext, strlen(ptext)); */
/*             } */
/* #<{(| #ifdef LOGSTATUS |)}># */
/* #<{(|         } else { |)}># */
/* #<{(|             printf("\nkey = %s\nNon-valid string: ", key); |)}># */
/* #<{(|             char *p = ptext; |)}># */
/* #<{(|             while (*p) { |)}># */
/* #<{(|                 printf("\\%+0.3d", *p++); |)}># */
/* #<{(|             } |)}># */
/* #<{(|             printf("\n"); |)}># */
/* #<{(| #endif |)}># */
/*         } */
/*         #<{(| clean-up |)}># */
/*         free(xor); */
/*         free(ptext); */
/*     } */
/*  */
/*     return out; */
/* } */
/*  */
/* #<{(|------------------------------------------------------------------------------ */
/*  *         Find single byte XOR string in a file */
/*  *----------------------------------------------------------------------------|)}># */
/* XOR_NODE *findSingleByteXOR(const char *filename) */
/* { */
/*     XOR_NODE *out = NULL; */
/*     FILE *fp = NULL; */
/*     char buffer[MAX_WORD_LEN]; */
/*     char message[2*MAX_PAGE_NUM]; */
/*     BZERO(buffer, MAX_WORD_LEN); */
/*     BZERO(message, 2*MAX_PAGE_NUM); */
/*  */
/*     out = init_xor_node(); */
/*  */
/*     #<{(| open file stream |)}># */
/*     fp = fopen(filename, "r"); */
/*     if (fp == NULL) { */
/*         snprintf(message, 2*MAX_PAGE_NUM, "File %s could not be read!", filename); */
/*         ERROR(message); */
/*         exit(-1); */
/*     } */
/*  */
/*     int file_line = 1; */
/*  */
/*     #<{(| For each line, run singleByteXORDecode, return {key, string, score} |)}># */
/*     while ( fgets(buffer, sizeof(buffer), fp) ) { */
/*         buffer[strcspn(buffer, "\n")] = 0;  #<{(| remove trailing '\n' |)}># */
/*  */
/* #ifdef LOGSTATUS */
/*         printf("---------- Line: %3d\n", file_line); */
/* #endif */
/*  */
/*         #<{(| Find most likely key for this line |)}># */
/*         XOR_NODE *temp = singleByteXORDecode(buffer); */
/*         if (*temp->plaintext) { */
/*             #<{(| Track {key, string, score} by lowest score |)}># */
/*             if (temp->score < out->score) { */
/*                 BZERO(out->key, sizeof(out->key)); */
/*                 strncpy(out->key, temp->key, strlen(temp->key)); */
/*                 BZERO(out->plaintext, sizeof(out->plaintext)); */
/*                 strncpy(out->plaintext, temp->plaintext, strlen(temp->plaintext)); */
/*                 out->score = temp->score; */
/*                 out->file_line = file_line; */
/*             } */
/*         } */
/* #ifdef LOGSTATUS */
/*         else { printf("\x1B[A\r"); #<{(| move cursor up and overwrite |)}># } */
/* #endif */
/*         free(temp); #<{(| clean-up |)}># */
/*         file_line++; */
/*     } */
/*  */
/* #ifdef LOGSTATUS */
/*     printf("\x1B[A\r\n\n"); #<{(| erase last title line |)}># */
/* #endif */
/*     fclose(fp); */
/*     return out; */
/* } */
/*  */
/* #<{(|------------------------------------------------------------------------------ */
/*  *         Encode hex string using repeating-key XOR */
/*  *----------------------------------------------------------------------------|)}># */
/* char *repeatingKeyXOR(const char *hex, const char *key_hex) */
/* { */
/*     size_t nchar   = strlen(hex); */
/*     size_t key_len = strlen(key_hex); */
/*     if ((nchar & 1) || (key_len & 1)) { */
/*         ERROR("Input string is not a valid hex string!"); */
/*     } */
/*  */
/*     #<{(| XOR each byte in the ciphertext with the key |)}># */
/*     char *key_str = strnrepeat_hex(key_hex, key_len, nchar); */
/*     char *xor = fixedXOR(hex, key_str); */
/*     free(key_str); */
/*     return xor; */
/* } */
/*  */
/* #<{(|------------------------------------------------------------------------------ */
/*  *         Compute Hamming distance between strings */
/*  *----------------------------------------------------------------------------|)}># */
/* size_t hamming_dist(const char *a, const char *b) */
/* { */
/*     char *xor = fixedXOR(a, b); #<{(| XOR returns differing bits |)}># */
/*     size_t weight = hamming_weight(xor); */
/*     free(xor); */
/*     return weight; */
/* } */
/*  */
/*  */
/* #<{(|------------------------------------------------------------------------------ */
/*  *         Get most probable key length of repeating XOR  */
/*  *----------------------------------------------------------------------------|)}># */
/* size_t getKeyLength(const char *hex) */
/* { */
/*     int n_samples = 4;   #<{(| number of Hamming distances to take |)}># */
/*     size_t key_byte = 0; */
/*     float min_mean_dist = FLT_MAX; */
/*  */
/*     size_t nchar = strlen(hex); */
/*     if (nchar & 1) { ERROR("Input string is not a valid hex string!"); } */
/*     size_t nbyte = nchar/2; */
/*  */
/*     #<{(|---------- Determine probable key length ----------|)}># */
/*     #<{(| key length in bytes |)}># */
/*     size_t max_key_len = (size_t)min(40.0, nbyte/(2.0*n_samples)); */
/*  */
/*     #<{(| Allocate 2 strings of max key length bytes |)}># */
/*     char *a = init_str(2*max_key_len); */
/*     char *b = init_str(2*max_key_len); */
/*  */
/*     for (size_t k = 3; k <= max_key_len; k++) { */
/*         #<{(| Get total Hamming distance of all samples |)}># */
/*         unsigned long tot_dist = 0; */
/*  */
/*         for (int i = 0; i < n_samples; i++) { */
/*             strncpy(a, hex+2*k*i,     2*k);   #<{(| 2 hex chars == 1 byte |)}># */
/*             strncpy(b, hex+2*k*(i+1), 2*k); */
/*             tot_dist += hamming_dist(a,b); */
/*         } */
/*  */
/*         #<{(| Average Hamming distances normalized by total bits in key |)}># */
/*         float norm_tot = tot_dist / (8.0*k); */
/*         float mean_dist = norm_tot / n_samples; */
/* #ifdef LOGSTATUS */
/*         printf("%3zu\t%5lu\t%8.4f\t%8.4f\n", k, tot_dist, norm_tot, mean_dist); */
/* #endif */
/*  */
/*         #<{(| Take key with minimum mean Hamming distance. |)}># */
/*         if (mean_dist < min_mean_dist) { */
/*             min_mean_dist = mean_dist; */
/*             key_byte = k; */
/*         } */
/*     } */
/*  */
/* #ifdef LOGSTATUS */
/*     printf("n_samples = %d\n",    n_samples); */
/*     printf("key_byte  = %zu\n",   key_byte); */
/*     printf("min_dist  = %6.4f\n", min_mean_dist); */
/* #endif */
/*  */
/*     free(a); */
/*     free(b); */
/*     return key_byte; */
/* } */
/*  */
/* #<{(|------------------------------------------------------------------------------ */
/*  *         Break repeating key XOR cipher */
/*  *----------------------------------------------------------------------------|)}># */
/* XOR_NODE *breakRepeatingXOR(const char *hex) */
/* { */
/*     size_t nchar = strlen(hex); */
/*     size_t nbyte = nchar/2; */
/*  */
/*     #<{(| Get most probable key length |)}># */
/*     #<{(| TODO return sorted list of possible key sizes |)}># */
/*     #<{(| size_t key_byte = getKeyLength(hex); |)}># */
/*     size_t key_byte = 29; */
/*  */
/*     #<{(| Number of bytes in each substring |)}># */
/*     size_t str_byte = (nbyte + (key_byte - (nbyte % key_byte))) / key_byte; */
/*     size_t str_len = 2*str_byte; */
/*  */
/*     #<{(| TODO change XOR_NODE.plaintext to just pointer and malloc appropriate */
/*      * size each time? i.e. only need 60 chars or so for single strings. Pass */
/*      * in string size to init function|)}># */
/*     XOR_NODE *out = init_xor_node(); */
/*  */
/*     for (size_t k = 0; k < key_byte; k++) { */
/*         #<{(| Get every kth char from hex |)}># */
/* #ifdef LOGSTATUS */
/*         printf("---------- k = %zu\n", k); */
/* #endif */
/*         char *str = init_str(str_len); */
/*         for (size_t i = 0; i < str_byte; i++) { */
/*             size_t ind = 2*k+2*i*key_byte; */
/*             if (ind < nchar) { */
/*                 *(str+2*i)   = *(hex+ind); */
/*                 *(str+2*i+1) = *(hex+ind+1); */
/*             } */
/*         } */
/*  */
/*         #<{(| Run single byte xor on each chunk |)}># */
/*         XOR_NODE *temp = singleByteXORDecode(str); */
/*         strncpy(out->key+2*k, temp->key, 2);  #<{(| keep kth byte of key |)}># */
/*  */
/*         free(temp); */
/*         free(str); */
/*     } */
/*  */
/*     if (*out->key) { */
/*         #<{(| XOR original string with found key! |)}># */
/*         char *ptext = repeatingKeyXOR(hex, out->key); */
/*         char *ascii = htoa(ptext); */
/*         strncpy(out->plaintext, ascii, nbyte); */
/*         free(ascii); */
/*         free(ptext); */
/*     } else { */
/*         WARNING("Key not found!"); */
/*     } */
/*  */
/*     return out; */
/* } */
/*  */
/* #<{(|============================================================================== */
/*  *============================================================================|)}># */
