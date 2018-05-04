/*==============================================================================
 *     File: findECB.c
 *  Created: 07/28/2017, 15:17
 *   Author: Bernie Roesler
 *
 *  Description: 
 *
 *============================================================================*/
#include <stdio.h>

#include "aes_openssl.h"
#include "header.h"
#include "crypto_util.h"
#include "crypto1.h"

int main(int argc, char **argv)
{
    char *filename = NULL;

    /* Get one more argument of filename */
    if (argc > 1) {
        filename = argv[1];
    } else {
        fprintf(stderr, "Usage: %s [base64_file]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    BYTE *ciphertext = NULL;
    int file_line = find_AES_ECB(&ciphertext, filename);
    if (file_line < 0) { WARNING("ECB encryption not found!"); }

    printf("%d\n", file_line);

    free(ciphertext);
    return 0;
}

/*------------------------------------------------------------------------------
 *         Challenge 8: Detect AES in ECB mode 
 *----------------------------------------------------------------------------*/
int find_AES_ECB(BYTE **out, const char *hex_filename)
{
    int file_line = -1;
    FILE *fp = NULL;
    char buffer[MAX_WORD_LEN];
    char message[2*MAX_LINE_LEN];
    BZERO(buffer, MAX_WORD_LEN);
    BZERO(message, 2*MAX_LINE_LEN);

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
