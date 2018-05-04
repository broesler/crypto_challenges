/*==============================================================================
 *     File: findSingleByteXOR.c
 *  Created: 07/28/2017, 13:13
 *   Author: Bernie Roesler
 *
 *  Description: Challenge 4: Find single byte XOR string in file
 *
 *============================================================================*/
#include <stdio.h>

#include "header.h"
#include "crypto_util.h"
#include "crypto1.h"

int main(int argc, char **argv)
{
    char *filename = NULL;

    /* Get filename */
    if (argc > 1) {
        filename = argv[1];
    } else {
        fprintf(stderr, "Usage: %s [filename]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Find and decrypt */
    XOR_NODE *out = findSingleByteXOR(filename);

#ifdef LOGSTATUS
    printf("line  = %3d\n",            out->file_line);
    printf("key   =  0x%.2X\n",       *out->key);
    printf("score = %8.4f\n",          out->score);
#endif

    /* Print discovered string */
    printf("%s\n", out->plaintext);

    free(out);
    return 0;
}


/*------------------------------------------------------------------------------
 *         Challenge 4: Find single byte XOR string in a file
 *----------------------------------------------------------------------------*/
XOR_NODE *findSingleByteXOR(const char *filename)
{
    XOR_NODE *out = NULL;
    FILE *fp = NULL;
    char buffer[MAX_WORD_LEN];
    char message[2*MAX_LINE_LEN];
    BZERO(buffer, MAX_WORD_LEN);
    BZERO(message, 2*MAX_LINE_LEN);

    /* initialize output */
    out = init_xor_node();

    /* open file stream */
    fp = fopen(filename, "r");
    if (fp == NULL) {
        snprintf(message, 2*MAX_LINE_LEN, "File %s could not be read!", filename);
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

/*==============================================================================
 *============================================================================*/
