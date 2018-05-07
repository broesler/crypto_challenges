/*==============================================================================
 *     File: util_file.c
 *  Created: 05/07/2018, 16:40
 *   Author: Bernie Roesler
 *
 *  Description: Utility functions for handling files
 *
 *============================================================================*/

#include "util_file.h"

/*------------------------------------------------------------------------------
 *          Read file as single string 
 *----------------------------------------------------------------------------*/
unsigned long fileToString(char **buffer, const char *filename)
{
    FILE *fp = NULL;
    int result = 0;
    unsigned long file_length = -1;

    /* Determine length of temp file */
    fp = fopen(filename, "r");
    if (!fp) {
        ERROR("File %s could not be read!", filename);
    }

    fseek(fp, 0, SEEK_END);   /* move pointer to end of file */
    file_length = ftell(fp);
    rewind(fp);               /* reset to top of file */

    /* malloc buffer to file_length+1 */
    *buffer = init_str(file_length);

    /* read temp into buffer */
    result = fread(*buffer, sizeof(char), file_length, fp);

    if (result != file_length) {
        WARNING("File read error!");
        free(*buffer);
        return -1;
    }

    fclose(fp);
    return file_length;
}

/*------------------------------------------------------------------------------
 *          Count lines in file
 *----------------------------------------------------------------------------*/
size_t lines_in_file(const char *filename)
{
    char buffer[1024];
    char last = 'X';    /* arbitrary non-newline character */
    size_t nchr = 0;
    size_t lines = 0;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        ERROR("File %s could not be read!", filename);
    }

    /* Read in fixed chunks to avoid internal memory copying of fgets() */
    while ((nchr = fread(buffer, 1, sizeof(buffer)-1, fp))) {
        last = buffer[nchr-1];
        /* Count the newlines in the buffer */
        for (size_t i = 0; i < nchr; i++) {
            if (buffer[i] == '\n') {
                lines++; 
            } 
        }
    }

    if (last != '\n') { lines++; } /* count last line even if no newline */

    if (ferror(fp)) {
        fclose(fp);
        ERROR("File %s failed to read properly", filename);
    }

    fclose(fp);
    return lines;
}


/*==============================================================================
 *============================================================================*/
