/*==============================================================================
 *     File: test_utiL_file.c
 *  Created: 05/07/2018, 17:18
 *   Author: Bernie Roesler
 *
 *  Description: 
 *
 *============================================================================*/

/* User-defined headers */
#include "header.h"
#include "fmemopen.h"
#include "crypto_util.h"
#include "unit_test.h"

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* Test file2str() */
int File2str1()
{
    START_TEST_CASE;
    char filename[] = "../../data/ftest_oneline.txt";
    char *buffer = NULL;
    char expect[] =  "I was a terror since the public school era.";
    SHOULD_BE(file2str(&buffer, filename) > 0);
    SHOULD_BE(!memcmp(buffer, expect, strlen(expect)));
#ifdef LOGSTATUS
    printf("Got      = %s\nExpected = %s\n", buffer, expect);
#endif
    free(buffer);
    END_TEST_CASE;
}

int File2str2()
{
    START_TEST_CASE;
    char filename[] = "../../data/ftest_multiline.txt";
    char *buffer = NULL;
    char expect[] =  "I was a terror\nsince the public\nschool era.";
    SHOULD_BE(file2str(&buffer, filename) > 0);
    SHOULD_BE(!memcmp(buffer, expect, strlen(expect)));
#ifdef LOGSTATUS
    printf("Got      = %s\nExpected = %s\n", buffer, expect);
#endif
    free(buffer);
    END_TEST_CASE;
}

/* Test lines_in_file() */
int LineInFile1()
{
    START_TEST_CASE;
    char filename[] = "../../data/19.txt";
    size_t Nl = lines_in_file(filename);
    SHOULD_BE(Nl == 40);
    END_TEST_CASE;
}

/* Test fmemopen stream function */
int FMEM1()
{
    START_TEST_CASE;
    char *x = (char *)"Hello, friends!";
    size_t x_len = strlen(x);
    FILE *xs = fmemopen(x, x_len, "r");  /* create stream from byte array */
    FILE *ys = tmpfile();
    int c;
    while ((c = fgetc(xs)) != EOF) {
        fputc(c, ys);
    }
    /* Rewind output stream */
    REWIND_CHECK(ys);
    BYTE *yb = init_byte(x_len);
    if (fread(yb, 1, x_len, ys)) {
#ifdef LOGSTATUS
        printf("ys = \"%s\"\n", yb);
#endif
    }
    SHOULD_BE(!memcmp(yb, x, x_len));
    free(yb);
    fclose(xs);
    fclose(ys);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(File2str1,   "file2str() 1    ");
    RUN_TEST(File2str2,   "file2str() 2    ");
    RUN_TEST(LineInFile1, "lines_in_file() ");
    RUN_TEST(FMEM1,       "fmemopen()      ");

    /* Count errors */
    if (!fails) {
        printf("\033[0;32mAll %d tests passed!\033[0m\n", total); 
        return 0;
    } else {
        printf("\033[0;31m%d/%d tests failed!\033[0m\n", fails, total);
        return 1;
    }
}


/*==============================================================================
 *============================================================================*/
