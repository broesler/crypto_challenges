/*==============================================================================
 *     File: test_util_print.c
 *  Created: 05/07/2018, 17:20
 *   Author: Bernie Roesler
 *
 *  Description:
 *
 *============================================================================*/

#include <fcntl.h>

/* User-defined headers */
#include "header.h"
#include "crypto_util.h"
#include "unit_test.h"

/* Declare function of no arguments to use in capturing output. */
#define MAKE_TEST_FUN(postfix, s) \
static void run_test ## postfix ()\
{\
    BYTE str[] = s;\
    size_t len = strlen((char *)str);\
    printall(str, len);\
}

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* This function tests the validity of printable characters */
int IsPrintable1()
{
    START_TEST_CASE;
    /* everything prints */
    char str[] = "Anything less than the best is a felony.";
    int test = isprintable((BYTE *)str, strlen(str));
    int expect = 1;
    SHOULD_BE(test == expect);
#ifdef LOGSTATUS
    printf("Got:    %d\nExpect: %d\n", test, expect);
#endif
    END_TEST_CASE;
}

int IsPrintable2()
{
    START_TEST_CASE;
    /* include non-printing char */
    char str2[] = "Anything \u1801less than the best is a felony.";
    int test = isprintable((BYTE *)str2, strlen(str2));
    int expect = 0;
    SHOULD_BE(test == expect);
#ifdef LOGSTATUS
    printf("Got:    %d\nExpect: %d\n", test, expect);
#endif
    END_TEST_CASE;
}

int capture_printall(void (*run_test)(), BYTE **out, size_t buflen) 
{
    BYTE *buffer = init_byte(buflen);
    int fd = -1,
        saveout = -1;
    *out = init_byte(buflen); /* initialize output buffer */
    if ((fd = open("/dev/null", O_WRONLY)) < 0) {
        ERROR("Failed to open file!");
    }
    if ((saveout = dup(STDOUT_FILENO)) < 0) {
        ERROR("dup failed.");
    }
    fflush(stdout); /* flush stdout before redirecting */
    if (dup2(fd, STDOUT_FILENO) < 0) {  /* redirect stdout */
        ERROR("dup2 failed.");
    }
    close(fd);
    setvbuf(stdout, (char *)buffer, _IOFBF, buflen); /* buffer stdout to our own buffer */
    run_test();
    memcpy(*out, buffer, buflen);           /* write buffer to output array */
    setvbuf(stdout, NULL, _IOLBF, 0);       /* reset buffering of stdout */
    if (dup2(saveout, STDOUT_FILENO) < 0) { /* redirect stdout back to original */
        ERROR("dup2 failed.");
    }
    close(saveout);
    free(buffer);
    return 0;
}

/* create "run_test1()" */
MAKE_TEST_FUN(1, "Anything less than the best is a felony.")

/* This function tests the printall function for proper hex codes*/
int PrintAll1()
{
    START_TEST_CASE;
    BYTE expect[] = "Anything less than the best is a felony.";
    BYTE *test = NULL;
    size_t buflen = strlen((char *)expect);
    capture_printall(run_test1, &test, buflen);
    SHOULD_BE(!memcmp(test, expect, buflen));
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", test, expect);
#endif
    free(test);
    END_TEST_CASE;
}

/* creates "run_test2()" */
MAKE_TEST_FUN(2, "Anything\x01\x02\x03.")

/* This function tests the printall function for proper hex codes*/
int PrintAll2()
{
    START_TEST_CASE;
    BYTE expect[] = "Anything\\x01\\x02\\x03.";
    size_t buflen = strlen((char *)expect);
    BYTE *test = NULL;
    capture_printall(run_test2, &test, buflen);
    SHOULD_BE(!memcmp(test, expect, buflen));
#ifdef LOGSTATUS
    printf("Got:    ");
    printall(test, buflen);
    printf("\nExpect: ");
    printall(expect, buflen);
    printf("\n");
#endif
    free(test);
    END_TEST_CASE;
}

/*------------------------------------------------------------------------------
 *        Run tests
 *----------------------------------------------------------------------------*/
int main(void)
{
    int fails = 0;
    int total = 0;

    RUN_TEST(IsPrintable1,  "isprintable() 1  ");
    RUN_TEST(IsPrintable2,  "isprintable() 2  ");
    RUN_TEST(PrintAll1,     "printall() 1     ");
    RUN_TEST(PrintAll2,     "printall() 2     ");

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
