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

/*------------------------------------------------------------------------------
 *        Define test functions
 *----------------------------------------------------------------------------*/
/* This function tests the validity of printable characters */
int IsPrintable1()
{
    START_TEST_CASE;
    /* everything prints */
    char str1[] = "Anything less than the best is a felony.";
    int test = isprintable((BYTE *)str1, strlen(str1));
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


/* This function tests the printall function for proper hex codes*/
int PrintAll1()
{
    START_TEST_CASE;
    BYTE str1[] = "Anything less than the best is a felony.";
    BYTE *expect = str1;
    size_t len1 = strlen((char *)str1);
    size_t buflen = strlen((char *)expect);
    char *buffer = init_str(buflen);  /* should be exactly same length */
    int fd = -1,
        saveout = -1;
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
    /*----- RUN TEST -----*/
    printall(str1, len1);
    SHOULD_BE(!memcmp(buffer, expect, buflen));
    /*----- END TEST -----*/
    setvbuf(stdout, NULL, _IOLBF, 0); /* reset buffering of stdout */
    dup2(saveout, 1);                 /* redirect stdout back to original */
    close(saveout);
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", buffer, str1);
#endif
    free(buffer);
    END_TEST_CASE;
}

/* This function tests the printall function for proper hex codes*/
int PrintAll2()
{
    START_TEST_CASE;
    BYTE str1[] = "Anything\x01\x02\x03.";
    BYTE expect[] = "Anything\\x01\\x02\\x03.";
    size_t len1 = strlen((char *)str1);
    size_t buflen = strlen((char *)expect);
    BYTE *buffer = init_byte(buflen); /* room for hex chars */
    int fd = -1,
        saveout = -1;
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
    /*----- RUN TEST -----*/
    printall(str1, len1);
    SHOULD_BE(!memcmp(buffer, expect, buflen));
    /*----- END TEST -----*/
    setvbuf(stdout, NULL, _IOLBF, 0); /* reset buffering of stdout */
    dup2(saveout, 1);                 /* redirect stdout back to original */
    close(saveout);
#ifdef LOGSTATUS
    printf("Got:    ");
    printall(buffer, buflen);
    printf("\nExpect: ");
    printall(str1, len1);
    printf("\n");
#endif
    free(buffer);
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
