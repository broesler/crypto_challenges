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
    char str1[] = "Anything less than the best is a felony.";
    size_t len1 = strlen(str1);
    char *buffer = init_str(len1);  /* should be exactly same length */
    /* if ((fd = open("/dev/null", O_WRONLY)) < 0) { */
    FILE *fp = NULL;
    if (!(fp = fopen("/dev/null", "a"))) {
        ERROR("Failed to open file!");
    }
    int fd = fileno(fp);
    int saveout;
    if ((saveout = dup(STDOUT_FILENO)) < 0) { ERROR("dup failed."); }
    fflush(stdout);
    /* redirect stdout */
    if (dup2(fd, STDOUT_FILENO) < 0) { ERROR("dup2 failed."); }
    close(fd);
    setbuffer(stdout, buffer, len1); /* buffer stdout to our own buffer */
    /*----- RUN TEST -----*/
    printall((BYTE *)str1, len1);
    fflush(stdout);
    SHOULD_BE(!strncmp(str1, buffer, len1)); 
    /* Redirect stdout back to original location for normal output */
    dup2(saveout, 1);
    close(saveout);
    fclose(fp);
#ifdef LOGSTATUS
    printf("Got:    %s\nExpect: %s\n", buffer, str1);
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
