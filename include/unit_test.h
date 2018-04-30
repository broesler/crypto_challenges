//==============================================================================
//      File: unit_test.h
//   Created: 08/05/2016, 11:26
//    Author: Bernie Roesler
//
//   Description: Useful unit testing macros
//==============================================================================
#ifndef _UNIT_TEST_H
#define _UNIT_TEST_H

// each test should start by setting the result count to zero
#define START_TEST_CASE  int rs=0

// check a condition and if false print the test condition failed
// e.g., SHOULD_BE(dict->start == NULL)
#define SHOULD_BE(x) if (!(x))  {rs=rs+1; \
    printf("\033[0;31m[%s:%d] Test fails!\033[0m\n", __FILE__, __LINE__); \
}

// return the result count at the end of a test
#define END_TEST_CASE return rs

// general macro for running a test
// e.g., RUN_TEST(TestDAdd1, "DAdd Test case 1");
// translates to:
// if (!TestDAdd1()) {
//     printf("Test %s passed\n","DAdd Test case 1");
// } else {
//     printf("Test %s failed\n", "DAdd Test case 1");
//     cnt = cnt +1;
// }
// \u2713 gives escape sequence for ✓ (U+2713), or ✗ (U+2717)
#define RUN_TEST(x, y) \
if (!x()) {                          \
    printf("\033[0;32m\u2713\033[0m Test %s passed.\n", y);  \
    total++;                         \
} else {                             \
    printf("\033[0;31m\u2717\033[0m Test %s failed!\n", y);  \
    total++;                         \
    fails = fails + 1;               \
}

#endif
//==============================================================================
//==============================================================================
