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
    printf("Line %d Fails\n", __LINE__); \
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
#define RUN_TEST(x, y) \
if (!x()) {                          \
    printf("Test %s passed.\n", y);  \
    total++;                         \
} else {                             \
    printf("Test %s failed!\n", y);  \
    total++;                         \
    fails = fails + 1;               \
}

#endif
//==============================================================================
//==============================================================================
