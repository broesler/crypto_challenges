/*==============================================================================
 *     File: strtoupper_test.c
 *  Created: 10/20/2016, 14:14
 *   Author: Bernie Roesler
 *
 *  Description: 
 *
 *============================================================================*/
#include <stdio.h>

void upper_string(char *);

int main()
{
    char string[] = "test";
    upper_string(string);

    printf("Entered string in upper case is \"%s\"\n", string);

    return 0;
}

void upper_string(char *s) {
    int c = 0;

    while (s[c]) {
        if (s[c] >= 'a' && s[c] <= 'z') {
            s[c] -= 32;
            /* s[c] = s[c] - 32; */
        }
        c++;
    }
}

/*==============================================================================
 *============================================================================*/
