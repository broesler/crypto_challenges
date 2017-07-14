/*==============================================================================
 *     File: test_strtoul.c
 *  Created: 07/08/2017, 01:15
 *   Author: Bernie Roesler
 *
 *  Description: 
 *
 *============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int main(void)
{
    /* char str1[] = "4D616E"; */
    char str1[]   = "1c0111001f010100061a024b53535009181c";
    /* char str1[]   = "686974207468652062756c6c277320657965"; */
    /* char str1[] = "746865206b696420646f6e277420706c6179"; */
    char *endp = NULL;
    unsigned long long test = strtoul(str1, &endp, 16); /* interpret at hex */
    printf("str: %s\nhex: %llX\nint: %llu\n", str1, test, test);
    printf("INT_MAX = %d\nUINT_MAX = %u\nLONG_MAX = %ld\nULONG_MAX = %lu\n", \
            INT_MAX, UINT_MAX, LONG_MAX, ULONG_MAX);
    return EXIT_SUCCESS;
}

/*==============================================================================
 *============================================================================*/
