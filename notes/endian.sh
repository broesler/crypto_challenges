#!/usr/local/bin/bash
#===============================================================================
#     File: endian.sh
#  Created: 05/02/2018, 17:21
#   Author: Bernie Roesler
#
#  Description: Determine if this machine is little or big endian.
#
#===============================================================================
binary=$(mktemp)
cat <<\EOF | gcc-7 -o $binary -x c -
#include <stdio.h>
int main() {
    unsigned int i = 1;
    char *c = (char *)&i;
    if (*c)
        printf("little endian\n");
    else
        printf("big endian\n");
    int j = 0;
    if (j++ > 0) { printf("j++ > 0\n"); }
    if (++j > 0) { printf("++j > 0\n"); }
    return 0;
}
EOF
$binary
rm $binary
#===============================================================================
#===============================================================================
