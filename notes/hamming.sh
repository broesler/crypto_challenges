#!/usr/local/bin/bash
#===============================================================================
#     File: hamming.sh
#  Created: 07/08/2017, 12:44
#   Author: Bernie Roesler
#
#  Description: Compute Hamming distance using shell script
#
#===============================================================================

# a='this'
# b='wokk'
a='this is a test'
b='wokka wokka!!!'

ascii_to_bin() {
    hex=$(echo -n "$1" | od -A n -t x1 | sed 's/ //g')
    bin_raw=$(echo "ibase=16; obase=2; ${hex^^}" | bc)
    # no quotes! otherwise "\ " gets interpreted as newline
    echo $bin_raw | sed 's/\\ //g'  
}

hamming_weight() {
    echo "$1" | sed 's/\(.\)/\1\n/g' | sort | uniq -ic
}

ab=$(ascii_to_bin "$a")
bb=$(ascii_to_bin "$b")
# unsure if the $(()) operation is unlimited precision...
xorb=$(echo "obase=2; $((2#$ab ^ 2#$bb))" | bc)
# echo $ab
# echo $bb
# echo $xorb
# echo $xorb | sed 's/\(.\)/\1\n/g' | sort | uniq -ic
hamming_weight $xorb
hamming_weight $ab
# counts only 24 1's in output??
#===============================================================================
#===============================================================================
