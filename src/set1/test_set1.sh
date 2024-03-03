#!/usr/bin/env bash
#===============================================================================
#     File: test_set1.sh
#  Created: 07/28/2017, 13:56
#   Author: Bernie Roesler
#
#  Description: Run unit tests and challenge tests for Set 1
#
#===============================================================================

# Include test functions
source "../test_funcs.sh"

DATA_PATH="../../data/"

# Log file header
printf "\n##### SET 1 TEST LOG: $(date) #####\n"

# Make all executables
printf "Building executables...\n"
make clean > /dev/null && make > /dev/null
if [ "$?" -ne 0 ]; then
    printf "[$0: $LINENO]: Error! make failed to execute properly.\n"
    exit 2
fi
printf "done.\n"

printf "Running tests...\n"

# Test utilities
./test1
pass_check "$?" "Set 1 Utilities"

# Test challenge 4
diff <(./find_single_byte_xor "${DATA_PATH}/4.txt") \
    <(printf "Now that the party is jumping\n\n")
pass_check "$?" "Challenge 4"

# Test challenge 6
diff <(./break_repeating_xor "${DATA_PATH}/6.txt") \
    "${DATA_PATH}/play_that_funky_music.txt"
pass_check "$?" "Challenge 6"

# Test challenge 7
diff <(./aes_ecb_file "${DATA_PATH}/7.txt" 0) \
    "${DATA_PATH}/play_that_funky_music.txt"
pass_check "$?" "Challenge 7"

# Test challenge 7
line=$(./find_ecb "${DATA_PATH}/8.txt")
[ "$line" -eq 133 ]
pass_check "$?" "Challenge 8"

printf "done.\n"
exit 0
#===============================================================================
#===============================================================================
