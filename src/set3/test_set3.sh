#!/usr/local/bin/bash
#===============================================================================
#     File: test_set2.sh
#  Created: 07/28/2017, 16:04
#   Author: Bernie Roesler
#
#  Description: Run unit tests and challenge tests for Set 2
#
#===============================================================================

# Include test functions
source "../test_funcs.sh"

DATA_PATH="../../data/"

# Log file header
printf "##### TEST LOG: $(date) #####\n"

# Make all executables
printf "Building executables...\n"
make clean > /dev/null && make > /dev/null
if [ "$?" -ne 0 ]; then
    printf "\033[0;31[$0: $LINENO]: Error! make failed to execute properly.\033[0m\n"
    exit 2
fi
printf "done.\n"

printf "Running tests...\n"

# Test utilities
./test2
pass_check "$?" "Set 2 Utilities"

# Test challenge 10
diff <(./aes_cbc_file "${DATA_PATH}/10.txt") \
    "${DATA_PATH}play_that_funky_music.txt"
pass_check "$?" "Challenge 10"

# Test challenge 11
isecb=$(./detect_block_mode)
[[ "$isecb" -eq "ECB" ]]
pass_check "$?" "Challenge 11"

# Test challenge 12
diff <(./one_byte_ecb easy "${DATA_PATH}/12.txt") \
    "${DATA_PATH}rollin.txt"
pass_check "$?" "Challenge 12"

# Test challenge 13
diff <(./make_admin_profile) \
    <(printf "{\n\temail: 'bernie@me.com',\n\tuid: 56,\n\trole: 'admin'\n}")
pass_check "$?" "Challenge 13"

# Test challenge 12
diff <(./one_byte_ecb hard "${DATA_PATH}/12.txt") \
    "${DATA_PATH}rollin.txt"
pass_check "$?" "Challenge 14"

# Test challenge 16
./cbc_bit_flip
pass_check "$?" "Challenge 16"

printf "done.\n"
exit 0
#===============================================================================
#===============================================================================
