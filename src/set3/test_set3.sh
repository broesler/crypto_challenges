#!/usr/local/bin/bash
#===============================================================================
#     File: test_set3.sh
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
printf "##### SET 3 TEST LOG: $(date) #####\n"

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
./test3
./test_cbc_padding_oracle
pass_check "$?" "Set 3 Utilities"

# Test challenge 17
diff <(./cbc_padding_oracle_main) "${DATA_PATH}/17.txt"
pass_check "$?" "Challenge 17"

# Test Challenge 23
./clone_rng
pass_check "$?" "Challenge 23"

printf "done.\n"
exit 0
#===============================================================================
#===============================================================================
