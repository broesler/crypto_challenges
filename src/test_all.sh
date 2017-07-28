#!/usr/local/bin/bash
#===============================================================================
#     File: test_all.sh
#  Created: 07/27/2017, 12:28
#   Author: Bernie Roesler
#
#  Description: Run unit tests for crypto challenges
#
#===============================================================================

# Include test functions
source "./test_funcs.sh"

# Log file header
printf "\n##### TEST LOG: $(date) #####\n"

# Change into util directory and test those
cd ./util
make clean && make debug
make_check
./test_util
pass_check "$?" "Utilities"
cd .. # change back to src

# Build the main tests in the src directory
make clean && make debug
make_check

# Run tests
./test1
pass_check "$?" "Set 1"

./test2
pass_check "$?" "Set 2"

exit 0
#===============================================================================
#===============================================================================
