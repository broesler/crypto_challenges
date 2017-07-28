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
./test_util.sh
cd .. # change back to src

# cd into each set and run their tests

# Set 1
cd set1
./test_set1.sh
cd ..

# Set 2
cd set2
./test_set2.sh
cd ..

exit 0
#===============================================================================
#===============================================================================
