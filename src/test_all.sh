#!/usr/bin/env bash
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
printf "##### TEST LOG: $(date) #####\n"

# Change into util directory and test those
cd ./util
./test_util.sh
cd .. # change back to src

# cd into each set and run their tests
for i in {1..3}; do
    test_set $i
done

exit 0
#===============================================================================
#===============================================================================
