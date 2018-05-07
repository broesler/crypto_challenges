#!/usr/local/bin/bash
#===============================================================================
#     File: test_util.sh
#  Created: 07/28/2017, 17:27
#   Author: Bernie Roesler
#
#  Description: Test utilities
#
#===============================================================================

# Include test functions
source "../test_funcs.sh"

# Log file header
printf "##### TEST LOG: $(date) #####\n"

# Make all executables
printf "Building executables...\n"
make clean > /dev/null &&\
make > /dev/null

if [ "$?" -ne 0 ]; then
    printf "[$0: $LINENO]: Error! make failed to execute properly.\n"
    exit 2
fi
printf "done.\n"

printf "Running tests...\n"

./test_util
pass_check "$?" "Utilities"

#===============================================================================
#===============================================================================
