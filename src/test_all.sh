#!/usr/local/bin/bash
#===============================================================================
#     File: test_all.sh
#  Created: 07/27/2017, 12:28
#   Author: Bernie Roesler
#
#  Description: Run unit tests for crypto challenges
#
#===============================================================================

pass_check() {
  if [ "$1" -eq 0 ]; then
    printf "\033[0;32m##### $2 passed test! #####\033[0m\n"
  else
    printf "\033[0;31m##### $2 failed test! #####\033[0m\n"
    exit 1
  fi
}

make_check() {
  if [ "$?" -ne 0 ]; then
    printf "[$0: $LINENO]: Error! make failed to execute properly.\n"
    exit 2
  fi
}

# Log file header
printf "\n##### UNIT TEST LOG: $(date) #####\n"

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
