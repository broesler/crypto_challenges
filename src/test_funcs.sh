#!/usr/local/bin/bash
#===============================================================================
#     File: test_funcs.sh
#  Created: 07/28/2017, 14:01
#   Author: Bernie Roesler
#
#  Description: General utility functions for shell script testing
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

#===============================================================================
#===============================================================================
