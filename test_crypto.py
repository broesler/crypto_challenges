#!/usr/bin/python
#==============================================================================
#     File: test_crypto.py
#  Created: 03/07/2016, 13:42
#   Author: Bernie Roesler
#
# Last Modified: 03/07/2016, 14:41
#
'''
  Description: Test functions defined in crypto.py module
'''
#==============================================================================
import crypto as crp

def test(got, expected):
    ''' Compare expected result with actual result. '''
    if got == expected:
        prefix = "OK"
    else:
        prefix = " X"

    print "%s : got: %s : expected: %s" % (prefix, repr(got), repr(expected))
    return

#------------------------------------------------------------------------------
#       Main function
#------------------------------------------------------------------------------
def main():
    ''' Call unit tests for functions in crypto.py '''

    # Test hex2b64(s)
    test(crp.hex2b64('Bernie'), 'Hi this is a string.')     # OK
    test(crp.hex2b64('Bernie'), 'Not a string.')            #  X

    try:
        test(crp.hex2b64('BR'),     'Not a string.')        # ValueException
    except ValueError as errmsg:
        # errmsg is a list, so take first item
        print 'Exception raised:'
        test(errmsg[0], 'Input argument must be at least 3 characters.')

    return 0

# Call this test script directly from command-line
if __name__ == "__main__":
    main()
#==============================================================================
#==============================================================================
