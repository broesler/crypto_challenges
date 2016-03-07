#!/usr/bin/python
#==============================================================================
#     File: test_crypto.py
#  Created: 03/07/2016, 13:42
#   Author: Bernie Roesler
#
# Last Modified: 03/07/2016, 16:43
#
'''
  Description: Test functions defined in crypto.py module
'''
#==============================================================================
import crypto as crp

def test(result, expected):
    ''' Compare expected result with actual result. '''
    if result == expected:
        prefix = "OK"
    else:
        prefix = " X"

    print "%s : result: %s : expected: %s" \
          % (prefix, repr(result), repr(expected))
    return

#------------------------------------------------------------------------------
#       Main function
#------------------------------------------------------------------------------
def main():
    ''' Call unit tests for functions in crypto.py '''

    #--------------------------------------------------------------------------
    #       Test hex2b64 
    #--------------------------------------------------------------------------
    # Simple ASCII test
    string = 'Man'
    expect = 'TWFu'
    test(crp.hex2b64(string.encode('hex')), expect)

    # I/O test taken from <http://cryptopals.com/sets/1/challenges/1>
    string = '49276d206b696c6c696e6720796f75722'\
             '0627261696e206c696b65206120706f69'\
             '736f6e6f7573206d757368726f6f6d'
    expect = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa'\
             'WtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    test(crp.hex2b64(string), expect)

    # Run decode test
    # test(crp.b642hex(string), expect)

    try:
        test(crp.hex2b64('BR'),     'Not a string.')        # ValueException
    except ValueError as errmsg:
        print 'Exception raised:'
        test(errmsg[0], 'Input argument must be at least 3 characters.')

    return 0

# Call this test script directly from command-line
if __name__ == "__main__":
    main()
#==============================================================================
#==============================================================================
