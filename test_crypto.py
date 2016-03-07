#!/usr/bin/python
#==============================================================================
#     File: test_crypto.py
#  Created: 03/07/2016, 13:42
#   Author: Bernie Roesler
#
# Last Modified: 03/07/2016, 17:43
#
'''
  Description: Test functions defined in crypto.py module
'''
#==============================================================================
import crypto as crp

def test(result, expected):
    ''' Compare expected result with actual result. '''
    if result == expected:
        prefix = 'OK'
    else:
        prefix = ' X'

    print '%s :\tresult: %s\n\texpect: %s' \
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
    print '---- hex2b64 ----'
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

    # Test for a string that is too short 
    try:
        test(crp.hex2b64('B'.encode('hex')), 'Whatever.')        
    except ValueError as errmsg:
        test(errmsg[0], 'Input argument must be at least 3 characters.')

    # Test for output padding (or lack thereof)
    try:
        test(crp.hex2b64('sure.'.encode('hex')), 'c3VyZS4=')        
    except Exception as errmsg:
        test(errmsg[0], 'Number of input bytes not divisible by 6, not'\
                ' including padding characters in output.')

    #--------------------------------------------------------------------------
    #        Test fixedXOR
    #--------------------------------------------------------------------------
    print '---- fixedXOR ----'
    str1    = '1c0111001f010100061a024b53535009181c'
    key     = '686974207468652062756c6c277320657965'
    expect  = '746865206b696420646f6e277420706c6179' 

    # Return an integer XOR
    test_int = crp.fixedXOR(str1,key) 

    # Python hex() inclues '0x...L' for hex long integers, so remove them
    test_str = hex(test_int).rstrip('L').lstrip('0x') or '0'
    test(test_str, expect)

    # Test for different length inputs
    try:
        test( crp.fixedXOR('abc','de'), 'error?')
    except ValueError as errmsg:
        test(errmsg[0], 'Input strings must be of equal length!')

    return

# Call this test script directly from command-line
if __name__ == '__main__':
    main()
#==============================================================================
#==============================================================================
