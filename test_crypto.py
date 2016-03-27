#!/usr/bin/python
#==============================================================================
#     File: test_crypto.py
#  Created: 03/07/2016, 13:42
#   Author: Bernie Roesler
#
# Last Modified: 03/26/2016, 20:59
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
    #       Test hex2b64_str
    #--------------------------------------------------------------------------
    print '---- hex2b64_str ----'
    # ASCII string to base64 string
    string = 'Man'
    expect = 'TWFu'

    # Convert ASCII string to hex before passing
    test(crp.hex2b64_str(string.encode('hex')), expect)

    # Hex string to base64 string
    # I/O test taken from <http://cryptopals.com/sets/1/challenges/1>
    string = '49276d206b696c6c696e6720796f75722'\
             '0627261696e206c696b65206120706f69'\
             '736f6e6f7573206d757368726f6f6d'
    expect = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa'\
             'WtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    # Input already a hex-encoded string
    test(crp.hex2b64_str(string), expect)

    # Test for a string that is too short
    try:
        test(crp.hex2b64_str('B'), 'Whatever.')
    except ValueError as errmsg:
        test(errmsg[0], 'Input argument must be at least 3 characters.')

    # Test for output padding (or lack thereof)
    try:
        test(crp.hex2b64_str('sure.'.encode('hex')), 'c3VyZS4=')
    except Exception as errmsg:
        test(errmsg[0], 'Number of input bytes not divisible by 6, not'\
                ' including padding characters in output.')

    #--------------------------------------------------------------------------
    #        Test fixedXOR
    #--------------------------------------------------------------------------
    print '---- fixedXOR ----'
    # Test for short string
    str1   = 'A'
    key    = '2'
    expect = '8'

    out_int = crp.fixedXOR(str1,key)
    # Python hex() inclues '0x...L' for hex long integers, so remove them
    out_str = hex(out_int).lstrip('0x').rstrip('L') or '0'

    test(out_str, expect)

    # I/O test from <http://cryptopals.com/sets/1/challenges/2>
    str1   = '1c0111001f010100061a024b53535009181c'
    key    = '686974207468652062756c6c277320657965'
    expect = '746865206b696420646f6e277420706c6179'

    out_int = crp.fixedXOR(str1,key)
    out_str = hex(out_int).lstrip('0x').rstrip('L') or '0'
    test(out_str, expect)

    # Test for different length inputs
    try:
        test( hex(crp.fixedXOR('abc','de')).lstrip('0x').rstrip('L'), 'error?')
    except ValueError as errmsg:
        test(errmsg[0], 'Input strings must be of equal length!')

    return

# Call this test script directly from command-line
if __name__ == '__main__':
    main()
#==============================================================================
#==============================================================================
