#!/usr/bin/python
#==============================================================================
#     File: test_crypto.py
#  Created: 03/07/2016, 13:42
#   Author: Bernie Roesler
#
# Last Modified: 04/07/2016, 14:22
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
    # Simple ASCII string to base64 string
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

    # Test padding
    test(crp.hex2b64_str('M'.encode('hex')), 'TQ==')
    test(crp.hex2b64_str('Ma'.encode('hex')), 'TWE=')

    #--------------------------------------------------------------------------
    #        Test fixedXOR
    #--------------------------------------------------------------------------
    print '---- fixedXOR ----'
    # Test for short string
    str1   = 'A'
    key    = '2'
    expect = '8'

    out_int = crp.fixedXOR(str1, key)
    # Python hex() inclues '0x...L' for hex long integers, so remove them
    out_str = hex(out_int).lstrip('0x').rstrip('L') or '0'

    test(out_str, expect)

    # I/O test from <http://cryptopals.com/sets/1/challenges/2>
    str1   = '1c0111001f010100061a024b53535009181c'
    key    = '686974207468652062756c6c277320657965'
    expect = '746865206b696420646f6e277420706c6179'

    # strings are already hex-encoded
    out_int = crp.fixedXOR(str1, key)
    out_str = hex(out_int).lstrip('0x').rstrip('L') or '0'
    test(out_str, expect)

    # Test for different length inputs
    try:
        test(hex(crp.fixedXOR('abc', 'de')).lstrip('0x').rstrip('L'), 'error?')
    except ValueError as errmsg:
        test(errmsg[0], 'Input strings must be of equal length!')

    #--------------------------------------------------------------------------
    #        Test get_frequency_order
    #--------------------------------------------------------------------------
    print '---- get_frequency_order ----'
    string = 'Hello'
    r = crp.get_frequency_order(string)
    test(r, 'lHeo')     # remaining characters put in alphabetical order

    #--------------------------------------------------------------------------
    #        Test char_freq_score
    #--------------------------------------------------------------------------
    print '---- char_freq_score ----'
    string = 'EtAoIn'
    r = crp.char_freq_score(string)
    test(r, 6)

    #--------------------------------------------------------------------------
    #       Test single_byte_XOR_decode
    #--------------------------------------------------------------------------
    print '---- single_byte_XOR_decode ----'
    # I/O test from <http://cryptopals.com/sets/1/challenges/3>
    ciphertext = '1b37373331363f78151b7f2b783431333'\
                 'd78397828372d363c78373e783a393b3736'

    # Returns namedtuple with fields key, score, decrypt, can also return those
    # fields as individual variables on LHS
    out = crp.single_byte_XOR_decode(ciphertext)
    test(out.key, '58')
    test(out.score, 15)
    test(out.decrypt, 'Cooking MC\'s like a pound of bacon')

    #--------------------------------------------------------------------------
    #        Test repeating_key_XOR
    #--------------------------------------------------------------------------
    print '---- repeating_key_XOR ----'
    # I/O test from <http://cryptopals.com/sets/1/challenges/5>
    # plaintext = 'Burning \'em, if you ain\'t quick and nimble'\
    #             'I go crazy when I hear a cymbal'
    plaintext = 'Burning \'em, if you ain\'t quick and nimble\n'\
                'I go crazy when I hear a cymbal'
    expect = '0b3637272a2b2e63622c2e69692a23693a2a'\
             '3c6324202d623d63343c2a26226324272765272'\
             'a282b2f20430a652e2c652a3124333a653e2'\
             'b2027630c692b20283165286326302e27282f'
    key = 'ICE'

    ciphertext = crp.repeating_key_XOR(plaintext, key)
    test(ciphertext, expect)

    #--------------------------------------------------------------------------
    return # end main()
    #--------------------------------------------------------------------------

# Call this test script directly from command-line
if __name__ == '__main__':
    main()
#==============================================================================
#==============================================================================
