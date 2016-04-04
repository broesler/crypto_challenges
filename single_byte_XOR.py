#!/usr/bin/python
#==============================================================================
#     File: single_byte_XOR.py
#  Created: 03/08/2016, 13:34
#   Author: Bernie Roesler
#
# Last Modified: 04/04/2016, 18:29
#
'''
  Description: Solve single-byte XOR cipher
'''
#==============================================================================
import crypto as crp

#------------------------------------------------------------------------------
#       XOR input with single byte 
#------------------------------------------------------------------------------
def main():
    ''' Take a hex-encoded string that has been XOR'd against a single
    character, and decode it. '''

    ciphertext = '1b37373331363f78151b7f2b783431333'\
                 'd78397828372d363c78373e783a393b3736'

    N = len(ciphertext)   # number of bytes in ciphertext

    # Initialize variables
    cfreq_score_max = 0
    plaintext_decrypt = ''

    # For each possible byte
    # for i in range(0x56, 0x60):
    for i in range(0x00, 0x100):
        # XOR each character in ciphertext with key
        key = hex(i).lstrip('0x') or '0'

        # Single-digit hex numbers need a padding 0
        if len(key) == 1:
            key = '0' + key

        plaintext = '' 
        # XOR each byte in the ciphertext with the key (1 byte == 2 chars)
        for cipherbyte in [ciphertext[a:a+2] for a in range(0, N, 2)]:
            plaintext += chr(crp.fixedXOR(cipherbyte, key))

        # Calculate character frequency score
        cfreq_score = crp.char_freq_score(plaintext)

        # Track maximum score and actual key
        if cfreq_score > cfreq_score_max:
            cfreq_score_max = cfreq_score
            plaintext_decrypt = plaintext

    print plaintext_decrypt
    return

# Call this test script directly from command-line
if __name__ == '__main__':
    main()
#==============================================================================
#==============================================================================
