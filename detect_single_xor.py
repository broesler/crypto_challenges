#!/usr/bin/python
#==============================================================================
#     File: detect_single_xor.py
#  Created: 04/04/2016, 21:25
#   Author: Bernie Roesler
#
# Last Modified: 04/04/2016, 22:21
#
'''
  Description: Detect single-character XOR in file.
'''
#==============================================================================
import sys
import crypto as crp

# Steps:
# 1. open file
# 2. for each line in file
#   a. pass through single-byte XOR to find most likely candidate for key
#   b. track which line has highest score

def main(filename):
    ''' Find the line in a file that contains an XORed string. '''
    ifile = open(filename, 'rU')

    # Initialize variables
    Nline = 0
    true_key = 0
    plaintext_decrypt = ''
    cfreq_score_max = 0
    found_line = 0

    # XOR each line in the file to fine most likely candidate
    for line in ifile:
        Nline += 1
        xor_out = crp.single_byte_XOR(line.rstrip('\n').encode('hex'))

        # Track actual output
        if xor_out.score > cfreq_score_max:
            true_key = xor_out.key
            plaintext_decrypt = xor_out.decrypt
            cfreq_score_max = xor_out.score
            found_line = Nline

    print 'Line: \t', Nline
    print 'Key: \t', true_key
    print 'String: \t', plaintext_decrypt
    return

# Call this test script directly from command-line
if __name__ == '__main__':
    main(sys.argv[1])
#==============================================================================
#==============================================================================
