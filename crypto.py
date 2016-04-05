#!/usr/bin/python
#==============================================================================
#     File: crypto.py
#  Created: 03/03/2016, 14:55
#   Author: Bernie Roesler
#
# Last Modified: 04/05/2016, 14:00
#
'''
  Functions to support solutions to Matasano Crypto Challenges, Set 1.
'''
#==============================================================================
from collections import namedtuple
import pdb, traceback, sys

#------------------------------------------------------------------------------
#       Convert hexadecimal string to base64 string
#------------------------------------------------------------------------------
def hex2b64_str(hex_str):
    '''Convert hex string to base64 string.'''
    b64_lut = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    nchr_in = len(hex_str)     # Number of chars in encoded string
    nbyte = nchr_in / 2         # 2 hex chars == 1 byte
    # nchr_out = nbyte * 4/3      # Number of chars in output

    # Byte array (2 hex chars == 1 byte)
    hex_byte = [int(hex_str[i:i+2], 16) for i in range(0, nchr_in, 2)]

    b64_str = ''
    # Operate in chunks of 3 bytes  in ==> 4 bytes out
    for i in range(0, nbyte, 3):
        # Add first character using first 6 bits of first byte
        # Need 2 chars of hex to get 1 byte
        b64_int = (hex_byte[i] & 0xFC) >> 2
        b64_str += b64_lut[b64_int]

        # get last 2 bits of first byte
        b64_int = (hex_byte[i] & 0x03) << 4

        # if we have more bytes to go
        if i+1 < nbyte:
            # Add second character using first 4 bits of second byte and
            # combine with 2 from above
            b64_int |= (hex_byte[i+1] & 0xF0) >> 4
            b64_str += b64_lut[b64_int]

            # get last 4 bits of second byte
            b64_int = (hex_byte[i+1] & 0x0F) << 2

            # if we have more bytes to go
            if i+2 < nbyte:
                # Add third character
                # get first 2 bits of third byte and combine with 4 from above
                # b64_int |= (hex_byte[i+2] & 0xC0) >> 6

                # The following construct is the same as "dbstop if error":
                try:
                    b64_int |= (hex_byte[i+2] & 0xC0) >> 6
                except:
                    type, value, tb = sys.exc_info()
                    traceback.print_exc()
                    pdb.post_mortem(tb)

                b64_str += b64_lut[b64_int]

                # Add fourth character using last 6 bits of third byte
                b64_int = (hex_byte[i+2] & 0x3F)
                b64_str += b64_lut[b64_int]

            # There are only 2 bytes of input, so interpret 3rd character with
            # a "0x00" byte appended, and pad with an '=' character
            else:
                b64_str += b64_lut[b64_int]
                b64_str += '='

        # There is only 1 bytes of input, so interpret 2nd character with
        # two "0x00" bytes appended, and pad with an '=' character
        else:
            b64_str += b64_lut[b64_int]
            b64_str += '=='

    return b64_str

#------------------------------------------------------------------------------
#       Fixed-length XOR
#------------------------------------------------------------------------------
def fixedXOR(str1, key):
    '''Take a hex-encoded string and XOR it with a hex-encoded key to return
    a hex-encoded string.'''

    if len(str1) != len(key):
        raise ValueError('Input strings must be of equal length!')

    # XOR the numbers
    out_int = int(str1, 16) ^ int(key, 16)

    return out_int

#------------------------------------------------------------------------------
#      Character frequency score (English)
#------------------------------------------------------------------------------
def char_freq_score(plaintext):
    '''Score an English string on a scale of 0 to 12 based on character
    frequency.'''
    # Most common English letters in order
    etaoin = 'etaoinshrdlcumwfgypbvkjxqz'

    # Get list of lowercase letters in order of most frequency to least
    freqOrder = get_frequency_order(plaintext.lower())

    # Find matches in top N characters
    N = 6   # typically 6, could use more... needs experiment
    score = 0
    for ch in etaoin[:N]:
        if ch in freqOrder[:N]:
            score += 1

    return score

#------------------------------------------------------------------------------
#       String character frequency order
#------------------------------------------------------------------------------
def get_frequency_order(plaintext):
    '''Return string of character frequencies in input string ranked highest
    to lowest.'''
    ranks = ''

    # Build dictionary
    mydict = {}
    for c in plaintext:
        if c not in mydict:
            mydict[c] = 1
        else:
            mydict[c] += 1

    # Sort by character frequency
    for k in sorted(mydict, key=mydict.get, reverse=True):
        ranks += k

    return ranks

#------------------------------------------------------------------------------
#       Decode XOR input with single byte
#------------------------------------------------------------------------------
def single_byte_XOR(ciphertext):
    '''
    Take a hex-encoded string that has been XOR'd against a single
    character, and decode it. single_byte_XOR returns a struct containing:
        out.key         integer value of the "true key" used for decryption
        out.decrypt     actual decrypted string
        out.score       integer character frequency score
    '''
    # Input checking
    N = len(ciphertext)   # number of bytes in ciphertext

    if N % 2 != 0:
        raise ValueError('Input string must have even number of characters!')

    # Prepare output struct
    output = namedtuple('output', 'key decrypt score')

    # Initialize variables
    cfreq_score_max = 0
    true_key = 0x00
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
        # XOR each byte in the ciphertext with the key (1 byte == 2 hex chars)
        for cipherbyte in [ciphertext[a:a+2] for a in range(0, N, 2)]:
            plaintext += chr(fixedXOR(cipherbyte, key))

        # Calculate character frequency score
        cfreq_score = char_freq_score(plaintext)

        # Track maximum score and actual key
        if cfreq_score > cfreq_score_max:
            cfreq_score_max = cfreq_score   # int
            true_key = key                  # chr
            plaintext_decrypt = plaintext   # str

    # Store output in named tuple
    out = output(true_key, plaintext_decrypt, cfreq_score_max)

    return out

#==============================================================================
#==============================================================================
