#!/usr/bin/python
#==============================================================================
#     File: crypto.py
#  Created: 03/03/2016, 14:55
#   Author: Bernie Roesler
#
'''
  Functions to support solutions to Matasano Crypto Challenges, Set 1.
'''
#==============================================================================
from collections import namedtuple
import string
# import pdb
# import traceback
# import sys

# base64 look-up table
b64_lut = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

#------------------------------------------------------------------------------
#       Convert base64 string to hexadecimal string
#------------------------------------------------------------------------------
def b642hex_str(b64_str):
    '''Convert base64 string to hex string.'''
    nbyte = len(b64_str)     # Number of chars in encoded string == # bytes

    if nbyte % 4 != 0:
        raise ValueError('Input string must have a multiple of 4 characters!')
        
    # List of integers corresponding to b64 characters in input
    b64_byte = [b64_lut.find(b64_str[i]) for i in range(0, nbyte)]

    hex_int = []
    for i in range(0, nbyte, 4):
        # Take chunks of 4 bytes --> 3 bytes of output
        chunk = b64_byte[i:i+4]

        # First char of output
        #   Need to mask off MSBs for left-shifts so we don't keep large #s
        hex_int.append((chunk[0] << 2) & 0xFF | (chunk[1] >> 4))

        # Second char
        if (chunk[2] < 0x40) and (chunk[2] > 0x00):
            hex_int.append((chunk[1] << 4) & 0xFF | (chunk[2] >> 2))

            # Third char
            if (chunk[3] < 0x40) and (chunk[3] > 0x00):
               hex_int.append((chunk[2] << 6) & 0xFF | chunk[3])

    # Convert integer list to hex string
    hex_str = ''.join(['%02x'%k for k in hex_int])

    return hex_str

#------------------------------------------------------------------------------
#       Convert hexadecimal string to base64 string
#------------------------------------------------------------------------------
def hex2b64_str(hex_str):
    '''Convert hex string to base64 string.'''

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
                b64_int |= (hex_byte[i+2] & 0xC0) >> 6

                # # The following construct is the same as "dbstop if error":
                # try:
                #     b64_int |= (hex_byte[i+2] & 0xC0) >> 6
                # except:
                #     type, value, tb = sys.exc_info()
                #     traceback.print_exc()
                #     pdb.post_mortem(tb)

                b64_str += b64_lut[b64_int]

                # Add fourth character using last 6 bits of third byte
                b64_int = (hex_byte[i+2] & 0x3F)
                b64_str += b64_lut[b64_int]

            # There are only 2 bytes of input, so interpret 3rd character with
            # a "0x00" byte appended, and pad with an '=' character
            else:
                b64_str += b64_lut[b64_int]
                b64_str += '='

        # There is only 1 byte of input, so interpret 2nd character with
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
    an integer.'''

    if len(str1) != len(key):
        raise ValueError('Input strings must be of equal length!')

    # XOR the numbers
    out_int = int(str1, 16) ^ int(key, 16)

    return out_int

#------------------------------------------------------------------------------
#      Character frequency score (English)
#------------------------------------------------------------------------------
# def char_freq_score(plaintext):
#     '''Score an English string on a scale of 0 to 12 based on character
#     frequency.'''
#     # Set of printable characters
#     valid_characters = set(string.printable)-set(string.digits)-set(['#','$','%','/','~','`'])
#
#     if all(char in valid_characters for char in plaintext):
#         score = 100
#     else:
#         score = 0
#
#     return score

def char_freq_score(plaintext):
    '''Score an English string on a scale of 0 to 12 based on character
    frequency.'''
    # Most common English letters in order (include space!!)
    etaoin = ' etaoinshrdlcumwfgypbvkjxqz'

    # Get list of lowercase letters in order of most frequency to least
    freqOrder = get_frequency_order(plaintext)

    # Find matches in top N characters
    N = 22
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

    # Build dictionary
    mydict = {}
    for c in plaintext:
        if c not in mydict:
            mydict[c] = 1
        else:
            mydict[c] += 1

    # Sort by character frequency, return string instead of list
    ranks = ''.join(sorted(mydict, key=mydict.get, reverse=True))

    return ranks

#------------------------------------------------------------------------------
#       Decode XOR input with single byte
#------------------------------------------------------------------------------
def single_byte_XOR_decode(ciphertext):
    '''
    Take a hex-encoded string that has been XOR'd against a single
    character, and decode it.
    Input:
        ciphertext      hex-encoded string
    Output:
        out.key         integer value of the "true key" used for decryption
        out.decrypt     actual decrypted string
        out.score       integer character frequency score
    '''
    # Input checking
    N = len(ciphertext)   # number of bytes in ciphertext

    if N % 2 != 0:
        raise ValueError('Input string must have even number of characters!')

    # Initialize variables
    cfreq_score_max = 0
    true_key = 0x00
    plaintext_decrypt = ''

    # For each possible byte
    for i in range(0x00, 0x100):
        # XOR each character in ciphertext with key
        key = hex(i).lstrip('0x') or '0'

        # Single-digit hex numbers need a padding 0
        if len(key) == 1:
            key = '0' + key

        plaintext = ''
        # XOR each byte in the ciphertext with the key (1 byte == 2 hex chars)
        for cipherbyte in [ciphertext[j:j+2] for j in range(0, N, 2)]:
            plaintext += chr(fixedXOR(cipherbyte, key))

        # Calculate character frequency score
        cfreq_score = char_freq_score(plaintext)

        # Track maximum score and actual key
        if cfreq_score >= cfreq_score_max:
            cfreq_score_max   = cfreq_score # int
            true_key          = key         # chr (in hex!)
            plaintext_decrypt = plaintext   # str

    # Store output in named tuple
    output = namedtuple('output', 'key decrypt score')
    out = output(true_key, plaintext_decrypt, cfreq_score_max)

    return out

#------------------------------------------------------------------------------
#       Repeating key XOR
#------------------------------------------------------------------------------
def repeating_key_XOR(plaintext_hex, key_hex):
    '''Return an encrypted string from a hex-encoded input, XORed with
    a repeating key.'''

    N = len(plaintext_hex)
    M = len(key_hex)

    pt_byte = [plaintext_hex[i:i+2] for i in range(0, N, 2)]
    key_byte = [key_hex[i:i+2] for i in range(0, M, 2)]

    ciphertext_hex = ''
    for i in range(0, N/2):
        ciphertext_int = fixedXOR(pt_byte[i], key_byte[i % (M/2)])
        ciphertext_hex += '{0:02x}'.format(ciphertext_int)

    return ciphertext_hex

#------------------------------------------------------------------------------
#       Hamming distance
#------------------------------------------------------------------------------
def hamming_dist(str1, str2):
    '''Returns the number of differing bits of two hex-encoded strings.'''
    # XOR the strings to get 1's where the bits differ
    str_xor = fixedXOR(str1,str2)

    # Count the number of bits that differ
    H = bin(str_xor).count('1')

    return H
#==============================================================================
#==============================================================================
