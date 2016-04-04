#!/usr/bin/python
#==============================================================================
#     File: crypto.py
#  Created: 03/03/2016, 14:55
#   Author: Bernie Roesler
#
# Last Modified: 04/04/2016, 10:57
#
'''
  Functions to support solutions to Matasano Crypto Challenges, Set 1.
'''
#==============================================================================

import pdb

def b64_chr_dict():
    ''' base64 dictionary with chars as keys. '''
    mydict = {'A': 0,
              'B': 1,
              'C': 2,
              'D': 3,
              'E': 4,
              'F': 5,
              'G': 6,
              'H': 7,
              'I': 8,
              'J': 9,
              'K':10,
              'L':11,
              'M':12,
              'N':13,
              'O':14,
              'P':15,
              'Q':16,
              'R':17,
              'S':18,
              'T':19,
              'U':20,
              'V':21,
              'W':22,
              'X':23,
              'Y':24,
              'Z':25,
              'a':26,
              'b':27,
              'c':28,
              'd':29,
              'e':30,
              'f':31,
              'g':32,
              'h':33,
              'i':34,
              'j':35,
              'k':36,
              'l':37,
              'm':38,
              'n':39,
              'o':40,
              'p':41,
              'q':42,
              'r':43,
              's':44,
              't':45,
              'u':46,
              'v':47,
              'w':48,
              'x':49,
              'y':50,
              'z':51,
              '0':52,
              '1':53,
              '2':54,
              '3':55,
              '4':56,
              '5':57,
              '6':58,
              '7':59,
              '8':60,
              '9':61,
              '+':62,
              '/':63};
    return mydict

#------------------------------------------------------------------------------
#       Convert hexadecimal string to base64 string
#------------------------------------------------------------------------------
def hex2b64_str(str_type):
    ''' Convert hex string to base64 string. '''
    b64_lut = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    # pdb.set_trace()
    nchr_in = len(str_type)     # Number of chars in encoded string
    nbyte = nchr_in / 2         # 2 hex chars == 1 byte
    # nchr_out = nbyte * 4/3      # Number of chars in output

    # Convert input hex string to integer
    hex_int = int(str_type, 16)

    b64_str = ''
    # Operate in chunks of 3 bytes in ==> 4 bytes out
    for i in range(0, nbyte, 3):
        # get first 6 bits of first byte
        shift = 8 * (nbyte - (i+1))
        mask = 0xFC << shift
        b64_int = (hex_int & mask) >> (shift+2)

        # Add first character
        b64_str += b64_lut[b64_int]

        # get last 2 bits of first byte
        mask = 0x03 << shift
        b64_2 = (hex_int & mask) >> (shift-4)

        # if we have more bytes to go
        if i+1 < nbyte:
            # get first 4 bits of second byte and combine with 2 from above
            mask = 0xF0 << (shift-8)
            b64_4 = (hex_int & mask) >> (shift-4)
            b64_int = b64_2 | b64_4

            # Add second character
            b64_str += b64_lut[b64_int]

            # get last 4 bits of second byte
            mask = 0x0F << (shift-8)
            b64_2 = (hex_int & mask) >> (shift-10)

            # if we have more bytes to go
            if i+2 < nbyte:
                # get first 2 bits of last byte and combine with 4 from above
                mask = 0xC0 << (shift-16)
                b64_4 = (hex_int & mask) >> (shift-10)
                b64_int = b64_2 | b64_4

                # Add third character
                b64_str += b64_lut[b64_int]

                # Get last 6 bits of last byte
                mask = 0x3F << (shift-16)
                b64_int = (hex_int & mask) >> (shift-16)

                # Add fourth character
                b64_str += b64_lut[b64_int]

            # There are only 2 bytes of input, so interpret 3rd character with
            # a "0x00" byte appended, and pad with an '=' character 
            else:
                b64_str += b64_lut[b64_2]
                b64_str += '='

        # There is only 1 bytes of input, so interpret 2nd character with
        # two "0x00" bytes appended, and pad with an '=' character 
        else:
            b64_str += b64_lut[b64_2]
            b64_str += '=='

    return b64_str

#------------------------------------------------------------------------------
#       Fixed-length XOR
#------------------------------------------------------------------------------
def fixedXOR(str1, key):
    ''' Take a hex-encoded string and XOR it with a hex-encoded key to return
    a hex-encoded string. '''

    if len(str1) != len(key):
        raise ValueError('Input strings must be of equal length!')

    # XOR the numbers
    out_int = int(str1, 16) ^ int(key, 16)

    return out_int

#==============================================================================
#==============================================================================
