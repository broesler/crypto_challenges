#!/usr/bin/python
#==============================================================================
#     File: crypto.py
#  Created: 03/03/2016, 14:55
#   Author: Bernie Roesler
#
# Last Modified: 04/04/2016, 16:33
#
'''
  Functions to support solutions to Matasano Crypto Challenges, Set 1.
'''
#==============================================================================

#------------------------------------------------------------------------------
#       Convert hexadecimal string to base64 string
#------------------------------------------------------------------------------
def hex2b64_str(hex_str):
    ''' Convert hex string to base64 string. '''
    b64_lut = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    nchr_in = len(hex_str)     # Number of chars in encoded string
    # nbyte = nchr_in / 2         # 2 hex chars == 1 byte
    # nchr_out = nbyte * 4/3      # Number of chars in output

    b64_str = ''
    # Operate in chunks of 3 bytes (6 hex chars) in ==> 4 bytes out
    for i in range(0, nchr_in, 6):
        byte1 = int(hex_str[i:i+2],16)

        # Add first character using first 6 bits of first byte
        # Need 2 chars of hex to get 1 byte
        b64_int = (byte1 & 0xFC) >> 2
        b64_str += b64_lut[b64_int]

        # get last 2 bits of first byte
        b64_int = (byte1 & 0x03) << 4

        # if we have more bytes to go
        if i+2 < nchr_in:
            byte2 = int(hex_str[i+2:i+4],16)

            # Add second character using first 4 bits of second byte and
            # combine with 2 from above
            b64_int |= (byte2 & 0xF0) >> 4
            b64_str += b64_lut[b64_int]

            # get last 4 bits of second byte
            b64_int = (byte2 & 0x0F) << 2

            # if we have more bytes to go
            if i+4 < nchr_in:
                # Add third character
                byte3 = int(hex_str[i+4:i+6],16)

                # get first 2 bits of third byte and combine with 4 from above
                b64_int |= (byte3 & 0xC0) >> 6
                b64_str += b64_lut[b64_int]

                # Add fourth character using last 6 bits of third byte
                b64_int = (byte3 & 0x3F)
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
    ''' Take a hex-encoded string and XOR it with a hex-encoded key to return
    a hex-encoded string. '''

    if len(str1) != len(key):
        raise ValueError('Input strings must be of equal length!')

    # XOR the numbers
    out_int = int(str1, 16) ^ int(key, 16)

    return out_int

#==============================================================================
#==============================================================================
