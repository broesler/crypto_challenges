#!/usr/bin/python
#==============================================================================
#     File: crypto.py
#  Created: 03/03/2016, 14:55
#   Author: Bernie Roesler
#
# Last Modified: 03/26/2016, 21:04
#
'''
  Solutions to Matasano Crypto Challenges, Set 1.
'''
#==============================================================================

def b64_int_dict(): #{{{
    ''' base64 dictionary with integers as keys. '''
    mydict = {0:'A',
              1:'B',
              2:'C',
              3:'D',
              4:'E',
              5:'F',
              6:'G',
              7:'H',
              8:'I',
              9:'J',
              10:'K',
              11:'L',
              12:'M',
              13:'N',
              14:'O',
              15:'P',
              16:'Q',
              17:'R',
              18:'S',
              19:'T',
              20:'U',
              21:'V',
              22:'W',
              23:'X',
              24:'Y',
              25:'Z',
              26:'a',
              27:'b',
              28:'c',
              29:'d',
              30:'e',
              31:'f',
              32:'g',
              33:'h',
              34:'i',
              35:'j',
              36:'k',
              37:'l',
              38:'m',
              39:'n',
              40:'o',
              41:'p',
              42:'q',
              43:'r',
              44:'s',
              45:'t',
              46:'u',
              47:'v',
              48:'w',
              49:'x',
              50:'y',
              51:'z',
              52:'0',
              53:'1',
              54:'2',
              55:'3',
              56:'4',
              57:'5',
              58:'6',
              59:'7',
              60:'8',
              61:'9',
              62:'+',
              63:'/'};
    return mydict #}}}

def b64_chr_dict(): #{{{
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
    return mydict #}}}

#------------------------------------------------------------------------------
#       Convert hexadecimal string to base64 string 
#------------------------------------------------------------------------------
def hex2b64_str(str_type):
    ''' Convert hex string to base64 string. '''
    # lookup table of base64 characters, keys are integers
    b64_lut = b64_int_dict()    

    # Need multiples of 3 bytes to get base64 (6 bits per char)
    if len(str_type) < 3:
        raise ValueError('Input argument must be at least 3 characters.')

    if (4*len(str_type) % 3) != 0:
        raise RuntimeWarning('Number of input bytes not divisible by 6, not'\
                ' including padding characters in output.')

    # Number of characters in encoded string (need to divide by 2 because hex
    # characters only need 4 bits, not 8)
    nchr = 2*len(str_type) / 3

    # Convert hex string to integer
    hex_int = int(str_type, 16)

    b64_str = ''
    for i in range(nchr):
        shift = 6 * (nchr - (i+1))              # take chunks of 6 bits
        mask = 0b111111 << shift
        b64_int = (hex_int & mask) >> shift     # mask off relevant bits
        b64_str += b64_lut[b64_int]             # look up encoding

    return b64_str

# def hex2b64_int(int_type):
#     ''' Convert hex int to base64 int. '''
#     # lookup table of base64 characters, keys are chars
#     b64_lut = b64_chr_dict()    
#
#     nchr = 2*len(str(int_type)) / 3
#
#     return b64_int

# def b64_encode(str_type)
#     ''' Encode base64 string as integer '''
#     return b64_int

#------------------------------------------------------------------------------
#       Fixed-length XOR 
#------------------------------------------------------------------------------
def fixedXOR(str1, key):
    ''' Take a hex-encoded string and XOR it with a hex-encoded key to return
    a hex-encoded string. '''

    if len(str1) != len(key):
        raise ValueError('Input strings must be of equal length!')

    # XOR the numbers
    out_int = int(str1,16) ^ int(key,16)

    return out_int

#==============================================================================
#==============================================================================
