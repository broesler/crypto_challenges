#!/usr/bin/python
#==============================================================================
#     File: break_repeating_XOR.py
#  Created: 04/08/2016, 11:36
#   Author: Bernie Roesler
#
# Last Modified: 05/13/2016, 14:39
#
''' 
  Description: Decode file that has been encrypted by repeating key XOR
'''
#==============================================================================
import sys
import crypto as crp
# import pdb

# def main(filename):
def main():
    '''Decode file that has been encrypted by repeating key XOR.'''
    #-------------------
    # Test using file:
    #-------------------
    filename = '6.txt'
    fp = open(filename, 'rU')

    # Join all lines in file into a single string for decoding
    fstr_b64 = ''.join(line.strip() for line in fp)

    #-------------------
    # Test input
    #-------------------
    # expect = 'Burning \'em, if you ain\'t quick and nimble\n'\
    #          'I go crazy when I hear a cymbal'
    #
    # # Output when repeatedly XORed with key='ICE'
    # ciphertext = '0b3637272a2b2e63622c2e69692a23693a2a'\
    #              '3c6324202d623d63343c2a26226324272765272'\
    #              'a282b2f20430a652e2c652a3124333a653e2'\
    #              'b2027630c692b20283165286326302e27282f'
    # # key = 'ICE'
    #
    # # Test by base64ing known input
    # fstr_b64 = crp.hex2b64_str(ciphertext)

    #--------------------------------------------------------------------------
    #        Find most probable keysize
    #--------------------------------------------------------------------------
    # String is base64 encoded, so convert to hex
    fstr_hex = crp.b642hex_str(fstr_b64)
    N = len(fstr_hex)

    # number of chunks of each keysize to take -- MUST BE EVEN
    num_chunks = 10

    # largest possible keysize (given this test) must fit integer number of
    # times into the ciphertext
    KEYSIZEMAX = min(40, N/(2*num_chunks))

    min_hd = 99*N       # start with impossibly high distance

    for k in range(2, KEYSIZEMAX):
        # for k in [2, 3]:
        # chunks are groups of 2 hex chars == 1 byte
        chunk = [fstr_hex[i*2*k:(i+1)*2*k] for i in range(0, num_chunks)]

        # Find normalized Hamming distance between pairs of chunks
        norm_hd_list = [crp.hamming_dist(chunk[i], chunk[i+1]) / float(k) \
                        for i in range(0, len(chunk), 2)]

        # Average over all Hamming distances found
        norm_hd = sum(norm_hd_list) / float(len(norm_hd_list))

        # Keep the minimum Hamming distance, which reveals the likely KEYSIZE
        if norm_hd < min_hd:
            min_hd = norm_hd
            keylen = k

    print '{0:0.4f}'.format(min_hd), keylen, KEYSIZEMAX

    #--------------------------------------------------------------------------
    #       Run single_byte_XOR_decode() on block of every Nth character 
    #--------------------------------------------------------------------------
    key = ''
    # For each byte of the key
    for j in range(0, keylen):
        # Get every ith byte of the ciphertext (transpose it)
        str_trans = ''.join([fstr_hex[i:i+2] for i in range(2*j, N, 2*keylen)])

        out = crp.single_byte_XOR_decode(str_trans)
        key += out.key
        # print 'score: ', out.score
        # print 'decrypt: ', out.decrypt

    print key.decode('hex')

    #--------------------------------------------------------------------------
    #        XOR encrypted text with key to get decrypted text!
    #--------------------------------------------------------------------------
    plaintext = crp.repeating_key_XOR(fstr_hex, key)
    print plaintext.decode('hex')

    return

if __name__ == '__main__':
    # main(sys.argv[1])
    main()  # use for debugging
#==============================================================================
#==============================================================================
