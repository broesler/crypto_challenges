#!/usr/local/bin/ruby 
require "openssl"

# Define decryption function
def decrypt_aes_128_ecb(data, key)
  # Advanced Encryption Standard, 128 bit, Electronic Codebook
  alg = "AES-128-ECB"

  # Create class for decryption
  decipher = OpenSSL::Cipher.new(alg)
  decipher.decrypt
  decipher.key = key

  # Decrypt
  plain = decipher.update(data) + decipher.final

  return plain
end


if __FILE__ == $0
  # Read encrypted file in as base64, remove newlines
  data_b64 = File.open("../data/7.txt", "rb").read.gsub("\n","")

  # Convert to byte array
  data = data_b64.unpack('m')[0]

  # Choose key
  key = "YELLOW SUBMARINE"

  plain = decrypt_aes_128_ecb(data, key)
  puts plain
end

