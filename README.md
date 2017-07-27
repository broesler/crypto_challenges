# README #

Here are my solutions to the [Matasano Crypto Challenges](https://cryptopals.com)!

Partially because I'm a masochist and partically because it feels more hacker-y,
I wrote them in C. There's something deeply satisfying about performing actual
bit-flipping operations in about the lowest level language you can get short of
machine code.

## The Structure ##
.
├── README.md
├── data
│   ├── 10.txt
│   ├── 4.txt
│   ├── 6.txt
│   ├── 7.txt
│   ├── 8.txt
│   └── play_that_funky_music.txt
├── include
│   ├── aes_openssl.h
│   ├── crypto1.h
│   ├── crypto2.h
│   ├── crypto_util.h
│   ├── header.h
│   └── unit_test.h
├── notes
│   ├── aes_demo.c
│   ├── char_test.m
│   ├── hamming.sh
│   ├── makefile_aesdemo
│   ├── makefile_ruby
│   ├── notes_padding.txt
│   ├── ruby_ssl.rb
│   ├── ruby_test.c
│   ├── strassign_test.c
│   └── test_strtoul.c
├── python
│   ├── break_repeating_XOR.py
│   ├── crypto.py
│   ├── detect_single_xor.py
│   ├── single_byte_XOR.py
│   └── test_crypto.py
└── src
    ├── breakRepeatingXOR.c
    ├── crypto1.c
    ├── crypto2.c
    ├── makefile
    ├── test_all.sh
    ├── test_crypto1.c
    ├── test_crypto2.c
    ├── types.vim
    └── util
        ├── aes_openssl.c
        ├── crypto_util.c
        ├── makefile
        └── test_util.c

##---------- Details ----------##
### `data/`
  * data files used in the exercises. Files are linked to in each challenge on
    the Matasano site.

### `include/`
  * Header files for the C code, see descriptions of [source](#src/) below.
  * `header.h`: general macros for allocating memory, initializing structures,
    and error checking or throwing warnings.
  * `unit_test.h`: macros for the unit testing routines. Keeps a count of failed
    tests and displays easy-to-read output on pass/fail status.

### `notes/`
  * Small code snippets and little tests I've run along the way.
  * `aes_demo.c`: Test of AES encrypt/decrypt functions from the OpenSSL
    library. Mostly borrowed from the [OpenSSL wiki](https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption).
  * `makefile_aesdemo`: makefile for `aes_demo.c`. Run `$ make -f makefile_aesdemo` 
    to compile. Includes OpenSSL headers and crypto libraries.
  * `char_test.m`: Matlab code prototype of character frequency analysis score.
  * `hamming.sh`: Fun attempt at Hamming distance with a shell script.
  * `ruby_test.c`: Quick run at using ruby API with C. Originally I thought this
    was going to be an easier route to getting AES operational in C, but the
    OpenSSL library was plenty easy to incorporate.
  * `makefile_ruby`: makefile for `ruby_test.c`. Run `$ make -f makefile_ruby` 
    to compile.
  * `notes_padding.txt`: gdb output from earlier tests on the OpenSSL automatic
    padding during AES en/decryption. OpenSSL adds a full block of PKCS#7
    padding even when input is exactly one block length.
  * `ruby_ssl.rb`: Ruby code to en/decrypt using OpenSSL::Cipher.
  * `strassign_test.c`: Check pointer assignment for byte arrays.
  * `test_strtoul.c`: Check `strtoul` usage instead of byte array.

### `python/`
  * My initial attempt at the challenges was done in python to learn the
    language. I decided C instilled a bit more discipline and made me feel like
    more of a hacker. So here we are. This code is no longer maintained.

### `src/`
  * The main source code for my solutions to the challenges.
  * `breakRepeatingXOR.c`: Separate file to run `breakRepeatingXOR` as
    a standalone function to accept a filename as input. I'm experimenting with
    splitting some of the challenges out into their own `main()` functions, but
    for now most are encapsulated into the unit test harnesses.
  * `crypto1.c`: All functions solving the challenges in [Set 1](https://cryptopals.com/sets/1).
    Top-level functions are labeled where appropriate. Helper functions also
    included.
  * `crypto2.c`: All functions solving the challenges in [Set 2](https://cryptopals.com/sets/2).
    Top-level functions are labeled where appropriate. Helper functions also
    included.
  * `makefile`: Makefile to build all challenge solutions. See [build and run](#build-and-run)
    below for instructions.
  * `test_all.sh`: Shell script to run all tests.
  * `test_crypto1.c`: Unit test harness for set 1 challenges.
  * `test_crypto2.c`: Unit test harness for set 2 challenges.

### `src/util/`
  * Utility functions for running the crypto challenges.
  * `aes_openssl.c`: Core of the AES algorithm, as well as helper functions for
    setting up the OpenSSL library.
  * `crypto_util.c`: Helper C functions for string and byte array manipulation.
  * `makefile`: Makefile to build the utilities.
  * `test_util.c`: Unit test harness for the utilities.

## Build and Run ##
  * To build and run the challenges:
  ```shell
  $ cd src

  $ ./test_all.sh
  ```
  * This script will:
    1. Navigate to the `src/util/` directory, build and run the utilities test,
       and run a check to make sure all utilities pass.
    2. Navigate to the `src/` directory, build and run the tests for all
       challenges, and run a check to make sure all tests pass.
  * Verbose output via `make debug` can be set in `test_all.sh`.
