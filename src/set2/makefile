#==============================================================================
#    File: makefile
# Created: 09/27/2016, 20:58
#  Author: Bernie Roesler
#
#  Description: Build tests for crypto and queue functions
#==============================================================================

# Directories where source files are kept
SRCDIR   = ./
UTILDIR  = ../util/
INCLDIR  = ../../include/
SSLINCL  = /usr/local/opt/openssl/include/
DICTINCL = /Users/bernardroesler/Documents/School/cs50_software_design/labs/lab6/util/

# Set the compiler options
CC = gcc-7
CFLAGS = -Wall -pedantic -std=c99 -funsigned-char
SANFLAGS = -fsanitize=address -O1 -fno-omit-frame-pointer

# Look for header files here
OPT = -I$(INCLDIR) -I$(SSLINCL) -I$(DICTINCL)

# Libraries
LDLIBS = -lcrypto -lssl 
DLIBS = -L$(DICTINCL) -ldict

# Headers
INCL = $(wildcard $(INCLDIR)*.h)

# Define source files
SRC   = $(wildcard $(SRCDIR)*.c) $(wildcard $(UTILDIR)*.c)
UTIL  = crypto2.c ../set1/aes_ecb.c ../set1/crypto1.c 
UTIL += $(UTILDIR)aes_openssl.c $(UTILDIR)crypto_util.c

# Object files
OBJ_UTIL = $(UTIL:%.c=%.o)

# Make options
all: test2 c10 c11 c13 c14 c16 types
test: test2
c10: aes_cbc_file
c11: detect_block_mode
c13: make_admin_profile
c14: one_byte_ecb
c16: cbc_bit_flip

debug: CFLAGS += -DLOGSTATUS -ggdb3 -fno-inline
debug: all
verbose: CFLAGS += -DVERBOSE
verbose: debug

#------------------------------------------------------------------------------
# 		Compile and link steps 
#------------------------------------------------------------------------------
# Main executable:
test2: test_crypto2.o $(OBJ_UTIL)
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

aes_cbc_file: aes_cbc_file.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

detect_block_mode: detect_block_mode.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

make_admin_profile: make_admin_profile.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS) $(DLIBS)

one_byte_ecb: one_byte_ecb.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS) $(DLIBS)

cbc_bit_flip: cbc_bit_flip.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS) $(DLIBS)

.gitignore:
	@printf "test2\n\
	aes_cbc_file\n\
	detect_block_mode\n\
	make_admin_profile\n\
	one_byte_ecb\n\
	cbc_bit_flip\n" > $@

# Objects depend on source and headers
%.o: %.c $(INCL)
	$(CC) $(CFLAGS) $(OPT) -c $< -o $@

# Highlight custom types, unions, and structs!
types: .types.vim
.types.vim: $(SRC) $(UTIL) $(INCLDIR)/*.h
	ctags --c-kinds=gstu -o- ../../**/*.[ch] |\
		awk 'BEGIN{printf("syntax keyword Type\t")}\
			{printf("%s ", $$1)}END{print ""}' > $@

# clean up (do not do anything with file named clean)
.PHONY: depend clean
clean:
	rm -f *~
	rm -f ../set1/*.o
	rm -f ../set1/*.gch
	rm -rf ../set1/*.dSYM/
	rm -f $(SRCDIR)*.o
	rm -f $(SRCDIR)*.gch
	rm -rf $(SRCDIR)*.dSYM/
	rm -f $(UTILDIR)*.o
	rm -f $(UTILDIR)*.gch
	rm -rf $(UTILDIR)*.dSYM/
	rm -f test2
	rm -f aes_cbc_file
	rm -f cbc_bit_flip
	rm -f detect_block_mode
	rm -f one_byte_ecb
	rm -f make_admin_profile
	rm -f .gitignore

#==============================================================================
#==============================================================================
