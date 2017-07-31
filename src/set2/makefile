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
all: test2 c10 c11 c12 c13 c14 types
test: test2
c10: aes_cbc_file
c11: detect_block_mode
c12: one_byte_ecb_easy
c13: make_admin_profile
c14: one_byte_ecb_hard

debug: CFLAGS += -DLOGSTATUS -ggdb3
debug: all
verbose: CFLAGS += -DVERBOSE
verbose: debug

#------------------------------------------------------------------------------
# 		Compile and link steps 
#------------------------------------------------------------------------------
# Main executable:
test2: test_crypto2.o $(OBJ_UTIL)
	$(CC) $(CFLAGS) $(OPT) -o $@ $? $(LDLIBS)

aes_cbc_file: aes_cbc_file.o $(OBJ_UTIL)
	$(CC) $(CFLAGS) $(OPT) -o $@ $? $(LDLIBS)

detect_block_mode: detect_block_mode.o $(OBJ_UTIL)
	$(CC) $(CFLAGS) $(OPT) -o $@ $? $(LDLIBS)

one_byte_ecb_easy: one_byte_ecb_easy.o $(OBJ_UTIL)
	$(CC) $(CFLAGS) $(OPT) -o $@ $? $(LDLIBS) $(DLIBS)

make_admin_profile: make_admin_profile.o $(OBJ_UTIL)
	$(CC) $(CFLAGS) $(OPT) -o $@ $? $(LDLIBS) $(DLIBS)

one_byte_ecb_hard: one_byte_ecb_hard.o $(OBJ_UTIL)
	$(CC) $(CFLAGS) $(OPT) -o $@ $? $(LDLIBS) $(DLIBS)

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
	rm -f detect_block_mode
	rm -f one_byte_ecb_easy
	rm -f one_byte_ecb_hard

#==============================================================================
#==============================================================================
