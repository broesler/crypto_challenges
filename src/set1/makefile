#==============================================================================
#    File: makefile
# Created: 09/27/2016, 20:58
#  Author: Bernie Roesler
#
#  Description: Build tests for crypto and queue functions
#==============================================================================

# Directories where source files are kept
SRCDIR  = ./
UTILDIR = ../util/
INCLDIR = ../../include/
SSLINCL = /usr/local/opt/openssl/include/

# Set the compiler options
CC = gcc-7
CFLAGS = -Wall -pedantic -std=c99 -funsigned-char

# Look for header files here
OPT = -I$(INCLDIR) -I$(SSLINCL) 

# Libraries
LDLIBS = -lcrypto -lssl 

# Headers
INCL = $(wildcard $(INCLDIR)*.h)

# Define source files
SRC      = $(wildcard $(SRCDIR)*.c) $(wildcard $(UTILDIR)*.c)
UTIL     = crypto1.c $(UTILDIR)crypto_util.c
AES_UTIL = aes_ecb.c $(UTILDIR)aes_openssl.c

OBJ_UTIL = $(UTIL:%.c=%.o)
OBJ_AES  = $(AES_UTIL:%.c=%.o)

#------------------------------------------------------------------------------ 
#         Make options
#------------------------------------------------------------------------------
all: test1 breakRepeatingXOR findSingleByteXOR aes_ecb_file findECB types
test: test1
c4: findSingleByteXOR
c6: breakRepeatingXOR
c7: aes_ecb_file
c8: findECB

debug: CFLAGS += -DLOGSTATUS -ggdb3 -fno-inline
debug: all
verbose: CFLAGS += -DVERBOSE
verbose: debug

#------------------------------------------------------------------------------
# 		Compile and link steps 
#------------------------------------------------------------------------------
# Main executable:
test1: test_crypto1.o $(OBJ_AES) $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

findSingleByteXOR: findSingleByteXOR.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^

breakRepeatingXOR: breakRepeatingXOR.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^

aes_ecb_file: aes_ecb_file.o $(OBJ_AES) $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

findECB: findECB.o $(OBJ_AES) $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

.gitignore:
	@printf "test1\n\
	findSingleByteXOR\n\
	breakRepeatingXOR\n\
	aes_ecb_file\n\
	findECB\n" > $@

# Objects depend on source and headers
%.o: %.c $(INCL)
	$(CC) $(CFLAGS) $(OPT) -c $< -o $@

# Highlight custom types, unions, and structs!
types: .types.vim
.types.vim: $(SRC) $(INCL)
	ctags --c-kinds=gstu -o- ../../**/*.[ch] |\
		awk 'BEGIN{printf("syntax keyword Type\t")}\
			{printf("%s ", $$1)}END{print ""}' > $@

# clean up (do not do anything with file named clean)
.PHONY: depend clean
clean:
	rm -f *~
	rm -f $(SRCDIR)*.o
	rm -f $(SRCDIR)*.gch
	rm -rf $(SRCDIR)*.dSYM/
	rm -f $(UTILDIR)*.o
	rm -f $(UTILDIR)*.gch
	rm -rf $(UTILDIR)*.dSYM/
	rm -f test1
	rm -f findSingleByteXOR
	rm -f breakRepeatingXOR
	rm -f aes_ecb_file
	rm -f findECB
	rm -f .types.vim
	rm -f .gitignore

#==============================================================================
#==============================================================================
