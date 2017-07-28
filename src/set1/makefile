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

# Define source files, utility files (function files)
UTIL     = crypto1.c $(UTILDIR)crypto_util.c
AES_UTIL = aes_ecb.c $(UTILDIR)aes_openssl.c

SRC_TEST = test_crypto1.c $(AES_UTIL) $(UTIL)
SRC_c4   = findSingleByteXOR.c $(UTIL)
SRC_c6   = breakRepeatingXOR.c $(UTIL)
SRC_c7   = aes_ecb_file.c $(AES_UTIL) $(UTIL)
SRC_c8   = findECB.c $(AES_UTIL) $(UTIL)

OBJ_TEST = $(SRC_TEST:%.c=%.o)
OBJ_c4   = $(SRC_c4:%.c=%.o)
OBJ_c6   = $(SRC_c6:%.c=%.o)
OBJ_c7   = $(SRC_c7:%.c=%.o)
OBJ_c8   = $(SRC_c8:%.c=%.o)

#------------------------------------------------------------------------------ 
#         Make options
#------------------------------------------------------------------------------
all: test1 breakRepeatingXOR findSingleByteXOR types
test: test1
c4: findSingleByteXOR
c6: breakRepeatingXOR
c7: aes_ecb_file
c8: findECB
debug: CFLAGS += -DLOGSTATUS -ggdb3
debug: all
verbose: CFLAGS += -DVERBOSE
verbose: debug

#------------------------------------------------------------------------------
# 		Compile and link steps 
#------------------------------------------------------------------------------
# Main executable:
test1: $(OBJ_TEST)
	$(CC) $(CFLAGS) $(OPT) -o $@ $(OBJ_TEST) $(LDLIBS)

findSingleByteXOR: $(OBJ_c4)
	$(CC) $(CFLAGS) $(OPT) -o $@ $(OBJ_c4) 

breakRepeatingXOR: $(OBJ_c6)
	$(CC) $(CFLAGS) $(OPT) -o $@ $(OBJ_c6)

aes_ecb_file: $(OBJ_c7)
	$(CC) $(CFLAGS) $(OPT) -o $@ $(OBJ_c7) $(LDLIBS)

findECB: $(OBJ_c8)
	$(CC) $(CFLAGS) $(OPT) -o $@ $(OBJ_c8) $(LDLIBS)

# Objects depend on source and headers
%.o: %.c $(INCL)
	$(CC) $(CFLAGS) $(OPT) -c $< -o $@

# Highlight custom types, unions, and structs!
types: .types.vim
.types.vim: $(SRC_TEST) $(SRC_c4) $(SRC_c6) $(SRC_c7) $(INCL)
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
	rm -f .types.vim

#==============================================================================
#==============================================================================
