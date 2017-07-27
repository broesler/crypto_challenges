#==============================================================================
#    File: makefile
# Created: 09/27/2016, 20:58
#  Author: Bernie Roesler
#
#  Description: Build tests for crypto and queue functions
#==============================================================================

# Directories where source files are kept
SRCDIR  = ./
UTILDIR = ./util/
INCLDIR = ../include/
SSLINCL = /usr/local/opt/openssl/include
DICTINCL = /Users/bernardroesler/Documents/School/cs50_software_design/labs/lab6/util/

# Set the compiler options
CC = gcc-7
CFLAGS = -Wall -pedantic -std=c99 -funsigned-char

# Define source files, utility files (function files)
SRC = test_crypto1.c breakRepeatingXOR.c  test_crypto2.c 
UTIL = crypto1.c crypto2.c aes_openssl.c $(UTILDIR)/crypto_util.c
# UTIL += $(UTILDIR)/dictionary.c $(UTILDIR)/hash.c

# Look for header files here
OPT = -I$(INCLDIR) -I$(SSLINCL) 
OPT += -I$(DICTINCL)

# Libraries
LDLIBS = -lcrypto -lssl 
LDLIBS += -L$(DICTINCL) -ldict

# Make options
all: test1 test2 breakRepeatingXOR types
break: breakRepeatingXOR
debug: DEBUG += -DLOGSTATUS -Og -ggdb3
debug: all
verbose: DEBUG = -DVERBOSE
verbose: debug

#------------------------------------------------------------------------------
# 		Compile and link steps 
#------------------------------------------------------------------------------
# Main executable:
test1: test_crypto1.c $(UTIL)
	$(CC) $(CFLAGS) $(DEBUG) $(OPT) -o $@ test_crypto1.c $(UTIL) $(LDLIBS)

test2: test_crypto2.c $(UTIL)
	$(CC) $(CFLAGS) $(DEBUG) $(OPT) -o $@ test_crypto2.c $(UTIL) $(LDLIBS)

# Secondary executables:
breakRepeatingXOR: breakRepeatingXOR.c $(UTIL)
	$(CC) $(CFLAGS) $(DEBUG) $(OPT) -o $@ breakRepeatingXOR.c $(UTIL) $(LDLIBS)

# Highlight custom types, unions, and structs!
types: types.vim
types.vim: $(SRC) $(UTIL) $(INCLDIR)/*.h
	ctags --c-kinds=gstu -o- ../**/*.[ch] |\
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
	rm -f test1 test2
	rm -f breakRepeatingXOR
	rm -f types.vim

#==============================================================================
#==============================================================================
