#==============================================================================
#    File: src/util/makefile
# Created: 09/27/2016, 20:58
#  Author: Bernie Roesler
#
#  Description: Build tests for crypto and queue functions
#==============================================================================

# Directories where source files are kept
SRCDIR = ./
INCLDIR = ../../include/
SSLINCL = /usr/local/opt/openssl/include

# Set the compiler options
CC = gcc-7
CFLAGS = -Wall -pedantic -std=c99 -funsigned-char

# Look for header files here -- store all headers in ../include/
OPT = -I$(INCLDIR) -I$(SSLINCL) 

# Define source files, utility files (function files)
SRC = test_util.c crypto_util.c aes_openssl.c 

# Define object files
OBJ = $(SRC:%.c=%.o)

# Define header files
INCL = $(wildcard $(INCLDIR)*.h)

# Libraries
LDLIBS = -lcrypto -lssl 

# Make options
all: test_util types
debug: DEBUG = -DLOGSTATUS -Og -ggdb3
debug: all

#------------------------------------------------------------------------------
# 	Compile and link steps 
#------------------------------------------------------------------------------
# Main executable:
test_util: $(OBJ) | .gitignore
	$(CC) $(CFLAGS) $(DEBUG) $(OPT) -o $@ $^ $(LDLIBS)

# object rules
%.o: %.c $(INCL)
	$(CC) $(CFLAGS) $(DEBUG) $(OPT) -c $< -o $@

.gitignore:
	@printf test_util > $@

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
	rm -f $(SRCDIR)*.o
	rm -f $(SRCDIR)*.gch
	rm -rf $(SRCDIR)*.dSYM/
	rm -f test_util
	rm -f .gitignore

#==============================================================================
#==============================================================================
