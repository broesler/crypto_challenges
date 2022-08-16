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
CC = gcc-8
CFLAGS = -Wall -pedantic -std=c99 -funsigned-char

# Look for header files here
OPT = -I$(INCLDIR) -I$(SSLINCL) 

# Libraries
LDLIBS = -lcrypto -lssl 

# Headers
INCL = $(wildcard $(INCLDIR)*.h)

TARGETS = find_single_byte_xor break_repeating_xor aes_ecb_file find_ecb

# Define source files
SRC      = $(wildcard $(SRCDIR)*.c) $(wildcard $(UTILDIR)*.c)
UTIL     = crypto1.c $(wildcard $(UTILDIR)util_*.c)
AES_UTIL = aes_ecb.c $(UTILDIR)aes_openssl.c

OBJ_UTIL = $(UTIL:%.c=%.o)
OBJ_AES  = $(AES_UTIL:%.c=%.o)

#------------------------------------------------------------------------------ 
#         Make options
#------------------------------------------------------------------------------
all: test1 $(TARGETS) types
test: test1

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

$(TARGETS): % : %.o $(OBJ_UTIL) $(OBJ_AES) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

.gitignore:
	@printf "test1\n$(shell echo "$(TARGETS)" | sed -e 's/ /\\n/g')" > $@

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
	rm -f test1 $(TARGETS)
	rm -f .gitignore
	rm -f .types.vim

#==============================================================================
#==============================================================================
