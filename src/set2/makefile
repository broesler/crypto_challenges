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
SSLPATH = /usr/local/opt/openssl@1.1/
DICTINCL = /Users/bernardroesler/Documents/Courses/cs50_software_design/labs/lab6/util/

# Set the compiler options
CC = gcc-11
CFLAGS = -Wall -pedantic -std=c99 -funsigned-char
SANFLAGS = -fsanitize=address -O1 -fno-omit-frame-pointer

# Look for header files here
OPT = -I$(INCLDIR) -I$(SSLPATH)/include -I$(DICTINCL)

# Libraries
LDLIBS = -L$(SSLPATH)/lib -lcrypto -lssl 
DLIBS = -L$(DICTINCL) -ldict

# NOTE: to build dictionary:
# 	cd ~/Documents/School/cs50_software_design/labs/lab6/util
# 	make dlib

# Headers
INCL = $(wildcard $(INCLDIR)*.h)

# Define source files
SRC   = $(wildcard $(SRCDIR)*.c) $(wildcard $(UTILDIR)*.c)
UTIL  = crypto2.c ../set1/aes_ecb.c ../set1/crypto1.c 
UTIL += $(UTILDIR)aes_openssl.c $(wildcard $(UTILDIR)util_*.c)

# Object files
OBJ_UTIL = $(UTIL:%.c=%.o)

# Individual challenges
TARGETS  = aes_cbc_file detect_block_mode make_admin_profile 
TARGETS += one_byte_ecb cbc_bit_flip

# Make options
all: $(TARGETS) test types
test: test2

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

$(TARGETS): % : %.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS) $(DLIBS)

.gitignore:
	@printf "test2\n$(shell echo "$(TARGETS)" | sed -e 's/ /\\n/g')" > $@

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
	rm -f $(SRCDIR)*.o
	rm -f $(SRCDIR)*.gch
	rm -rf $(SRCDIR)*.dSYM/
	rm -f test2 $(TARGETS)
	rm -f .gitignore
	rm -f .types.vim

#==============================================================================
#==============================================================================
