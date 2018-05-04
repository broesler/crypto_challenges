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
SANFLAGS = -fsanitize=address -fsanitize-recover=address -O1 -fno-omit-frame-pointer
SANFLAGS += -fsanitize-address-use-after-scope

# Look for header files here
OPT = -I$(INCLDIR) -I$(SSLINCL) -I$(DICTINCL)

# Libraries
LDLIBS = -lcrypto -lssl 
DLIBS = -L$(DICTINCL) -ldict

# Headers
INCL = $(wildcard $(INCLDIR)*.h)

# Define source files
SRC   = $(wildcard $(SRCDIR)*.c) $(wildcard $(UTILDIR)*.c)
UTIL  = ./crypto3.c ./cbc_padding_oracle.c 
UTIL += ../set2/crypto2.c ../set1/aes_ecb.c ../set1/crypto1.c
UTIL += $(UTILDIR)aes_openssl.c $(UTILDIR)crypto_util.c $(UTILDIR)fmemopen.c

# Object files
OBJ_UTIL = $(UTIL:%.c=%.o)

# Make options
all: test3 c17 c19 test_cbc_padding_oracle types
c17: cbc_padding_oracle_main
c19: break_CTR_subs

debug: CFLAGS += -DLOGSTATUS -ggdb3 -fno-inline
# debug: CFLAGS += $(SANFLAGS)
debug: all
verbose: CFLAGS += -DVERBOSE
verbose: debug

#------------------------------------------------------------------------------
# 		Compile and link steps 
#------------------------------------------------------------------------------
# Main tests: ignore cbc_padding_oracle files
test3: test_crypto3.o $(OBJ_UTIL:./cbc_padding_oracle.o=) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

test_cbc_padding_oracle: test_cbc_padding_oracle.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

cbc_padding_oracle_main: cbc_padding_oracle_main.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

break_CTR_subs: break_CTR_subs.o $(OBJ_UTIL:./cbc_padding_oracle.o=) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

.gitignore:
	@printf "cbc_padding_oracle_main\n\
	break_CTR_subs\n\
	test_cbc_padding_oracle\n\
	test3" > $@

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
	rm -f ../set2/*.o
	rm -f ../set2/*.gch
	rm -rf ../set2/*.dSYM/
	rm -f $(SRCDIR)*.o
	rm -f $(SRCDIR)*.gch
	rm -rf $(SRCDIR)*.dSYM/
	rm -f $(UTILDIR)*.o
	rm -f $(UTILDIR)*.gch
	rm -rf $(UTILDIR)*.dSYM/
	rm -f cbc_padding_oracle_main
	rm -f break_CTR_subs
	rm -f test_cbc_padding_oracle
	rm -f test3
	rm -f .gitignore
	# rm -f test3

#==============================================================================
#==============================================================================
