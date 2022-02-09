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
SSLPATH  = /usr/local/opt/openssl@3/
DICTINCL = /Users/bernardroesler/Documents/School/cs50_software_design/labs/lab6/util/

# Set the compiler options
CC = /usr/local/opt/llvm/bin/clang
CFLAGS = -Wall -pedantic -std=c99 -funsigned-char 
CFLAGS += -Wno-nullability-completeness -Wno-nullability-extension 
CFLAGS += -Wno-availability -Wno-expansion-to-defined
SANFLAGS = -fsanitize=address -O1 -fno-omit-frame-pointer
CFLAGS += $(SANFLAGS)
DEBUGFLAGS = -DLOGSTATUS -ggdb3 -fno-inline

# Look for header files here
OPT = -I$(INCLDIR) -I$(SSLPATH)/include -I$(DICTINCL)

# Libraries
LDLIBS = -L$(SSLPATH)/lib -lcrypto -lssl 
DLIBS = -L$(DICTINCL) -ldict

# Headers
INCL = $(wildcard $(INCLDIR)*.h)

# Define source files
SRC   = $(wildcard $(SRCDIR)*.c) $(wildcard $(UTILDIR)*.c)
UTIL  = ./crypto3.c ./cbc_padding_oracle.c 
UTIL += ../set2/crypto2.c ../set1/aes_ecb.c ../set1/crypto1.c
UTIL += $(UTILDIR)aes_openssl.c $(wildcard $(UTILDIR)util_*.c) 
UTIL += $(UTILDIR)fmemopen.c

# Object files
OBJ_UTIL = $(UTIL:%.c=%.o)

TARGETS = test_cbc_padding_oracle cbc_padding_oracle_main 

# Make options
all: test3 $(TARGETS) break_ctr_subs create_rng_seed types
test: test3

debug: CFLAGS += $(DEBUGFLAGS)
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

$(TARGETS): % : %.o $(OBJ_UTIL) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

break_ctr_subs: break_ctr_subs.o $(OBJ_UTIL:./cbc_padding_oracle.o=) | .gitignore
	$(CC) $(CFLAGS) $(OPT) -o $@ $^ $(LDLIBS)

break_ctr_subs.o: break_ctr_subs.c $(INCL)
	$(CC) $(CFLAGS) $(OPT) -c $< -o $@

create_rng_seed: create_rng_seed.o $(UTILDIR)util_twister.o | .gitignore
	$(CC) $(CFLAGS) -o $@ $^

create_rng_seed.o: create_rng_seed.c $(INCLDIR)header.h $(INCLDIR)util_twister.h
	$(CC) $(CFLAGS) -I$(INCLDIR) -c $< -o $@

crack_rng_seed: crack_rng_seed.o $(UTILDIR)util_twister.o | .gitignore
	$(CC) $(CFLAGS) -o $@ $^

crack_rng_seed.o: crack_rng_seed.c $(INCLDIR)header.h $(INCLDIR)util_twister.h
	$(CC) $(CFLAGS) -I$(INCLDIR) -c $< -o $@

# Objects depend on source and headers
%.o: %.c $(INCL)
	$(CC) $(CFLAGS) $(OPT) -c $< -o $@

# Highlight custom types, unions, and structs!
types: .types.vim
.types.vim: $(SRC) $(UTIL) $(INCLDIR)/*.h
	ctags --c-kinds=gstu -o- ../../**/*.[ch] |\
		awk 'BEGIN{printf("syntax keyword Type\t")}\
			{printf("%s ", $$1)}END{print ""}' > $@

# Ignore executables
.gitignore:
	@printf "break_ctr_subs\n\
	create_rng_seed\n\
	crack_rng_seed\n\
	$(shell echo "$(TARGETS)" | sed -e 's/ /\\n/g')\n\
	test3" > $@

# clean up (do not do anything with file named clean)
.PHONY: depend clean
clean:
	rm -f *~
	rm -f $(SRCDIR)*.o
	rm -f $(SRCDIR)*.gch
	rm -rf $(SRCDIR)*.dSYM/
	rm -f test3 $(TARGETS)
	rm -f break_ctr_subs create_rng_seed crack_rng_seed
	rm -f .gitignore

#==============================================================================
#==============================================================================
