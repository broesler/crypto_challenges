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

# Define source files
SRC  = $(wildcard test_*.c)
UTIL = $(wildcard util_*.c) aes_openssl.c fmemopen.c

# Define object files
OBJ = $(UTIL:.c=.o)

# Target executables for each test
TARGETS = $(SRC:.c=)

# Define header files
INCL = $(wildcard $(INCLDIR)*.h)

# Libraries
LDLIBS = -lcrypto -lssl 

# Make options
all: $(TARGETS) types
debug: DEBUG = -DLOGSTATUS -Og -ggdb3 -fno-inline
debug: all

#------------------------------------------------------------------------------
# 		Compile and link steps 
#------------------------------------------------------------------------------
# Make all targets
$(TARGETS): % : %.o $(OBJ) | .gitignore
	$(CC) $(CFLAGS) $(DEBUG) $(OPT) -o $@ $^ $(LDLIBS)

# object rules
%.o: %.c $(INCL)
	$(CC) $(CFLAGS) $(DEBUG) $(OPT) -o $@ -c $< 

# $(file >$@) $(foreach T,$(TARGETS),$(file >>$@,$T))
.gitignore:
	@printf "$(shell echo "$(TARGETS)" | sed -e 's/ /\\n/g')" > $@

# Highlight custom types, unions, and structs!
types: .types.vim
.types.vim: $(SRC) $(UTIL) $(INCLDIR)/*.h
	ctags --c-kinds=gstu -o- ../../**/*.[ch] |\
		awk 'BEGIN{printf("syntax keyword Type\t")}\
			{printf("%s ", $$1)}END{print ""}' > $@

# clean up
.PHONY: clean
clean:
	rm -f *~
	rm -f $(OBJ) $(SRC:.c=.o)
	rm -f $(SRCDIR)*.gch
	rm -rf $(SRCDIR)*.dSYM/
	rm -f $(TARGETS)
	rm -f .gitignore
	rm -f .types.vim

#==============================================================================
#==============================================================================
