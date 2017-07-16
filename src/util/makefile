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

# Set the compiler options
CC = gcc
CFLAGS = -Wall -pedantic -std=c99
CFLAGS += -funsigned-char

# Look for header files here -- store all headers in ../include/
OPT = -I$(INCLDIR)

# Define source files, utility files (function files)
SRC = test_util.c crypto_util.c

# Define object files
OBJ = $(SRC:%.c=%.o)

# Define header files
INCL = $(wildcard $(INCLDIR)*.h)

# Make options
all: test_util
debug: DEBUG = -DLOGSTATUS -g -ggdb
debug: all

#------------------------------------------------------------------------------
# 	Compile and link steps 
#------------------------------------------------------------------------------
# Main executable:
test_util: $(OBJ)
	$(CC) $(CFLAGS) $(DEBUG) $(OPT) -o $@ $(OBJ)

# object rules
%.o: %.c $(INCL)
	$(CC) $(CFLAGS) $(DEBUG) $(OPT) -c $< -o $@

# clean up (do not do anything with file named clean)
.PHONY: depend clean
clean:
	rm -f *~
	rm -f $(SRCDIR)*.o
	rm -f $(SRCDIR)*.gch
	rm -rf $(SRCDIR)*.dSYM/
	rm -f test_util

#==============================================================================
#==============================================================================
