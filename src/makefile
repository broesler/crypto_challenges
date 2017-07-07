#==============================================================================
#    File: makefile
# Created: 09/27/2016, 20:58
#  Author: Bernie Roesler
#
#  Description: Build tests for crypto and queue functions
#==============================================================================

# Directories where source files are kept
SRCDIR = ./
UTILDIR = ./util/
INCLDIR = ../include/

# Set the compiler options
CC = gcc
CFLAGS = -Wall -pedantic -std=c99
# CFLAGS += -fPIC

# Look for header files here -- store all headers in ../include/
# OPT = -I$(SRCDIR) -I$(UTILDIR) -I$(INCLDIR)
OPT = -I$(INCLDIR)

# Define source files, utility files (function files)
SRC = test_crypto1.c crypto.c
UTIL = $(wildcard $(UTILDIR)*.c)

# Define object files
OBJ = $(SRC:%.c=%.o) $(UTIL:%.c=%.o) 

# Define header files
INCL = $(wildcard $(INCLDIR)*.h)

# Make options
all: test1
debug: DEBUG = -DLOGSTATUS -g -ggdb
debug: all

#------------------------------------------------------------------------------
# 	Compile and link steps 
#------------------------------------------------------------------------------
# Main executable:
test1: $(OBJ)
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
	rm -f $(UTILDIR)*.o
	rm -f $(UTILDIR)*.gch
	rm -rf $(UTILDIR)*.dSYM/
	rm -f test1

#==============================================================================
#==============================================================================
