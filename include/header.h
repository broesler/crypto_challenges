//==============================================================================
//    Filename: header.h
//
//    Description: Some utilites for the TinySearchEngine engine project
//    - MACROs for general memory allocation and initialization and some program
//    exceptions processing
//
//==============================================================================
// Note, the header check below makes sure you do not include a header file twice. Use it.

#ifndef _HEADER_H_
#define _HEADER_H_

#include <errno.h>
#include <memory.h>     // needed for memset()
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The max length of a terminal line
#define MAX_CHAR 81

// minimum number comparison
#define min(x,y)   ((x)>(y))?(y):(x)

// Print  s together with the source file name and the current line number.
#define LOG(s)  printf("\033[0;34m[%s @ %s:%d]\033[0m %s\n", __func__,  __FILE__, __LINE__, s)

// Print  s together with the source file name and the current line number.
#define ERROR(s) do { \
    fprintf(stderr,"\033[0;31mERROR: [%s:%d]\033[0m %s\n", \
            __FILE__, __LINE__, s); \
    exit(EXIT_FAILURE); \
} while(0)

#define WARNING(s) fprintf(stderr,"\033[0;33mWARNING: [%s:%d]\033[0m %s\n", __FILE__, __LINE__, s)

// malloc a new data structure t
#define NEW(t) malloc(sizeof(t))

// Check whether  s is NULL or not. Quit this program if it is NULL.
#define MY_ASSERT(s)  if (!(s))   { \
    fprintf(stderr,"[%s:line %d]: General assert error\n",  __FILE__, __LINE__);  \
    exit(EXIT_FAILURE); \
}

// Check whether s is NULL or not on a memory allocation. Quit this program if it is NULL.
#define MALLOC_CHECK(s)  if ((s) == NULL)   { \
    fprintf(stderr,"Not enough memory at %s: line%d ", __FILE__, __LINE__); \
    perror(":"); \
    exit(EXIT_FAILURE); \
}

// Set memory space starts at pointer \a n of size \a m to zero. 
// Usage: BZERO(buffer,sizeof(buffer));
#define BZERO(n,m)  memset(n, 0, m)

#endif
//==============================================================================
//==============================================================================
