/*==============================================================================
 *     File: gdb_macros.c
 *  Created: 05/03/2018, 19:55
 *   Author: Bernie Roesler
 *
 *  Description: 
 *
 *============================================================================*/

#include <stdio.h>
#include "gdb_macros.h"

#define M 42
#define ADD(x) (M + x)

main ()
{
#define N 28
  printf ("Hello, world!\n");
#undef N
  printf ("We're so creative.\n");
#define N 1729
  printf ("Goodbye, world!\n");
}

/*==============================================================================
 *============================================================================*/
