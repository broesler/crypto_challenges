/*==============================================================================
 *     File: ruby_test.c
 *  Created: 07/18/2017, 23:07
 *   Author: Bernie Roesler
 *
 *  Description: Test ruby environment in C for AES-128-ECB decryption
 *
 *============================================================================*/
#include <ruby.h>
#include <stdio.h>

/* int main(int argc, char* argv[]) */
int main(void)
{
	if (ruby_setup())
	{
		/* run code without Ruby */
        fprintf(stderr, "Ruby could not start :(\n");
        exit(EXIT_FAILURE);
	} 
    else 
    {
        /* TODO Make my ruby script into a function (class? method?) that
         * accepts a byte array to decrypt, and a key */
        int state;
        VALUE result;
        result = rb_eval_string_protect("puts 'Hello, world!'", &state);

		ruby_finalize(); /* XXX rescue exceptions here!!! */
	}

	return 0;
}


/*==============================================================================
 *============================================================================*/
