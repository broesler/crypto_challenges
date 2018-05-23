/*==============================================================================
 *     File: dup2-a.c
 *  Created: 05/22/2018, 23:16
 *   Author: Bernie Roesler
 *
 *  Description: output redirection with dup2(), Super-simple example
 *  Original Author: Paul Krzyzanowski
 *      <https://www.cs.rutgers.edu/~pxk/416/notes/c-tutorials/dup2.html>
 *
 *============================================================================*/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    int newfd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s output_file\n", argv[0]);
		exit(1);
	}
	if ((newfd = open(argv[1], O_CREAT|O_TRUNC|O_WRONLY, 0644)) < 0) {
		perror(argv[1]);	/* open failed */
		exit(1);
	}

#if 0
    /* These lines also get the job done, but with another function call. */
	FILE *fp;	/* new file descriptor */
    if (!(fp = fopen(argv[1], "w"))) {
        perror(argv[1]); /* open failed */
        exit(1);
    }
    newfd = fileno(fp);
#endif

	printf("This goes to the standard output.\n");
	printf("Now the standard output will go to \"%s\", at fd = %d.\n",
            argv[1], newfd);

    /* NOTE without this flush,
     *      $ ./dup2-a abc.txt > def.txt
     * will send ALL output to abc.txt, because it gets buffered. */
    fflush(stdout);

	/* this new file will become the standard output */
	/* standard output is file descriptor 1, so we use dup2 to */
	/* to copy the new file descriptor onto file descriptor 1 */
	/* dup2 will close the current standard output */

	dup2(newfd, 1); 

	printf("This goes to the standard output too.\n");

    /* fclose(fp); */
	exit(0);
}


/*==============================================================================
 *============================================================================*/
