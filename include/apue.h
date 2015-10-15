/*
	Our own header, to be included before all standard system headers.
*/

#ifndef _APUE_H_
#define _APUE_H_

#define _POSIX_C_SOURCE 200809L

#if defined(SOLARIS)   /*solaris 10*/
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 700
#endif

#include <sys/types.h>  /* some system still requires this */
#include <sys/stat.h>
#include <sys/termios.h>  /* for winsize */

#if defined(MACOS) || !defined(TIOCGWINSZ)
#include <sys/ioctl.h>
#endif

#include <stdio.h>     /* for convenience */
#include <stdlib.h>    /* for convenience */
#include <stddef.h>    /* for offsetof */
#include <string.h>    /* for convenience */
#include <unistd.h>    /* for convenience */
#include <signal.h>    /* for SIG_ERR*/

#define MAXLINE 4096   /* max line length */

/*
	Default file access permissions for new files.
*/
#define FILE_MODE (S_IRUSR |S_IWUSR |S_IRGRP |S_IROTH )

/*
	Define permissions for new directories.
*/
#define DIR_MODE (FILE_MODE |S_IXUSR |S_IXGRP |S_IXOTH )

typedef void    Sigfunc(int);    /* for signal handlers */

#define min(a,b)   ( (a) < (b) ? (a) : (b) )
#define max(a,b)   ( (a) > (b) ? (a) : (b) )

/*
	Prototypes for our own functions.
*/
char   *path_alloc(size_t *);            /* Figure 2.16  */
char   open_max(void);                   /* Figuer 2.17  */

char   set_cloexec(int);                 /* Figure 13.9  */
char   clr_fl(int, int);
char   ser_fl(int, int);                 /* Figure 3.12  */

char   pr_exit(int);                     /* Figure 8.5   */

char   pr_mask(const char *);            /* Figure 10.14 */
char   *signal_intr(int, Sigfunc*);      /* Figure 10.19 */






















#endif /*_APUE_H_*/

