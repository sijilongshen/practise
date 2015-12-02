#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include "elf.h"

/* Default # chars to show per line */
#define DEFWIDTH 32
/* Maximum # of bytes per line	*/
#define MAXWIDTH 32		

#define TRUE	1
#define FALSE	0

static long	linesize = DEFWIDTH;	/* # of bytes to print per line */
static bool	eflag = FALSE;		/* display ebcdic if true */
static bool	cflag = FALSE;		/* show printables as ASCII if true */
static bool	gflag = FALSE;		/* suppress mid-page gutter if true */
static long	start = 0L;		/* file offset to start dumping at */
static long	length = 0L;		/* if nz, how many chars to dump */

int StartOfSectionHeader_old = 0;
int StartOfProgramHeader_old = 0;
int SizeOfSectionHeader_old = 0;
int SizeOfProgramHeader_old = 0;
int CountOfSectionHeader_old = 0;
int CountOfProgramHeader_old = 0;
int StartOfSectionHeader_new = 0;
int StartOfProgramHeader_new = 0;
int SizeOfSectionHeader_new = 0;
int SizeOfProgramHeader_new = 0;
int CountOfSectionHeader_new = 0;
int CountOfProgramHeader_new = 0;
char* file_addr_old = NULL;          /*the address point to the memory of the old file*/
char* file_addr_new = NULL;          /*the address point to the memory of the new file*/
int str_tab_index_old = 0;
int str_tab_index_new = 0;
int str_tab_offset_old = 0;
int str_tab_offset_new = 0;

void dumpfile(FILE	*f)
/* dump a single, specified file -- stdin if filename is NULL */
{
    int     ch = '\0';		/* current character            */
    char    ascii[MAXWIDTH+3];	/* printable ascii data         */
    int     i = 0;		/* counter: # bytes processed	*/
    int     ai = 0;		/* index into ascii[]           */
    int     offset = 0;		/* byte offset of line in file  */
    int     hpos;		/* horizontal position counter  */
    long    fstart = start;
    long    flength = length;
    char    *specials = "\b\f\n\r\t";
    char    *escapes = "bfnrt";
    char    *cp;

    do {
	ch = getc(f);

	if (ch != EOF)
	{
	    if (start && fstart-- > 0)
		continue;

	    if (length && flength-- <= 0)
		ch = EOF;
	}

	if (ch != EOF)
	{
	    if (i++ % linesize == 0)
	    {
		(void) printf("%04x ", offset);
		offset += linesize;
		hpos = 5;
	    }

	    /* output one space for the mid-page gutter */
	    if (!gflag)
		if ((i - 1) % (linesize / 2) == 0)
		{
		    (void) putchar(' ');
		    hpos++;
		    ascii[ai++] = ' ';
		}

	    /* we're dumping ASCII */
		ascii[ai] = (isprint (ch) || ch == ' ') ? ch : '.';

		if (cflag && (isprint(ch) || ch == ' '))
		    (void) printf("%c  ", ch);
		else if (cflag && ch && (cp = strchr(specials, ch)))
		    (void) printf("\\%c ", escapes[cp - specials]);
		else
		    (void) printf("%02x ", ch);

	    /* update counters and things */
	    ai++;
	    hpos += 3;
	}

	/* At end-of-line or EOF, show ASCII or EBCDIC version of data. */
	if (i && (ch == EOF || (i % linesize == 0)))
	{
	    if (!cflag)
	    {
		while (hpos < linesize * 3 + 7)
		{
		    hpos++;
		    (void) putchar(' ');
		}

		ascii[ai] = '\0';
		(void) printf("%s", ascii);
	    }

	    if (ch != EOF || (i % linesize != 0))
		(void) putchar('\n');
	    ai = 0;		/* reset counters */
	}
    } while(ch != EOF);
}

void dumpstring(char *str, int len)
{
    int     ch = '\0';		/* current character            */
    char    ascii[MAXWIDTH+3];	/* printable ascii data         */
    int     i = 0;		/* counter: # bytes processed	*/
    int     ai = 0;		/* index into ascii[]           */
    int     offset = 0;		/* byte offset of line in file  */
    int     hpos;		/* horizontal position counter  */
    long    fstart = start;
    long    flength = length;
    char    *specials = "\b\f\n\r\t";
    char    *escapes = "bfnrt";
    char    *cp;
	int     index = 0;
	char*   temp_memory_old ;
	char*   temp_memory_new ;
	
	do{
		ch = str[index];
		if(ch < 0)
		{
			ch = ch*(-1);
		}
		if (i++ % linesize == 0)
		{
			//(void) printf("%04x ", offset);
			offset += linesize;
			hpos = 5;
		}
		if ((i - 1) % (linesize / 2) == 0)
		{
			(void) putchar(' ');
			hpos++;
			ascii[ai++] = ' ';
		}
		/* we're dumping ASCII */
		ascii[ai] = (isprint (ch) || ch == ' ') ? ch : '.';
		
		if (cflag && (isprint(ch) || ch == ' '))
		{
			(void) printf("%c  ", ch);
		}
		else if (cflag && ch && (cp = strchr(specials, ch))) 
		{
			(void) printf("\\%c ", escapes[cp - specials]);
		}
		else
		{
			//(void) printf("%02x ", ch);
		}
		ai++;
		hpos += 3;
		
		/* At end-of-line or EOF, show ASCII or EBCDIC version of data. */
		if (i && (ch == EOF || (i % linesize == 0)))
		{
			if (!cflag)
			{
				while (hpos < linesize * 3 + 7)
				{
					hpos++;
					(void) putchar(' ');
				}
				ascii[ai] = '\0';
				(void) printf("%s", ascii);
			}
			if (ch != EOF || (i % linesize != 0))
				//(void) putchar('\n');
			ai = 0;		// reset counters 
		}
		index ++;
	}while(index <= len);
	printf("\n");
}

int findElfHeader(char* fileadr,long filelen)
{
	char ch = '\0';
	char ch1 = '\127';
	char ch2 = '\69';
	char ch3 = '\76';
	char ch4 = '\70';
	long offset = 0;
	
	while(1)
	{
		ch = fileadr[offset];
		offset ++;
		printf("%c",ch);
		if( ch == ch1 )
		{
			if( fileadr[offset+1] == ch2 && fileadr[offset+1] == ch3 && fileadr[offset+1] == ch4 )
			{
				break;
			}
		}
		if(offset >= filelen)
		{
			offset = -1;
			break;
		}
	}
	
	return offset;
}

int main(int argc, char* argv[])
{
	int                    fd_old = 0;
	int                    fd_new = 0;
	struct stat            statbuff_old;
	struct stat            statbuff_new;
	char                   *file_addr_old;
	char                   *file_addr_new;
	long                   filesize_old = 0;
	long                   filesize_new = 0;
	long                   size = 0;
	long                   offset = 0;
	int                    res =0;
	
	if (argv[1] == NULL || argv[2] == NULL)
	{
		printf("Usage: ./getobj file_old  file_new:");
		res = -1;
		goto finish_ret;
	}
	fd_old = open(argv[1],O_RDWR);
	fd_new = open(argv[2],O_RDWR);
	if(stat(argv[1], &statbuff_old) < 0 || stat(argv[2], &statbuff_new) < 0)
	{
		printf("get file stat failed");
		res = -1;
		goto finish_ret; 
	}else{
		filesize_old = statbuff_old.st_size;
		filesize_new = statbuff_new.st_size;
	}
	file_addr_old = (char* )malloc(filesize_old);
	file_addr_new = (char* )malloc(filesize_new);
	//printf("filesize_old :  %d\nfilesize_new : %d\n",filesize_old,filesize_new);
	//printf("fileaddr_old :  %x\nfileaddr_new : %x\n",file_addr_old,file_addr_new);
	memset(file_addr_old, 0x00, filesize_old);
	memset(file_addr_new, 0x00, filesize_new);
	size = read(fd_old, file_addr_old, filesize_old);
	if(size < filesize_old)
	{
		printf("get file content failed\n");
		res = -1;
		goto finish_ret;
	}
	close(fd_old);fd_old = 0;	
	offset = findElfHeader(file_addr_old, size);
	if(offset == -1)
	{
		printf("get file offset failed\n");
		res = -1;
		goto finish_ret;
	}
	dumpstring(file_addr_old+ offset, 64);

	
finish_ret:
	return 0;
}
