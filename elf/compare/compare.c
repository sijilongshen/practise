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
/*
typedef struct
{
  unsigned char e_ident[EI_NIDENT];     // Magic number and other info  
  Elf64_Half    e_type;                 // Object file type  
  Elf64_Half    e_machine;              // Architecture  
  Elf64_Word    e_version;              // Object file version  
  Elf64_Addr    e_entry;                // Entry point virtual address  
  Elf64_Off     e_phoff;                // Program header table file offset  
  Elf64_Off     e_shoff;                // Section header table file offset  
  Elf64_Word    e_flags;                // Processor-specific flags  
  Elf64_Half    e_ehsize;               // ELF header size in bytes  
  Elf64_Half    e_phentsize;            // Program header table entry size  
  Elf64_Half    e_phnum;                // Program header table entry count  
  Elf64_Half    e_shentsize;            // Section header table entry size  
  Elf64_Half    e_shnum;                // Section header table entry count  
  Elf64_Half    e_shstrndx;             // Section header string table index  
} Elf64_Ehdr;

typedef struct
{
  Elf64_Word    sh_name;                // Section name (string tbl index) 
  Elf64_Word    sh_type;                // Section type 
  Elf64_Xword   sh_flags;               // Section flags 
  Elf64_Addr    sh_addr;                // Section virtual addr at execution 
  Elf64_Off     sh_offset;              // Section file offset 
  Elf64_Xword   sh_size;                // Section size in bytes 
  Elf64_Word    sh_link;                // Link to another section 
  Elf64_Word    sh_info;                // Additional section information 
  Elf64_Xword   sh_addralign;           // Section alignment 
  Elf64_Xword   sh_entsize;             // Entry size if section holds table 
} Elf64_Shdr;
*/

int main(int argc, char* argv[])
{
		Elf64_Ehdr             *elf_hard_addr_old;
		Elf64_Ehdr             *elf_hard_addr_new;
		int                    fd_old;
		int                    fd_new;
		Elf64_Shdr             *SectionHeader_old;
		Elf64_Shdr             *SectionHeader_new;
		Elf64_Phdr             *ProgramHeader_old;
		Elf64_Phdr             *ProgramHeader_new;
		unsigned long          filesize_old = -1;
		unsigned long          filesize_new = -1;
		struct stat            statbuff_old;
		struct stat            statbuff_new;
		long                   sec_header_size_old = 0;
		long                   sec_header_size_new = 0;
		char*                  temp_memory_old = NULL;
		char*                  temp_memory_new = NULL;
		long                   offset = 0;
		long                   index = 0;
		int                    res = 0;
		long                   size = 0;
		int                    same_flag = 1;
		int                    diff_count = 0;
		//long                   sum = 0;
		
		elf_hard_addr_old = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
		elf_hard_addr_new = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
		SectionHeader_old = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
		SectionHeader_new = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
		ProgramHeader_old = (Elf64_Phdr *)malloc(sizeof(Elf64_Phdr));
		ProgramHeader_new = (Elf64_Phdr *)malloc(sizeof(Elf64_Phdr));
		memset(elf_hard_addr_old, 0x00, sizeof(Elf64_Ehdr));
		memset(SectionHeader_old, 0x00, sizeof(Elf64_Shdr));
		memset(ProgramHeader_old, 0x00, sizeof(Elf64_Phdr));
		memset(elf_hard_addr_new, 0x00, sizeof(Elf64_Ehdr));
		memset(SectionHeader_new, 0x00, sizeof(Elf64_Shdr));
		memset(ProgramHeader_new, 0x00, sizeof(Elf64_Phdr));
		
/* 		printf("Elf64_Half: %d\n",sizeof(Elf64_Half));
		printf("Elf64_Word: %d\n",sizeof(Elf64_Word));
		printf("Elf64_Addr: %d\n",sizeof(Elf64_Addr));
		printf("Elf64_Off: %d\n",sizeof(Elf64_Off)); 
*/
		if (argv[1] == NULL || argv[2] == NULL)
		{
			printf("Usage: ./compare file_old  file_new:");
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
		printf("filesize_old :  %d\nfilesize_new : %d\n",filesize_old,filesize_new);
		printf("fileaddr_old :  %x\nfileaddr_new : %x\n",file_addr_old,file_addr_new);
		memset(file_addr_old, 0x00, filesize_old);
		memset(file_addr_new, 0x00, filesize_new);
		size = read(fd_old, file_addr_old, filesize_old);
		if(size < filesize_old)
		{
			printf("get file content failed");
			res = -1;
			goto finish_ret;
		}
        close(fd_old);fd_old = 0;
		size = read(fd_new, file_addr_new, filesize_new);
		if(size < filesize_new)
		{
			printf("get file content failed");
			res = -1;
			goto finish_ret;
		}
        close(fd_new);fd_new = 0;
		
		memcpy(elf_hard_addr_old, file_addr_old, sizeof(Elf64_Ehdr));
		memcpy(elf_hard_addr_new, file_addr_new, sizeof(Elf64_Ehdr));
		
		//dumpstring((char*)elf_hard_addr, sizeof(Elf64_Ehdr));
		
		if(elf_hard_addr_old->e_shnum != elf_hard_addr_new->e_shnum)
		{
			printf("section number is different\n");
			printf("file   %16s and %16s   is   differ \n",argv[1],argv[2]);
			res = -1;
			goto finish_ret;
		}
		if(elf_hard_addr_old->e_phnum != elf_hard_addr_new->e_phnum)
		{
			printf("program number is different\n");
			printf("file   %16s and %16s   is   differ \n",argv[1],argv[2]);
			res = -1;
			goto finish_ret;
		}
		if(elf_hard_addr_old->e_shnum != elf_hard_addr_new->e_shnum)
		{
			printf("section number is different\n");
			printf("file   %16s and %16s   is   differ \n",argv[1],argv[2]);
			res = -1;
			goto finish_ret;
		}
		if(elf_hard_addr_old->e_shentsize != elf_hard_addr_new->e_shentsize)
		{
			printf("size of section header is different\n");
			printf("file   %16s and %16s   is   differ \n",argv[1],argv[2]);
			res = -1;
			goto finish_ret;
		}
		if(elf_hard_addr_old->e_phentsize != elf_hard_addr_new->e_phentsize)
		{
			printf("size of program header is different\n");
			printf("file   %16s and %16s   is   differ \n",argv[1],argv[2]);
			res = -1;
			goto finish_ret;
		}
		/*e_entry   program entry */
		printf("Entry point address: %x\n",elf_hard_addr_old->e_entry);
		/*e_phoff: program header table address*/
		printf("Start of program headers: %d\n",elf_hard_addr_old->e_phoff);
		/*e_shoff: section header table address */
		printf("Start of section headers: %d\n",elf_hard_addr_old->e_shoff);
		/*e_ehsize: size of ELF header */
		printf("Size of this header: %d\n",elf_hard_addr_old->e_ehsize);
		/*e_phentsize: size of each item in program header table */
		printf("Size of program headers: %d\n",elf_hard_addr_old->e_phentsize);
		/*e_phnum: number of items in program header table */
		printf("Number of program headers: %d\n",elf_hard_addr_old->e_phnum);
		/*e_shentsize: size of each item in section header table  */
		printf("Size of section headers: %d\n",elf_hard_addr_old->e_shentsize);
		/*e_shnum: number of items in program header table */
		printf("Number of section headers: %d\n",elf_hard_addr_old->e_shnum);
		/*the index of section header table and name header table*/
		printf("Section header string table index: %d\n",elf_hard_addr_old->e_shstrndx);
		
		StartOfSectionHeader_old = elf_hard_addr_old->e_shoff;
		StartOfProgramHeader_old = elf_hard_addr_old->e_phoff;
		SizeOfSectionHeader_old = elf_hard_addr_old->e_shentsize;
		SizeOfProgramHeader_old = elf_hard_addr_old->e_phentsize;
		CountOfSectionHeader_old = elf_hard_addr_old->e_shnum;
		CountOfProgramHeader_old = elf_hard_addr_old->e_phnum;
		
		StartOfSectionHeader_new = elf_hard_addr_new->e_shoff;
		StartOfProgramHeader_new = elf_hard_addr_new->e_phoff;
		SizeOfSectionHeader_new = elf_hard_addr_new->e_shentsize;
		SizeOfProgramHeader_new = elf_hard_addr_new->e_phentsize;
		CountOfSectionHeader_new = elf_hard_addr_new->e_shnum;
		CountOfProgramHeader_new = elf_hard_addr_new->e_phnum;
		
		index = 0;
		
		while(index <= CountOfSectionHeader_old)
		{
			memset(SectionHeader_old, 0x00, sizeof(Elf64_Shdr));
			memcpy(SectionHeader_old, file_addr_old+StartOfSectionHeader_old+index*SizeOfSectionHeader_old, SizeOfSectionHeader_old);
			if (SectionHeader_old->sh_type == 3)
			{
				memset(SectionHeader_old, 0x00, sizeof(Elf64_Shdr));
				memcpy(SectionHeader_old, file_addr_old+StartOfSectionHeader_old+(index+1)*SizeOfSectionHeader_old, SizeOfSectionHeader_old);
				if(SectionHeader_old->sh_type == 2)
				{
					memset(SectionHeader_old, 0x00, sizeof(Elf64_Shdr));
					memcpy(SectionHeader_old, file_addr_old+StartOfSectionHeader_old+index*SizeOfSectionHeader_old, SizeOfSectionHeader_old);
					str_tab_index_old = index;
					str_tab_offset_old = SectionHeader_old->sh_offset;
					//printf(" str_tab_index_old = %d\n",str_tab_index_old);
					break;
				}
			}
			index ++;
		}		
		index = 0;
		while(index <= CountOfSectionHeader_new)
		{
			memset(SectionHeader_new, 0x00, sizeof(Elf64_Shdr));
			memcpy(SectionHeader_new, file_addr_old+StartOfSectionHeader_new+index*SizeOfSectionHeader_new, SizeOfSectionHeader_new);
			if (SectionHeader_new->sh_type == 3)
			{
				memset(SectionHeader_new, 0x00, sizeof(Elf64_Shdr));
				memcpy(SectionHeader_new, file_addr_old+StartOfSectionHeader_new+(index+1)*SizeOfSectionHeader_new, SizeOfSectionHeader_new);
				if(SectionHeader_new->sh_type == 2)
				{
					memset(SectionHeader_new, 0x00, sizeof(Elf64_Shdr));
					memcpy(SectionHeader_new, file_addr_old+StartOfSectionHeader_new+index*SizeOfSectionHeader_new, SizeOfSectionHeader_new);
					str_tab_index_new = index;
					str_tab_offset_new = SectionHeader_new->sh_offset;
					//printf(" str_tab_index_new = %d\n",str_tab_index_new);
					break;
				}
			}
			index ++;
		}
		index = 0;
		temp_memory_old = (char*)malloc(64);
		temp_memory_new = (char*)malloc(64);
		while(index < CountOfSectionHeader_old && index < CountOfSectionHeader_new)
		{
			offset = 0;
			diff_count = 0;
			memset(SectionHeader_old, 0x00, sizeof(Elf64_Shdr));
			memset(SectionHeader_new, 0x00, sizeof(Elf64_Shdr));
			memcpy(SectionHeader_old, file_addr_old+StartOfSectionHeader_old+index*SizeOfSectionHeader_old, SizeOfSectionHeader_old);
			memcpy(SectionHeader_new, file_addr_new+StartOfSectionHeader_new+index*SizeOfSectionHeader_new, SizeOfSectionHeader_new);
			sec_header_size_old = SectionHeader_old->sh_size;
			sec_header_size_new = SectionHeader_new->sh_size;
			/*  .bss 段存放未初始化的全局变量，运行时由系统初始化为0，其长度应为0  */
			/*  SHT_NOBITS  表示此节的内容为空，节并不占用实际的空间， 节.bss就是此类型  */
			if( SectionHeader_old->sh_type == 8 || SectionHeader_old->sh_type == 8 || SectionHeader_old->sh_type == 0 || SectionHeader_old->sh_type == 0)
			{
				index ++;
				continue;
			}
			while(sec_header_size_old >0 && sec_header_size_new >0)
			{
				memset(temp_memory_old, 0x00, 64);
				memset(temp_memory_new, 0x00, 64);
				memcpy(temp_memory_old, file_addr_old +SectionHeader_old->sh_offset+offset, 64);
				memcpy(temp_memory_new, file_addr_new +SectionHeader_new->sh_offset+offset, 64);
				if( memcmp(temp_memory_old, temp_memory_new, 64) )
				{
					printf("differ section name: %s\n",file_addr_old + str_tab_offset_old + SectionHeader_old->sh_name);
					dumpstring(file_addr_old+SectionHeader_old->sh_offset+offset,64);
					dumpstring(file_addr_new+SectionHeader_new->sh_offset+offset,64);
					//printf("-------------------------------------------------------------------\n");
					same_flag = 0;
					diff_count ++;
					if(diff_count >= 6)
					{
						index ++;
						break;
					}
					//break;
				}
				sec_header_size_old -= 64;
				sec_header_size_new -= 64;
				offset += 64;
			}
			if(diff_count >= 6)
			{
				break;
			}
			index ++;
		}
		if(same_flag == 0)
		{
			printf("file   %16s and %16s   is   differ \n",argv[1],argv[2]);
		}
		else
		{
			printf("file   %16s and %16s   is  the same \n",argv[1],argv[2]);
		}
		
finish_ret:
		if(elf_hard_addr_old != NULL)
		{
			free(elf_hard_addr_old);
			elf_hard_addr_old = NULL;
		}
		if(elf_hard_addr_new != NULL)
		{
			free(elf_hard_addr_new);
			elf_hard_addr_new = NULL;
		}
		if(SectionHeader_old != NULL)
		{
			free(SectionHeader_old);
			SectionHeader_old = NULL;
		}
		if(SectionHeader_new != NULL)
		{
			free(SectionHeader_new);
			SectionHeader_new = NULL;
		}
		if(ProgramHeader_old != NULL)
		{
			free(ProgramHeader_old);
			ProgramHeader_old = NULL;
		}
		if(ProgramHeader_new != NULL)
		{
			free(ProgramHeader_new);
			ProgramHeader_new = NULL;
		}
		if(file_addr_old != NULL)
		{
			free(file_addr_old);
			file_addr_old = NULL;
		}
		if(file_addr_new != NULL)
		{
			free(file_addr_new);
			file_addr_new = NULL;
		}
		if(temp_memory_old != NULL)
		{
			free(temp_memory_old);
			temp_memory_old = NULL;
		}
		if(temp_memory_new != NULL)
		{
			free(temp_memory_new);
			temp_memory_new = NULL;
		}
		if(fd_old != 0)
			close(fd_old);
		if(fd_new != 0)
			close(fd_new);
        return res;
}
