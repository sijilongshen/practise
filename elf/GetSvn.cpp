#include <elf.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>

#define ELF_FILE       "./hello"

/*
typedef struct
{
  unsigned char    e_ident[EI_NIDENT];    // Magic number and other info 
  Elf64_Half       e_type;                // Object file type 
  Elf64_Half       e_machine;             // Architecture 
  Elf64_Word       e_version;             // Object file version 
  Elf64_Addr       e_entry;               // Entry point virtual address 
  Elf64_Off        e_phoff;               // Program header table file offset 
  Elf64_Off        e_shoff;               // Section header table file offset 
  Elf64_Word       e_flags;               // Processor-specific flags 
  Elf64_Half       e_ehsize;              // ELF header size in bytes 
  Elf64_Half       e_phentsize;           // Program header table entry size 
  Elf64_Half       e_phnum;               // Program header table entry count 
  Elf64_Half       e_shentsize;           // Section header table entry size 
  Elf64_Half       e_shnum;               // Section header table entry count 
  Elf64_Half       e_shstrndx;            // Section header string table index 
} Elf64_Ehdr;

typedef struct
{
  Elf64_Word       sh_name;               // Section name (string tbl index) 
  Elf64_Word       sh_type;               // Section type 
  Elf64_Xword      sh_flags;              // Section flags 
  Elf64_Addr       sh_addr;               // Section virtual addr at execution 
  Elf64_Off        sh_offset;             // Section file offset 
  Elf64_Xword      sh_size;               // Section size in bytes 
  Elf64_Word       sh_link;               // Link to another section 
  Elf64_Word       sh_info;               // Additional section information 
  Elf64_Xword      sh_addralign;          // Section alignment 
  Elf64_Xword      sh_entsize;            // Entry size if section holds table 
} Elf64_Shdr;
*/

int main() 
{
    
	Elf64_Ehdr main_elf;
	Elf64_Shdr session_header;
	int i = 0;
	int index = 0;
	int fd = open(ELF_FILE,O_RDONLY);
	memset( &main_elf, 0, sizeof(Elf64_Ehdr) );
	memset( &session_header, 0, sizeof(Elf64_Shdr) );
	if(fd < 0)
	{
		perror("open main elferror");
	}
	if(read(fd,&main_elf,sizeof(main_elf))< 1)
	{
		perror("read main elf error");
	}

	printf("EFL Header:\n");
	printf("Magic:       ");
	for(; i < EI_NIDENT ;i++)
	{
		printf("%2X",main_elf.e_ident[i]);
	}
	printf("\n");
	printf("Class:                                             ");
	if(main_elf.e_ident[4] == ELFCLASS32)
	{
		printf("ELF32");
	}
	else if(main_elf.e_ident[4] == ELFCLASS64)
	{
		printf("ELF64");
	}
	printf("\n");
	printf("Type:                                              ");
	if(main_elf.e_type == ET_EXEC)
	{
		printf("EXEC (Executablefile)\n");
	}
	printf("Entry point address:                               0x%X\n",main_elf.e_entry);
	printf("Start of program headers:                          %d\n",main_elf.e_phoff);
	printf("Start of section headers:                          %u\n",main_elf.e_shoff);
	printf("Size of this header:                               %u\n",main_elf.e_ehsize);
	printf("Size of program headers:                           %u\n",main_elf.e_phentsize);
	printf("Number of programheaders:                          %u\n",main_elf.e_phnum);
	printf("Size of section headers:                           %u\n",main_elf.e_shentsize);
	printf("Number of sectionheaders:                          %u\n",main_elf.e_shnum);
	printf("Section header string tableindex:                  %u\n",main_elf.e_shstrndx);

	//while (index < main_elf.e_shnum)
	{
		lseek(fd, 0, SEEK_SET);
		lseek(fd, main_elf.e_phoff + main_elf.e_phnum * main_elf.e_phentsize + main_elf.e_shentsize, SEEK_SET);
		read(fd, &session_header, sizeof(Elf64_Shdr));
		printf("session name is %s\n", &session_header.sh_name);
		index ++;
	}

	close(fd);

	return 0;

}


