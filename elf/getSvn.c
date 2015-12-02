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

int main() 
{
	Elf32_Ehdr main_elf;
	memset(&main_elf,0,sizeof(Elf32_Ehdr));
	int fd = open(ELF_FILE,O_RDONLY);
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
	int i = 0;
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
	printf("Start of section headers:                            %u\n",main_elf.e_shoff);
	printf("Size of this header:                                 %u\n",main_elf.e_ehsize);
	printf("Size of program headers:                             %u\n",main_elf.e_phentsize);
	printf("Number of programheaders:                         %u\n",main_elf.e_phnum);
	printf("Size of section headers:                              %u\n",main_elf.e_shentsize);
	printf("Number of sectionheaders:                           %u\n",main_elf.e_shnum);
	printf("Section header string tableindex:                 %u\n",main_elf.e_shstrndx);
	close(fd);

	return 0;

}


