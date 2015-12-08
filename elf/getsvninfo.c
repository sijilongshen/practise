#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>

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

int findKeyStrIndex(const char* strAddr, const char* key);

int main(int argc, char* argv[]) 
{
	int ret = 0;
	int fd ;
	int session_header_offset = 0;
	int session_count = 0;
	int session_size = 0;
	int session_header_size = 0;
	char*   rodataAddr = NULL;
	char*   printAddr = NULL;
	char* tmpstr = NULL;
	int tmpstrlen;
	int i = 0;
	int index = 0;
	int sess_index = 0;
	char ch = ' ';
	int startIndex = 0;
	int findflag = 0;
	char *ELF_FILE = NULL;
	char tmp[60];
	
	char svnnum[6];
	int svn = 0;
	char version[8];
	char buildtime[20];

	Elf64_Ehdr main_elf;
	Elf64_Shdr   elf_session_header;
	
	if( argc != 2 )
	{
		printf("error: lack of argv\n");
		printf("Usage: %s funcname\n", argv[0]);
		exit(1);
	}else
	{
		ELF_FILE = argv[1];
	}
	
	bzero(svnnum, 6);
	bzero(version, 8);
	bzero(buildtime, 20);
	bzero(tmp, 60);
	memset(&main_elf,0,sizeof(Elf64_Ehdr));
	memset(&elf_session_header,0,sizeof(Elf64_Shdr));
	
	fd = open(ELF_FILE,O_RDONLY);
	if(fd < 0)
	{
		perror("open main elferror");
	}
	if(read(fd,&main_elf,sizeof(main_elf))< 1)
	{
		perror("read main elf error");
	}

/*	printf("EFL Header:\n");
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
*/

	session_header_offset = main_elf.e_shoff;
	session_count = main_elf.e_shnum;
	session_header_size = main_elf.e_shentsize;
	
	/*遍历所有的 session 头查找到 .rodata 节*/
	for( sess_index = 0;sess_index < session_count;sess_index ++ )
	{
		session_size = 0;
		lseek(fd, 0, SEEK_SET);
		lseek(fd, session_header_offset + sess_index*session_header_size, SEEK_SET);
		read(fd, &elf_session_header, sizeof(Elf64_Shdr) );
		session_size = elf_session_header.sh_size;
		/*找到了.rodata节 则将此节的内容保存下来 不一定只有一个.rodata节*/
		if ( elf_session_header.sh_type == SHT_PROGBITS )
		{
			if(session_size > 0)
			{
				rodataAddr = (char*)malloc(session_size);
				if( rodataAddr == NULL)
				{
					printf("error: malloc rodataAddr error\n");
					exit(1);
				}
				bzero(rodataAddr, session_size);
				
				printAddr = (char*)malloc(session_size + 1);
				if( printAddr == NULL)
				{
					printf("error: malloc printAddr error\n");
					exit(1);
				}
				bzero(printAddr, session_size + 1);
				
				lseek(fd, 0, SEEK_SET);
				lseek(fd, elf_session_header.sh_offset, SEEK_SET);
				ret = read(fd, rodataAddr, session_size);
				if(ret == -1)
				{
					printf("cannot read elf_session_header.sh_size from fd\n");
				}
				/*将内存内容以可视化字符串形式输出到文件*/
				for (index = 0; index < session_size; index ++ )
				{
					ch = rodataAddr[index];
					if(ch < 0)
					{
						ch = ch*(-1);
					}
					printAddr[index] = ( isprint(ch) || rodataAddr[index] == ' ') ? ch : '.';
				}
				printAddr[index] = '\0';
				/*查找字符串*/
				/*0x00426fa0 0052656c 65617365 2025732e 25732e25 .Release %s.%s.%
				  0x00426fb0 73204275 696c6420 25732025 730a004d s Build %s %s..M*/
				/*查找 Build 关键字 验证前17位的字符串是不是Release 获取前51位的字符串 取五位转化为数值 */
				startIndex = 0;
				while (findflag == 0)
				{
					startIndex = findKeyStrIndex( printAddr + startIndex, "Build");
					if ( startIndex == -1 )
					{
						break;
					}
					if( !strncmp(printAddr + startIndex - 17, "Release", 7) )
					{
						/* 验证 svnnum 位置是否是数值 */
						memcpy(svnnum, printAddr+startIndex-51, 5);
						svnnum[5] = '\0';
						svn = atoi(svnnum);
						printf("svn = %d\n", svn);
						if( svn > 10000 && svn < 100000)
						{
							memcpy(tmp, printAddr+startIndex-51, 60);
							startIndex = startIndex - 51;
							findflag = 1;
							break;
						}						
					}
					startIndex ++;
				}
				if ( findflag == 1 )
				{
					memcpy(buildtime, printAddr+startIndex+6, 19);
					memcpy(version, printAddr+startIndex+26, 7);
					buildtime[19] = '\0';
					version[7] = '\0';
					printf("buildtime = %s\n", buildtime);
					printf("version = %s\n", version);
					break;
				}
				
				if( rodataAddr != NULL)
				{
					free(rodataAddr);
					rodataAddr = NULL;
				}
				if( printAddr != NULL)
				{
					free(printAddr);
					printAddr = NULL;
				}
			}else
			{
				printf("session index is %d but session size is 0\n", sess_index);
			}
		}
	}

	close(fd);

	return 0;

}

/***********************************************************
* DESCRIPTION：
*	查找目标字符串中的第一个关键字符串位置下标
*	找到目标字符串中的 关键字中第一个字母 找到则寻找第二个 全不找到返回第一个关键字下标 失败则返回-1
* INPUT ： 
*	const char*      strAddr;   目标字符串指针
*	const char*      key;       关键字指针
* OUTPUT： 
*	成功则返回关键字下标，失败则返回-1
* 
***********************************************************/
int findKeyStrIndex(const char* strAddr, const char* key)
{
	int ret = -1;
	int keylen = 0;
	int keyStartIndex = 0;
	int index = 0;
	char ch;
	char* tmpAddr = NULL;
		
	if (key == NULL || strAddr == NULL || strlen(strAddr) == 0 || strlen(key) == 0)
	{
		goto finish;
	}

	keylen = strlen(key);
	for (;;)
	{
		ch = key[index];
		//ch = 'l';
		tmpAddr = strchr( strAddr + keyStartIndex, ch);
		if ( tmpAddr == NULL)
		{
			goto finish;
		}
		for (index = 0;index < keylen;index ++)
		{
			if( key[index] != tmpAddr[index] )
			{
				break;
			}
		}
		keyStartIndex = strlen(strAddr) - strlen(tmpAddr);
		if(index >= keylen)
		{
			ret = keyStartIndex;
			break;
		}
		keyStartIndex ++;
	}

finish:
	return ret;
	
}



















