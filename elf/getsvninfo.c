#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>

#define ELF_FILE       "gmon"

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

int main() 
{
	int ret = 0;
	int fd ;
	int session_header_offset = 0;
	int session_count = 0;
	int session_size = 0;
	int session_header_size = 0;
	char svnnum[6];
	char*   rodataAddr = NULL;
	char*   printAddr = NULL;
	char* tmpstr = NULL;
	int tmpstrlen;
	
	int i = 0;
	int index = 0;
	int sess_index = 0;
	char* findBuildFlag = NULL;
	char ch = ' ';
	
	Elf64_Ehdr main_elf;
	Elf64_Shdr   elf_session_header;
	
	bzero(svnnum, 6);
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
				printf("elf_session_header.sh_size is %d\n",session_size);
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
				findBuildFlag = strstr((const char*)printAddr, "Build");
				if (findBuildFlag != NULL)
				{
					tmpstr = printAddr;
					while ( (tmpstr = strpbrk(tmpstr, "Build")) != NULL )
					{
						tmpstrlen = strlen(tmpstr);
						printf("tmpstrlen = %d session_size = %d\n", tmpstrlen, session_size);
						printf("tmpstr = %c", tmpstr[0]);
						printf("tmpstr = %c", tmpstr[1]);
						printf("tmpstr = %c", tmpstr[2]);
						printf("tmpstr = %c", tmpstr[3]);
						printf("tmpstr = %c", tmpstr[4]);
						if( ! strncmp( (char *)(printAddr+session_size+1-tmpstrlen-17), (const char*)"Release" , 7) )
						{
							memcpy(svnnum, (char *)(printAddr+session_size+1-tmpstrlen-51), 5);
							svnnum[5] = '\0';								
							printf("svn num is %d\n", atoi(svnnum));
							bzero(svnnum, 6);
						}
						tmpstr = (char *)(printAddr+session_size+1-tmpstrlen+5);
					}
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
* 描述：  查找字符串中svn号所在
* 返回值：成功返回SVN号 失败返回 -1
* 
***********************************************************/
/*
# 313730353300323031352d31312d323700622a602031383a32333a303700322e3100320000622a70330052656c656173652025732e25732e00622a802573204275696c64
# 17053.2015-11-27 18:23:07.2.1.2.3.Release %s.%s.%s Build
# 版本号关键字长度为 136     Build hex 4275696c64 长度为 10   Release hex 52656c65617365 长度为 14 
# 攻略：每找到一个Build关键字 查找他的前28个字符是不是Release不是的话 截掉这部分字符串继续查找
# 使用 awk 获取 Build 关键字所在下标 查询他的前 28个字符
##每找到一个关键字 ##
*/
int findSvnInfo(const char* strAddr)
{
	int ret = 0;
	
	
	
	return ret;
	
}



















