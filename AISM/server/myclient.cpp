#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

int _verbose = 0; //  是否输出调试信息

#define    ERROR_LOG         0
#define    INFO_LOG          1
#define    DEBUG_LOG         2

void LEVEL_PRINT(int log_level, const char* fmt, ...)
{
    va_list arglist;

	if(_verbose  >= log_level)
	{
		va_start(arglist, fmt);
		printf((const char*)fmt,arglist);
		va_end(arglist);
	}
}

int Usage(const char* proc_name)
{
	printf("Usage;%s -s server_ip -p server_port\n");
	printf("Usage;%s -h (help)\n");
	printf("Usage;%s -v (run with debug info)\n");
	exit(0);
}

int main()
{
	int					ret = 0;
	int					fd = 0;
	struct sockaddr_in  serv_addr;
	char                serv_ip[64] = {0};
	char				serv_port = 0;

	// 获取参数  -s servip -p port -v denug -h help
	while((opt=getopt(argc, argv, "s:p:vh"))!=-1)
	{
		switch(opt)
		{
			case 's':
				if( strlen(optarg) < (int)sizeof(serv_ip) )
				{
					strcpy(serv_ip, optarg, strlen(optarg)+1);break;
					LEVEL_PRINT(INFO_LOG, "get ip info %s\n", serv_ip);
				}else{
					LEVEL_PRINT(ERROR_LOG, "error ip info, exit\n");
					Usage();
				}
				break;
			case 'p':
				serv_port = atoi(optarg);
				if(serv_port <= 0 || serv_port > 65536 )
				{
					LEVEL_PRINT(ERROR_LOG, "error server port:%d, exit\n", serv_port);
					Usage();
				}
				break;
			case 'v':
				_verbose++;
				break;
			case 'h':
				Usage(argv[0]);
				break;
			default:
				 break;
		}
	}
	//  make file description
	fd = socket(AF_INET,SOCK_STREAM,0);  

	int yes = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));  

	memset(&serv_addr,0x00,sizeof(serv_addr));  
	serv_addr.sin_family=AF_INET;				// ipv4 
	serv_addr.sin_port=htons(__PORT);			// port  
	serv_addr.sin_addr.s_addr=

	return ret;
}
