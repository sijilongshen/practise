/**************************************************
 *	预期：
 *		最多允许 1 个 
 *		操作只进行时间的获取
 * ************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define    __PORT		 5678
#define    CLIENT_MAX    1024	

int main()
{
	int					ret = 0;
	int					serv_fd;
	struct sockaddr_in  serv_addr;  
	struct sockaddr_in  client_addr;  
	//int					nready = 0;
	int					maxfd = -1;
	int                 client_fd = 0;
	fd_set				readfds ;
	struct timeval		timeout={3,0};  
	char                ret_str[64] = {0};
	socklen_t			len = 0;

	//  make file description
	serv_fd = socket(AF_INET,SOCK_STREAM,0);  
	if( serv_fd < 0 )  
	{  
		perror("socket()");  
		exit(2);  
	}  
	//  set socket option
	int yes = 1;
	setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));  

	memset(&serv_addr,0x00,sizeof(serv_addr));  
	serv_addr.sin_family=AF_INET;				// ipv4 
	serv_addr.sin_port=htons(__PORT);			// port  
	serv_addr.sin_addr.s_addr=INADDR_ANY;

	if (bind(serv_fd,(struct sockaddr*)&serv_addr,sizeof(serv_addr))<0)  
	{  
		perror("bind()");  
		exit(3);  
	}

	if(listen(serv_fd, 2)<0)  
	{  
		perror("listen");  
		exit(4);  
	}  

	//  
	FD_ZERO(& readfds);
	while ( 1 )
	{
		FD_SET(serv_fd, &readfds);
		timeout.tv_sec = 3;
		maxfd = serv_fd + 1;
		switch( ret = select(maxfd+1, &readfds, NULL, NULL, &timeout) )
		{  
			case -1:  
				perror("select");  
				printf("ret = -1\n");  
				exit(5);  
				break;  
			case 0:  
				printf("ret = 0\n");  
				break;  
			default:  
				len = sizeof(client_addr);  
				client_fd = accept(serv_fd, (struct sockaddr*)&client_addr, &len);
				if(-1 != client_fd)  
				{  
					printf("client ip:%s\n", inet_ntoa(client_addr.sin_addr));
					time_t cur_time;
					time(&cur_time);
					memset(ret_str, 0x00, sizeof(ret_str));
					sprintf(ret_str, "hello ,time is %ld\n", cur_time); 
					ret = write(client_fd, ret_str, sizeof(ret_str));
					if( ret <= 0 )
					{
						printf("write fd failed\n");  
					}
					close(client_fd);
				}  
				break;
		}  
	}

	return ret;
}


