#include<string.h>  
#include<stdlib.h>  
#include<sys/socket.h>  
#include<sys/types.h>  
#include<sys/select.h>  
#include<netinet/in.h>  

#define _MAX_SIZE_ 10  
#define __PORT     5678

int fd_arr[_MAX_SIZE_];  
int max_fd=0;  

static void Useage(const char* proc)  
{  
	printf("Useage:%s port");  
	exit(1);  
}  

static int add_fd_arr(int fd)  
{  
	//fd add to fd_arr  
	int i=0;  
	for(;i<_MAX_SIZE_;++i)  
	{  
		if(fd_arr[i]==-1)  
		{  
			fd_arr[i]=fd;  
			return 0;  
		}  
	}  
	return 1;  
}  

int select_server()
{  
	struct sockaddr_in ser;  
	struct sockaddr_in cli;  

	fd_set fds;  
	int fd=socket(AF_INET,SOCK_STREAM,0);  
	if( fd < 0 )  
	{  
		perror("socket()");  
		exit(2);  
	}  
	int yes=1;  
	setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));  

	memset(&ser,0x00,sizeof(ser));  
	ser.sin_family=AF_INET;  
	ser.sin_port=htons(__PORT);  
	ser.sin_addr.s_addr=INADDR_ANY;

	if(bind(fd,(struct sockaddr*)&ser,sizeof(ser))<0)  
	{  
		perror("bind()");  
		exit(3);  
	}  

	//init fd_arr  
	int i=0;  
	for(;i<_MAX_SIZE_;++i)  
	{  
		fd_arr[i]=-1;  
	}  

	add_fd_arr(fd);  


	FD_ZERO(&fds);  
	if(listen(fd,5)<0)  
	{  
		perror("listen");  
		exit(4);  
	}  

	while(1)  
	{  
		//reset fd_arr  
		for(i=0;i<_MAX_SIZE_;++i)  
		{  
			if(fd_arr[i]!=-1)  
			{  
				FD_SET(fd_arr[i],&fds);  
				if(fd_arr[i]>max_fd)  
				{  
					max_fd=fd_arr[i];  
				}  
			}  
		}  
		struct timeval timeout={3,0};  
		switch(select(max_fd+1,&fds,NULL,NULL,&timeout))  
		{  
			case -1:  
				{  
					perror("select");  
					exit(5);  
					break;  
				}  
			case 0:  
				{  
					printf("select timeout......");  
					break;  
				}  
			default:  
				{  
					for(i=0;i<_MAX_SIZE_;++i)  
					{  
						if(i==0&&fd_arr[i]!=-1&&FD_ISSET(fd_arr[i],&fds))  
						{  
							socklen_t len=sizeof(cli);  
							int new_fd=accept(fd,(struct sockaddr*)&cli,&len);  
							if(-1!=new_fd)  
							{  
								printf("get a new link");  
								if(1==add_fd_arr(new_fd))  
								{  
									perror("fd_arr is full,close new_fd\n");  
									close(new_fd);  
								}  

							}  
							continue;  
						}  
						if(fd_arr[i]!=-1&&FD_ISSET(fd_arr[i],&fds))  
						{  
							char buf[1024];  
							memset(buf,'\0',sizeof(buf));  
							ssize_t size=recv(fd_arr[i],buf,sizeof(buf)-1,0);  
							if(size==0||size==-1)  
							{  
								printf("remote client close,size is%d\n",size);  
								int j=0;  
								for(;j<_MAX_SIZE_;++j)  
								{  
									if(fd_arr[j]==fd_arr[i])  
									{  
										fd_arr[j]=-1;  
										break;  
									}  
								}  
								close(fd_arr[i]);  
								FD_CLR(fd_arr[i],&fds);  
							}else  
							{  
								printf("fd:%d,msg:%s",fd_arr[i],buf);  
							}  
						}  
					}  
				}  
				break;  
		}  

	}  
}  

int main(int argc,char* argv[])  
{  
	select_server();
	return 0;  
}  

