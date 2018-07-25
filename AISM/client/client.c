#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char* argv[])
{
    int cfd;
    int recbytes;
    int sin_size;
    char buffer[1024]={0};   
    struct sockaddr_in s_add,c_add;

    char use_ip[32] = {0};
    int use_port = 0;
    if( argc != 3 )
    {
        exit(0);
    }else{
        strncpy(use_ip, argv[1], sizeof(use_ip));
        use_port = atoi(argv[2]);
    }

    printf("Hello,welcome to client !\r\n");

    cfd = socket(AF_INET, SOCK_STREAM, 0);
    if(-1 == cfd)
    {
        printf("socket fail ! \r\n");
        return -1;
    }
    printf("socket ok !\r\n");

    bzero(&s_add,sizeof(struct sockaddr_in));
    s_add.sin_family=AF_INET;
    s_add.sin_addr.s_addr= inet_addr(use_ip);
    s_add.sin_port=htons(use_port);
    printf("s_addr = %#x ,port : %#x\r\n",s_add.sin_addr.s_addr,s_add.sin_port);

    if(-1 == connect(cfd,(struct sockaddr *)(&s_add), sizeof(struct sockaddr)))
    {
        printf("connect fail !\r\n");
        return -1;
    }
    printf("connect ok !\r\n");

    if(-1 == (recbytes = read(cfd,buffer,1024)))
    {
        printf("read data fail !\r\n");
        return -1;
    }
    printf("read ok\r\nREC:\r\n");

    buffer[recbytes]='\0';
    printf("%s\r\n",buffer);

    getchar();
    close(cfd);
    return 0;
}

