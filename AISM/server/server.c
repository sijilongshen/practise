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
#include <pthread.h>

const char* global_config_file = "../config/server.conf";

typedef struct t_run_env{
    pthread_mutex_t     thread_mutex_env;
    char                log_path[128];
    char                server_ip[64];
    int                 server_port;
    int                 max_connect;
}

typedef struct t_client_info{
    int                 client_fd;
}

t_config_info   global_config;
t_run_env       run_env;

int init_run_env()
{
    int     ret = 0;
    char    tmp_str[128] = {0};

    if ( Config_Init(global_config_file, global_config) != 0 )
    {
        printf("init config file failed\n");
        return GET_CONFIG_VALUE_FAILED;
    }

    if ( Config_GetValue(global_config, "server_ip", run_env.server_ip, sizeof(run_env.server_ip)) != 0 )
    {
        printf("get server_ip from config failed\n");
        return GET_CONFIG_VALUE_FAILED;
    }

    if ( Config_GetValue(global_config, "max_connect", tmp_str, sizeof(tmp_str)) != 0 )
    {
        printf("get max_connect from config failed\n");
        return GET_CONFIG_VALUE_FAILED;
    }else{
        run_env.max_connect = atoi(tmp_str);
    }

    if ( Config_GetValue(global_config, "server_port", tmp_str, sizeof(tmp_str)) != 0 )
    {
        printf("get server_port from config failed\n");
        return GET_CONFIG_VALUE_FAILED;
    }else{
        run_env.server_port = atoi(tmp_str);
    }

    if ( Config_GetValue(global_config, "log_path", run_env.log_path, sizeof(run_env.log_path)) != 0 )
    {
        printf("get log_path from config failed\n");
        return GET_CONFIG_VALUE_FAILED;
    }

    return 0;
}

void thread_create_connect()
{
	int					        ret = 0;
	int                         yes = 1;
    int                         port;
    int                         max_connect;
	int                         client_fd = 0;
	int                         serv_fd;
	char                        ret_str[64] = {0};
	fd_set				        readfds ;
	socklen_t			        len = 0;
	struct sockaddr_in          serv_addr;  
	struct sockaddr_in          client_addr;  
	time_t cur_time;

    // 获取配置信息
    port = run_env.server_port;
	serv_fd = socket(AF_INET, SOCK_STREAM, 0);  
	if( serv_fd < 0 )
	{  
        printf("create connect info failed\n");
		exit(2);
	}  
	setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));  

	memset(&serv_addr,0x00,sizeof(serv_addr));  
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_port=htons(port);
    if ( strcmp(run_env.server_ip, "0.0.0.0") == 0)
	    serv_addr.sin_addr.s_addr=INADDR_ANY;
    else
	    serv_addr.sin_addr.s_addr=inet_addr(run_env.server_ip);

	if (bind(serv_fd,(struct sockaddr*)&(serv_addr),sizeof(serv_addr))<0)  
	{  
		perror("bind()");  
		exit(3);  
	}

	if(listen(serv_fd, 2)<0)  
	{  
		perror("listen");  
		exit(4);  
	}  

	FD_ZERO(&readfds);
	timeout.tv_sec = 1;
	while ( 1 )
	{
		FD_SET(serv_fd, &readfds);
		switch( ret = select(serv_fd+1, &readfds, NULL, NULL, &timeout) )
		{  
			case -1:  
				perror("select");  
				printf("ret = -1\n");  
				exit(5);  
				break;  
			case 0:  
				//printf("wait timeout\n");  
				break;  
			default:  
				len = sizeof(client_addr);
				client_fd = accept(serv_fd, (struct sockaddr*)&client_addr, &len);
				if(-1 != client_fd)
				{
					printf("client ip:%s\n", inet_ntoa(client_addr.sin_addr));
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

int main(int argc, char* argv[])
{
    int         ret = 0;

    // 初始化线程锁
    pthread_mutex_lock(&global_config.thread_mutex_env);
    // 初始化配置信息
    if ( init_run_env() != 0 )
    {
        printf("get run env failed\n");
        exit(1);
    }

    // 执行线程监控
    int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
	return ret;
}


