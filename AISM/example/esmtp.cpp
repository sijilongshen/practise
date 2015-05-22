#include <stdio.h>  
#include <stdlib.h>  
#include <ctype.h>  
#include <unistd.h>  
#include <getopt.h>  
#include <string.h>  
#include <fcntl.h>  
#include <signal.h>  
#include <errno.h>  
#include <stdarg.h>  
#include <libesmtp.h>                                                           // 包含libesmtp函数库  
  
int main()  
{  
	int ret = 0;
	smtp_session_t session;                                                      // 定义SMTP会话  
	smtp_message_t message;                                                      // 定义SMTP消息结构  
	struct sigaction sa;                                                         // 该结构包含收到信号后程序的行为  
	const smtp_status_t *status;                                         // 用于保存SMTP状态  
	char buf[128];                                                          // 用于文件的缓冲区  
	FILE *fp;   
                                                             // 文件标识符  
	if((session = smtp_create_session ()) == NULL)
	{                      // 创建SMTP会话  
		fprintf (stderr, "创建会话失败：%s\n", smtp_strerror(smtp_errno(), buf, sizeof(buf)));  
		return 1;  
	}  
	if((message = smtp_add_message (session)) == NULL) 
	{ // 从SMTP会话中接受消息，判断是否成功  
		fprintf (stderr, "服务器无应答：%s\n", smtp_strerror(smtp_errno(), buf, sizeof(buf)));  
		return 1;  
	}  

	sa.sa_handler = SIG_IGN;                                            // 避免进程僵死  
	sigemptyset(&sa.sa_mask);                                         // 初始化信号集  
	sa.sa_flags = 0;                                                            // 使信息不被阻塞  
	sigaction (SIGPIPE, &sa, NULL);                              // 设置信号行为  
	smtp_set_server (session, "smtp.163.com:25");         // 设置SMTP服务器地址与端口  
	smtp_set_reverse_path (message, "benguaer@163.com");       // 设置发送者邮箱地址  
	smtp_set_header (message, "To", NULL, NULL);                 // 使邮件头包含目的地邮箱地址  
	smtp_set_header (message, "Subject", " test mail");          // 使邮件头包含主题  
	smtp_set_header_option (message, "Subject", Hdr_OVERRIDE, 1);// 使用默认的邮件头设置  
	fprintf(stderr, "%s\n", "SMTP服务器设置成功");  

	if ((fp = fopen ("mail.eml", "r")) == NULL) 
	{  
		perror("打开文件失败");  
		return 1;  
	}  
	smtp_set_message_fp (message, fp);                          // 将文件中的内容作为邮件消息内容  
	smtp_add_recipient (message,"benguaer@163.com");                  // 为消息添加一个容器  

	ret = smtp_start_session (session);
	printf("ret = %d\n",ret);

	if (!ret)
	{                         // 连接SMTP服务器传送邮件  
		fprintf (stderr, "SMTP server problem %s\n",  
		smtp_strerror (smtp_errno (), buf, sizeof buf));  
	}  
	else  
	{  
		status = smtp_message_transfer_status (message);  // 获取发送状态  
		printf ("%d %s", status->code, (status->text != NULL) ? status->text : "\n");  
	}  

	smtp_destroy_session (session);                           // 结束SMTP会话  
	if(fp != NULL)  
		fclose(fp);// 关闭文件
	return 0;  
}  


























