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
#include <libesmtp.h>

//-hsmtp.163.com:25 -fbenguaer@163.com -sTest -m -c -t ./test-mail benguaer@163.com

int main(int argc, char* argv[])
{
	int      ret = 0;
	char*    server = "smtp.163.com:25";
	char*    from = "benguaer@163.com";
	char*    subject = "Test";
	int      nocrlf = 1;
	int      noauth = 0;
	int      to_cc_bcc = 0;
	char*    file = "mail";
	FILE     *fp = NULL;

	struct   sigaction  sa;
	auth_context_t  authctx;

	smtp_session_t session;                                                                                                                │
	smtp_message_t message;                                                                                                                │
	smtp_recipient_t recipient;

	auth_client_init ();
	
	session = smtp_create_session();
	if ( NULL == session )
	{
		printf("smtp_create_session failed\n");
		exit(1);
	}
	message = smtp_add_message(session);
	if ( NULL == message )
	{
		printf("smtp_add_message failed\n");
		exit(1);
	}

	smtp_set_monitorcb (session, monitor_cb, stdout, 1);
	smtp_starttls_enable (session, Starttls_ENABLED);

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);

	smtp_set_server(session, server);
	authctx = auth_create_context();
	auth_set_mechanism_flags (authctx, AUTH_PLUGIN_PLAIN, 0);                                                                              │
	auth_set_interact_cb (authctx, authinteract, NULL);
	
	smtp_starttls_set_password_cb (tlsinteract, NULL);
	smtp_set_eventcb(session, event_cb, NULL);

	if (!noauth)
		smtp_auth_set_context (session, authctx);

	smtp_set_reverse_path (message, from); 
	
	if(!to_cc_bcc)
		smtp_set_header(message, "To", NULL, NULL);

	if(subject != NULL)
	{
		smtp_set_header (message, "Subject", subject);
		smtp_set_header_option (message, "Subject", Hdr_OVERRIDE, 1);
	}

	if(file != NULL)
	{
		fp = fopen(file,"r");
		if(fp == NULL)
		{
			printf("cannot open context file\n");
			exit(1);
		}
		if (nocrlf)
			smtp_set_messagecb (message, readlinefp_cb, fp);
		else
			smtp_set_message_fp (message, fp);

		recipient = smtp_add_recipient(message, "benguaer@163.com");
		/* Recipient options set here */
		if (notify != Notify_NOTSET)
			smtp_dsn_set_notify (recipient, notify);

		if (!smtp_start_session (session))
	       	{
			char buf[128];
			fprintf (stderr, "SMTP server problem %s\n", smtp_strerror (smtp_errno (), buf, sizeof buf));
		}
		else
		{
			/* Report on the success or otherwise of the mail transfer */ 
			
			status = smtp_message_transfer_status (message);
			printf ("%d %s", status->code,(status->text != NULL) ? status->text : "\n");
			smtp_enumerate_recipients (message, print_recipient_status, NULL);
		}

	}
	mtp_destroy_session (session);
	auth_destroy_context (authctx);
	fclose (fp);
	auth_client_exit ();                                                                                                                   │
	exit(0);

	return ret;

}
















