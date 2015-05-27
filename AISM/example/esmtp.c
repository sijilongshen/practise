#define _XOPEN_SOURCE 500

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

#include <openssl/ssl.h>
#include <auth-client.h>
#include <libesmtp.h>

#if !defined (__GNUC__) || __GNUC__ < 2
# define __attribute__(x)
#endif
#define unused      __attribute__((unused))
#define BUFLEN	8192

const char *readlinefp_cb (void **buf, int *len, void *arg);
void monitor_cb (const char *buf, int buflen, int writing, void *arg);
void print_recipient_status (smtp_recipient_t recipient, const char *mailbox, void *arg);
int authinteract (auth_client_request_t request, char **result, int fields, void *arg);
int tlsinteract (char *buf, int buflen, int rwflag, void *arg);
void event_cb (smtp_session_t session, int event_no, void *arg, ...);

//-hsmtp.163.com:25 -fbenguaer@163.com -sTest -m -c -t ./test-mail benguaer@163.com


/* Callback to prnt the recipient status */
void print_recipient_status (smtp_recipient_t recipient, const char *mailbox, void *arg unused)
{
	const smtp_status_t *status;
	status = smtp_recipient_status (recipient);
	printf ("%s: %d %s", mailbox, status->code, status->text);
}

/* Callback function to read the message from a file.  Since libESMTP
   does not provide callbacks which translate line endings, one must
   be provided by the application.

   The message is read a line at a time and the newlines converted
   to \r\n.  Unfortunately, RFC 822 states that bare \n and \r are
   acceptable in messages and that individually they do not constitute a
   line termination.  This requirement cannot be reconciled with storing
   messages with Unix line terminations.  RFC 2822 rescues this situation
   slightly by prohibiting lone \r and \n in messages.

   The following code cannot therefore work correctly in all situations.
   Furthermore it is very inefficient since it must search for the \n.
 */

const char * readlinefp_cb (void **buf, int *len, void *arg)
{
	int octets;

	if (*buf == NULL)
	*buf = malloc (BUFLEN);

	if (len == NULL)
	{
		rewind ((FILE *) arg);
		return NULL;
	}

	if (fgets (*buf, BUFLEN - 2, (FILE *) arg) == NULL)
	{
		octets = 0;
	}
	else
	{
		char *p = strchr (*buf, '\0');
		if (p[-1] == '\n' && p[-2] != '\r')
		{
			strcpy (p - 1, "\r\n");
			p++;
		}
		octets = p - (char *) *buf;
	}
	*len = octets;
	return *buf;
}

void monitor_cb (const char *buf, int buflen, int writing, void *arg)
{
	FILE *fp = arg;

	if (writing == SMTP_CB_HEADERS)
	{
		fputs ("H: ", fp);
		fwrite (buf, 1, buflen, fp);
		return;
	}

	fputs (writing ? "C: " : "S: ", fp);
	fwrite (buf, 1, buflen, fp);
	if (buf[buflen - 1] != '\n')
		putc ('\n', fp);
}

/* Callback to request user/password info.  Not thread safe. */
int authinteract (auth_client_request_t request, char **result, int fields, void *arg unused)
{
	char prompt[64];
	static char resp[512];
	char *p, *rp;
	int i, n, tty;
	char *name="benguaer";
	char* passwd="yin925430722";

	rp = resp;
	result[0]=name;
	result[1]=passwd;
	/*for (i = 0; i < fields; i++)
	{
		n = snprintf (prompt, sizeof prompt, "%s%s: ", request[i].prompt,
		(request[i].flags & AUTH_CLEARTEXT) ? " (not encrypted)" : "");
		if (request[i].flags & AUTH_PASS)
		{
			result[i] = getpass (prompt);
		}
		else
		{
			tty = open ("/dev/tty", O_RDWR);
			write (tty, prompt, n);
			n = read (tty, rp, sizeof resp - (rp - resp));
			close (tty);
			p = rp + n;
			while (isspace (p[-1]))
			p--;
			*p++ = '\0';
			result[i] = rp;
			rp = p;
		}
		printf("fields=%d,i=%d\n", fields, i );
	}*/
	
	return 1;
}

int tlsinteract (char *buf, int buflen, int rwflag unused, void *arg unused)
{
	char *pw;
	int len;

	pw = getpass ("certificate password");
	len = strlen (pw);
	if (len + 1 > buflen)
		return 0;
	strcpy (buf, pw);
	return len;
}
int handle_invalid_peer_certificate(long vfy_result)
{
	const char *k ="rare error";
	switch(vfy_result) 
	{
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			k="X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT"; break;
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			k="X509_V_ERR_UNABLE_TO_GET_CRL"; break;
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			k="X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE"; break;
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
			k="X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE"; break;
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			k="X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY"; break;
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			k="X509_V_ERR_CERT_SIGNATURE_FAILURE"; break;
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			k="X509_V_ERR_CRL_SIGNATURE_FAILURE"; break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
			k="X509_V_ERR_CERT_NOT_YET_VALID"; break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
			k="X509_V_ERR_CERT_HAS_EXPIRED"; break;
		case X509_V_ERR_CRL_NOT_YET_VALID:
			k="X509_V_ERR_CRL_NOT_YET_VALID"; break;
		case X509_V_ERR_CRL_HAS_EXPIRED:
			k="X509_V_ERR_CRL_HAS_EXPIRED"; break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			k="X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD"; break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			k="X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD"; break;
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
			k="X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD"; break;
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			k="X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD"; break;
		case X509_V_ERR_OUT_OF_MEM:
			k="X509_V_ERR_OUT_OF_MEM"; break;
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			k="X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT"; break;
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			k="X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN"; break;
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			k="X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"; break;
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			k="X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE"; break;
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			k="X509_V_ERR_CERT_CHAIN_TOO_LONG"; break;
		case X509_V_ERR_CERT_REVOKED:
			k="X509_V_ERR_CERT_REVOKED"; break;
		case X509_V_ERR_INVALID_CA:
			k="X509_V_ERR_INVALID_CA"; break;
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			k="X509_V_ERR_PATH_LENGTH_EXCEEDED"; break;
		case X509_V_ERR_INVALID_PURPOSE:
			k="X509_V_ERR_INVALID_PURPOSE"; break;
		case X509_V_ERR_CERT_UNTRUSTED:
			k="X509_V_ERR_CERT_UNTRUSTED"; break;
		case X509_V_ERR_CERT_REJECTED:
			k="X509_V_ERR_CERT_REJECTED"; break;
	}
	printf("SMTP_EV_INVALID_PEER_CERTIFICATE: %ld: %s\n", vfy_result, k);
	return 1; /* Accept the problem */
}

void event_cb (smtp_session_t session, int event_no, void *arg,...)
{
	va_list alist;
	int *ok;

	va_start(alist, arg);
	switch(event_no) 
	{
		case SMTP_EV_CONNECT: 
		case SMTP_EV_MAILSTATUS:
		case SMTP_EV_RCPTSTATUS:
		case SMTP_EV_MESSAGEDATA:
		case SMTP_EV_MESSAGESENT:
		case SMTP_EV_DISCONNECT: 
			break;
		case SMTP_EV_WEAK_CIPHER: 
			{
				int bits;
				bits = va_arg(alist, long); ok = va_arg(alist, int*);
				printf("SMTP_EV_WEAK_CIPHER, bits=%d - accepted.\n", bits);
				*ok = 1; 
				break;
			}
		case SMTP_EV_STARTTLS_OK:
			{
				puts("SMTP_EV_STARTTLS_OK - TLS started here."); 
				break;
			}
		case SMTP_EV_INVALID_PEER_CERTIFICATE: 
			{
				long vfy_result;
				vfy_result = va_arg(alist, long); ok = va_arg(alist, int*);
				*ok = handle_invalid_peer_certificate(vfy_result);
				break;
			}
		case SMTP_EV_NO_PEER_CERTIFICATE: 
			{
				ok = va_arg(alist, int*); 
				puts("SMTP_EV_NO_PEER_CERTIFICATE - accepted.");
				*ok = 1; break;
			}
		case SMTP_EV_WRONG_PEER_CERTIFICATE: 
			{
				ok = va_arg(alist, int*);
				puts("SMTP_EV_WRONG_PEER_CERTIFICATE - accepted.");
				*ok = 1; break;
			}
		case SMTP_EV_NO_CLIENT_CERTIFICATE: 
			{
				ok = va_arg(alist, int*); 
				puts("SMTP_EV_NO_CLIENT_CERTIFICATE - accepted.");
				*ok = 1; break;
			}
		default:
			printf("Got event: %d - ignored.\n", event_no);
	}
	va_end(alist);
}

int main(int argc, char* argv[])
{
	int      ret = 0;
	char*    server = "smtp.163.com:25";
	char*    from = "benguaer@163.com";
	char*    subject = "Test";
	int      nocrlf = 1;
	int      noauth = 0;
	int      to_cc_bcc = 0;
	char*    file = "test-mail.eml";
	FILE     *fp = NULL;
	enum notify_flags notify = Notify_NOTSET;
	const smtp_status_t *status;

	struct   sigaction  sa;
	auth_context_t  authctx;

	smtp_session_t session;
	smtp_message_t message;
	smtp_recipient_t recipient;

	auth_client_init();
	
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
	auth_set_mechanism_flags (authctx, AUTH_PLUGIN_PLAIN, 0);
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
		
		ret = smtp_start_session (session);
		if (!ret)
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
	smtp_destroy_session (session);
	auth_destroy_context (authctx);
	fclose (fp);
	auth_client_exit ();
	exit(0);

	return ret;

}
















