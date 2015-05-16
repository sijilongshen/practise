/********************************************
**	npc.cpp
**	
**
**	author:  madianjun@schina.cn
**	Copyright (C) 2012 SChina (www.schina.cn) 
**
**
*********************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h> /* for exit() */
#include <glib.h>

#include <string.h>
#include <ctype.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <signal.h>
#include <errno.h>
#include<arpa/inet.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_LIBCAP
# include <sys/prctl.h>
# include <sys/capability.h>
#endif

#include <sys/socket.h>
#include <sys/un.h>

#include "capture-pcap-util.h"
#include "pcapio.h"
#include "capture_opts.h"
#include "capture_ifinfo.h"
#include "capture_sync.h"
#include "libpcap.h"

#include "dbfw_ipc.h"
#include "npc_interface.h"
#include "dbfwsga_session.h"
#include "npc_util.h"
#include "dbfw_log.h"
#include "dbfw_fixarray_interface.h"
#include "npp_interface.h"
#include "dbfw_ac.h"
#include "npc_errno.h"
#include "dump.h"
#ifndef NO_LICENCE
#include "dbfw_cklicense.h"
#endif

#ifdef HAVE_LIBTIS
#include "libtis.h"
#endif
/* 2015-05-07 ���hash�����֧�� */
#include "libbslhash.h"

#define HAVE_HEADER_INDEX   /* ����ʹ��header_index���Ұ� */

#define NPC_MEMORY_GATE_PERCENT 95  /* NPC�ڴ�������ްٷֱ�(95%) */
/*
* Timeout, in milliseconds, for reads from the stream of captured packets
* from a capture device.
*/

#define CAP_READ_TIMEOUT        250

/*
* Timeout, in microseconds, for reads from the stream of captured packets
* from a pipe.  Pipes don't have the same problem that BPF devices do
* in OS X 10.6, 10.6.1, 10.6.3, and 10.6.4, so we always use a timeout
* of 250ms, i.e. the same value as CAP_READ_TIMEOUT when not on one
* of the offending versions of Snow Leopard.
*/
#define PIPE_READ_TIMEOUT		250000

#define REQUEST_PACKET			0x01
#define RESPONSE_PACKET         0x02

//#define NPC_MAX_SESSIONS DBFW_MAX_SESSIONS/2


#define NPC_UPDATE_HEARTBEAT_INTERVAL   1000000         /* ����������ʱ���� */

#define NPC_THREAD_MAIN				0x01		/* ���̵߳��̺߳� */
#define NPC_THREAD_HEARTBEAT		0x02		/* �����̵߳��̺߳� */

#define NPC_MAX_NPP_ARG				8192			/* ����߳��ڴ���NPP����ʱ,�������������ͬʱ����128���ȴ�������NPP���� */

#define DBFW_NPC_LOG_DEFAULT_SIZE   8*1024*1024

#define NPC_MAX_SEMVALUE            32000      /* ������ź���ֵ�߽�:�ڼ�������£������һ��session��NPP�ٶȸϲ��ϰ����ٶȣ�
                                                  ��ɴ�����session���Ķѻ���Ϊ�˼��ٸöѻ�������Ӱ�죬���С�����������
                                                  ͬʱ��Ҳ���Ա�������NPP������ɵĴ�����Ҫ�����ͨѶ�����ѻ���npc�Ļ�����
                                               */
#define NPC_NORMAL_SEMVALUE         128        /* �ָ��ɼ����ź���ֵ�߽磬���ź�������󣬲��ٲɼ��ûỰ������
                                                  ���ź����ָ�����ֵʱ���ָ��ɼ�
                                               */
#define NPC_CK_LICENSE_TIME         0
#define NPC_CK_LICENSE_DISK         1
#define NPC_CK_LICENSE_ALL          2

#define NPC_SUSPEND_NPPPOOL_COUNT   128

/* �������µ�ÿ�ν��д���License��麯��ʹ�õĺ� */
#define NPC_CK_LICENSE_GETDISKID    0
#define NPC_CK_LICENSE_HAVEDISKID   1
/*Makefile�ļ���ָ��������*/
#if defined DROP_STABLE_STEP && defined DROP_STABLE_INDEX
	#define NPC_DROP_STABLE_STEP	DROP_STABLE_STEP
	#define NPC_DROP_STABLE_INDEX	(DROP_STABLE_INDEX-1)
#else
	#ifdef DROP_RANDOM
	#define NPC_DROP_RANDOM		DROP_RANDOM
	#else
	#define NPC_DROP_PACKET			0
	#define NPC_DROP_STABLE_STEP	1
	#define NPC_DROP_STABLE_INDEX	-1
	#endif

#endif

u_int64	__DROP_PACKET_COUNT;
u_int64	__TOTAL_PACKET_COUNT;
u_int64	__TOTAL_PACKET_INDEX;
u_int64	__TOTAL_SESSION_COUNT;

char *__FILTER=NULL;

//#define NPC_DBSERVER_ADDR_CONFIG_FILE	"npc_dbserver_addr.ini"

/* whatever the deal with pcap_breakloop, linux doesn't support timeouts
* in pcap_dispatch(); on the other hand, select() works just fine there.
* Hence we use a select for that come what may.
*/
#define MUST_DO_SELECT

#define NPC_LOCK_MUTEX(P_MUTEX, RET) \
{\
	if((RET=pthread_mutex_lock(P_MUTEX))!=0) \
	{\
	NPC_PRINT("[Error]: main thread: lock \"mutex_for_clear_session\" error: errno=%d\n", RET);\
	}\
}

#define NPC_UNLOCK_MUTEX(P_MUTEX, RET) \
{\
	if((RET=pthread_mutex_unlock(P_MUTEX))!=0) \
	{\
	NPC_PRINT("[Error]: main thread: unlock \"mutex_for_clear_session\" error: errno=%d\n", RET);\
	}\
}

/** init the capture filter */
typedef enum {
	INITFILTER_NO_ERROR,
	INITFILTER_BAD_FILTER,
	INITFILTER_OTHER_ERROR
} initfilter_status_t;

#   define NPC_HTON16(x)    ((((x) & 0xff00u) >> 1*8) | \
    (((x) & 0x00ffu) << 1*8))
#   define NPC_HTON32(x)    ((((x) & 0x000000ffu) << 24) | \
    (((x) & 0x0000ff00u) << 8)  | \
    (((x) & 0x00ff0000u) >> 8)  | \
    (((x) & 0xff000000u) >> 24))

#define NPC_NTOH16(x) NPC_HTON16(x)
#define NPC_NTOH32(x) NPC_HTON32(x)

#pragma pack(1)
typedef struct _pcap_options {
	guint32        received;
	guint32        dropped;
	pcap_t         *pcap_h;
#ifdef MUST_DO_SELECT
	int            pcap_fd;               /* pcap file descriptor */
#endif
	gboolean       pcap_err;
	guint          interface_id;
	GThread        *tid;
	int            snaplen;
	int            linktype;
} pcap_options;

/***************************
**
**	26�ֽ�
**
***************************/
typedef struct NppArg
{
	u_int	client_ip;
	u_short client_port;
	u_char	client_mac[6];
	u_int	server_ip;
	u_short	server_port;
	u_char	server_mac[6];
	u_short	session_id;
}NppArg;

typedef struct _loop_data 
{
	/* common */
	int				npc_id;						/* NPC���̵�ID: 1-4 */
	u_char			dbfw_home[64];				/* $DBFW_HOME�������� */
#ifdef USE_FILTER
	DBFW_NPC_INFO	npc_info;					/* NPC�Ĳ���:������,���˹�����ʽ.��Fixarray���ȡ */
#endif
	gboolean		go;							/* TRUE as long as we're supposed to keep capturing */

	GArray			*pcaps;

	int				shm_id;						/* �����ڴ�id */
	u_char			*sga_addr;					/* SGA�׵�ַ */
	#ifdef HAVE_LIBTIS
	Tis_Manager     *tis;
	#else
	u_int			buffer_id;					/* ����ʹ�õ�˫��������id:0��1 */
	u_char			*header_addr[2];			/* ˫��������header��ַ */
	u_char			*body_addr[2];				/* ˫��������body��ַ */
	u_char			*tail_addr[2];				/* ˫��������ĩβ��ַ */
	u_char			*p_header;					/* ������һ��header�ĵ�ַ */
	u_char			*p_body;					/* ������һ��body�ĵ�ַ */
	#endif
	Npc_HashPool	session_hashmap;			/* client ip+port => session_id��ӳ�� */
    Npc_SessionWithClient   session_withclients[DBFW_MAX_SESSIONS]; /* �������лỰ��client�Ĺ�ϵ��Ϣ */
#ifdef USE_BSLHASH_FORSESSION
    Bslhash_Config  session_withclients_bslist_config;       /* �������лỰ��client�Ĺ�ϵ��Ϣ(bslhash��ʽ) */
    u_char          *mem_sess_bslist;           /* bslist���ڴ�����ÿ��Npc_SessionWithClientԪ����Ҫ12�ֽڣ�8192���ỰԪ�أ���Ҫ3M�Ŀռ� */
#endif    
	Npc_HashPool	db_hashmap[2];				/* �����������ݿ��������ַ => 1 ��ӳ�� */
	u_int			db_hashmap_id;				/* ����ʹ�õ�db_hashmap���±�: 0��1 */
	Dbfw_Sga_ACBuf	*acbuf;						/* �ڳ�ʼ��db_hashmapʱ, ������ACBuf�м���db��ַ */
	#ifdef HAVE_LIBTIS
	
	#else
	u_int64			header_id[DBFW_MAX_SESSIONS];	/* ÿ��session��header_id,��1��ʼ */
    /* 2014-06-23 ���ӱ���ÿ���Ự�ĵ�ǰcapbuf_header�����λ���±�,��ʼֵΪDBFW_NEXTHEADERIDX_UNKNOWN,����2��buffer˳�����ӣ������������� */
    u_int           current_capbuf_header_idx;      /* ��ǰ��ʹ�õ�capbuf_header���±� */
    u_int           last_capbuf_header_idx[DBFW_MAX_SESSIONS];
    #endif
    u_char          semvalue_outofrange_flag[DBFW_MAX_SESSIONS];    /* 
                                                                        �Ự���ź������ޱ�� 
                                                                        ��ĳ���Ự���ź���ֵ������NPC_MAX_SEMVALUE�����ñ����Ϊ1
                                                                        ���ź����ָ���NPC_NORMAL_SEMVALUE����ʱ�����ñ����Ϊ0
                                                                    */
	SessBuf_SemForSession *sems;				/*�洢�����ӽ����ź���������*/
    SessBuf_SessionArray *session_array;

	NppArg			npp_args[NPC_MAX_NPP_ARG];	/*���߳�֪ͨ����̴߳���NPPʱ,��NPP�Ĳ��������������. ����̴߳�������ȡ����.������ѭ��ʹ�õ�.*/
	int				sem_id_for_create_npp;		/*����ͬ�����̺߳ʹ���NPP���߳�*/
	int				npp_arg_idx;				/*npp�������е��±�:0~NPC_MAX_NPP_ARG, ���߳�������д�����ʱʹ����*/
	pthread_mutex_t	mutex_for_clear_session;	/*����ͬ�����̺߳�����session_hashmap�̵߳Ļ�����*/

	u_int64			max_captured_packets_count;	/*ץ�����������*/
	u_int64			captured_packets_count;     /*��ǰ�Ѿ�ץ��������*/
	u_int64			captured_bytes_count;
	u_int64			server_addr[8];				/*�洢������IP��Port*/
	u_int			server_addr_count;	        /*��������ַ������*/

	u_int64			alivetime;					/* ����ֵ */
	u_int64			worktime;                   /* ����ֵ,���ݲ����İ��������ж��Ƿ��ڹ��� */
	time_t			start_time;
	time_t			end_time;

	u_char			dbfw_instance_name[PROCESS_PARAM_MAX_VALUES_LEN];	/* dbfwʵ���� */
	int				dbfw_max_session;			/* SGA�еĲ���,�����ж�npp�����Ƿ�ﵽ���ֵ */
	int				error_no;					/* ����ץ��ѭ���г���,������ű�����errno�� */
    /* 
        2014-06-23 ������License״̬�йص�����
        License�ļ��:
        1:ÿ������NPCʱ����License��飬�����ü��Ľ��
        2:��Npc_UpdateHeartbeat�߳���ÿ���60����һ�Σ������ݽ�������״̬ 
    */
    int             license_result;             /* License���Ľ�� 0-δ֪ >0�ɹ� <0ʧ�� */
    time_t			license_checktime;          /* License�������ʱ�� */
    /* 
        2014-10-15 �������ݿ��������飬���ڰ��շ�������IP��PORT�ж����ݿ�����ͣ���Ӧִ����ȷ��NPP_xxxx���� 
        ����㷨��
        ��ӣ�key=(���ݿ������IP<<16 | ���ݿ�������˿�)%64;
             ��keyΪ�����±꣬��dialect���뵽����Ԫ��
             �������������������Ԫ�أ���ʾȡģ��ֵ��ͬ�����뵽������
    */
    Npc_DBTypeWithIpAndPort_Bucket  dbtype_bucket[DBFW_MAX_PROTECTED_DATABASE]; /* �����±�����IP+PORT������key%DBFW_MAX_PROTECTED_DATABASE�õ� */
    /* 
        2015-05-17 ���Ӵ����ظ�������������跢�Ͷ��SYN��������������������ͬ��NPP 
        ����������¼���һ��SYN��clientkey,�������һ�ε���ͬ���򲻴���NPP�����򴴽�
    */
//     u_int64 last_clientkey_for_createnpp;
//     u_int64 last_timestamp_for_createcpp;
    /* ��ǰ���õĽ��̳ز���; 0-��ʾû�п������̳�(Ĭ��)��>0��ʾ�����˽��̳� */
    u_int   npp_pool_size;      /* ��Ҫ��Npc_InitGlobalLoopData�����г�ʼ��Ϊ0 */
    u_short npp_pool_type;      /* ��Ҫ��Npc_InitGlobalLoopData�����г�ʼ��Ϊ0 */    
    u_char  npp_pool_default_dbip[64];      /* ȱʡSUSPEND���ͽ��̳ص����ݿ�IP��ַ */
    u_int   npp_pool_default_dbaddress_value;
    u_short npp_pool_default_serverport;      /* ȱʡSUSPEND���ͽ��̳ص����ݿ�˿� */
    u_int   npp_pool_default_clientport;        /* ȱʡSUSPEND���ͽ��̳صĿͻ��˶˿ڣ���10000��ʼ������ */
} loop_data;

typedef struct
{
	char *name;
	pcap_t *pch;
} if_stat_t;

/*
    �������лỰ�����ʱ��
*/
typedef struct __npp_info
{
    u_short sessid;
    u_int   pid;
    u_int64 last_worktime;
} npp_info;

#pragma pack()

/*
* Standard secondary message for unexpected errors.
*/
const char please_report[] =
"Please report this to the Wireshark developers.\n"
"(This is not a crash; please do not report it as such.)";

void Npc_DropStatistic();

void *__SGA;
Dbfw_Sga_SessionBuf*    __NPC_SGA_SESSBUF = NULL;  /* sga's session buffer */
u_int __PID;
u_int64 __STOP;
u_int64 __COUNT;
capture_options *__OPTS;

#ifdef DUMP_PACKET
	FILE *__FOUT=NULL;
	//FILE *__FOUT_SIMPLE;
#endif

/*
* This needs to be static, so that the SIGINT handler can clear the "go"
* flag.
*/
loop_data   global_ld;

Dbfw_LogFile npc_log_file;      /* ֻ��Ϊinfo��־ */
Dbfw_LogFile npc_errlog_file;   /* ��Ϊerr��־ */

Dbfw_ErrorLog error_log;
Dbfw_DebugLog debug_log;
Dbfw_WarnLog warn_log;
Dbfw_InfoLog info_log;

/* capture related options */
capture_options global_capture_opts;
/* 2014-09-10 �����ڴ泬�ޱ��(ȫ��) */
u_char      __OUT_OF_MEMORY_FLAG = 0;   /* 0-δ����(Ĭ��) 1-���� */
/* 2014-09-11 ��������NPP��Ϣ������ */
npp_info    __NPP_INFO[DBFW_MAX_SESSIONS];  /* DBFW_MAX_SESSIONS������ */
/* 2014-09-15 ���Ӵ���ID�ֶ� */
u_char      __DISKIDCRC[128] = {0};     /*����id*/
u_char      __TODAY_ISSYNC_FLAG = 0;        /* �����賿5���Npc_SyncSessionWithClientAndBSList��ִ�б�� */
/***************************************����������ʼ*******************************/

/** Stop a low-level capture (stops the capture child). */
void capture_loop_stop(void);

void capture_loop_write_packet_cb(u_char *pcap_opts_p, const struct pcap_pkthdr *phdr,
										 const u_char *pd);

int get_pcap_linktype(pcap_t *pch, const char *devname);
void exit_main(int err) ;

void report_packet_drops(guint32 received, guint32 drops, gchar *name);
void report_capture_error(const char *error_msg, const char *secondary_error_msg);
void report_cfilter_error(capture_options *capture_opts, guint i, const char *errmsg);

void Npc_PrintThroughput(void);

void* Npc_UpdateHeartbeat(void *arg);
void* Npc_CreateNppThread(void *arg);

int GetIntParamInFixarray(u_char* sga, u_short param_index);

/**********************************************
**
**	�������ݿ��IP�Ͷ˿ڣ����npp�������ȷ����(npp_ora,npp_mssql,npp_mysql,npp_dm,npp_db2...)
**  ���������
**      npp_name:���npp�������ƣ���Ҫ���ⲿ����ռ�
**	RETURN
**		<0: error, return errno
**		=0: ok
**
**********************************************/
int Npc_GetNppnameForDB(u_int server_ip, u_short server_port, u_char *npp_name, u_int npp_name_size);
/**********************************************
**
**	��ACBuf�м���db��ַ��hashmap��
**	RETURN
**		<0: error, return errno
**		=0: ok
**
**********************************************/
int Npc_LoadDBAddress(Dbfw_Sga_ACBuf *acbuf, Npc_HashPool *db_hashmap);
/*******************************************
**
**	��ʼ��ȫ�����ݵĽṹ��
**
*******************************************/
int Npc_InitGlobalLoopData(int shm_id, u_char *shm_addr, u_int offset_for_capbuf);
int Npc_OpenDevice(capture_options *capture_opts);
gboolean capture_loop_start(capture_options *capture_opts, struct pcap_stat *stats);

/*
    2014-06-02 ����°汾�ĻỰ���Һ�������
*/
u_short Npc_FindSessionWithClient(u_int64 key);     /* ���Npc_HashmapFind */
int Npc_SetSessionWithClient(u_int64 key, u_short value, u_short dialect, u_char is_dynaport, int sem_id=-1);    /* ���Npc_HashmapInsert */
int Npc_ClearSessionWithClient();   /* ���Npc_HashmapClear */
/***************************************������������*******************************/

#define MSG_MAX_LENGTH 4096

static void bsllist_enum_sessions(FILE *fp,u_int64 key,void *data)
{
#ifdef USE_BSLHASH_FORSESSION
    Npc_SessionWithClient *tmp_sessionwithclient = NULL;
    tmp_sessionwithclient = (Npc_SessionWithClient*)data;
    NPC_NEW_LOG(INFO_LEVEL, info_log, "bellist client_key=%llu, session_id=%u, _sem_id=%u, timestamp_for_createcpp=%llu",tmp_sessionwithclient->client_key,tmp_sessionwithclient->session_id,tmp_sessionwithclient->_sem_id,tmp_sessionwithclient->timestamp_for_createcpp);
    DBFW_INFO_PRINT(&npc_log_file, &info_log);
#endif
}

void NPC_GetLocalTime_Now(struct tm *tm_current)
{
    struct tm tm1;
#ifdef WIN32
    time_t lt;
    lt =time(NULL);
    tm1 = *localtime(&lt);
#else
    time_t lt;
    lt =time(NULL);
    localtime_r(&lt, &tm1 );
#endif
    memcpy(tm_current,&tm1,sizeof(tm1));
}

u_int64 NPC_GetEpochTime(void)
{
    struct timeval          current_timeval;
    gettimeofday(&current_timeval, NULL);
    return (u_int64)current_timeval.tv_sec;
}
u_short Npc_FindSessionWithClient(u_int64 key)
{
    int i = 0;
    int ret = 0;
    u_short session_id = 0;
    u_int clientip;
    u_short clientport;
#ifdef USE_BSLHASH_FORSESSION
    Npc_SessionWithClient *tmp_sessionwithclient = NULL;
    tmp_sessionwithclient = (Npc_SessionWithClient*)Bslhash_Find((Bslhash_t*)global_ld.mem_sess_bslist,key);
    if(tmp_sessionwithclient!=NULL)
    {
        if(tmp_sessionwithclient->client_key==key)
        {
            /* 
                ��Ҫ�ķ����߼��� 
                �����ӳص�״̬�£��ý��̵��ź����ǲ��رյģ����ԸûỰ���ᱻ����
            */
            session_id = tmp_sessionwithclient->session_id;
            clientport = (u_short)(key&0xFFFF);
            clientip = (u_int)(key>>16);
            if(global_ld.session_array->sessions_used[session_id]==DBFW_SESSIONARRAY_FLAG_USED &&
               global_ld.session_array->clientip[session_id]==clientip &&
               global_ld.session_array->clientport[session_id]==clientport
              )
            {
                /* �����ڵ���Ϣ��SGA������Ϣһ�� */
                return tmp_sessionwithclient->session_id;
            }
            else
            {
                /* ��Ϣ��һ���ˣ���Ҫ���� */
                //printf("closed session for clientip=%u, clientport=%d\n",clientip,clientport);
                global_ld.session_withclients[session_id].client_key = 0;
                global_ld.session_withclients[session_id]._sem_id = -1;
                global_ld.session_withclients[session_id].timestamp_for_createcpp = 0;
                global_ld.session_withclients[session_id].dialect = 0;
                global_ld.session_withclients[session_id].is_dynaport = 0;
                ret = Bslhash_Delete((Bslhash_t*)global_ld.mem_sess_bslist,key);
                if(ret<0)
                {
                    /* ʧ���� */
                    NPC_NEW_LOG(INFO_LEVEL, info_log, "Bslhash_Delete is fail for key=%llu errorNo=%d",key,ret);
                    DBFW_INFO_PRINT(&npc_log_file, &info_log);
                }
#ifdef HAVE_LIBTIS
                /* ǿ���ͷ�capbuf��λ */
                Tis_Slot_Close(global_ld.tis,session_id);
#endif
                return NPC_HASHMAP_NOT_FIND_KEY;
            }
        }
    }
    return NPC_HASHMAP_NOT_FIND_KEY;
#else
    for(i=(DBFW_MAX_SESSIONS-1);i>0;i--)
    {
        if(global_ld.session_withclients[i].client_key==key)
        {
            return i;
        }
    }
    return NPC_HASHMAP_NOT_FIND_KEY;
#endif
}

/**********************************************
**
**	�������ݿ��IP�Ͷ˿ڣ����Ŀ�����ݿ�����(dialect)
**	RETURN
**		=0: δ֪���͵����ݿ�
**		>0: ok
**
**********************************************/
u_short Npc_GetDBDialectForServer(u_int server_ip, u_short server_port)
{
    u_int64 key = 0;
    u_int64 key_dbtype_bucket = 0;
    u_int i = 0;
    u_short dialect = 0;

    key = (u_int64)server_ip;
    key = ((key<<16)|server_port);
    key_dbtype_bucket = key%DBFW_MAX_PROTECTED_DATABASE;
    if(global_ld.dbtype_bucket[key_dbtype_bucket].dbcount>0)
    {
        for(i=0;i<global_ld.dbtype_bucket[key_dbtype_bucket].dbcount;i++)
        {
            if(global_ld.dbtype_bucket[key_dbtype_bucket].dbserver_key[i]==key)
            {
                dialect = global_ld.dbtype_bucket[key_dbtype_bucket].dialect[i];
                return dialect;
            }
        }
        return 0;
    }
    else
    {
        /* û�пɹ����ҵ����ݣ�ֱ�ӷ���0 */
        return 0;
    }
}


/**********************************************
**
**	�������ݿ��IP�Ͷ˿ڣ����npp�������ȷ����(npp_ora,npp_mssql,npp_mysql,npp_dm,npp_db2...)
**  ���������
**      npp_name:���npp�������ƣ���Ҫ���ⲿ����ռ�
**	RETURN
**		<0: error, return errno
**		=0: ok
**
**********************************************/
int Npc_GetNppnameForDB(u_int server_ip, u_short server_port, u_char *npp_name, u_int npp_name_size)
{
    u_int64 key = 0;
    u_int64 key_dbtype_bucket = 0;
    u_int i = 0;
    u_short dialect = 0;

    key = (u_int64)server_ip;
    key = ((key<<16)|server_port);
    key_dbtype_bucket = key%DBFW_MAX_PROTECTED_DATABASE;
    if(global_ld.dbtype_bucket[key_dbtype_bucket].dbcount>0)
    {
        for(i=0;i<global_ld.dbtype_bucket[key_dbtype_bucket].dbcount;i++)
        {
            if(global_ld.dbtype_bucket[key_dbtype_bucket].dbserver_key[i]==key)
            {
                dialect = global_ld.dbtype_bucket[key_dbtype_bucket].dialect[i];
                break;
            }
        }
        memset(npp_name,0x00,npp_name_size);
        switch (dialect)
        {
            case DBFW_DBTYPE_ORACLE:    /* Oracle���ݿ� */
                strcpy((char*)npp_name,(char*)"npp_ora");
        	    break;
            case DBFW_DBTYPE_MSSQL:     /* MSSQL���ݿ� */
                strcpy((char*)npp_name,(char*)"npp_mssql");
                break;
            case DBFW_DBTYPE_DB2:       /* Db2���ݿ� */
                strcpy((char*)npp_name,(char*)"npp_db2");
                break;
            case DBFW_DBTYPE_MYSQL:     /* mysql���ݿ� */
            case DBFW_DBTYPE_SHENTONG:  /* gbase���ݿ� */
                strcpy((char*)npp_name,(char*)"npp_mysql");
                break;
            case DBFW_DBTYPE_DM:        /* �������ݿ� */
                strcpy((char*)npp_name,(char*)"npp_dm");
                break;
            default:
                strcpy((char*)npp_name,(char*)"npp");
                break;
        }

        return 0;
    }
    else
    {
        /* û�пɹ����ҵ����ݣ�ֱ�ӷ���npp */
        memset(npp_name,0x00,npp_name_size);
        strcpy((char*)npp_name,(char*)"npp");
        return 0;
    }
}

int Npc_SetSessionWithClient(u_int64 key, u_short value, u_short dialect, u_char is_dynaport, int sem_id)
{
    /* �Ȳ����Ƿ��и�key�ĻỰ������������ø�sessionֵ��Ȼ��value��Ӧ�Ĳ�λ��key��sem_id���� */
    int i = 0;
    int ret = 0;
    u_short session_id = 0;
    u_int64 del_bslhash_key = 0;
    u_int64 current_timestamp_for_createnpp = 0;
    if(value>=DBFW_MAX_SESSIONS)
    {
        /* ���Ϸ���sessionֵ */
        return -2;
    }
    current_timestamp_for_createnpp = NPC_GetEpochTime();
#ifdef USE_BSLHASH_FORSESSION
    /* �ȴ�hash�����в����Ƿ�����Ӧ��key */
    Npc_SessionWithClient *tmp_sessionwithclient = NULL;
    tmp_sessionwithclient = (Npc_SessionWithClient*)Bslhash_Find((Bslhash_t*)global_ld.mem_sess_bslist,key);
    if(tmp_sessionwithclient!=NULL)
    {
        /* �ҵ��ò�λ��,����ֵ */
        {
            /* �ҵ��ò�λ��,����ֵ */
//             if(global_ld.session_withclients[tmp_sessionwithclient->session_id].client_key==key)
//             {
//                 /* �ҵ��ò�λ��,����ֵ */
//                 global_ld.session_withclients[tmp_sessionwithclient->session_id].client_key = 0;
//                 global_ld.session_withclients[tmp_sessionwithclient->session_id]._sem_id = -1;
//             }
            /* ����mem_sess_bslist */
            session_id = tmp_sessionwithclient->session_id;
            if(global_ld.session_withclients[session_id].client_key>0 && 
               global_ld.session_withclients[session_id].client_key != key
              )
            {
                /* ������session_withclients�еĻỰ�Ѿ�ʧЧ������������������Ҫ����mem_sess_bslist */
                del_bslhash_key = global_ld.session_withclients[session_id].client_key;
                ret = Bslhash_Delete((Bslhash_t*)global_ld.mem_sess_bslist,del_bslhash_key);
                if(ret<0)
                {
                    /* ʧ���� */
                    NPC_NEW_LOG(INFO_LEVEL, info_log, "Bslhash_Delete is fail for key=%llu errorNo=%d",del_bslhash_key,ret);
                    DBFW_INFO_PRINT(&npc_log_file, &info_log);
                }
            }
            /* 
                ����session_withclients��������ݣ��������������̵߳���Npc_ClearSessionWithClient����ʱ������������˵�ǰ�ĻỰ 
                ���Գ�����ʹ��loadrunner.pcap����������жϴ�����򣬵ȹ�5������´������������ÿ���3�����������һ��NPP����
                ��������Ŀǰֻ�������δ��ʹ�õ���ͬһ��clientIP+Port������³���
            */
            global_ld.session_withclients[session_id].client_key = 0;
            global_ld.session_withclients[session_id]._sem_id = 0;
            global_ld.session_withclients[session_id].session_id = 0;
            global_ld.session_withclients[session_id].timestamp_for_createcpp = 0;
            global_ld.session_withclients[session_id].dialect = 0;
            global_ld.session_withclients[session_id].is_dynaport = 0;
            /* ������� */
            tmp_sessionwithclient->client_key = key;
            tmp_sessionwithclient->_sem_id = sem_id;
            tmp_sessionwithclient->session_id = value;
            tmp_sessionwithclient->timestamp_for_createcpp = current_timestamp_for_createnpp;
            tmp_sessionwithclient->dialect = dialect;
            tmp_sessionwithclient->is_dynaport = is_dynaport;
            /* ����session��λ������ */
            global_ld.session_withclients[value].client_key = key;
            global_ld.session_withclients[value]._sem_id = sem_id;
            global_ld.session_withclients[value].timestamp_for_createcpp = current_timestamp_for_createnpp;
            global_ld.session_withclients[value].dialect = dialect;
            global_ld.session_withclients[value].is_dynaport = is_dynaport;
            return value;
        }
    }
    else
    {
        /* 
            û���ҵ����ʵĲ�λ������µ� 
            �����ǰ��Ҫ����Ƿ�����Ҫ�����mem_sess_bslistԪ��
        */
        session_id = value;
        if(global_ld.session_withclients[session_id].client_key>0 && 
            global_ld.session_withclients[session_id].client_key != key
            )
        {
            /* ������session_withclients�еĻỰ�Ѿ�ʧЧ������������������Ҫ����mem_sess_bslist */
            del_bslhash_key = global_ld.session_withclients[session_id].client_key;
            ret = Bslhash_Delete((Bslhash_t*)global_ld.mem_sess_bslist,del_bslhash_key);
            if(ret<0)
            {
                /* ʧ���� */
                NPC_NEW_LOG(INFO_LEVEL, info_log, "Bslhash_Delete is fail for key=%llu errorNo=%d",del_bslhash_key,ret);
                DBFW_INFO_PRINT(&npc_log_file, &info_log);
            }
        }
        tmp_sessionwithclient = (Npc_SessionWithClient*)malloc(sizeof(Npc_SessionWithClient));
        memset(tmp_sessionwithclient,0x00,sizeof(Npc_SessionWithClient));
        tmp_sessionwithclient->client_key = key;
        tmp_sessionwithclient->_sem_id = sem_id;
        tmp_sessionwithclient->session_id = value;
        tmp_sessionwithclient->timestamp_for_createcpp = current_timestamp_for_createnpp;
        tmp_sessionwithclient->dialect = dialect;
        tmp_sessionwithclient->is_dynaport = is_dynaport;
        ret = Bslhash_Insert((Bslhash_t*)global_ld.mem_sess_bslist,key,(void*)tmp_sessionwithclient,0);
        free(tmp_sessionwithclient);
        tmp_sessionwithclient = NULL;
        /* ����session��λ������ */
        global_ld.session_withclients[value].client_key = key;
        global_ld.session_withclients[value]._sem_id = sem_id;
        global_ld.session_withclients[value].timestamp_for_createcpp = current_timestamp_for_createnpp;
        global_ld.session_withclients[value].dialect = dialect;
        global_ld.session_withclients[value].is_dynaport = is_dynaport;
        return value;
    }
#else
    /* 
        2014-06-13 ���
        �����ϲ������������߼� 
        �����ڳ��֡��ظ��˿ھ���ʱ�������������������ͬclient_key��SYN������ɳ�����������������Ҫ����
    */
    for(i=(DBFW_MAX_SESSIONS-1);i>0;i--)
    {
        if(global_ld.session_withclients[i].client_key==key)
        {
            /* �ҵ��ò�λ��,����ֵ */
            global_ld.session_withclients[i].client_key = 0;
            global_ld.session_withclients[i]._sem_id = -1;
            global_ld.session_withclients[i].timestamp_for_createcpp = 0;
            global_ld.session_withclients[i].dialect = 0;
            global_ld.session_withclients[i].is_dynaport = 0;
        }
    }
    /* ����session��λ������ */
    global_ld.session_withclients[value].client_key = key;
    global_ld.session_withclients[value]._sem_id = sem_id;
    global_ld.session_withclients[value].timestamp_for_createcpp = current_timestamp_for_createnpp;
    global_ld.session_withclients[value].dialect = dialect;
    global_ld.session_withclients[value].is_dynaport = is_dynaport;
    return value;
#endif
}
int Npc_ClearSessionWithClient()
{
    int i = 0;
    u_int64 key = 0;
    int ret = 0;
    u_int clientip = 0;
    u_short clientport = 0;
    __TOTAL_SESSION_COUNT = 0;
    u_int   close_sessionid = 0;
    for(i=(DBFW_MAX_SESSIONS-1);i>0;i--)
    {
        if(global_ld.session_withclients[i].client_key>0)
        {
            /* �ò�λ��һ��client��Ӧ��Ҳ����ʹ�õ�session */
            key = global_ld.session_withclients[i].client_key;
            clientport = (u_short)(key&0xFFFF);
            clientip = (u_int)(key>>16);

            if((global_ld.session_array->sessions_used[i] != DBFW_SESSIONARRAY_FLAG_USED) ||
               (global_ld.session_array->clientip[i]!=clientip) ||
               (global_ld.session_array->clientport[i]!=clientport) ||
               (global_ld.session_withclients[i]._sem_id>=0 && Dbfw_GetSemValue(global_ld.session_withclients[i]._sem_id)==-1)
              )
            {
                /* �ûỰ�Ѿ��������ˣ�ֱ������ */
                close_sessionid = i;
                key = global_ld.session_withclients[i].client_key;
                global_ld.session_withclients[i].client_key = 0;
                global_ld.session_withclients[i]._sem_id = -1;
                global_ld.session_withclients[i].timestamp_for_createcpp = 0;
                global_ld.session_withclients[i].dialect = 0;
                global_ld.session_withclients[i].is_dynaport = 0;
                /* ɾ��hash�����е����� */
#ifdef USE_BSLHASH_FORSESSION
                ret = Bslhash_Delete((Bslhash_t*)global_ld.mem_sess_bslist,key);
                if(ret<0)
                {
                    /* ʧ���� */
                    NPC_NEW_LOG(INFO_LEVEL, info_log, "Bslhash_Delete is fail for key=%llu errorNo=%d",key,ret);
                    DBFW_INFO_PRINT(&npc_log_file, &info_log);
                }
#endif
#ifdef HAVE_LIBTIS
                /* ǿ���ͷ�capbuf��λ */
                Tis_Slot_Close(global_ld.tis,close_sessionid);
#endif
            }
            else if(global_ld.session_withclients[i]._sem_id<0)
            {
                close_sessionid = i;
                key = global_ld.session_withclients[i].client_key;
                global_ld.session_withclients[i].client_key = 0;
                global_ld.session_withclients[i]._sem_id = -1;
                global_ld.session_withclients[i].timestamp_for_createcpp = 0;
                global_ld.session_withclients[i].dialect = 0;
                global_ld.session_withclients[i].is_dynaport = 0;
#ifdef USE_BSLHASH_FORSESSION
                ret = Bslhash_Delete((Bslhash_t*)global_ld.mem_sess_bslist,key);
                if(ret<0)
                {
                    /* ʧ���� */
                    NPC_NEW_LOG(INFO_LEVEL, info_log, "Bslhash_Delete is fail for key=%llu errorNo=%d",key,ret);
                    DBFW_INFO_PRINT(&npc_log_file, &info_log);
                }
#endif
#ifdef HAVE_LIBTIS
                /* ǿ���ͷ�capbuf��λ */
                Tis_Slot_Close(global_ld.tis,close_sessionid);
#endif
            }
            else
            {
                __TOTAL_SESSION_COUNT = __TOTAL_SESSION_COUNT + 1;
            }
        }
    }
    return 0;
}

/* 
    ��session_withclients��������mem_sess_bslist������ͬ�� 
    ������Ҫ����������ÿ���賿5��ִ��һ�μ���
*/
int Npc_SyncSessionWithClientAndBSList()
{
    int i = 0;
    u_int64 key = 0;
    int ret = 0;
    int bslhash_element_count = 0;
    Npc_SessionWithClient *tmp_sessionwithclient = NULL;

#ifdef USE_BSLHASH_FORSESSION    
    __TOTAL_SESSION_COUNT = 0;
    /* ������mem_sess_bslist */
    Bslhash_Clear((Bslhash_t*)global_ld.mem_sess_bslist);
    for(i=(DBFW_MAX_SESSIONS-1);i>0;i--)
    {
        if(global_ld.session_withclients[i].client_key>0)
        {
            /* �ò�λ��һ��client��Ӧ��Ҳ����ʹ�õ�session */
            if(global_ld.session_withclients[i]._sem_id>=0 && Dbfw_GetSemValue(global_ld.session_withclients[i]._sem_id)==-1)
            {
                /* �ûỰ�Ѿ��������ˣ�ֱ������ */
                key = global_ld.session_withclients[i].client_key;
                global_ld.session_withclients[i].client_key = 0;
                global_ld.session_withclients[i]._sem_id = -1;
                global_ld.session_withclients[i].timestamp_for_createcpp = 0;
                global_ld.session_withclients[i].dialect = 0;
                global_ld.session_withclients[i].is_dynaport = 0;
            }
            else if(global_ld.session_withclients[i]._sem_id<0)
            {
                key = global_ld.session_withclients[i].client_key;
                global_ld.session_withclients[i].client_key = 0;
                global_ld.session_withclients[i]._sem_id = -1;
                global_ld.session_withclients[i].timestamp_for_createcpp = 0;
                global_ld.session_withclients[i].dialect = 0;
                global_ld.session_withclients[i].is_dynaport = 0;
            }
            else
            {
                __TOTAL_SESSION_COUNT = __TOTAL_SESSION_COUNT + 1;
                /* ���뵽mem_sess_bslist */
                key = global_ld.session_withclients[i].client_key;
                tmp_sessionwithclient = (Npc_SessionWithClient*)malloc(sizeof(Npc_SessionWithClient));
                memset(tmp_sessionwithclient,0x00,sizeof(Npc_SessionWithClient));
                tmp_sessionwithclient->client_key = global_ld.session_withclients[i].client_key;
                tmp_sessionwithclient->_sem_id = global_ld.session_withclients[i]._sem_id;
                tmp_sessionwithclient->session_id = i;
                tmp_sessionwithclient->timestamp_for_createcpp = global_ld.session_withclients[i].timestamp_for_createcpp;
                tmp_sessionwithclient->dialect = global_ld.session_withclients[i].dialect;
                tmp_sessionwithclient->is_dynaport = global_ld.session_withclients[i].is_dynaport;
                ret = Bslhash_Insert((Bslhash_t*)global_ld.mem_sess_bslist,key,(void*)tmp_sessionwithclient,0);
                free(tmp_sessionwithclient);
                tmp_sessionwithclient = NULL;
            }
        }
    }
#endif
    return 0;
}

void print_usage(char *argv[], int use_filter)
{
	if(use_filter)
	{
		//printf( "Usage: %s -m shm_id -d device_name -i npc_id\n\t[-l] list network device name\n\t[-s] print capturing packets statistics\n\t[-h] help\n", argv[0]);
		printf( "Usage: %s -m shm_id -d device_name -i npc_id\n", argv[0]);
	}
	else
	{
		//printf( "Usage: %s -m shm_id -d device_name -f filter_expression\n\t[-l] list network device name\n\t[-s] print capturing packets statistics\n\t[-h] help\n", argv[0]);
		printf( "Usage: %s -m shm_id -d device_name -f filter_expression\n", argv[0]);
	}
}

/***********************************************************************
**
** NAME
**      Npp_GetSessionWithClient
**
** DESCRIPTION
**      get sessionid that bind to clientip and port
**      
** PARAM
**      clientip : client ip address of DBMS,ip4+ip3*255+ip2*255*255+ip1*255*255*255
**      port : client port
** RETURN
**      >0:bind session id
**      65535:no session for client
**      -1:error
**      
************************************************************************
*/
// int Npc_GetSessionWithClient(
//                              /* client ip addr */    u_int64 clientip,
//                              /* client port */       u_short port)
// {
//     int     ret = 0;
//     u_int   i;
//     u_int   sessionid = 65535;
//     for(i=0;i<DBFW_MAX_SESSIONS;i++)
//     {
//         if((__NPC_SGA_SESSBUF->session_array->clientip[i]==clientip) && (__NPC_SGA_SESSBUF->session_array->clientport[i]==port))
//         {
//             /* is exists */
//             sessionid = i;
//             break;
//         }
//     }
//     return sessionid;
// }

void npc_print_version(char *module)
{
	printf("\n");
//	printf("XSecure DBFirewall Enterprise Edition Release %s.%s.%s Build %s %s\n",DBFW_VERSION_MAX,DBFW_VERSION_MIN,DBFW_VERSION_PATCH,BUILD_DATE,BUILD_SVN);
//	printf("Copyright by SChina\n");
//	printf("web:    www.schina.cn\n");
	printf("Release %s.%s.%s Build %s %s\n",DBFW_VERSION_MAX,DBFW_VERSION_MIN,DBFW_VERSION_PATCH,BUILD_DATE,BUILD_SVN);
#ifdef CK_LICENCE_TIME 
	printf("Module: %s(CK_LICENCE_TIME)\n",module);
#else
	printf("Module: %s\n",module);
#endif
    printf("With Option(LICENSE");
#ifdef HAVE_SPLIT_NPP
    printf(",SPLIT_NPP");
#endif
#ifdef HAVE_LIBTIS 
	printf(",Tis");
#endif
#ifdef USE_FILTER
    printf(",USE_FILTER");
#endif
#ifdef HAVE_NOCONNECT_SESSION
    printf(",HAVE_NOCONNECT_SESSION");
#endif
#ifdef HAVE_SPLIT_NPP
    printf(",HAVE_SPLIT_NPP");
#endif
#ifdef PRINT_THROUGHPUT
    printf(",PRINT_THROUGHPUT");
#endif
#ifdef USE_BSLHASH_FORSESSION 
    printf(",USE_BSLHASH_FORSESSION");
#endif
#ifdef NPC_USE_SYNANDACK_START 
    printf(",NPC_USE_SYNANDACK_START");
#endif
	printf(")\n");
//����License������£���Ҫ�����Ƿ�Ϊ���˵�License����
#ifndef NO_LICENCE
	Dbfw_sGetVendorInfor(); 
#endif 	
}

/*******************************************
**
**	���ϵͳLicense
**  ������������ÿ�ν��д���License��鹦�ܵ�Npc_CheckLicense_WithDiskCheck�������Ѿ���������ʹ����
**  ckType: 
**        0-���ʱ��License
**        1-������License
**        2-ȫ�����
**
*******************************************/
int Npc_CheckLicense(int ckType)
{
    int ret = 0;
    int license_result_old = 0;
    time_t current_time;
    license_result_old = global_ld.license_result;
#ifdef NO_LICENCE
    /* ��������ж����˲�����License��� */
    global_ld.license_result = 1;       /* ��ʼ��ΪLicense���Ϊͨ�� */    
#else
    current_time = time(NULL);
    if(global_ld.license_result==ERROR_GETDISKID || global_ld.license_result==ERROR_CKDISK)
    {
        /* ��ǰ��License�����Ϊ���̲����� */
        if(ckType<NPC_CK_LICENSE_DISK)
        {
            /* ���Ҫ���еļ��ֻ��ʱ�䣬����Ҫ�ٽ��м���� */
            global_ld.license_checktime = current_time;
            return global_ld.license_result;
        }
        else
        {
            /* ��������ȻҪ�����̵�License������� */
        }
    }
    if(global_ld.license_checktime==0 || global_ld.license_checktime>current_time || global_ld.license_checktime<(current_time-60))
    {
        /* ����ʱ���Ҫ��:ʱ�䱻���ˣ��򳬹���60�룬���һ�μ��,��Ҫ���¼��License */
        //if(global_ld.license_result == 0)
        {
            /* ֮ǰû�н��й�License��� */
            switch (ckType)
            {
                case NPC_CK_LICENSE_TIME: /* ���ʱ�� */
                    ret = Dbfw_sCheckLicenseFile_Time();
            	    break;
                case NPC_CK_LICENSE_DISK: /* ������ */
                    ret = Dbfw_sCheckLicenseFile_Disk();
                    break;
                case NPC_CK_LICENSE_ALL: /* ���ȫ�� */
                    ret = Dbfw_sCheckLicenseFile();
                    break;
                default:
                    ret = 0;
                    break;
            }            
            
            if(ret<0)
            {
                /* License���ʧ�� */
                global_ld.license_result = ret;
            }
            else
            {
                /* License���ɹ� */
                global_ld.license_result = 1;
            }
        }
        global_ld.license_checktime = current_time;
    }    
#endif
    /* ��ӡLicense���Ľ�� */
    if(license_result_old!=global_ld.license_result)
    {
        printf("License Check Result = %d\n",global_ld.license_result);
    }
    return global_ld.license_result;
}

/*******************************************
**
**	���ϵͳLicense
**  ��������֧��ÿ�ν��д���License�����°汾License��麯��
**  �ڵ�һ�μ��ʱ��ҪrootȨ�޲��һ�ô��̵�ID��֮��ֱ��ͨ������ID��У��License
**  ckType: 
**        0-��һ�ν��뱾��������Ҫ��ȡ����ID���������ROOTȨ��(NPC_CK_LICENSE_GETDISKID)
**        1-���ǵ�һ�ν��룬����Ҫ��ȡ����ID��(NPC_CK_LICENSE_HAVEDISKID)
**
*******************************************/
int Npc_CheckLicense_WithDiskCheck(int ckType)
{
    int ret = 0;
    int license_result_old = 0;
    time_t current_time;
    int loopcount = 3;  /* ѭ����ȡ����ID�Ĵ��� */
    int i = 0;
    license_result_old = global_ld.license_result;
#ifdef NO_LICENCE
    /* ��������ж����˲�����License��� */
    global_ld.license_result = 1;       /* ��ʼ��ΪLicense���Ϊͨ�� */    
#else
    current_time = time(NULL);
    if(global_ld.license_checktime==0 || global_ld.license_checktime>current_time || global_ld.license_checktime<(current_time-10))
    {
        /* ����ʱ���Ҫ��:ʱ�䱻���ˣ��򳬹���10�룬���һ�μ��,��Ҫ���¼��License */
        //if(global_ld.license_result == 0)
        {
            /* ֮ǰû�н��й�License��� */
            switch (ckType)
            {
            case NPC_CK_LICENSE_GETDISKID: /* ��һ�ν��뱾��������Ҫ��ȡ����ID���������ROOTȨ�� */
                for(i=0;i<loopcount;i++)
                {
                    ret = Dbfw_sGetDiskIdCRCLVM((char* )__DISKIDCRC);
                    if(ret<0)
                    {
                        /* ��ȡʧ�ܣ����»�ȡһ�� */
                        memset(__DISKIDCRC,0x00,sizeof(__DISKIDCRC));
                    }
                    else
                    {
                        /* ��ȡ�ɹ� */
                        break;
                    }
                }
                if(__DISKIDCRC[0]==0x00 && __DISKIDCRC[1]==0x00)
                {
                    /* ǰ�波��3�λ�ȡ����ID��ʧ����,����һ��ȱʡ�Ĵ���ID */
                    strcpy((char*)__DISKIDCRC,(char*)"1234567890123456");
                }
                /* �ȼ�����License */
                ret = Dbfw_sCheckLicenseFile_Disk((char *)__DISKIDCRC); 
                if(ret<0)
                {
                    /* ����License���ʧ�� */
                    break;
                }
                /* ���ʱ��License */
                ret = Dbfw_sCheckLicenseFile_Time();
                break;
            case NPC_CK_LICENSE_HAVEDISKID: /* ���ǵ�һ�ν��룬����Ҫ��ȡ����ID�� */
                /* �ȼ�����License */
                ret = Dbfw_sCheckLicenseFile_Disk((char *)__DISKIDCRC); 
                if(ret<0)
                {
                    /* ����License���ʧ�� */
                    break;
                }
                /* ���ʱ��License */
                ret = Dbfw_sCheckLicenseFile_Time();
                break;
            default:
                ret = 0;
                break;
            }            

            if(ret<0)
            {
                /* License���ʧ�� */
                global_ld.license_result = ret;
            }
            else
            {
                /* License���ɹ� */
                global_ld.license_result = 1;
            }
        }
        global_ld.license_checktime = current_time;
    }    
#endif
    /* ��ӡLicense���Ľ��(ֻ����License���Ľ�������仯ʱ�Ŵ�ӡ) */
    if(license_result_old!=global_ld.license_result)
    {
        printf("License Check Result = %d\n",global_ld.license_result);
    }
    return global_ld.license_result;
}

pcap_t *open_capture_device(interface_options *interface_opts,
							char (*open_err_str)[PCAP_ERRBUF_SIZE])
{
	pcap_t *pcap_h;
#ifdef HAVE_PCAP_CREATE
	int         err;
#endif

	/* Open the network interface to capture from it.
	Some versions of libpcap may put warnings into the error buffer
	if they succeed; to tell if that's happened, we have to clear
	the error buffer, and check if it's still a null string.  */

	NPC_NEW_LOG(INFO_LEVEL, info_log, "Open network device %s.", interface_opts->name);
	DBFW_INFO_PRINT(&npc_log_file, &info_log);

	(*open_err_str)[0] = '\0';

	/*
	* If we're not opening a remote device, use pcap_create() and
	* pcap_activate() if we have them, so that we can set the buffer
	* size, otherwise use pcap_open_live().
	*/
	//#ifdef HAVE_PCAP_CREATE
	//	
	//	pcap_h = pcap_create(interface_opts->name, *open_err_str);
	//	
	//	if (pcap_h != NULL) {
	//		/* set max length of packet to be captured */
	//		pcap_set_snaplen(pcap_h, interface_opts->snaplen);
	//			
	//		pcap_set_promisc(pcap_h, interface_opts->promisc_mode);
	//		pcap_set_timeout(pcap_h, CAP_READ_TIMEOUT);
	//
	//			
	//		if (interface_opts->buffer_size > 1) {
	//			pcap_set_buffer_size(pcap_h, interface_opts->buffer_size * 1024 * 1024);
	//		}
	//
	//		err = pcap_activate(pcap_h);
	//
	//		if (err < 0) {
	//			/* Failed to activate, set to NULL */
	//			if (err == PCAP_ERROR)
	//				g_strlcpy(*open_err_str, pcap_geterr(pcap_h), sizeof *open_err_str);
	//			else
	//				g_strlcpy(*open_err_str, pcap_statustostr(err), sizeof *open_err_str);
	//			pcap_close(pcap_h);
	//			pcap_h = NULL;
	//		}
	//	}
	//#else/*ִ�д˴�*/
	pcap_h = pcap_open_live(interface_opts->name, interface_opts->snaplen,
		interface_opts->promisc_mode, CAP_READ_TIMEOUT,
		*open_err_str);
	//printf("[Info]: No #define HAVE_PCAP_CREATE\n");
	//#endif

	return pcap_h;
}


/* Set the data link type on a pcap. */
gboolean
set_pcap_linktype(pcap_t *pcap_h, int linktype,
				  char *name,
				  char *errmsg, size_t errmsg_len,
				  char *secondary_errmsg, size_t secondary_errmsg_len)
{
	char *set_linktype_err_str;

	if (linktype == -1)
		return TRUE; /* just use the default */
#ifdef HAVE_PCAP_SET_DATALINK
	if (pcap_set_datalink(pcap_h, linktype) == 0)
		return TRUE; /* no error */
	set_linktype_err_str = pcap_geterr(pcap_h);
#else
	/* Let them set it to the type it is; reject any other request. */
	if (get_pcap_linktype(pcap_h, name) == linktype)
		return TRUE; /* no error */
	set_linktype_err_str =
		"That DLT isn't one of the DLTs supported by this device";
#endif
	g_snprintf(errmsg, (gulong) errmsg_len, "Unable to set data link type (%s).",
		set_linktype_err_str);
	/*
	* If the error isn't "XXX is not one of the DLTs supported by this device",
	* tell the user to tell the Wireshark developers about it.
	*/
	if (strstr(set_linktype_err_str, "is not one of the DLTs supported by this device") == NULL)
		g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len, please_report);
	else
		secondary_errmsg[0] = '\0';
	return FALSE;
}

gboolean
compile_capture_filter(const char *iface, 
						pcap_t *pcap_h,
						struct bpf_program *fcode, 
						const char *cfilter)
{
	bpf_u_int32 netnum, netmask;
	gchar       lookup_net_err_str[PCAP_ERRBUF_SIZE];

	if (pcap_lookupnet(iface, &netnum, &netmask, lookup_net_err_str) < 0) {
		/*
		* Well, we can't get the netmask for this interface; it's used
		* only for filters that check for broadcast IP addresses, so
		* we just punt and use 0.  It might be nice to warn the user,
		* but that's a pain in a GUI application, as it'd involve popping
		* up a message box, and it's not clear how often this would make
		* a difference (only filters that check for IP broadcast addresses
		* use the netmask).
		*/
		/*cmdarg_err(
		"Warning:  Couldn't obtain netmask info (%s).", lookup_net_err_str);*/
		netmask = 0;
	}

	/*
	* Sigh.  Older versions of libpcap don't properly declare the
	* third argument to pcap_compile() as a const pointer.  Cast
	* away the warning.
	*/
	NPC_NEW_LOG(INFO_LEVEL, info_log,"calling pcap_compile()", cfilter);
	DBFW_INFO_PRINT(&npc_log_file, &info_log);
	if (pcap_compile(pcap_h, fcode, (char *)cfilter, 1, netmask) < 0)
		return FALSE;
	return TRUE;
}


/*
* capture_interface_list() is expected to do the right thing to get
* a list of interfaces.
*
* In most of the programs in the Wireshark suite, "the right thing"
* is to run dumpcap and ask it for the list, because dumpcap may
* be the only program in the suite with enough privileges to get
* the list.
*
* In dumpcap itself, however, we obviously can't run dumpcap to
* ask for the list.  Therefore, our capture_interface_list() should
* just call get_interface_list().
*/
GList *capture_interface_list(int *err, char **err_str)
{
	return get_interface_list(err, err_str);
}

/*
* Get the data-link type for a libpcap device.
* This works around AIX 5.x's non-standard and incompatible-with-the-
* rest-of-the-universe libpcap.
*/
int get_pcap_linktype(pcap_t *pch, const char *devname
#ifndef _AIX
				  //_U_
#endif
				  )
{
	int linktype;
#ifdef _AIX
	const char *ifacename;
#endif

	linktype = pcap_datalink(pch);
#ifdef _AIX

	/*
	* The libpcap that comes with AIX 5.x uses RFC 1573 ifType values
	* rather than DLT_ values for link-layer types; the ifType values
	* for LAN devices are:
	*
	*  Ethernet        6
	*  802.3           7
	*  Token Ring      9
	*  FDDI            15
	*
	* and the ifType value for a loopback device is 24.
	*
	* The AIX names for LAN devices begin with:
	*
	*  Ethernet                en
	*  802.3                   et
	*  Token Ring              tr
	*  FDDI                    fi
	*
	* and the AIX names for loopback devices begin with "lo".
	*
	* (The difference between "Ethernet" and "802.3" is presumably
	* whether packets have an Ethernet header, with a packet type,
	* or an 802.3 header, with a packet length, followed by an 802.2
	* header and possibly a SNAP header.)
	*
	* If the device name matches "linktype" interpreted as an ifType
	* value, rather than as a DLT_ value, we will assume this is AIX's
	* non-standard, incompatible libpcap, rather than a standard libpcap,
	* and will map the link-layer type to the standard DLT_ value for
	* that link-layer type, as that's what the rest of Wireshark expects.
	*
	* (This means the capture files won't be readable by a tcpdump
	* linked with AIX's non-standard libpcap, but so it goes.  They
	* *will* be readable by standard versions of tcpdump, Wireshark,
	* and so on.)
	*
	* XXX - if we conclude we're using AIX libpcap, should we also
	* set a flag to cause us to assume the time stamps are in
	* seconds-and-nanoseconds form, and to convert them to
	* seconds-and-microseconds form before processing them and
	* writing them out?
	*/

	/*
	* Find the last component of the device name, which is the
	* interface name.
	*/
	ifacename = strchr(devname, '/');
	if (ifacename == NULL)
		ifacename = devname;

	/* See if it matches any of the LAN device names. */
	if (strncmp(ifacename, "en", 2) == 0) {
		if (linktype == 6) {
			/*
			* That's the RFC 1573 value for Ethernet; map it to DLT_EN10MB.
			*/
			linktype = 1;
		}
	} else if (strncmp(ifacename, "et", 2) == 0) {
		if (linktype == 7) {
			/*
			* That's the RFC 1573 value for 802.3; map it to DLT_EN10MB.
			* (libpcap, tcpdump, Wireshark, etc. don't care if it's Ethernet
			* or 802.3.)
			*/
			linktype = 1;
		}
	} else if (strncmp(ifacename, "tr", 2) == 0) {
		if (linktype == 9) {
			/*
			* That's the RFC 1573 value for 802.5 (Token Ring); map it to
			* DLT_IEEE802, which is what's used for Token Ring.
			*/
			linktype = 6;
		}
	} else if (strncmp(ifacename, "fi", 2) == 0) {
		if (linktype == 15) {
			/*
			* That's the RFC 1573 value for FDDI; map it to DLT_FDDI.
			*/
			linktype = 10;
		}
	} else if (strncmp(ifacename, "lo", 2) == 0) {
		if (linktype == 24) {
			/*
			* That's the RFC 1573 value for "software loopback" devices; map it
			* to DLT_NULL, which is what's used for loopback devices on BSD.
			*/
			linktype = 0;
		}
	}
#endif

	return linktype;
}

/* Print the number of packets captured for each interface until we're killed. */
int
print_statistics_loop(gboolean machine_readable)
{
	GList       *if_list, *if_entry, *stat_list = NULL, *stat_entry;
	if_info_t   *if_info;
	if_stat_t   *if_stat;
	int         err;
	gchar       *err_str;
	pcap_t      *pch;
	char        errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_stat ps;

	if_list = get_interface_list(&err, &err_str);
	if (if_list == NULL)
	{
		switch (err)
		{
		case CANT_GET_INTERFACE_LIST:
			NPC_PRINT("[Error]: %s", err_str);
			g_free(err_str);
			break;

		case NO_INTERFACES_FOUND:
			NPC_PRINT("[Error]: there are no interfaces on which a capture can be done");
			break;
		}
		return err;
	}

	for (if_entry = g_list_first(if_list); if_entry != NULL; if_entry = g_list_next(if_entry))
	{
		if_info = (if_info_t *)if_entry->data;
#ifdef HAVE_PCAP_OPEN
		pch = pcap_open(if_info->name, MIN_PACKET_SIZE, 0, 0, NULL, errbuf);
#else
		pch = pcap_open_live(if_info->name, MIN_PACKET_SIZE, 0, 0, errbuf);
#endif

		if (pch)
		{
			if_stat = (if_stat_t *)g_malloc(sizeof(if_stat_t));
			if_stat->name = g_strdup(if_info->name);
			if_stat->pch = pch;
			stat_list = g_list_append(stat_list, if_stat);
		}
	}

	if (!stat_list)
	{
		NPC_PRINT("[Error]: there are no interfaces on which a capture can be done");
		return 2;
	}

	if (!machine_readable)
	{
		NPC_PRINT("%-15s  %10s  %10s\n", "Interface", "Received",
			"Dropped");
	}

	global_ld.go = TRUE;
	while (global_ld.go)
	{
		for (stat_entry = g_list_first(stat_list); stat_entry != NULL; stat_entry = g_list_next(stat_entry)) {
			if_stat = (if_stat_t *)stat_entry->data;
			pcap_stats(if_stat->pch, &ps);

			if (!machine_readable)
			{
				NPC_PRINT("%-15s  %10u  %10u\n", if_stat->name,
					ps.ps_recv, ps.ps_drop);
			}
			else
			{
				NPC_PRINT("%s\t%u\t%u\n", if_stat->name,
					ps.ps_recv, ps.ps_drop);
				fflush(stdout);
			}
		}

		sleep(1);

	}

	/* XXX - Not reached.  Should we look for 'q' in stdin? */
	for (stat_entry = g_list_first(stat_list); stat_entry != NULL; stat_entry = g_list_next(stat_entry)) {
		if_stat = (if_stat_t *)stat_entry->data;
		pcap_close(if_stat->pch);
		g_free(if_stat->name);
		g_free(if_stat);
	}
	g_list_free(stat_list);
	free_interface_list(if_list);

	return 0;
}

/******************************************
**
**	�ͷ�hashmap�Ļ����
**	ɾ���ź���sem_id_for_create_npp
**	�ͷŻ�����mutex_for_clear_session
**
******************************************/
void Npc_Clear(int delete_process)
{
	int i = 0;
	for(i=(DBFW_MAX_SESSIONS-1);i>0;i--)
	{
		if(global_ld.session_withclients[i].client_key>0)
		{
			/* �ò�λ��һ��client��Ӧ��Ҳ����ʹ�õ�session */
			if(global_ld.session_withclients[i]._sem_id>=0)
			{
				NPC_PRINT("[Info]: remove sem %d for sem_id\n", global_ld.session_withclients[i]._sem_id);
				Dbfw_RemoveSem(global_ld.session_withclients[i]._sem_id);
			}
		}
	}
#ifdef USE_BSLHASH_FORSESSION
    /* �б�����������ڵ��� */
    //Bslhash_Enum((Bslhash_t*)global_ld.mem_sess_bslist,0,NULL,bsllist_enum_sessions);
    if(global_ld.mem_sess_bslist)
        Bslhash_Destroy((Bslhash_t*)global_ld.mem_sess_bslist);
#endif
	Npc_HashmapDestroy(&global_ld.session_hashmap);
	Npc_HashmapDestroy(&global_ld.db_hashmap[0]);
	Npc_HashmapDestroy(&global_ld.db_hashmap[1]);

	NPC_PRINT("[Info]: remove sem %d for sem_id_for_create_npp\n", global_ld.sem_id_for_create_npp);

	Dbfw_RemoveSem(global_ld.sem_id_for_create_npp);
	pthread_mutex_destroy(&global_ld.mutex_for_clear_session);

	/*��smon����npcʱ,��Ȼʹ��ԭ���Ĺ��˱��ʽ*/
	if(delete_process==1)
	{
		Dbfw_Fixarray_ResetNpcInfo((u_char*)__SGA, global_ld.npc_id); 
		/*��ս�����Ϣ*/
		Dbfw_Fixarray_DeleteProcess((u_char*)__SGA, __PID);
	}
#ifdef DUMP_PACKET
	fclose(__FOUT);
	//fclose(__FOUT_SIMPLE);
#endif

	DBFW_CLOSE_LOG(&npc_log_file);

}
/**************************************************
**
**	���ڲ�������ʱ���������
**
**************************************************/
void Npc_PrintStatistics()
{
	//guint32 received;
	//guint32 dropped;
	//pcap_options *pcap_opts;
	//struct pcap_stat     stats;

	//pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, 0);
	//received = pcap_opts->received;
	//dropped = pcap_opts->dropped;
	//if (pcap_opts->pcap_h != NULL) {
	//	/* Get the capture statistics, so we know how many packets were dropped. */
	//	if (pcap_stats(pcap_opts->pcap_h, &stats) >= 0) 
	//	{
	//		/* Let the parent process know. */
	//		dropped += stats.ps_drop;
	//	} else 
	//	{
	//		g_print("Can't get packet-drop statistics: %s",
	//			pcap_geterr(pcap_opts->pcap_h));
	//	}
	//}
	//if(received+dropped==0)
	//{
	//	printf("[Info]: received+dropped = 0\n");
	//}
	//else
	//{
	//	g_print("[Info]: received/dropped:%u/%u (%.2lf)\n",received, dropped, 100.0*received/(received+dropped));
	//}
	//printf("[Info]: global_ld.captured_packets_count:%llu, captured_bytes_count:%llu\n", global_ld.captured_packets_count, global_ld.captured_bytes_count);
	
	//NPC_PRINT("[Info]: __COUNT=%llu, __STOP=%llu\n", __COUNT, __STOP);

	Npc_DropStatistic();

}
/**************************************
**
**	NPC�����˳��Ĵ�����,���źŴ���
**
**************************************/
void Npc_NormalExitHandler(int signum)
{

	NPC_PRINT("[Info]: NPC is exiting...\n");

	capture_loop_stop();


	//Npc_PrintStatistics();

#ifdef PRINT_STATS
	Npc_PrintStatistics();
#endif
#ifdef PRINT_THROUGHPUT
	Npc_PrintThroughput();
#endif
	if(signum==SIGUSR1)
	{
		Npc_Clear(1);
	}
	else
	{
		Npc_Clear(0);
	}
	exit(0);
}
/**************************************
**
**	NPC���˳�����,��������������
**
**************************************/
void exit_main(int status)
{
	capture_loop_stop();
	Npc_Clear(1);
	exit(status);
}


#if !defined(_WIN32) || defined(MUST_DO_SELECT)
/* Provide select() functionality for a single file descriptor
* on UNIX/POSIX. Windows uses cap_pipe_read via a thread.
*
* Returns the same values as select.
*/
int cap_pipe_select(int pipe_fd)
{
	fd_set      rfds;
	struct timeval timeout;

	FD_ZERO(&rfds);
	FD_SET(pipe_fd, &rfds);

	timeout.tv_sec = PIPE_READ_TIMEOUT / 1000000;
	timeout.tv_usec = PIPE_READ_TIMEOUT % 1000000;

	return select(pipe_fd+1, &rfds, NULL, NULL, &timeout);
}
#endif


/******************************************
**
**	������
**	RETURN:
**		TRUE: ok
**		FALSE: failed
**
**********************************************/
gboolean capture_loop_open_input(capture_options *capture_opts, loop_data *ld,
										char *errmsg, size_t errmsg_len,
										char *secondary_errmsg, size_t secondary_errmsg_len)
{
	gchar             open_err_str[PCAP_ERRBUF_SIZE];
	gchar             *sync_msg_str;
	interface_options interface_opts;
	pcap_options      *pcap_opts;
	guint             i;


	if (capture_opts->ifaces->len > 1) 
	{
		g_snprintf(errmsg, (gulong) errmsg_len,
			"Using threads is required for capturing on mulitple interfaces!");
		return FALSE;
	}

	for (i = 0; i < capture_opts->ifaces->len; i++)
	{
		interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
		pcap_opts = (pcap_options *)g_malloc(sizeof (pcap_options));
		if (pcap_opts == NULL) {
			g_snprintf(errmsg, (gulong) errmsg_len,
				"Could not allocate memory.");
			return FALSE;
		}
		pcap_opts->received = 0;
		pcap_opts->dropped = 0;
		pcap_opts->pcap_h = NULL;
#ifdef MUST_DO_SELECT/*�ж���*/
		pcap_opts->pcap_fd = -1;
#else
		NPC_PRINT("[Info]: No #define MUST_DO_SELECT\n");
#endif
		pcap_opts->pcap_err = FALSE;
		pcap_opts->interface_id = i;
		pcap_opts->tid = NULL;
		pcap_opts->snaplen = 0;
		pcap_opts->linktype = -1;


		g_array_append_val(ld->pcaps, pcap_opts);

		pcap_opts->pcap_h = open_capture_device(&interface_opts, &open_err_str);

		if (pcap_opts->pcap_h == NULL) 
		{

			NPC_NEW_LOG(ERROR_LEVEL, error_log,"%s", "Capture handle is null.");
			DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);

			NPC_PRINT("[Error]: %s\n", open_err_str);	

			return FALSE;
		}
		else 
		{

#if defined(HAVE_PCAP_SETSAMPLING)
			if (interface_opts.sampling_method != CAPTURE_SAMP_NONE) 
			{
				struct pcap_samp *samp;

				if ((samp = pcap_setsampling(pcap_opts->pcap_h)) != NULL) 
				{
					switch (interface_opts.sampling_method) 
					{
					case CAPTURE_SAMP_BY_COUNT:
						samp->method = PCAP_SAMP_1_EVERY_N;
						break;

					case CAPTURE_SAMP_BY_TIMER:
						samp->method = PCAP_SAMP_FIRST_AFTER_N_MS;
						break;

					default:
						sync_msg_str = g_strdup_printf(
							"Unknown sampling method %d specified,\n"
							"continue without packet sampling",
							interface_opts.sampling_method);
						report_capture_error("Couldn't set the capture "
							"sampling", sync_msg_str);
						g_free(sync_msg_str);
					}
					samp->value = interface_opts.sampling_param;
				} else 
				{
					report_capture_error("Couldn't set the capture sampling",
						"Cannot get packet sampling data structure");
				}
			}
			//#else/*û�ж���HAVE_PCAP_SETSAMPLING*/
			//			NPC_PRINT("[Info]: No #define HAVE_PCAP_SETSAMPLING\n");
#endif

			/* setting the data link type only works on real interfaces */
			if (!set_pcap_linktype(pcap_opts->pcap_h, interface_opts.linktype, interface_opts.name,
				errmsg, errmsg_len,
				secondary_errmsg, secondary_errmsg_len))
			{
				return FALSE;
			}
			pcap_opts->linktype = get_pcap_linktype(pcap_opts->pcap_h, interface_opts.name);
		}

		/* XXX - will this work for tshark? */
#ifdef MUST_DO_SELECT

		//#ifdef HAVE_PCAP_GET_SELECTABLE_FD
		//		pcap_opts->pcap_fd = pcap_get_selectable_fd(pcap_opts->pcap_h);
		//#else
		//NPC_PRINT("[Info]: No #define HAVE_PCAP_GET_SELECTABLE_FD\n");
		pcap_opts->pcap_fd = pcap_fileno(pcap_opts->pcap_h);
		//#endif

#endif

		/* Does "open_err_str" contain a non-empty string?  If so, "pcap_open_live()"
		returned a warning; print it, but keep capturing. */
		if (open_err_str[0] != '\0') {
			sync_msg_str = g_strdup_printf("%s.", open_err_str);
			report_capture_error(sync_msg_str, "");
			g_free(sync_msg_str);
		}
		capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, i);
		g_array_insert_val(capture_opts->ifaces, i, interface_opts);
	}

	return TRUE;
}

/* close the capture input file (pcap or capture pipe) */
void capture_loop_close_input(loop_data *ld)
{
	guint i;
	pcap_options *pcap_opts;

	for (i = 0; i < ld->pcaps->len; i++) {
		pcap_opts = g_array_index(ld->pcaps, pcap_options *, i);

		/* if open, close the pcap "input file" */
		if (pcap_opts->pcap_h != NULL) {

			NPC_NEW_LOG(INFO_LEVEL, info_log,"Close capture handle.");
			DBFW_INFO_PRINT(&npc_log_file, &info_log);

			pcap_close(pcap_opts->pcap_h);
			pcap_opts->pcap_h = NULL;
		}
	}

	ld->go = FALSE;

}


/***********************************
**
**	��ʼ�����˱��ʽ
**
***********************************/
initfilter_status_t capture_loop_init_filter(pcap_t *pcap_h, 
													const gchar * name, const gchar * cfilter)
{
	struct bpf_program fcode;

	NPC_NEW_LOG(INFO_LEVEL, info_log,"Init capture filter:%s.", cfilter);
	DBFW_INFO_PRINT(&npc_log_file, &info_log);

	/* capture filters only work on real interfaces */
	if (cfilter)
	{
		/* A capture filter was specified; set it up. */
		NPC_NEW_LOG(INFO_LEVEL, info_log,"compile capture filter");
		DBFW_INFO_PRINT(&npc_log_file, &info_log);
		if (!compile_capture_filter(name, pcap_h, &fcode, cfilter))
		{
			/* Treat this specially - our caller might try to compile this
			as a display filter and, if that succeeds, warn the user that
			the display and capture filter syntaxes are different. */
			return INITFILTER_BAD_FILTER;
		}

		NPC_NEW_LOG(INFO_LEVEL, info_log,"set capture filter");
		DBFW_INFO_PRINT(&npc_log_file, &info_log);
		if (pcap_setfilter(pcap_h, &fcode) < 0)
		{
#ifdef HAVE_PCAP_FREECODE
			pcap_freecode(&fcode);
#endif
			return INITFILTER_OTHER_ERROR;
		}
#ifdef HAVE_PCAP_FREECODE
		pcap_freecode(&fcode);
#endif
	}
	return INITFILTER_NO_ERROR;
}



/* dispatch incoming packets (pcap or capture pipe)
*
* Waits for incoming packets to be available, and calls pcap_dispatch()
* to cause them to be processed.
*
* Returns the number of packets which were processed.
*
* Times out (returning zero) after CAP_READ_TIMEOUT ms; this ensures that the
* packet-batching behaviour does not cause packets to get held back
* indefinitely.
*/
int capture_loop_dispatch(loop_data *ld,
								char *errmsg, 
								int errmsg_len, 
								pcap_options *pcap_opts)
{
	int       inpkts;

#ifndef _WIN32
	int       sel_ret;
#endif

	/* dispatch from pcap */
#ifdef MUST_DO_SELECT
	/*
	* If we have "pcap_get_selectable_fd()", we use it to get the
	* descriptor on which to select; if that's -1, it means there
	* is no descriptor on which you can do a "select()" (perhaps
	* because you're capturing on a special device, and that device's
	* driver unfortunately doesn't support "select()", in which case
	* we don't do the select - which means it might not be possible
	* to stop a capture until a packet arrives.  If that's unacceptable,
	* plead with whoever supplies the software for that device to add
	* "select()" support, or upgrade to libpcap 0.8.1 or later, and
	* rebuild Wireshark or get a version built with libpcap 0.8.1 or
	* later, so it can use pcap_breakloop().
	*/

	if (pcap_opts->pcap_fd != -1) {
		sel_ret = cap_pipe_select(pcap_opts->pcap_fd);
		if (sel_ret > 0) {
			/*
			* "select()" says we can read from it without blocking; go for
			* it.
			*
			* We don't have pcap_breakloop(), so we only process one packet
			* per pcap_dispatch() call, to allow a signal to stop the
			* processing immediately, rather than processing all packets
			* in a batch before quitting.
			*/
			/*�ڶ�������ָ����������ǰ���������ݰ������ֵ*/
            //printf("run for 1\n");
//             NPC_NEW_LOG(ERROR_LEVEL, error_log,"%s", "test errorlog.");
//             DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
//             NPC_NEW_LOG(INFO_LEVEL, info_log,"%s", "test infolog.");
//             DBFW_INFO_PRINT(&npc_log_file, &info_log);
			inpkts = pcap_dispatch(pcap_opts->pcap_h, 1, capture_loop_write_packet_cb, (u_char *)pcap_opts);

			if (inpkts < 0) {
				if (inpkts == -1) {
					/* Error, rather than pcap_breakloop(). */
					pcap_opts->pcap_err = TRUE;
				}
				ld->go = FALSE; /* error or pcap_breakloop() - stop capturing */
			}
		} else 
		{
			if (sel_ret < 0 && errno != EINTR) 
			{
				g_snprintf(errmsg, errmsg_len,
					"Unexpected error from select: %s", g_strerror(errno));
				report_capture_error(errmsg, please_report);
				ld->go = FALSE;
			}
		}
	}
	else
#endif /* MUST_DO_SELECT */
	{
		/* dispatch from pcap without select */
		/* -1��ʾ��һ���������д������е����ݰ� */
		//NPC_PRINT("[Info]: pcap_dispatch in No #define MUST_DO_SELECT\n");
        //printf("run for 2\n");
		inpkts = pcap_dispatch(pcap_opts->pcap_h, -1, capture_loop_write_packet_cb, (u_char *)pcap_opts);

		if (inpkts < 0) 
		{
			if (inpkts == -1) 
			{
				/* Error, rather than pcap_breakloop(). */
				pcap_opts->pcap_err = TRUE;
			}
			ld->go = FALSE; /* error or pcap_breakloop() - stop capturing */
		}
	}

	return 1;
}

/*******************************************
*   ����ԴIP,Port��Ŀ��IP,Port,�������ֽ��򷵻�
*	����ֵ:
*		1:�������ӵ������
*		0:��ͨ��
*		-1:��TCP��
*******************************************/
int Npc_ParseSourceAndDestIpPort(const u_char *p_frame_packet, 
								 u_int* src_ip, u_short *src_port,
								 u_int* dst_ip, u_short *dst_port)
{
	const u_char* p_ip_packet;
	const u_char* p_ip;
	const u_char* p_tcp_packet;
	u_int ip_header_len;
    u_int cursor = 0;
	u_char protocol;
	u_char control_field;
    u_short eth_type_code = 0;

    memcpy(&eth_type_code,(u_char*)p_frame_packet+12,sizeof(u_short));
    eth_type_code = ntohs(eth_type_code);
    cursor = 14;
    p_ip_packet = p_frame_packet+cursor;    
    while(eth_type_code==0x8100)
    {
        /* 
            Type: 802.1Q Virtual LAN (0x8100),�������2�ֽڵ�VLan��Ϣ��2�ֽڵ�type��Ϣ 
            �������type��Ϣ����0x8000
        */
        /* ������2�ֽ� */
        cursor = cursor + 2;
        memcpy(&eth_type_code,(u_char*)p_frame_packet+cursor,sizeof(u_short));
        eth_type_code = ntohs(eth_type_code);
        cursor = cursor + 2;
        p_ip_packet = p_frame_packet+cursor;
        /* 
            ��Ҫ�ķ����߼���
            �����ϣ����ܻ���ֶ��VLand������Ӧ�ó��ִ�����VLan�������������һ�������߼����������5�ε�VLan(20�ֽ�)����Ϊ�ǲ���ȷ��TCPIP�� 
        */
        if(cursor>(14+20))
        {
            protocol = 0;
            return -1;
        }
    }

	protocol = *(p_ip_packet+9);
	if(protocol!=0x06)
	{
		return -1;
	}
	/*������Դip*/
	p_ip=p_ip_packet+12;
	*src_ip = ntohl(*(u_int*)p_ip);
	/*������Ŀ��ip*/
	p_ip=p_ip_packet+16;
	*dst_ip = ntohl(*(u_int*)p_ip);

	ip_header_len = (*p_ip_packet)&0x0f;
	p_tcp_packet = p_ip_packet + (ip_header_len<<2);
	/*������Դport*/
	*src_port = ntohs(*(u_short*)p_tcp_packet);
	/*������Ŀ��port*/
	*dst_port = ntohs(*(u_short*)(p_tcp_packet+2));


	control_field = *(p_tcp_packet+13);
	//if((control_field&0x01)==0x01)/*�ж��Ƿ���FIN��*/
	//{
	//	__FIN=1;
	//}
    /* 
        ������������ĺ�����������Ŀ�з��ֳ�������10.117.202.67��ֻ��SYN��ͨѶ��(����)���������ܴ�Ӧ����һ������豸�����ģ�����ɴ���������NPP 
        ��ˣ���NPC��NPP�������˵�����ԭ������ֻ��SYN����ACKʱ����NPP����Ϊͬʱ��SYN��ACKʱ����NPP��Ҳ���Ƿ�����������Ӧ��
    */
#ifdef NPC_USE_SYNANDACK_START
    if((control_field&0x12)==0x02)
    {/* ������SYN,��û������ACK,˵������һ���������ӵĵ�һ��ͨѶ������Ҫ�ӵ� */
        return -1;
    }
    else if((control_field&0x12)==0x12)
    {
        /* ������SYN,Ҳ������ACK,˵������һ���������ӵĵ�һ��Ӧ�������ʼ����NPP */
        return 1;
    }
#else
    if((control_field&0x12)==0x02)
    {/* ������SYN,��û������ACK,˵������һ���������ӵİ� */
        return 1;
    }  
#endif
	return 0;
}


void capture_loop_stop(void)
{
#ifdef HAVE_PCAP_BREAKLOOP
	guint i;
	pcap_options *pcap_opts;
	for (i = 0; i < global_ld.pcaps->len; i++) {
		pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
		if (pcap_opts->pcap_h != NULL)
			pcap_breakloop(pcap_opts->pcap_h);
	}
#endif
	global_ld.go = FALSE;

}


void Npc_PrintThroughput(void)
{
	u_int used_time;
	double speed;
	u_int64 bytes_per_packet;
	if(global_ld.captured_packets_count==0)
	{
		bytes_per_packet = 0;
	}else
	{
		bytes_per_packet = global_ld.captured_bytes_count/global_ld.captured_packets_count;
	}
	global_ld.end_time=time(NULL);
	used_time = global_ld.end_time - global_ld.start_time;
	if(used_time==0)
	{
		used_time=1;
	}
	speed = (double)global_ld.captured_packets_count/used_time;
	NPC_PRINT("[Info]: Packets=%llu, time=%u(s), throughput=%.2f, (bytes=%llu, bytes/packet=%llu)\n", global_ld.captured_packets_count, used_time, speed, 
		global_ld.captured_bytes_count, bytes_per_packet);
}


/*********************************************************
**
**	������־�ļ�create log file
**	��ʼ��error_log, info_log, debug_log, warn log.
**
*********************************************************/
int Npc_InitNpcLogFile(u_char *sga)
{
	int ret;
	int create_log_file=0;
    int create_errlog_file=0;
	u_char log_file_path[PROCESS_PARAM_MAX_VALUES_LEN];
    u_char errlog_file_path[PROCESS_PARAM_MAX_VALUES_LEN];
    u_char *dir_tail;

	pid_t pid;
	pthread_t tid;
	pid = getpid();
	tid = NPC_THREAD_MAIN;

	memset(log_file_path, 0 ,sizeof(log_file_path));
    memset(errlog_file_path, 0 ,sizeof(log_file_path));
	int log_file_path_len = Dbfw_Fixarray_GetValueAndValuelenInGlobal(sga, S_LOG_HOME, log_file_path, PROCESS_PARAM_MAX_VALUES_LEN);
	if(log_file_path_len==0)
	{
		NPC_PRINT("[Error]: DBFW_LOG_HOME is null\n");
		return NPC_ERROR_DBFWLOGHOME_NULL-NPC_ERRNO_START;
	}
    strcpy((char*)errlog_file_path,(char*)log_file_path);
	u_char log_file_name[64];
    //u_char errlog_file_name[64];
	/* TODO:�滻��ʵ�ʵ�ʵ���� */
	//ȡʵ����
	u_char dbfw_inst_name[PROCESS_PARAM_MAX_VALUES_LEN];
	memset((char*)dbfw_inst_name, 0, PROCESS_PARAM_MAX_VALUES_LEN);
	ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal(sga, DBFW_INSTANCE_NAME, dbfw_inst_name, PROCESS_PARAM_MAX_VALUES_LEN);
	if(ret==0)
	{
		NPC_NEW_LOG(ERROR_LEVEL, error_log, "DBFW_INSTANCE_NAME is null");
		DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
		return NPC_ERROR_DBFWINSTNAME_NULL-NPC_ERRNO_START;
	}

	time_t cur_time;
	u_char time_str[32];
	time(&cur_time);
	strftime((char*)time_str, 32, "%Y%m%d%H%M%S", localtime(&cur_time));
	sprintf((char*)log_file_name, "%s_npc_%s_%d", dbfw_inst_name, time_str, pid);
	strcat((char*)log_file_path, "/pdump/npc/info/");
    strcat((char*)errlog_file_path, "/pdump/npc/error/");
	/* ���/dbfw_log_home/pdump/npcĿ¼�Ƿ��Ѿ����� */
	if(access((char*)log_file_path, F_OK)==-1)
	{
		NPC_PRINT("[Error]: %s does not exist\n", log_file_path);
		return NPC_ERROR_NPCLOGDIRECTORY_NOEXIST-NPC_ERRNO_START;
	}
    if(access((char*)errlog_file_path, F_OK)==-1)
    {
        NPC_PRINT("[Error]: %s does not exist\n", errlog_file_path);
        return NPC_ERROR_NPCLOGDIRECTORY_NOEXIST-NPC_ERRNO_START;
    }
    
	dir_tail=(u_char*)strrchr((char*)npc_log_file.path_name, '/');
	if(dir_tail==NULL)/*��������ʱ��һ�γ�ʼ����־*/
	{
		strcat((char*)log_file_path, (char*)log_file_name);
		strcpy((char*)npc_log_file.path_name, (char*)log_file_path);
		create_log_file = 1;
	}else
	{
		u_char	old_dir[256];
		memset(old_dir, 0x00, sizeof(old_dir));
		memcpy(old_dir, npc_log_file.path_name, dir_tail-npc_log_file.path_name+1);/*������β��'/'*/
		if(strcmp((char*)old_dir, (char*)log_file_path)!=0)
		{/*��־�ļ�·�������仯*/
			DBFW_CLOSE_LOG(&npc_log_file);
			strcat((char*)log_file_path, (char*)log_file_name);
			strcpy((char*)npc_log_file.path_name, (char*)log_file_path);
			create_log_file = 1;
		}else
		{
			create_log_file = 0;
		}
	}

    dir_tail=(u_char*)strrchr((char*)npc_errlog_file.path_name, '/');
    if(dir_tail==NULL)/*��������ʱ��һ�γ�ʼ����־*/
    {
        strcat((char*)errlog_file_path, (char*)log_file_name);
        strcpy((char*)npc_errlog_file.path_name, (char*)errlog_file_path);
        create_errlog_file = 1;
    }else
    {
        u_char	old_dir[256];
        memset(old_dir, 0x00, sizeof(old_dir));
        memcpy(old_dir, npc_errlog_file.path_name, dir_tail-npc_errlog_file.path_name+1);/*������β��'/'*/
        if(strcmp((char*)old_dir, (char*)errlog_file_path)!=0)
        {/*��־�ļ�·�������仯*/
            DBFW_CLOSE_LOG(&npc_errlog_file);
            strcat((char*)errlog_file_path, (char*)log_file_name);
            strcpy((char*)npc_errlog_file.path_name, (char*)errlog_file_path);
            create_errlog_file = 1;
        }else
        {
            create_errlog_file = 0;
        }
    }
	
	
	/* TODO: ����6����Ҫ��ȡ���ò��� */
	npc_log_file.max_size= GetIntParamInFixarray(sga, S_NPC_LOG_SIZE);
	if(npc_log_file.max_size==0)
	{
		//npc_log_file.max_size = 8*1024*1024;
        npc_log_file.max_size = DBFW_NPC_LOG_DEFAULT_SIZE;
        //npc_log_file.max_size = 32*1024;
	}
	else
	{
		npc_log_file.max_size *= 1024;//�����ļ��еĲ�����λ��K
        //npc_log_file.max_size = 32*1024;//�����ļ��еĲ�����λ��K
	}

	/*infoʹ��ѭ����־*/
	npc_log_file.log_type = LOG_TYPE_LOOP;
	/*���ӳٴ�����־*/
	npc_log_file.delay_create = 0; 
	int log_level = GetIntParamInFixarray(sga, S_NPC_LOG_LEVEL);

	//npc_log_file.level_enable[ERROR_LEVEL]=(log_level>>3)&0x01;
    npc_log_file.level_enable[ERROR_LEVEL]=0;
	npc_log_file.level_enable[WARN_LEVEL]=(log_level>>2)&0x01;
	npc_log_file.level_enable[DEBUG_LEVEL]=(log_level>>1)&0x01;
	npc_log_file.level_enable[INFO_LEVEL]=(log_level)&0x01;

    /*errʹ��˳����־*/
    npc_errlog_file.max_size= GetIntParamInFixarray(sga, S_NPC_LOG_SIZE);
    if(npc_errlog_file.max_size==0)
    {
        //npc_log_file.max_size = 8*1024*1024;
        npc_errlog_file.max_size = DBFW_NPC_LOG_DEFAULT_SIZE;
        //npc_errlog_file.max_size = 32*1024;
    }
    else
    {
        npc_errlog_file.max_size *= 1024;//�����ļ��еĲ�����λ��K
        //npc_errlog_file.max_size = 32*1024;//�����ļ��еĲ�����λ��K
    }
    npc_errlog_file.log_type = LOG_TYPE_SEQU;
    /*�ӳٴ�����־*/
    npc_errlog_file.delay_create = 1; 
    //int log_level = GetIntParamInFixarray(sga, S_NPC_LOG_LEVEL);

    //npc_log_file.level_enable[ERROR_LEVEL]=(log_level>>3)&0x01;
    npc_errlog_file.level_enable[ERROR_LEVEL]=1;
    npc_errlog_file.level_enable[WARN_LEVEL]=0;
    npc_errlog_file.level_enable[DEBUG_LEVEL]=0;
    npc_errlog_file.level_enable[INFO_LEVEL]=0;

	strcpy((char*)error_log.module_name,"npc");
	error_log.processid=pid;
	error_log.threadid=tid;

	strcpy((char*)warn_log.module_name,"npc");
	warn_log.processid=pid;
	warn_log.threadid=tid;

	strcpy((char*)debug_log.module_name,"npc");
	debug_log.processid=pid;
	debug_log.threadid=tid;

	strcpy((char*)info_log.module_name,"npc");
	info_log.processid=pid;
	info_log.threadid=tid;

	if(create_log_file == 1)
	{
		return DBFW_CREATE_LOG(&npc_log_file);
	}

    if(create_errlog_file == 1)
    {
        return DBFW_CREATE_LOG(&npc_errlog_file);
    }
	return 0;/*û���޸���־·��,ֻ���޸�����־�ļ�����*/
}

/***************************************************************************
**
**	ˢ������ֵ�͹���ֵ���߳�
**
***************************************************************************/
void* Npc_UpdateHeartbeat(void *arg)
{
	u_int64 last_captured_count = global_ld.captured_packets_count;

	/*	ȫ�ֲ������������,�������
	*	��־Ŀ¼��DBFW_MAX_SESSION�Ƿ����仯 
	*/
	u_int64	last_param_change_count = Dbfw_Fixarray_GetParamChange((u_char*)__SGA);
	u_int64	param_change_count;
	u_char	value[PROCESS_PARAM_MAX_VALUES_LEN];
    u_int64 key = 0;
    u_int   bslhash_element_count = 0;

	int filter_len;
	int last_filter_version=0;
	int filter_version;
	/**********************************************************************************
	**  ʵ����,last_acbuf_change_countӦ�ø�ֵΪ���̼߳���db_hashmapʱ�ļ���ֵ.
	**  ��Ϊ�����̼߳���db_hashmap�������߳�����֮����һ��ʱ���,�ڼ�acbuf���ܱ�ˢ��,
	**  ��last_acbuf_change_countȡ����ˢ��֮��ļ���ֵ,ѭ���Ĵ���Ͳ����ټ���db_hashmap
	**********************************************************************************/
	u_int64 acbuf_change_count;
	u_int64 last_acbuf_change_count = Dbfw_Fixarray_GetAcbufChange((u_char*)__SGA);
	struct timeval  current_timeval;
    struct tm __tm_current;

	int ret=0;
    DBFW_SYSTEM_RESOURCE s_system_source;
    DBFW_SYSTEM_RESOURCE s_system_source_new;
    int     i,j,k,pid,npp_count,npp_count_forclose;
    u_int   sessionid = 65535;
    u_int64 last_worktime = 0;
    u_int64 last_memory_clear_time = 0;     /* ���һ�ν����ڴ������ʱ��� */
    npp_info  tmp_npp_info;
    int nppinfo_idx_for_minimum_worktime = 0;   /* ���浱ǰ����Сworktimeֵ��npp_info������±� */
	for(;;)
	{
		//usleep(NPC_UPDATE_HEARTBEAT_INTERVAL);
		//sleep(1);
        sleep(3);   /* ÿ���3��ִ��һ�� */
       
		/* ��������ֵ */
		gettimeofday(&current_timeval, NULL);        
        /* 2014-06-23 ���Ӷ���License����߼�(���������ʱ����) */
        //ret = Npc_CheckLicense(NPC_CK_LICENSE_TIME);
        ret = Npc_CheckLicense_WithDiskCheck(NPC_CK_LICENSE_HAVEDISKID);

        global_ld.alivetime = (u_int64)current_timeval.tv_sec*1000000;
		global_ld.alivetime = global_ld.alivetime + (u_int64)current_timeval.tv_usec;
		Dbfw_Fixarray_SetProcessAliveSignal((u_char*)__SGA, __PID, global_ld.alivetime);

		/*����һ��ʱ��֮��,�������������仯,˵��NPC���ڹ���*/
		if(global_ld.captured_packets_count > last_captured_count)
		{
			last_captured_count = global_ld.captured_packets_count;
			global_ld.worktime = global_ld.alivetime;
			Dbfw_Fixarray_SetProcessWorkSignal((u_char*)__SGA, __PID, global_ld.worktime);
		}

		/************************************
		**
		**	����Ƿ���Ҫ����filter
		**
		************************************/
#ifdef USE_FILTER
		filter_version = Dbfw_Fixarray_GetNpcInfoVersion((u_char*)__SGA, global_ld.npc_id);
		if(filter_version> last_filter_version)
		{
			NPC_NEW_LOG(INFO_LEVEL, info_log, "switch filter: old_version=%d, new_version=%d", last_filter_version, filter_version);
			DBFW_INFO_PRINT(&npc_log_file, &info_log);

			NPC_NEW_LOG(INFO_LEVEL, info_log, "old filter: %s", global_ld.npc_info.filter);
			DBFW_INFO_PRINT(&npc_log_file, &info_log);

			Dbfw_Fixarray_GetNpcInfo((u_char*)__SGA, global_ld.npc_id, &global_ld.npc_info);

			NPC_NEW_LOG(INFO_LEVEL, info_log, "new filter: %s", global_ld.npc_info.filter);
			DBFW_INFO_PRINT(&npc_log_file, &info_log);

			if(strlen((char*)global_ld.npc_info.filter)>0)
			{
				pcap_options *pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, 0);

				switch (capture_loop_init_filter(pcap_opts->pcap_h, 
					(char*)global_ld.npc_info.device,
					(char*)global_ld.npc_info.filter))//__FILTER)) //(char*)npc_arg.filter)) 
				{

				case INITFILTER_NO_ERROR:
					NPC_PRINT("[Info]: switch filter ok: version=%d, filter_len=%d\n", global_ld.npc_info.version, strlen((char*)global_ld.npc_info.filter));
					NPC_NEW_LOG(INFO_LEVEL, info_log, "switch filter ok");
					DBFW_INFO_PRINT(&npc_log_file, &info_log);
					break;

				case INITFILTER_BAD_FILTER:					
					NPC_PRINT("[Info]: switch filter error: bad filter\n");
					error_log.dbfw_error_no = NPC_ERROR_COMPILE_FILTER-NPC_ERRNO_START;
					NPC_NEW_LOG(ERROR_LEVEL, error_log, "switch filter error: bad filter");
					DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
					ret = NPC_ERROR_COMPILE_FILTER-NPC_ERRNO_START;
					break;

				case INITFILTER_OTHER_ERROR:						
					NPC_PRINT("[Info]: switch filter error: other error\n");
					error_log.dbfw_error_no = NPC_ERROR_SET_FILTER-NPC_ERRNO_START;
					NPC_NEW_LOG(ERROR_LEVEL, error_log, "switch filter error: other error");
					DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
					ret = NPC_ERROR_SET_FILTER-NPC_ERRNO_START;
					break;
				}
			}
			last_filter_version = filter_version;
		}
#endif
        /**********************************
		**
		**	2013-08-29 ��ӷ����߼� 
        **  ����ڴ���ʹ�����Ƿ�>80%,����ﵽ������Ϊ�ڴ������㣬���ٴ���NPP����
        **  ͬʱ��Ҫ�����20%��NPP����
        **  ���⣬���ڴ�û�лָ���80%����ʱ�����ٴ����κ�NPP����,��ͨѶ����Ȼ�ɼ�
        **  �ͷ�NPP����Ҫ����һ��ʱ��SMON�Ż����²ɼ��ڴ�ռ������������Ҫ���30��󣬽�__OUT_OF_MEMORY_FLAG��Ϊ0
        **  ֮���Զ������¿�ʼ�µļ�����
		**
		**********************************/
        /* �Ƚ���30��ʱ������� */
        if(last_memory_clear_time==0)
        {
            /* ��ʼ��last_memory_clear_time */
            last_memory_clear_time = global_ld.alivetime;
        }
        if((last_memory_clear_time+(30*1000000)) < global_ld.alivetime)
        {
            /* �������һ�ν����ڴ������Ѿ���ȥ��30��������,��Ҫ��__OUT_OF_MEMORY_FLAG�����û�0��Ȼ�����¿�ʼ�����ڴ�ļ�� */
            /* �������߳�ʹ�õ��Ǻ�ȼ�飬���Բ���Ҫ���� */
            __OUT_OF_MEMORY_FLAG = 0x00;
        }
        memset(&s_system_source,0x00,sizeof(DBFW_SYSTEM_RESOURCE));
        memset(&s_system_source_new,0x00,sizeof(DBFW_SYSTEM_RESOURCE));
        ret = Dbfw_Fixarray_GetSystemResource(global_ld.sga_addr,&s_system_source);
        ret = Dbfw_Fixarray_GetSystemResource(global_ld.sga_addr,&s_system_source_new);
        if(__OUT_OF_MEMORY_FLAG==0x00 || __OUT_OF_MEMORY_FLAG!=0x01)
        {
            /* ��ǰ��״̬ʱû���ڴ泬�� */
            if(s_system_source.system_total_memory==s_system_source_new.system_total_memory &&
                s_system_source.system_used_memory==s_system_source_new.system_used_memory
              )
            {
                /* ���λ�õ�����һ��,�������ڼ����ˣ�����ֱ����Ϊ�ڴ湻��:�Ա���֮ǰ��״̬(__OUT_OF_MEMORY_FLAG����) */
                if(s_system_source.system_used_memory>0 && s_system_source.system_total_memory>0 && s_system_source.system_total_memory>=s_system_source.system_used_memory)
                {
                    /* ���Ǵ���0��ֵ�������ڴ�����>=��ʹ�õ��ڴ��� */
                    if(s_system_source.system_used_memory > ((s_system_source.system_total_memory*NPC_MEMORY_GATE_PERCENT)/100))
                    {
                        /* ʹ���ڴ������������ڴ��� */
                        __OUT_OF_MEMORY_FLAG = 0x01;
                    }
                    else
                    {
                        __OUT_OF_MEMORY_FLAG = 0x00;
                    }
                }
                else
                {
                    __OUT_OF_MEMORY_FLAG = 0x00;
                }
            }
            else
            {
                __OUT_OF_MEMORY_FLAG = 0x00;    /* Ϊ�˱��գ�������0 */
            }
            /* centos6.5 �·����ڴ��ͳ�ƽ��������ȷ����ʱȡ���ڴ��飬����Ϊ0 */
            //__OUT_OF_MEMORY_FLAG = 0x00;
            if(__OUT_OF_MEMORY_FLAG==0x01)
            {
                /* 
                    �ڴ泬�ޣ���Ҫ������е�NPP���̣�����NPP���̵ķ���ʱ��������򣬽�����ʱ�����20%��NPP���̽��С����� 
                    �����ǰ������Ϊ��NPP���ܽ�����>100��
                */
                memset(__NPP_INFO,0x00,sizeof(__NPP_INFO));
                npp_count = 0;
                npp_count_forclose = 0;
                j = 0;  /* ����__NPP_INFO���±�ֵ */
                for(i=0;i<DBFW_MAX_SESSIONS;i++)
                {
                    if((__NPC_SGA_SESSBUF->session_array->sessions_used[i]==DBFW_SESSIONARRAY_FLAG_USED) && (__NPC_SGA_SESSBUF->session_array->npppid[i]>0))
                    {
                        /* �ò�λ�лỰ����ʹ�ã���Ҫ���ûỰ��Ӧ�Ľ����Ƿ���� */
                        pid = __NPC_SGA_SESSBUF->session_array->npppid[i];
                        sessionid = i;
                        if(global_ld.session_withclients[sessionid]._sem_id>=0)
                        {
                            /* �ûỰ���ڱ�NPC���� */
                            last_worktime = Dbfw_Fixarray_GetProcessWorkSignal((u_char*)__SGA,pid);
                            __NPP_INFO[j].sessid = sessionid;
                            __NPP_INFO[j].pid    = pid;
                            __NPP_INFO[j].last_worktime = last_worktime;
                            npp_count++;
                            j++;
                        }
                    }
                }
                /* ������Ҫ�����NPP�Ľ�����:��ʽΪ(npp_count*0.2) */
                if(npp_count>100)
                {                    
                    /* ��NPP�ܽ���������100ʱ���Ž������� */
                    npp_count_forclose = (npp_count)*20/100;
                    //printf("npp_count = %d    npp_count_forclose=%d\n",npp_count,npp_count_forclose);
                    if(npp_count_forclose>0)
                    {
                        /* 
                            �������ѭ��������Ҫ�����NPP���� 
                            ÿ���ҵ�worktimeֵ��С�ĻỰ�����ҹ�����Ҫʹ�õ�tmp_npp_info
                        */
                        memset(&tmp_npp_info,0x00,sizeof(npp_info));
                        nppinfo_idx_for_minimum_worktime = 0;                                        
                        /* ��ʼѭ�� */
                        for(i=0;i<npp_count_forclose;i++)
                        {
                            //printf("i = %d\n",i);
                            for(j=0;j<npp_count;j++)
                            {
                                if(__NPP_INFO[j].sessid>0)
                                {
                                    /* ����Ҫ���ĻỰ������ */
                                    /* ��ʹ��npp_info����ĵ�һ��Ԫ���������tmp_npp_info */
                                    if(tmp_npp_info.sessid==0)
                                    {
                                        tmp_npp_info.sessid = __NPP_INFO[j].sessid;
                                        tmp_npp_info.pid    = __NPP_INFO[j].pid;
                                        tmp_npp_info.last_worktime  = __NPP_INFO[j].last_worktime;
                                        nppinfo_idx_for_minimum_worktime = j;
                                    }
                                    else if(__NPP_INFO[j].last_worktime<tmp_npp_info.last_worktime)
                                    {
                                        /* npp_infoԪ�ص�worktime<last_worktime,��Ҫ�滻 */
                                        tmp_npp_info.sessid = __NPP_INFO[j].sessid;
                                        tmp_npp_info.pid    = __NPP_INFO[j].pid;
                                        tmp_npp_info.last_worktime  = __NPP_INFO[j].last_worktime;
                                        nppinfo_idx_for_minimum_worktime = j;
                                    }
                                    else
                                    {
                                        /* ���򲻽����κδ��� */
                                    }
                                }
                            }
                            
                            if(tmp_npp_info.sessid>0 && tmp_npp_info.sessid<DBFW_MAX_SESSIONS)
                            {
                                /* 
                                    �����һ�ֵĲ��ң������ҵ�����һ�ֵ���Сworktime��Ԫ��,��һԪ�������Ҫ�������NPP����Ϣ 
                                    ����������sessions_free����ӦԪ����ֵΪ65535
                                */
                                //__NPC_SGA_SESSBUF->session_array->sessions_free[tmp_npp_info.sessid] = DBFW_SESSION_PRE_CLOSE_FLAG;
                                /* 2014-09-19 ��Ϊ���������ź����ķ�ʽ������NPP���� */
                                Dbfw_RemoveSem(global_ld.session_withclients[tmp_npp_info.sessid]._sem_id);
                                /* ������һ�ֵ�nppinfo_idx_for_minimum_worktime��npp_info��������Ӧ��Ԫ����������,�Ӷ����μӺ����Ĳ��� */
                                __NPP_INFO[nppinfo_idx_for_minimum_worktime].sessid = 0;
                                __NPP_INFO[nppinfo_idx_for_minimum_worktime].pid = 0;
                                __NPP_INFO[nppinfo_idx_for_minimum_worktime].last_worktime = 0;
                                /* ����NPC������ */
#ifdef USE_BSLHASH_FORSESSION
                                key = global_ld.session_withclients[tmp_npp_info.sessid].client_key;
                                Bslhash_Delete((Bslhash_t*)global_ld.mem_sess_bslist,key);
#endif
                                global_ld.session_withclients[tmp_npp_info.sessid].client_key = 0;
                                global_ld.session_withclients[tmp_npp_info.sessid]._sem_id = -1;
                            }
                            /* ����tmp_npp_info,Ϊ��һ�ֵļ����׼�� */
                            memset(&tmp_npp_info,0x00,sizeof(npp_info));
                            nppinfo_idx_for_minimum_worktime = 0;
                        }
                    }
                    /* ��¼��־ */
                    //printf("finish NPP's Check\n");
                    NPC_NEW_LOG(INFO_LEVEL, info_log, "Memory Exception: mem_total=%d, mem_used=%d ; will close %d sessions", 
                                s_system_source.system_total_memory, 
                                s_system_source.system_used_memory,
                                npp_count_forclose);
                    DBFW_INFO_PRINT(&npc_log_file, &info_log);
                    last_memory_clear_time = global_ld.alivetime;   /* �������һ�������ڴ��ʱ��� */
                }
            }
        }
//         else
//         {
//             /* ��ǰ��״̬�Ѿ����ڴ泬���ˣ�ֻ�����ڴ���֤���� */
//             if(s_system_source.system_total_memory==s_system_source_new.system_total_memory &&
//                 s_system_source.system_used_memory==s_system_source_new.system_used_memory
//                )
//             {
//                 /* ���λ�õ�����һ��,�������ڼ����ˣ�����ֱ����Ϊ�ڴ湻��:�Ա���֮ǰ��״̬(__OUT_OF_MEMORY_FLAG����) */
//                 if(s_system_source.system_used_memory>0 && s_system_source.system_total_memory>0 && s_system_source.system_total_memory>=s_system_source.system_used_memory)
//                 {
//                     /* ���Ǵ���0��ֵ�������ڴ�����>=��ʹ�õ��ڴ��� */
//                     if(s_system_source.system_used_memory > (s_system_source.system_total_memory*0.9))
//                     {
//                         /* ʹ���ڴ������������ڴ��� */
//                         __OUT_OF_MEMORY_FLAG = 0x01;
//                     }
//                     else
//                     {
//                         __OUT_OF_MEMORY_FLAG = 0x00;
//                     }
//                 }
//                 else
//                 {
//                     __OUT_OF_MEMORY_FLAG = 0x00;
//                 }
//             }
//             else
//             {
//                 /* ���ı��κ��߼� */
//                 //__OUT_OF_MEMORY_FLAG = 0x00;
//             }
//         }
		/* ����Ƿ���Ҫ���¼���db_hashmap */
		/* fixarray��acbuf�ļ������ĳ�ʼֵ��1,��ʱ�����л�db_hashmap */
		acbuf_change_count = Dbfw_Fixarray_GetAcbufChange((u_char*)__SGA);
		if(acbuf_change_count > last_acbuf_change_count)/*���¼���db��ַ*/
		{
			ret = Npc_HashmapReset(&global_ld.db_hashmap[1-global_ld.db_hashmap_id]);
			if(ret<0)
			{
				NPC_PRINT("[Error]: reload protected database's address error:%d, reset hashmap error\n", ret);
			}
			ret = Npc_LoadDBAddress(global_ld.acbuf, &global_ld.db_hashmap[1-global_ld.db_hashmap_id]);
			if(ret<0)/*���صĴ����ǻ�����ù���*/
			{
				NPC_PRINT("[Error]: reload protected database's address error:%d, hashpool is used out\n", ret);
			}
			else
			{
				global_ld.db_hashmap_id = 1-global_ld.db_hashmap_id;
				last_acbuf_change_count = acbuf_change_count;/*���سɹ�ʱ�Ÿ��¼���ֵ.�������ʧ��,����ֵ����,��ô�´�ѭ����Ҫ��������*/
				NPC_PRINT("[Info]: reload protected database's address ok, next db_hashmap_id:%d\n", global_ld.db_hashmap_id);			
			}
		}

		if((ret=pthread_mutex_lock(&global_ld.mutex_for_clear_session))!=0)
		{
			NPC_PRINT("[Error]: Npc_UpdateHeartbeat: lock \"mutex_for_clear_session\" error: errno=%d\n", ret);
		}

		//Npc_HashmapClear(&global_ld.session_hashmap);
#ifdef USE_BSLHASH_FORSESSION
        /* �賿5�����ͬ������ */
        NPC_GetLocalTime_Now(&__tm_current);
        if(__tm_current.tm_hour!=5)
        {
            __TODAY_ISSYNC_FLAG = 0;    /* �Ѿ�����5�㣬�����յ�δִ�б��,�ȴ���һ������� */
            Npc_ClearSessionWithClient();
        }
        else
        {
            /* ���賿5���ʱ��� */
            if(__TODAY_ISSYNC_FLAG==0)
            {
                /* ִ��ͬ������ */
                Npc_SyncSessionWithClientAndBSList();
                __TODAY_ISSYNC_FLAG = 1;    /* ������ִ�б�� */
            }
            else
            {
                Npc_ClearSessionWithClient();
            }
        }        
#else
        Npc_ClearSessionWithClient();
#endif
        /* ��ȡNPP���̳ز��� */
        memset(value, 0x00, sizeof(value));
        //ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal((u_char*)__SGA, S_NPP_POOL_NUM,value, PROCESS_PARAM_MAX_VALUES_LEN);
        ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal((u_char*)__SGA, S_NPP_POOL_NUM,(u_char*)value, SGA_PARAM_VALUES_LEN+1);
        if(ret == GET_PARAM_ERROR)
        {/*ȡֵ����,����ԭֵ����*/
            NPC_PRINT("[Error]: get S_NPP_POOL_NUM from fixarray error\n");
        }
        else
        {
            global_ld.npp_pool_size = atoi((char*)value);
            if(global_ld.npp_pool_size<=0)
            {
                global_ld.npp_pool_size = 0;/*δ����fixarray��Ĳ���,��Ĭ��ֵ����*/
            }
        }
        //printf("global_ld.npp_pool_size = %d\n",global_ld.npp_pool_size);
        /* ��ȡNPP���̳�����(�ݲ�����) */
        memset(value, 0x00, sizeof(value));
        ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal((u_char*)__SGA, NPP_POOL_TYPE,(u_char*)value, SGA_PARAM_VALUES_LEN+1);
        if(ret == GET_PARAM_ERROR)
        {/*ȡֵ����,����ԭֵ����*/
            NPC_PRINT("[Error]: get S_NPP_POOL_TYPE from fixarray error\n");
        }
        else
        {
            global_ld.npp_pool_type = atoi((char*)value);
            if(global_ld.npp_pool_type<1 || global_ld.npp_pool_type>2)
            {
                global_ld.npp_pool_type = NPP_POOL_TYPE_COMMON;/*δ����fixarray��Ĳ���,��Ĭ��ֵ����*/
            }
        }
        /* ���� */
#ifdef PRINT_THROUGHPUT
#ifdef USE_BSLHASH_FORSESSION
        bslhash_element_count = Bslhash_Count((Bslhash_t*)global_ld.mem_sess_bslist);
#endif
        NPC_NEW_LOG(INFO_LEVEL, info_log, "POOL_TYPE=%d, __TOTAL_PACKET_COUNT=%llu, __DROP_PACKET_COUNT=%llu, __TOTAL_SESSION_COUNT=%llu, bslhash_element_count=%u", 
            global_ld.npp_pool_type,
            __TOTAL_PACKET_COUNT, 
            __DROP_PACKET_COUNT,
            __TOTAL_SESSION_COUNT,
            bslhash_element_count);
        DBFW_INFO_PRINT(&npc_log_file, &info_log);
#endif

		if((ret=pthread_mutex_unlock(&global_ld.mutex_for_clear_session))!=0)
		{
			NPC_PRINT("[Error]: Npc_UpdateHeartbeat: unlock \"mutex_for_clear_session\" error: errno=%d\n", ret);
		}

		/*****************************
		**
		**	�����־�ļ��Ƿ���Ҫ���´���(��־Ŀ¼�б��)
		**
		*****************************/
		param_change_count = Dbfw_Fixarray_GetParamChange((u_char*)__SGA);
		if(param_change_count>last_param_change_count)
		{
			sleep(3);
			ret = Npc_InitNpcLogFile((u_char*)__SGA);
			if(ret<0)
			{
				NPC_PRINT("[Error]: switch log file error:%d\n", ret);
			}
			else
			{
				NPC_PRINT("[Info]: switch log file :%s\n", npc_log_file.path_name);
				last_param_change_count = param_change_count;
			}
			memset(value, 0x00, sizeof(value));
			ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal((u_char*)__SGA, DBFW_MAX_SESSION,value, PROCESS_PARAM_MAX_VALUES_LEN);
			if(ret == GET_PARAM_ERROR)
			{/*ȡֵ����,����ԭֵ����*/
				NPC_PRINT("[Error]: get DBFW_MAX_SESSION from fixarray error\n");
			}
			else
			{
				global_ld.dbfw_max_session = atoi((char*)value);
				if(global_ld.dbfw_max_session<=0)
				{
					global_ld.dbfw_max_session = DBFW_MAX_SESSIONS;/*δ����fixarray��Ĳ���,��Ĭ��ֵ����*/
				}
			}
		}

	}
	return NULL;
}

void* Npc_CreateNppThread(void *arg)
{
	int			arg_idx=0;
    int         ret = 0;
    u_short     session_used = 0;
    u_short     session_pid = 0;
    u_short     session_type = 0;
	NppArg		*npp_arg;
	u_char		*npp_argv[12];
	u_char		npp_file[128];
    u_char		npp_file_split[128];
    u_char      pool_flag = 0;
    u_char      is_dynaport = 0;
    u_short     dialect = 0;
    u_short     sessionid = 0;

#ifdef CK_LICENCE_TIME	
	time_t t = time(0);
	int year=0;
	int moon=0;
	int date=0;
	struct   tm     *timenow;         //ʵ����tm�ṹָ��
	timenow   =   localtime(&t);
	year = timenow->tm_year+ 1900;
	moon  = timenow->tm_mon +1;
	date = timenow->tm_mday;
	if(year>=CK_LICENCE_TIME_YEAR && moon>=CK_LICENCE_TIME_MON && date>=CK_LICENCE_TIME_DAY){
		printf("check license error");
		return NULL;
	}
#endif	
	npp_argv[0]=(u_char*)malloc(128);/* NPP name's length may be longer */
	for(int i=1;i<11;++i)
	{
		npp_argv[i]=(u_char*)malloc(32);
	}
	npp_argv[11]=(u_char*)0;
    memset(npp_file,0x00,sizeof(npp_file));
	strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
	strcat((char*)npp_file, "/bin/npp");                    /* ����ʵ�ʵ�npp�������� */
    
	sprintf((char*)npp_argv[0], "npp");						/*�滻�� "npp",��������ں���ᱻ���Ϊʵ����ʾ�Ľ�������:DBFWʵ����_nppx_xxxxx */
	sprintf((char*)npp_argv[1], "2");						/*Ҫ������NPP��������*/
	sprintf((char*)npp_argv[2], "%d", global_ld.shm_id);	/*�����ڴ�id*/
	sprintf((char*)npp_argv[10], "%d", global_ld.npc_id);	/*npc_id����capbuf_id*/

	for(;;)
	{
		if(Dbfw_LockSem(global_ld.sem_id_for_create_npp)==-1)
		{
			//NPC_PRINT("[Error]: Npc_CreateNppThread:Dbfw_LockSem error, %s\n", strerror(errno));
			break;
		}        
		npp_arg = &global_ld.npp_args[arg_idx];
//         printf("<<<<arg_idx = %d , sessionid=%d, client_ip=%u, client_port=%d, session_used=%d, session_pid=%d\n",
//             arg_idx,npp_arg->session_id,npp_arg->client_ip,npp_arg->client_port,
//             __NPC_SGA_SESSBUF->session_array->sessions_used[sessionid],
//             __NPC_SGA_SESSBUF->session_array->npppid[sessionid]);
        /************************************************************************/
        /* �����ǶԻỰ����У����߼�                                                       */
        /************************************************************************/
        /* ���npp_arg�Ƿ���Ч */
        if(npp_arg->session_id == 65535 || npp_arg->client_ip==0 ||npp_arg->client_port==0)
        {
            /* ��Ч��npp_arg */
            if(++arg_idx==NPC_MAX_NPP_ARG)
            {
                arg_idx = 0;
            }
            NPC_NEW_LOG(ERROR_LEVEL, error_log, "Npc_CreateNppThread exception_1 npp_arg->session_id=%d, npp_arg->client_ip=%u, npp_arg->client_port=%d\n",npp_arg->session_id,npp_arg->client_ip,npp_arg->client_port);
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
            //printf("Attention : Npc_CreateNppThread exception_1 npp_arg->session_id=%d, npp_arg->client_ip=%u, npp_arg->client_port=%d\n",npp_arg->session_id,npp_arg->client_ip,npp_arg->client_port);
            continue;
        }
        /* ���Ự��״̬ */
        sessionid = npp_arg->session_id;
        ret = Npp_Sga_Lock_Block31(__NPC_SGA_SESSBUF);
        if(ret<0)
        {
            /* ����ʧ�� */
            session_type = 0;
            session_pid = 0;
            session_used = 0;
        }
        else
        {
            session_type = __NPC_SGA_SESSBUF->session_array->session_type[sessionid];
            session_pid = __NPC_SGA_SESSBUF->session_array->npppid[sessionid];
            session_used = __NPC_SGA_SESSBUF->session_array->sessions_used[sessionid];
        }        
        ret = Npp_Sga_UnLock_Block31(__NPC_SGA_SESSBUF);
        if(session_used==DBFW_SESSIONARRAY_FLAG_FREE)
        {
            /* �Ự��״̬�쳣 */
            if(++arg_idx==NPC_MAX_NPP_ARG)
            {
                arg_idx = 0;
            }
            NPC_NEW_LOG(ERROR_LEVEL, error_log, "Npc_CreateNppThread exception_2 npp_arg->session_id=%d, npp_arg->client_ip=%u, npp_arg->client_port=%d\n",npp_arg->session_id,npp_arg->client_ip,npp_arg->client_port);
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
            //printf("Attention : Npc_CreateNppThread exception_2 npp_arg->session_id=%d, npp_arg->client_ip=%u, npp_arg->client_port=%d\n",npp_arg->session_id,npp_arg->client_ip,npp_arg->client_port);
            npp_arg->session_id = 65535;
            npp_arg->client_ip = 0;
            npp_arg->client_port = 0;
            continue;
        }
        /************************************************************************/
        /* У�����                                                                        */
        /************************************************************************/

		Npc_Ip2Str(npp_arg->client_ip, npp_argv[3]);
		Npc_Int2Str(npp_arg->client_port, npp_argv[4]);
		Npc_FormatMacAddress(npp_arg->client_mac, npp_argv[5]);

		Npc_Ip2Str(npp_arg->server_ip, npp_argv[6]);
		Npc_Int2Str(npp_arg->server_port, npp_argv[7]);
		Npc_FormatMacAddress(npp_arg->server_mac, npp_argv[8]);

		Npc_Int2Str(npp_arg->session_id, npp_argv[9]);
        is_dynaport = global_ld.session_withclients[npp_arg->session_id].is_dynaport;
        dialect = global_ld.session_withclients[npp_arg->session_id].dialect;        
        /* 2014-10-16 ���Ӹ���DB����ȷ����ӦNPP���̵��߼� */
#ifdef HAVE_SPLIT_NPP   /* NPP���뷽ʽ,�ع�npp�ļ����� */
        /* 
            ������Ҫ�����Ƿ����˽��̳���ȷ�������Ľ��̣���������˽��̳أ����������NPP��������������ֽ��̵�NPP
            ��ȡ��ǰ���õĽ��̳ز�����Ҫ��Npc_UpdateHeartbeat�̺߳����н��У�������Ȼ����һ���ӳ٣�������Ӱ������
            ע�⣺���ڶ�̬�˿ڣ�Ŀǰֻ�ܲ���ͨ�ý��̵�ģʽ������ģʽĿǰֻ֧��Oracle���ݿ�����
        */
        if(global_ld.npp_pool_size==0)
        {
            /* û������NPP���̳�,����ʹ�÷ֽ���ģʽ */
            if(is_dynaport==0/* ���Ƕ�̬�˿� */)
            {
                memset(npp_file,0x00,sizeof(npp_file));
                memset(npp_file_split,0x00,sizeof(npp_file_split));
                strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                strcat((char*)npp_file, "/bin/");                    /* ����ʵ�ʵ�npp�������� */
                Npc_GetNppnameForDB(npp_arg->server_ip,npp_arg->server_port,(u_char*)npp_file_split,sizeof(npp_file_split));
                strcat((char*)npp_file, (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
                strcpy((char*)npp_argv[0], (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
            }
            else
            {
                /* �Ƕ�̬�˿ڣ�Ŀǰֻ֧��Oracle���ݿ����ͣ���֧��DB2���͵Ķ�̬�˿� */
                memset(npp_file,0x00,sizeof(npp_file));
                memset(npp_file_split,0x00,sizeof(npp_file_split));
                strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                strcat((char*)npp_file, "/bin/npp_ora");                    /* ����ʵ�ʵ�npp�������� */
                //Npc_GetNppnameForDB(npp_arg->server_ip,npp_arg->server_port,(u_char*)npp_file_split,sizeof(npp_file_split));
                strcpy((char*)npp_file_split,(char*)"npp_ora");
                strcat((char*)npp_file, (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
                strcpy((char*)npp_argv[0], (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
            }
        }
        else
        {
            /* �����˽��̳أ�����ʹ�÷ֽ���ģʽ,������Ҫ������䣬��Ϊ��ʱ��һ��ѭ�����������ɴ�����������npc core */
            if(global_ld.npp_pool_type==NPP_POOL_TYPE_COMMON)
            {
                /* ��ͨ�����͵�NPP���̳� */
                if(dialect==DBFW_DBTYPE_MSSQL)
                {
                    /* ���Ự��������MSSQL���ͣ�ֻ��ʹ��npp_mssql������̣���֧�ֽ��̳� */
                    memset(npp_file,0x00,sizeof(npp_file));
                    strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                    strcat((char*)npp_file, "/bin/npp_mssql");                    /* ����ʵ�ʵ�npp�������� */
                    sprintf((char*)npp_argv[0], "npp_mssql");
                }
                else
                {
                    /* ����ʹ��ͨ�����ͽ��̳�npp */
                    memset(npp_file,0x00,sizeof(npp_file));
                    strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                    strcat((char*)npp_file, "/bin/npp");                    /* ����ʵ�ʵ�npp�������� */
                    sprintf((char*)npp_argv[0], "npp");						/*�滻�� "npp",��������ں���ᱻ���Ϊʵ����ʾ�Ľ�������:DBFWʵ����_nppx_xxxxx */
                }
            }
            else
            {
                /* ��MSSQL���ͽ��̳� */
                if(dialect!=DBFW_DBTYPE_MSSQL)
                {
                    /* ���Ự��������MSSQL���ͣ�ֻ��ʹ�÷�����̣���֧�ֽ��̳� */
                    memset(npp_file,0x00,sizeof(npp_file));
                    memset(npp_file_split,0x00,sizeof(npp_file_split));
                    strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                    strcat((char*)npp_file, "/bin/");                    /* ����ʵ�ʵ�npp�������� */
                    Npc_GetNppnameForDB(npp_arg->server_ip,npp_arg->server_port,(u_char*)npp_file_split,sizeof(npp_file_split));
                    strcat((char*)npp_file, (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
                    strcpy((char*)npp_argv[0], (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
                }
                else
                {
                    /* ��MSSQL�Ự������ʹ��MSSQL���͵Ľ��̳� */
                    memset(npp_file,0x00,sizeof(npp_file));
                    strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                    strcat((char*)npp_file, "/bin/npp_mssql");                    /* ����ʵ�ʵ�npp�������� */
                    sprintf((char*)npp_argv[0], "npp_mssql");
                }
            }
        }
#endif
        /* ����npp_arg */
        npp_arg->session_id = 65535;
        npp_arg->client_ip = 0;
        npp_arg->client_port = 0;
		Npc_ConstructNppName(npp_argv[0], global_ld.dbfw_instance_name);
        /* ����NPC������ʱ������NPP */
//#ifdef HAVE_NPP_POOL
        /* 
            ֧��NPP���̳�
            ���SGA���Ự��λ��session_type���ͺ�nppid,��������ǡ�����(DBFW_SESSION_TYPE_NPCPOOL)�����򲻴���NPP���̣��������ù���Ľ���
        */        
        if((session_type==DBFW_SESSION_TYPE_NPCPOOL) || (session_pid>0))
        {
            /* 
                �����߼��������ϲ����������
                �ǹ���Ľ��̣����ҽ���PID���� 
                ����ΪDBFW_SESSIONARRAY_FLAG_USED״̬(��Ҫ����������)
            */
            //__NPC_SGA_SESSBUF->session_array->sessions_used[npp_arg->session_id] = DBFW_SESSIONARRAY_FLAG_USED;
            //__NPC_SGA_SESSBUF->session_array->session_type[npp_arg->session_id] = DBFW_SESSION_TYPE_NPC;
            NPC_NEW_LOG(ERROR_LEVEL, error_log,"[EXCEPTION] IS NPPPOOL for session=%d, session_pid=%d", sessionid,session_pid);
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
            pool_flag = 1;
        }
        else
        {
            /* �����µ�NPP���� */
            pool_flag = 0;
            Dbfw_CreateProcess((char*)npp_file, (char**)npp_argv);
        }
//#else
//		Dbfw_CreateProcess((char*)npp_file, (char**)npp_argv);
//#endif


		NPC_NEW_LOG(INFO_LEVEL, info_log, "[sesseion_id=%s, pool_flag=%d] %s:%s [%s]  --->  %s:%s [%s] [%s]",
			npp_argv[9],
            pool_flag,
			npp_argv[3],
			npp_argv[4],
			npp_argv[5],
			npp_argv[6],
			npp_argv[7],
			npp_argv[8],
            npp_file);
		DBFW_INFO_PRINT(&npc_log_file, &info_log);


		NPC_PRINT("[Info]: npp_arg_idx=%d, [session_id=%s] %s:%s [%s]  --->  %s:%s [%s]\n",
			arg_idx,
			npp_argv[9],
			npp_argv[3],
			npp_argv[4],
			npp_argv[5],
			npp_argv[6],
			npp_argv[7],
			npp_argv[8]);

		if(++arg_idx==NPC_MAX_NPP_ARG)
		{
			arg_idx = 0;
		}
	}
	return NULL;
}

u_int npc_str2ip(u_char *data) {
    u_int    a, b, c, d;

    if(!data[0]) return(0);
    sscanf((char *)data, "%u.%u.%u.%u", &a, &b, &c, &d);
    return((a & 0xff) | ((b & 0xff) << 8) | ((c & 0xff) << 16) | ((d & 0xff) << 24));
}

void Npc_InitNppPool(void)
{
	int			arg_idx=0;
    int         ret = 0;
    int         i = 0;
    u_short     session_used_flag = 0;
    u_short     session_pid = 0;
	NppArg		*npp_arg;
	u_char		*npp_argv[12];
	u_char		npp_file[128];
    u_char		npp_file_split[128];
    u_char      pool_flag = 0;
    u_char      is_dynaport = 0;
    u_short     dialect = 0;
    u_short     cur_session_id=NPC_HASHMAP_NOT_FIND_KEY;
    u_short npp_dialect = 0;
    u_int64 client_ip_value;
    u_short client_port;
    int sem_id = 0;
    u_int64 client_key=0;
    u_char usepool_flag = 0;
    u_char value[PROCESS_PARAM_MAX_VALUES_LEN];

#ifdef CK_LICENCE_TIME	
	time_t t = time(0);
	int year=0;
	int moon=0;
	int date=0;
	struct   tm     *timenow;         //ʵ����tm�ṹָ��
	timenow   =   localtime(&t);
	year = timenow->tm_year+ 1900;
	moon  = timenow->tm_mon +1;
	date = timenow->tm_mday;
	if(year>=CK_LICENCE_TIME_YEAR && moon>=CK_LICENCE_TIME_MON && date>=CK_LICENCE_TIME_DAY){
		printf("check license error");
		return NULL;
	}
#endif	
	npp_argv[0]=(u_char*)malloc(128);/* NPP name's length may be longer */
	for(int i=1;i<11;++i)
	{
		npp_argv[i]=(u_char*)malloc(32);
	}
	npp_argv[11]=(u_char*)0;
    memset(npp_file,0x00,sizeof(npp_file));
	strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
	strcat((char*)npp_file, "/bin/npp");                    /* ����ʵ�ʵ�npp�������� */
    
	sprintf((char*)npp_argv[0], "npp");						/*�滻�� "npp",��������ں���ᱻ���Ϊʵ����ʾ�Ľ�������:DBFWʵ����_nppx_xxxxx */
	sprintf((char*)npp_argv[1], "8");						/*Ҫ������NPP��������:SUSPEND���͵�NPC */
	sprintf((char*)npp_argv[2], "%d", global_ld.shm_id);	/*�����ڴ�id*/
	sprintf((char*)npp_argv[10], "%d", global_ld.npc_id);	/*npc_id����capbuf_id*/

    //client_ip_value = (255*255*255)+(255*255)+255+global_ld.npc_id;        /* 1.1.1.1 */
    client_ip_value = npc_str2ip((u_char*)"1.1.1.1");
    client_ip_value = client_ip_value + global_ld.npc_id;

    /* ��ȡNPP���̳ز��� */
    memset(value, 0x00, sizeof(value));
    //ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal((u_char*)__SGA, S_NPP_POOL_NUM,value, PROCESS_PARAM_MAX_VALUES_LEN);
    ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal((u_char*)__SGA, S_NPP_POOL_NUM,(u_char*)value, SGA_PARAM_VALUES_LEN+1);
    if(ret == GET_PARAM_ERROR)
    {/*ȡֵ����,����ԭֵ����*/
        NPC_PRINT("[Error]: get S_NPP_POOL_NUM from fixarray error\n");
    }
    else
    {
        global_ld.npp_pool_size = atoi((char*)value);
        if(global_ld.npp_pool_size<=0)
        {
            global_ld.npp_pool_size = 0;/*δ����fixarray��Ĳ���,��Ĭ��ֵ����*/
        }
    }
    //printf("global_ld.npp_pool_size = %d\n",global_ld.npp_pool_size);
    /* ��ȡNPP���̳�����(�ݲ�����) */
    memset(value, 0x00, sizeof(value));
    ret = Dbfw_Fixarray_GetValueAndValuelenInGlobal((u_char*)__SGA, NPP_POOL_TYPE,(u_char*)value, SGA_PARAM_VALUES_LEN+1);
    if(ret == GET_PARAM_ERROR)
    {/*ȡֵ����,����ԭֵ����*/
        NPC_PRINT("[Error]: get S_NPP_POOL_TYPE from fixarray error\n");
    }
    else
    {
        global_ld.npp_pool_type = atoi((char*)value);
        if(global_ld.npp_pool_type<1 || global_ld.npp_pool_type>2)
        {
            global_ld.npp_pool_type = NPP_POOL_TYPE_COMMON;/*δ����fixarray��Ĳ���,��Ĭ��ֵ����*/
        }
    }

    if(global_ld.npp_pool_size==0)
    {
        /* û�����ý��̳� */
        NPC_NEW_LOG(INFO_LEVEL, info_log, "no config npp pools");
        DBFW_INFO_PRINT(&npc_log_file, &info_log);
        return;
    }

	for(i=0;i<NPC_SUSPEND_NPPPOOL_COUNT;i++)
	{
// 		if(Dbfw_LockSem(global_ld.sem_id_for_create_npp)==-1)
// 		{
// 			//NPC_PRINT("[Error]: Npc_CreateNppThread:Dbfw_LockSem error, %s\n", strerror(errno));
// 			break;
// 		}
        /**********************************
		**
		**	1.�ж�npp���������Ƿ�ﵽ���ֵ 
		**
		**********************************/
		ret = Dbfw_Fixarray_AddNppCount(global_ld.sga_addr, global_ld.dbfw_max_session);

		if(ret==-1)/* �Ի���������ʧ�� */
		{
			NPC_PRINT("[Error]: lock mutex error when add npp count\n");
			global_ld.error_no = NPC_ERROR_ADDNPPCOUNT_LOCK-NPC_ERRNO_START;
            NPC_NEW_LOG(ERROR_LEVEL, error_log, "lock mutex error when add npp count");
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
			return;
		}
		else if(ret==0)/* NPP�������ﵽ�����ֵ */
		{
			NPC_PRINT("[Error]: npp's count reach to DBFW_MAX_SESSIONS when add npp count\n");
            NPC_NEW_LOG(ERROR_LEVEL, error_log, "npp's count reach to DBFW_MAX_SESSIONS when add npp count");
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
			return;
		}

        /**********************************
		**
		**	3.���µ�session_id 
		**
		**********************************/
		/* ���ret=65535, ��ʾ�����µ�session_id */
        /* �ȼ���Ƿ��ܹ�ʹ��NPP���̳� */
        npp_dialect = Npc_GetDBDialectForServer(global_ld.npp_pool_default_dbaddress_value, global_ld.npp_pool_default_serverport);
        usepool_flag = 1;   /* ʹ�ý��̳ر�� */
//         if(npp_dialect==DBFW_DBTYPE_MSSQL)
//         {
//             /* �ǵ�ǰ������MSSQL���͵�NPP */
//             if(global_ld.npp_pool_type!=NPP_POOL_TYPE_MSSQL)
//             {
//                 /* �����̳�����Ϊ�ǡ�MSSQL�͡� */
//                 usepool_flag = 0;
//             }
//         }
//         else
//         {
//             /* ��ǰ�����ǡ�ͨ���͡�NPP */
//             if(global_ld.npp_pool_type==NPP_POOL_TYPE_MSSQL)
//             {
//                 /* �����̳�����Ϊ��MSSQL�͡� */
//                 usepool_flag = 0;
//             }
//                //usepool_flag = 1;
        client_port = (u_short)global_ld.npp_pool_default_clientport;
        client_key = client_ip_value;
        client_key = (client_key<<16)|client_port;
		ret = Dbfw_BindSessionForNPC(global_ld.sga_addr, client_ip_value, client_port, 65535,usepool_flag);
		if(ret == -1)
		{
            /* ��NPP���̸�����һ */
            Dbfw_Fixarray_SubNppCount((u_char*)global_ld.sga_addr);
            NPC_NEW_LOG(ERROR_LEVEL, error_log,"Dbfw_BindSessionForNPC() error: no free session can use.");
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
            NPC_PRINT("[Error]: Dbfw_BindSessionForNPC() error: no free session can use\n");
			return;
		}
		else if(ret == 65535)
		{/* û�п��õ�session_id */
            /* ��NPP���̸�����һ */
            Dbfw_Fixarray_SubNppCount((u_char*)global_ld.sga_addr);
			NPC_NEW_LOG(ERROR_LEVEL, error_log,"Dbfw_BindSessionForNPC() error: no free session can use.");
			DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
			NPC_PRINT("[Error]: Dbfw_BindSessionForNPC() error: no free session can use\n");

			return;
		}
		cur_session_id = ret;
        global_ld.semvalue_outofrange_flag[cur_session_id] = 0;

        Tis_Slot_Close(global_ld.tis,cur_session_id);
        ret = Tis_Slot_Open(global_ld.tis,cur_session_id);
        if(ret < 0)
        {
            NPC_NEW_LOG(ERROR_LEVEL, error_log,"Tis_Slot_Open() error: slot_id=%d ret=%d",
                cur_session_id,ret);
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
            printf("Tis_Slot_Open() error: slot_id=%d ret=%d",
                cur_session_id,ret);
            Dbfw_FreeSession(global_ld.sga_addr,cur_session_id);
            /* ��NPP���̸�����һ */
            Dbfw_Fixarray_SubNppCount((u_char*)global_ld.sga_addr);
            return;
        }
        /**********************************
		**
		**	4.���client ip+port => {session_id, sem_id} 
		**	  ��session_hashmap��,����
		**	  
		**********************************/
		sem_id = global_ld.sems->semid[cur_session_id];

		//NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
        ret = Npc_SetSessionWithClient(client_key, cur_session_id, npp_dialect, is_dynaport, sem_id);
		//NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
		if(ret==-2)
		{ /* ������ù��� */
			global_ld.error_no = NPC_ERROR_HASHPOOL_ALLUSED-NPC_ERRNO_START;
            NPC_NEW_LOG(ERROR_LEVEL, error_log,"The buffer pool for session_hashmap have not slot.");
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
			return;
		}

		//npp_arg = &global_ld.npp_args[arg_idx];
        /* clientip */
        //strcpy((char*)npp_argv[3],(char*)"1.1.1.1");        
		Npc_Ip2Str(client_ip_value, npp_argv[3]);
        /* clientport */        
		Npc_Int2Str(client_port, npp_argv[4]);
        global_ld.npp_pool_default_clientport++;
        /* client_mac */
        strcpy((char*)npp_argv[5],(char*)"00:00:00:00:00:00");
		//Npc_FormatMacAddress(npp_arg->client_mac, npp_argv[5]);
        /* ���ݿ�IP */
        strcpy((char*)npp_argv[6],(char*)global_ld.npp_pool_default_dbip);
		//Npc_Ip2Str(npp_arg->server_ip, npp_argv[6]);
        /* ���ݿ�˿� */
        Npc_Int2Str(global_ld.npp_pool_default_serverport,npp_argv[7]);
		//Npc_Int2Str(npp_arg->server_port, npp_argv[7]);
        /* ���ݿ�MAC */
        strcpy((char*)npp_argv[8],(char*)"00:00:00:00:00:00");
		//Npc_FormatMacAddress(npp_arg->server_mac, npp_argv[8]);

		Npc_Int2Str(cur_session_id, npp_argv[9]);
        //is_dynaport = global_ld.session_withclients[npp_arg->session_id].is_dynaport;
        dialect = global_ld.session_withclients[cur_session_id].dialect;
        /* 2014-10-16 ���Ӹ���DB����ȷ����ӦNPP���̵��߼� */
#ifdef HAVE_SPLIT_NPP   /* NPP���뷽ʽ,�ع�npp�ļ����� */
        /* 
            ������Ҫ�����Ƿ����˽��̳���ȷ�������Ľ��̣���������˽��̳أ����������NPP��������������ֽ��̵�NPP
            ��ȡ��ǰ���õĽ��̳ز�����Ҫ��Npc_UpdateHeartbeat�̺߳����н��У�������Ȼ����һ���ӳ٣�������Ӱ������
            ע�⣺���ڶ�̬�˿ڣ�Ŀǰֻ�ܲ���ͨ�ý��̵�ģʽ������ģʽĿǰֻ֧��Oracle���ݿ�����
        */
        if(global_ld.npp_pool_size==0)
        {
            /* û������NPP���̳�,����ʹ�÷ֽ���ģʽ */
            if(is_dynaport==0/* ���Ƕ�̬�˿� */)
            {
                memset(npp_file,0x00,sizeof(npp_file));
                memset(npp_file_split,0x00,sizeof(npp_file_split));
                strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                strcat((char*)npp_file, "/bin/");                    /* ����ʵ�ʵ�npp�������� */
                Npc_GetNppnameForDB(global_ld.npp_pool_default_dbaddress_value,
                    global_ld.npp_pool_default_serverport,
                    (u_char*)npp_file_split,
                    sizeof(npp_file_split)
                    );
                strcat((char*)npp_file, (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
                strcpy((char*)npp_argv[0], (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
            }
            else
            {
                /* �Ƕ�̬�˿ڣ�Ŀǰֻ֧��Oracle���ݿ����ͣ���֧��DB2���͵Ķ�̬�˿� */
                memset(npp_file,0x00,sizeof(npp_file));
                memset(npp_file_split,0x00,sizeof(npp_file_split));
                strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                strcat((char*)npp_file, "/bin/npp_ora");                    /* ����ʵ�ʵ�npp�������� */
                //Npc_GetNppnameForDB(npp_arg->server_ip,npp_arg->server_port,(u_char*)npp_file_split,sizeof(npp_file_split));
                strcpy((char*)npp_file_split,(char*)"npp_ora");
                strcat((char*)npp_file, (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
                strcpy((char*)npp_argv[0], (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
            }
        }
        else
        {
            /* �����˽��̳أ�����ʹ�÷ֽ���ģʽ,������Ҫ������䣬��Ϊ��ʱ��һ��ѭ�����������ɴ�����������npc core */
            if(global_ld.npp_pool_type==NPP_POOL_TYPE_COMMON)
            {
                /* ��ͨ�����͵�NPP���̳� */
                if(dialect==DBFW_DBTYPE_MSSQL)
                {
                    /* ���Ự��������MSSQL���ͣ�ֻ��ʹ��npp_mssql������̣���֧�ֽ��̳� */
                    memset(npp_file,0x00,sizeof(npp_file));
                    strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                    strcat((char*)npp_file, "/bin/npp_mssql");                    /* ����ʵ�ʵ�npp�������� */
                    sprintf((char*)npp_argv[0], "npp_mssql");
                }
                else
                {
                    /* ����ʹ��ͨ�����ͽ��̳�npp */
                    memset(npp_file,0x00,sizeof(npp_file));
                    strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                    strcat((char*)npp_file, "/bin/npp");                    /* ����ʵ�ʵ�npp�������� */
                    sprintf((char*)npp_argv[0], "npp");						/*�滻�� "npp",��������ں���ᱻ���Ϊʵ����ʾ�Ľ�������:DBFWʵ����_nppx_xxxxx */
                }
            }
            else
            {
                /* ��MSSQL���ͽ��̳� */
                if(dialect!=DBFW_DBTYPE_MSSQL)
                {
                    /* ���Ự��������MSSQL���ͣ�ֻ��ʹ�÷�����̣���֧�ֽ��̳� */
                    memset(npp_file,0x00,sizeof(npp_file));
                    memset(npp_file_split,0x00,sizeof(npp_file_split));
                    strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                    strcat((char*)npp_file, "/bin/");                    /* ����ʵ�ʵ�npp�������� */
                    Npc_GetNppnameForDB(global_ld.npp_pool_default_dbaddress_value,
                        global_ld.npp_pool_default_serverport,
                        (u_char*)npp_file_split,
                        sizeof(npp_file_split));
                    strcat((char*)npp_file, (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
                    strcpy((char*)npp_argv[0], (char*)npp_file_split);                    /* ����ʵ�ʵ�npp�������� */
                }
                else
                {
                    /* ��MSSQL�Ự������ʹ��MSSQL���͵Ľ��̳� */
                    memset(npp_file,0x00,sizeof(npp_file));
                    strcpy((char*)npp_file, (char*)global_ld.dbfw_home);
                    strcat((char*)npp_file, "/bin/npp_mssql");                    /* ����ʵ�ʵ�npp�������� */
                    sprintf((char*)npp_argv[0], "npp_mssql");
                }
            }
        }
#endif
		Npc_ConstructNppName(npp_argv[0], global_ld.dbfw_instance_name);
        /* ����NPC������ʱ������NPP */
//#ifdef HAVE_NPP_POOL
        /* 
            ֧��NPP���̳�
            ���SGA���Ự��λ��session_type���ͺ�nppid,��������ǡ�����(DBFW_SESSION_TYPE_NPCPOOL)�����򲻴���NPP���̣��������ù���Ľ���
        */

        ret = Npp_Sga_Lock_Block31(__NPC_SGA_SESSBUF);
        //printf("Npp_Sga_Lock_Block31 = %d\n",ret);
        if(ret<0)
        {
            /* ����ʧ�� */
            session_used_flag = 0;
            session_pid = 0;
        }
        else
        {
            session_used_flag = __NPC_SGA_SESSBUF->session_array->session_type[npp_arg->session_id];
            session_pid = __NPC_SGA_SESSBUF->session_array->npppid[npp_arg->session_id];
        }
        ret = Npp_Sga_UnLock_Block31(__NPC_SGA_SESSBUF);
        if((session_used_flag==DBFW_SESSION_TYPE_NPCPOOL) && 
           (session_pid>0)
          )
        {
            /* 
                �ǹ���Ľ��̣����ҽ���PID���� 
                ����ΪDBFW_SESSIONARRAY_FLAG_USED״̬(��Ҫ����������)
            */
            //__NPC_SGA_SESSBUF->session_array->sessions_used[npp_arg->session_id] = DBFW_SESSIONARRAY_FLAG_USED;
            //__NPC_SGA_SESSBUF->session_array->session_type[npp_arg->session_id] = DBFW_SESSION_TYPE_NPC;
            pool_flag = 1;
        }
        else
        {
            /* �����µ�NPP���� */
            pool_flag = 0;
            NPC_NEW_LOG(INFO_LEVEL, info_log, "[create process] %s",
                npp_file);
            DBFW_INFO_PRINT(&npc_log_file, &info_log);
            Dbfw_CreateProcess((char*)npp_file, (char**)npp_argv);
        }
//#else
//		Dbfw_CreateProcess((char*)npp_file, (char**)npp_argv);
//#endif


		NPC_NEW_LOG(INFO_LEVEL, info_log, "[sesseion_id=%s, pool_flag=%d] %s:%s [%s]  --->  %s:%s [%s] [%s]",
			npp_argv[9],
            pool_flag,
			npp_argv[3],
			npp_argv[4],
			npp_argv[5],
			npp_argv[6],
			npp_argv[7],
			npp_argv[8],
            npp_file);
		DBFW_INFO_PRINT(&npc_log_file, &info_log);


		NPC_PRINT("[Info]: npp_arg_idx=%d, [session_id=%s] %s:%s [%s]  --->  %s:%s [%s]\n",
			arg_idx,
			npp_argv[9],
			npp_argv[3],
			npp_argv[4],
			npp_argv[5],
			npp_argv[6],
			npp_argv[7],
			npp_argv[8]);
        usleep(1000);
	}
    /* ȫ��������ɺ���Ҫ��ʱ3�룬�ȴ����е�NPP���̽������״̬ */
    sleep(3);
	return;
}

/************************************************
**
**	������
**
************************************************/
int main(int argc, char *argv[])
{
	int ret=0;
    int i = 0;
	gboolean             start_capture = TRUE;
	int                  opt;

	struct pcap_stat     stats;
	gboolean             list_interfaces = FALSE;

	gboolean             machine_readable = FALSE;
	gboolean             print_statistics = FALSE;
	int                  status=0;
	guint                j;
	gboolean             loop_ret;
	char 				*optstring ="m:i:d:c:f:lsh";
	char				*device_name=NULL;

	u_char				library_path[512];
	char				*p_LD_LIBRARY_PATH=NULL;

	pthread_t			tid;

	int     shm_id=-1;
	u_char *shm_addr;

	int granule_offset_for_capbuf;
	int sga_granule_size;


	npc_print_version("npc");
	
	Npc_Sched_CPU();
	
	/* �����ӽ��̵��˳��ź� */
	if(Dbfw_IgnoreChildProcessExit()==-1)
	{
		NPC_PRINT( "[Error]: ignore child process exit failed\n");
	}

	/* ע��NPC���˳������� */
	if(Dbfw_RegisterProcessExitFunction(Npc_NormalExitHandler)==-1)
	{
		NPC_PRINT( "[Error]: register NPC's exit function failed\n");
	}
	/* ע��NPC��Crash������ */
	if(Dbfw_RegisterProcessCrashFunctionWithCoredump(Npc_FaultTrap)==-1)
	{
		NPC_PRINT( "[Error]: register NPC's crash function with coredump failed\n");	
	}


	/* Set the initial values in the capture options. This might be overwritten
	by the command line parameters. */
	

	__STOP=0;
	__COUNT=0;
	__DROP_PACKET_COUNT = 0;
	__TOTAL_PACKET_COUNT = 0;
	__TOTAL_PACKET_INDEX = 0;
    __TOTAL_SESSION_COUNT = 0;
    memset(&global_ld,0x00,sizeof(loop_data));
	global_ld.npc_id = 0;/*Ĭ��Ϊ1*/


	while((opt=getopt(argc, argv, optstring))!=-1)
	{
		switch(opt)
		{
		case 'm':
			shm_id = atoi(optarg);
			break;
		case 'i':/* NPC�ı�ʶ: 1-4 */
			global_ld.npc_id = atoi(optarg);
			break;
		case 'd':
			device_name = optarg;
#ifdef USE_FILTER
			strcpy((char*)global_ld.npc_info.device, device_name);
#endif
			break;
		case 'c':/* max count of capture packets*/
			__STOP=atoi(optarg);
			break;
		case 'f':
#ifdef USE_FILTER 
		/*��fixarray��ȡfilter*/
		
#else	/*�������в������ȡfilter���ʽ*/
			__FILTER = optarg;
#endif

			break;
		case 'l':
			list_interfaces = TRUE;
			//break;
		case 's':
			print_statistics = TRUE;
			break;
		case 'h':
			print_usage(argv, 0);
			return 0;

		}
	}

	/*�����в������*/
#ifdef USE_FILTER 
	if(shm_id==-1||device_name==NULL||global_ld.npc_id==0)
	{
		print_usage(argv, 1);
		return 0;
	}
#else
	if(shm_id==-1||device_name==NULL||__FILTER==NULL)
	{
		print_usage(argv, 0);
		return 0;
	}
	//global_ld.npc_id = 1;   /* �����Ҫ֧�ֶ��NPC�ɼ��������ȥ�����д��� */
#endif
	if(global_ld.npc_id<=0 || global_ld.npc_id > DBFW_NPC_FILTER_MAX_COUNT)//FIXARRAY_MAX_NPC_ARG)
	{
		NPC_PRINT("[Error]: invalid npc_id: %u\n", global_ld.npc_id);
		return NPC_ERROR_INVALID_NPCID-NPC_ERRNO_START;
	}


	if (list_interfaces) 
	{
		/* Get the list of interfaces */
		GList       *if_list;
		int         err;
		gchar       *err_str;

		if_list = capture_interface_list(&err, &err_str);
		if (if_list == NULL)
		{
			switch (err)
			{
			case CANT_GET_INTERFACE_LIST:
				NPC_PRINT("[Error]: %s", err_str);
				g_free(err_str);
				exit_main(2);
				break;

			case NO_INTERFACES_FOUND:
				/*
				* If we're being run by another program, just give them
				* an empty list of interfaces, don't report this as
				* an error; that lets them decide whether to report
				* this as an error or not.
				*/
				if (!machine_readable) {
					NPC_PRINT("[Error]: there are no interfaces on which a capture can be done");
					exit_main(2);
				}
				break;
			}
		}

		NPC_PRINT("Interfaces on this machine:\n");
		capture_opts_print_interfaces(if_list);
		NPC_PRINT("\n");
		free_interface_list(if_list);
		exit(0);
	}


	/*
	* "-S" requires no interface to be selected; it gives statistics
	* for all interfaces.
	*/
	if (print_statistics) {
		status = print_statistics_loop(machine_readable);
		exit(status);
	}


	if((shm_addr=(u_char*)Dbfw_AttachShm(shm_id))==(u_char*)-1)
	{
		NPC_PRINT("[Error]: attach sga error\n");
		return NPC_ERROR_ATTACHSHM-NPC_ERRNO_START;	
	}

	__SGA = (void*)shm_addr;
	__PID = getpid();
    /* Bind Session Buffer */
    //__NPC_SGA_SESSBUF = (Dbfw_Sga_SessionBuf*)malloc(sizeof(Dbfw_Sga_SessionBuf));         /*  */
    //ret = Npp_Sga_BindSessionBuf(__SGA,__NPC_SGA_SESSBUF);
    /* ��ʼ��global_ld.session_withclients */
    memset(global_ld.session_withclients,0x00,sizeof(global_ld.session_withclients));
	/* ��ʼ����־�ļ� */
	memset(&npc_log_file, 0x00, sizeof(Dbfw_LogFile));
    memset(&npc_errlog_file, 0x00, sizeof(Dbfw_LogFile));
	ret = Npc_InitNpcLogFile(shm_addr);
	if(ret<0)
	{
		NPC_PRINT("[Error]: Init log file error:%d\n", ret);
		return ret;
	}
	NPC_NEW_LOG(INFO_LEVEL, info_log, "%s", "NPC is starting");
	DBFW_INFO_PRINT(&npc_log_file,&info_log);
	/***********************************
	**
	**	��fixarray���ȡNPC_INFO
	**
	************************************/

#ifdef USE_FILTER
	Dbfw_Fixarray_GetNpcInfo((u_char*)__SGA, global_ld.npc_id, &global_ld.npc_info);
	__FILTER = (char*)global_ld.npc_info.filter;
	NPC_PRINT("[Info]: __FILTER is from Fixarray\n");
#endif


	NPC_PRINT("[Info]: npc_id:%d, device=%s, filter=%s\n", global_ld.npc_id, device_name, __FILTER);

	NPC_NEW_LOG(INFO_LEVEL, info_log, "npc_id:%d, device=%s, filter=%s\n", global_ld.npc_id, device_name, __FILTER);
	DBFW_INFO_PRINT(&npc_log_file,&info_log);


	/************************************
	**
	**	������
	**
	************************************/
	/* Initialize the pcaps list */
	global_ld.pcaps = g_array_new(FALSE, FALSE, sizeof(pcap_options *));

	capture_opts_init(&global_capture_opts, NULL);
    //printf("capture_opts->default_options.buffer_size=%d\n",global_capture_opts.default_options.buffer_size);
#ifdef USE_FILTER
	NPC_PRINT("[Info]: strlen(filter)=%d, global_ld.npc_info.filter=%s\n", strlen((char*)global_ld.npc_info.filter), global_ld.npc_info.filter);
	NPC_NEW_LOG(INFO_LEVEL, info_log, "strlen(filter)=%d, global_ld.npc_info.filter=%s", strlen((char*)global_ld.npc_info.filter), global_ld.npc_info.filter);
	DBFW_INFO_PRINT(&npc_log_file,&info_log);
	if(strlen((char*)global_ld.npc_info.filter)>0)
	{
		status = capture_opts_add_opt(&global_capture_opts, 'f', (char*)global_ld.npc_info.filter, &start_capture); 
	}
#else
	status = capture_opts_add_opt(&global_capture_opts, 'f', __FILTER, &start_capture); 
#endif
	NPC_PRINT("[Info]: status=%d\n", status);
	NPC_NEW_LOG(INFO_LEVEL, info_log, "status=%d", status);
	DBFW_INFO_PRINT(&npc_log_file,&info_log);
	if(status != 0) 
	{
		NPC_NEW_LOG(ERROR_LEVEL, error_log, "add filter to global_capture_opts error");
		DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
		//exit_main(1);
	}

	/* ��device_nameָ�����豸��ӵ�global_capture_opts->ifaces�� */
	if (capture_opts_trim_iface(&global_capture_opts, device_name) == FALSE) 
	{
		NPC_NEW_LOG(ERROR_LEVEL, error_log, "add device_name to global_capture_opts error");
		DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
		exit_main(1);
	}

	/* Let the user know what interfaces were chosen. */
	/* get_interface_descriptive_name() is not available! */
	for (j = 0; j < global_capture_opts.ifaces->len; j++) 
	{
		interface_options interface_opts;
		interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, j);	
		NPC_PRINT("[Info]: chosen interface : %s\n", interface_opts.name);
	}


	/* We're supposed to do a capture, or print the BPF code for a filter.
	Process the snapshot length, as that affects the generated BPF code. */
	capture_opts_trim_snaplen(&global_capture_opts, MIN_PACKET_SIZE);

	ret = Npc_OpenDevice(&global_capture_opts);
	if(ret<0)
	{
		return ret;
	}

    /********************************************
	**
	**	����ʱ��License���:(�����ڴ�root�û��л���dbfw�û�ǰִ��)
	**		����global_ld.license_resultֵ
    **      ���ۼ������Σ�����������Ĳ���
	**
	*********************************************/
    global_ld.license_result = 0;
    global_ld.license_checktime = 0;
    /* 2014-09-15 ��Ϊʹ��ÿ�ν��д���У����°汾����Npc_CheckLicense_WithDiskCheck */
    //ret = Npc_CheckLicense(NPC_CK_LICENSE_ALL);
    ret = Npc_CheckLicense_WithDiskCheck(NPC_CK_LICENSE_GETDISKID);
	
    /*���ó�ԭ������Ч�û�ID*/
	seteuid(getuid());
    NPC_NEW_LOG(INFO_LEVEL, info_log, "uid=%d\n", getuid());
    DBFW_INFO_PRINT(&npc_log_file,&info_log);

	u_char value[128];
	u_char *dbfw_home = (u_char*)getenv("DBFW_HOME");

	if(dbfw_home==NULL || strlen((char*)dbfw_home)==0)
	{
		NPC_PRINT("[Error]: not find \"DBFW_HOME\" \n");
		error_log.dbfw_error_no = NPC_ERROR_NOFIND_DBFW_HOME-NPC_ERRNO_START;
		NPC_NEW_LOG(ERROR_LEVEL, error_log, "not find \"DBFW_HOME\" in env\n");
		DBFW_ERROR_PRINT(&npc_errlog_file,&error_log);
		return NPC_ERROR_NOFIND_DBFW_HOME-NPC_ERRNO_START;
	}
	strcpy((char*)global_ld.dbfw_home, (char*)dbfw_home);

	/* ��$DBFW_HOME:$DBFW_HOME/lib��ӵ�LD_LIBRARY_PATH�� */
	memset((char*)value, 0, sizeof(value));
	memcpy((char*)value, dbfw_home, strlen((char*)dbfw_home));
	strcpy((char*)library_path, (char*)value);
	strcat((char*)library_path, ":");
	strcat((char*)library_path, (char*)value);
	strcat((char*)library_path, "/lib:");


	p_LD_LIBRARY_PATH = getenv("LD_LIBRARY_PATH");
	if(p_LD_LIBRARY_PATH!=NULL)
	{
		strcat((char*)library_path, p_LD_LIBRARY_PATH);
	}

	if(setenv("LD_LIBRARY_PATH", (char*)library_path, 1)!=0)
	{
		NPC_PRINT("[Error]: setenv error for LD_LIBRARY_PATH=%s\n", (char*)library_path);
		error_log.dbfw_error_no = NPC_ERROR_SET_LIBRARY_PATH-NPC_ERRNO_START;
		NPC_NEW_LOG(ERROR_LEVEL, error_log, "setenv error for LD_LIBRARY_PATH=%s\n", (char*)library_path);
		DBFW_ERROR_PRINT(&npc_errlog_file,&error_log);
		return NPC_ERROR_SET_LIBRARY_PATH-NPC_ERRNO_START;
	}

	NPC_PRINT("[Info]: LD_LIBRARY_PATH=%s\n", getenv("LD_LIBRARY_PATH"));
	NPC_NEW_LOG(INFO_LEVEL, info_log, "LD_LIBRARY_PATH=%s\n", getenv("LD_LIBRARY_PATH"));
	DBFW_INFO_PRINT(&npc_log_file,&info_log);

#ifdef DUMP_PACKET
	u_char	dump_file_name[64];
	sprintf((char*)dump_file_name, "npc_dump_%d.cap", __PID);
	__FOUT = fopen((char*)dump_file_name, "w");
	create_acp(__FOUT);
	//__FOUT_SIMPLE = fopen("npc_dump_raw.dat", "w");
#endif


	/*��fixarray�����ý�����Ϣ*/
	ret = Dbfw_Fixarray_SetProcess(shm_addr, __PID, DBFW_PTYPE_NPC);

    /* ���ý��̲�����fixArea */
    
//     for(i=1;i<argc;i++)
//     {
//         ret = Dbfw_Fixarray_SetValueAndValuelenForProcess((u_char*)__SGA,__PID,(i-1),(u_char*)argv[i],strlen((char*)argv[i]));
//         if(ret==65535)
//         {
//             //OraNet_DumpSql("Dbfw_Fixarray_SetValueAndValuelenForProcess error(%d) for NPC's param[%d]=%s\n",ret,i,(char*)argv[i]);
//             NPC_NEW_LOG(ERROR_LEVEL, error_log, "Dbfw_Fixarray_SetValueAndValuelenForProcess error(%d) for NPC's param[%d]=%s",ret,i,(char*)argv[i]);
//             DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
//         }
//     }
	/*
        ���ý��̽ṹ���еĲ���: npc_id��device_name
        NPC���̱Ƚ����⣬��һ����������Ϊnpc_id���ڶ�������Ϊ�豸��
    */
	u_char npc_param_value[PROCESS_PARAM_MAX_VALUES_LEN];
	sprintf((char*)npc_param_value, "%d", global_ld.npc_id);
	Dbfw_Fixarray_SetValueAndValuelenForProcess((u_char*)__SGA, __PID, NPC_PARAM_NPCID, npc_param_value, strlen((char*)npc_param_value));
	sprintf((char*)npc_param_value, "%s", device_name);
	Dbfw_Fixarray_SetValueAndValuelenForProcess((u_char*)__SGA, __PID, NPC_PARAM_DEVICENAME, npc_param_value, strlen((char*)npc_param_value));
	

	/*��ʼ��Loop Data*/
	/* TODO: �ڶ��������滻ΪCapdataBuffer��ʵ��ƫ����*/
	granule_offset_for_capbuf = GetIntParamInFixarray(shm_addr, DBFW_GRANULES_OFFSET_FOR_CAPBUF);
	sga_granule_size = 8*1024*1024;/* ������С��8M */ //GetIntParamInFixarray(shm_addr, SGA_GRANULE_SIZE);

	if(granule_offset_for_capbuf==0 )
	{
		error_log.dbfw_error_no = NPC_ERROR_CAPBUF_OFFSET_NOFIND-NPC_ERRNO_START;
		NPC_NEW_LOG(ERROR_LEVEL, error_log, "granule offset for capbuf is 0\n");
		DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
		return NPC_ERROR_CAPBUF_OFFSET_NOFIND-NPC_ERRNO_START;
	}
    /* ��ʼ��__NPP_INFO���� */
    memset(__NPP_INFO,0x00,sizeof(__NPP_INFO));
	/* ��ʼ��ȫ��ѭ������ */
	ret = Npc_InitGlobalLoopData(shm_id, shm_addr, granule_offset_for_capbuf*sga_granule_size);
	if(ret<0)
	{
		NPC_PRINT("[Error]: init global loop data error:%d\n", ret);
		error_log.dbfw_error_no = ret;
		NPC_NEW_LOG(ERROR_LEVEL, error_log, "init global loop data error\n");
		DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
		return ret;
	}
    
	/********************************************
	**
	**	����ˢ���߳�(������ѭ��):
	**		����worktime��alivetime
	**		����Ƿ���Ҫ���¼���db_hashmap
	**		��������session_hashmap
	**
	*********************************************/
	pthread_create(&tid, NULL, Npc_UpdateHeartbeat, NULL);
	NPC_NEW_LOG(INFO_LEVEL, info_log, "create thread \"Npc_UpdateHeartbeat\" ok\n");
	DBFW_INFO_PRINT(&npc_log_file,&info_log);

	/********************************************
	**
	**	��������NPP���߳�(ʹ���ź�������)
	**
	********************************************/
	pthread_create(&tid, NULL, Npc_CreateNppThread, NULL);
	NPC_NEW_LOG(INFO_LEVEL, info_log, "create thread \"Npc_CreateNppThread\" ok\n");
	DBFW_INFO_PRINT(&npc_log_file,&info_log);

    /********************************************
	**
	**	�������õĽ��̳������Ĭ��Ԥ����NPC_SUSPEND_NPPPOOL_COUNT�������NPP����
	**
	********************************************/
    //Npc_InitNppPool();
	/* ����ץ��ѭ�� */
	loop_ret = capture_loop_start(&global_capture_opts, &stats);

	//Npc_PrintStatistics();
	//Npc_PrintThroughput();
	exit_main(0);

	return 0; /* never here, make compiler happy */
}

/**********************************************
**
**	��ACBuf�м���db��ַ��hashmap��
**	RETURN
**		<0: error, return errno
**		=0: ok
**
**********************************************/
int Npc_LoadDBAddress(Dbfw_Sga_ACBuf *acbuf, Npc_HashPool *db_hashmap)
{
	u_int64 key = 0;
	u_int64 change_count=0;
	u_int64 key_dbtype_bucket = 0;
    u_short database_id = 0;
    u_short dbserver_key_idx = 0;
    u_short dialect = 0;
	do{
		change_count=Dbfw_Fixarray_GetChangeCount(global_ld.sga_addr);
		if(change_count==0)
		{
			sleep(1);	
		}else{
			//printf("rule flush finish\n")	;
		}
	}while(change_count==0);
	/* ��ʼ��dbtype_bucket */
    memset(global_ld.dbtype_bucket,0x00,sizeof(global_ld.dbtype_bucket));
	int buf_id = change_count%2;
	for(int i=0; i<DBFW_MAX_PROTECTED_DBADDRESS; ++i)
	{
		if(acbuf->databases->db_address[buf_id][i].address_id==0)/*����ĺ���û��������*/
		{
			break;
		}
        /* ȡ�õ�һ��IP��ַΪȱʡ���̳ص����ݿ�IP��ַ */
        if(i==0)
        {
            strcpy((char*)global_ld.npp_pool_default_dbip,(char*)acbuf->databases->db_address[buf_id][i].address);
            global_ld.npp_pool_default_serverport = acbuf->databases->db_address[buf_id][i].port;
            global_ld.npp_pool_default_dbaddress_value = acbuf->databases->db_address[buf_id][i].address_value;
        }
		key = acbuf->databases->db_address[buf_id][i].address_value;
		key = ((key<<16)|acbuf->databases->db_address[buf_id][i].port);
		if(Npc_HashmapInsert(db_hashmap, key, 1)==-2)
		{
			return NPC_ERROR_HASHPOOL_ALLUSED-NPC_ERRNO_START;
		}
		if(acbuf->databases->db_address[buf_id][i].dyna_port == 1)
		{
			key = acbuf->databases->db_address[buf_id][i].address_value;
			key = ((key<<16)|acbuf->databases->db_address[buf_id][i].port);
			key = key|(1<<63);
			if(Npc_HashmapInsert(db_hashmap, key, 1)==-2)
			{
				return NPC_ERROR_HASHPOOL_ALLUSED-NPC_ERRNO_START;
			}
			key = acbuf->databases->db_address[buf_id][i].address_value;
			key = (key<<16);
			if(Npc_HashmapInsert(db_hashmap, key, 1)==-2)
			{
				return NPC_ERROR_HASHPOOL_ALLUSED-NPC_ERRNO_START;
			}
		}
        /* ���dbtype_bucket */
        database_id = acbuf->databases->db_address[buf_id][i].database_id;
        if(database_id>0)
        {
            dialect = acbuf->databases->xsec_database[buf_id][database_id-1].dialect;
        }
        else
        {
            database_id = 1;    /* ǿ�ƽ�database_id����Ϊ1 */
            dialect = acbuf->databases->xsec_database[buf_id][database_id-1].dialect;
        }
        key_dbtype_bucket = key%DBFW_MAX_PROTECTED_DATABASE;
        if(global_ld.dbtype_bucket[key_dbtype_bucket].dbcount<DBFW_MAX_PROTECTED_DBADDRESS)
        {
            dbserver_key_idx = global_ld.dbtype_bucket[key_dbtype_bucket].dbcount;
            global_ld.dbtype_bucket[key_dbtype_bucket].dbserver_key[dbserver_key_idx] = key;
            global_ld.dbtype_bucket[key_dbtype_bucket].dialect[dbserver_key_idx] = dialect;
            global_ld.dbtype_bucket[key_dbtype_bucket].dbcount++;
        }
        
        
//#ifdef DEBUG
//		u_char ip_str[16];
//		Npc_Ip2Str(acbuf->databases->db_address[buf_id][i].address_value, ip_str);
//		NPC_PRINT("[Info]: load protected database: %s:%d\n", ip_str, acbuf->databases->db_address[buf_id][i].port);
//#endif
	}
	//#ifdef DEBUG
	//	Npc_HashmapCount(db_hashmap);
	//#endif
	return 0;
}
/*******************************************
**
**	��ʼ��ȫ������
**
*******************************************/
int Npc_InitGlobalLoopData(int shm_id, 
						   u_char *shm_addr, 
						   u_int offset_for_capbuf)/*capbuf��ƫ����,���ֽ�Ϊ��λ*/
{
	char errbuf[256];
	int ret = 0;
	global_ld.shm_id = shm_id;
	global_ld.sga_addr = shm_addr;

	/*��ʼ��session��hash��*/
	global_ld.session_hashmap._num_bucket = NPC_HASHMAP_PRIME_FOR_SESSION;
	global_ld.session_hashmap._num_element = NPC_HASHMAP_MAX_ELEMENTS_FOR_SESSION;
	if(Npc_HashmapInit(&(global_ld.session_hashmap))==-1)
	{
		return NPC_ERROR_INIT_SESSION_HASHMAP-NPC_ERRNO_START;
	}

	/*��ʼ��db��hash��*/
	global_ld.db_hashmap[0]._num_bucket = NPC_HASHMAP_PRIME_FOR_DB;
	global_ld.db_hashmap[0]._num_element = NPC_HASHMAP_MAX_ELEMENTS_FOR_DB;
	global_ld.db_hashmap[1]._num_bucket = NPC_HASHMAP_PRIME_FOR_DB;
	global_ld.db_hashmap[1]._num_element = NPC_HASHMAP_MAX_ELEMENTS_FOR_DB;
	if(Npc_HashmapInit(&(global_ld.db_hashmap[0]))==-1 ||
		Npc_HashmapInit(&(global_ld.db_hashmap[1]))==-1)
	{
		return NPC_ERROR_INIT_DB_HASHMAP-NPC_ERRNO_START;
	}
	/*��acbuf�����db�ĵ�ַ��Ϣ*/
	u_int acbuf_start_granule;
	ret = GetIntParamInFixarray((u_char*)__SGA, DBFW_GRANULES_OFFSET_FOR_ACBUF);
	if(ret<0)
	{
		NPC_PRINT("[Error]: DBFW_GRANULES_OFFSET_FOR_ACBUF is null\n");
		return NPC_ERROR_ACBUF_OFFSET_NOFIND-NPC_ERRNO_START;
	}
	acbuf_start_granule = ret;

	NPC_PRINT("[Info]: acbuf_start_granule=%d\n", acbuf_start_granule);

	global_ld.acbuf = (Dbfw_Sga_ACBuf*)malloc(sizeof(Dbfw_Sga_ACBuf));
	Npp_Sga_BindACBuf(__SGA, acbuf_start_granule, global_ld.acbuf);

	ret = Npc_LoadDBAddress(global_ld.acbuf, &global_ld.db_hashmap[0]);
	if(ret<0)
	{
		NPC_PRINT("[Error]: load protected database's address error:%d\n", ret);
		return ret;
	}
	global_ld.db_hashmap_id=0;
	//free(acbuf);

	global_ld.sem_id_for_create_npp = Dbfw_CreateSem(0);
	if(global_ld.sem_id_for_create_npp==-1)
	{
		NPC_PRINT("[Error]: create sem for create_npp_thread error:%s\n", strerror(errno));
		return NPC_ERROR_CREATESEM_FOR_CREATENPPTHREAD-NPC_ERRNO_START;
	}
	global_ld.npp_arg_idx = 0;	/* npp�������е��±�:0~NPC_MAX_NPP_ARG-1 */

	if(pthread_mutex_init(&global_ld.mutex_for_clear_session, NULL)!=0)
	{
		return NPC_ERROR_INITMUTEX_FOR_CLEARSESSION-NPC_ERRNO_START;
	}


	/* TODO:sessbuf��Ҫ��ӵĽӿ�:�����ź�������Ľṹ��ָ��*/
	/* e.g. sems->semid[101]*/
	Dbfw_Sga_SessionBuf *sga_session_buf = (Dbfw_Sga_SessionBuf *)malloc(sizeof(Dbfw_Sga_SessionBuf));    /* 96 Byte */
	Npp_Sga_BindSessionBuf(shm_addr, sga_session_buf);
	global_ld.sems = sga_session_buf->sem_for_session;
    global_ld.session_array = sga_session_buf->session_array;
	free(sga_session_buf);
    /* ��ʼ��__NPC_SGA_SESSBUF */
    __NPC_SGA_SESSBUF = (Dbfw_Sga_SessionBuf*)malloc(sizeof(Dbfw_Sga_SessionBuf));
    Npp_Sga_BindSessionBuf(shm_addr, __NPC_SGA_SESSBUF);
	
	/* ����npc_id��λ��capbuf */
	#ifdef HAVE_LIBTIS
	memset(errbuf,0,sizeof(errbuf));
	global_ld.tis = Tis_Get(shm_addr + offset_for_capbuf,errbuf);
	if(global_ld.tis == NULL)
	{
		NPC_NEW_LOG(ERROR_LEVEL, error_log,errbuf);
		DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
		printf("%s\n",errbuf);
		return -1;
	}
	printf("npc Info: Tis Get Success %p  %d\n",global_ld.tis,global_ld.tis->config.max_slot);
	#else
	global_ld.header_addr[0] = shm_addr + offset_for_capbuf+ (global_ld.npc_id-1)*DBFW_CAPBUF_SIZE*2;
	global_ld.body_addr[0] = global_ld.header_addr[0]+ DBFW_CAPBUF_MAX_HEADER_COUNT*DBFW_CAPBUF_HEADER_SIZE;
	global_ld.tail_addr[0] = 
	global_ld.header_addr[1] = global_ld.header_addr[0]+DBFW_CAPBUF_SIZE;
	global_ld.body_addr[1] = global_ld.header_addr[1]+ DBFW_CAPBUF_MAX_HEADER_COUNT*DBFW_CAPBUF_HEADER_SIZE;
	global_ld.tail_addr[1] = global_ld.header_addr[1]+DBFW_CAPBUF_SIZE;

	global_ld.buffer_id = 0;
	global_ld.p_header = global_ld.header_addr[0];
	global_ld.p_body = global_ld.body_addr[0];
	#endif

	global_ld.captured_packets_count = 0;
	global_ld.captured_bytes_count = 0;
	global_ld.max_captured_packets_count = global_capture_opts.autostop_packets;

	global_ld.alivetime = 0;
	global_ld.worktime = 0;

    /* ��ʼ��NPP���̳ز���Ϊ0����ʾ�����ý��̳� */
    global_ld.npp_pool_size = 0;
    global_ld.npp_pool_type = NPP_POOL_TYPE_COMMON; /* ͨ�����͵Ľ��̳� */

	//ȡʵ����
	memset((char*)global_ld.dbfw_instance_name, 0, sizeof(global_ld.dbfw_instance_name));
	Dbfw_Fixarray_GetValueAndValuelenInGlobal(shm_addr, DBFW_INSTANCE_NAME, global_ld.dbfw_instance_name, PROCESS_PARAM_MAX_VALUES_LEN);
	if(strlen((char*)global_ld.dbfw_instance_name)==0)
	{
		NPC_NEW_LOG(ERROR_LEVEL, error_log, "DBFW_INSTANCE_NAME is null");
		DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
		return NPC_ERROR_DBFWINSTNAME_NULL-NPC_ERRNO_START;
	}

	ret = GetIntParamInFixarray(shm_addr, DBFW_MAX_SESSION);
	if(ret<=0)
	{
		global_ld.dbfw_max_session = DBFW_MAX_SESSIONS;/*Ĭ����8192*/
	}else
	{
		global_ld.dbfw_max_session = ret;
	}
	#ifdef HAVE_LIBTIS
	memset(global_ld.semvalue_outofrange_flag,0,sizeof(global_ld.semvalue_outofrange_flag));
	#else
	for(int i=0;i<DBFW_MAX_SESSIONS;++i)/*��ʼ��ÿ��session�ļ�¼idΪ1*/
	{
		global_ld.header_id[i]=1;
        global_ld.last_capbuf_header_idx[i] = 0;
        global_ld.semvalue_outofrange_flag[i] = 0;
	}
    global_ld.current_capbuf_header_idx = 0;
	#endif
	global_ld.error_no = 0;
    /* ��ʼ��global_ld.session_withclients_bslist_config HASH�� */
#ifdef USE_BSLHASH_FORSESSION
    //Bslhash_Config  session_withclients_bslist_config;       /* �������лỰ��client�Ĺ�ϵ��Ϣ(bslhash��ʽ) */
    global_ld.mem_sess_bslist = (u_char*)malloc(3*1024*1024);   /* ����3M�Ŀռ� */
    memset(&global_ld.session_withclients_bslist_config,0,sizeof(Bslhash_Config));
    strcpy(global_ld.session_withclients_bslist_config.name,"unconn_bslist");
    global_ld.session_withclients_bslist_config.total_kbsize = 3000;   /* ��3MСһЩ */
    global_ld.session_withclients_bslist_config.slot_number = 100000;              /* Ͱ������������Ӧ������Ϊ100000��̫С�˻��������̫��Ӱ������ */
    global_ld.session_withclients_bslist_config.group_number = 1;
    global_ld.session_withclients_bslist_config.user_data_size = sizeof(Npc_SessionWithClient);
    Bslhash_Init((uint8_t*)global_ld.mem_sess_bslist ,&global_ld.session_withclients_bslist_config,errbuf);
#endif 
#ifdef NO_LICENCE
    /* ��������ж����˲�����License��� */
    global_ld.license_result = 1;       /* ��ʼ��ΪLicense���Ϊͨ�� */
    global_ld.license_checktime = 0;
#else
    //global_ld.license_result = 0;       /* �����������ʼ�������Ǳ���֮ǰLicense���Ľ�� */
    //global_ld.license_checktime = 0;      /* ���ܱ������ʱ�䣬����֮ǰ����ʱ��� */
#endif    
    global_ld.npp_pool_default_clientport = 10000;
	return 0;
}

/********************************
**
**	������,�����������Ĺ��˹���
**
********************************/
int Npc_OpenDevice(capture_options *capture_opts)
{
	int					ret = 0;
	u_char				errmsg[MSG_MAX_LENGTH+1];
	u_char				secondary_errmsg[MSG_MAX_LENGTH+1];
	gboolean			cfilter_error = FALSE;
	interface_options	interface_opts;
	pcap_options		*pcap_opts;
	u_int					error_index = 0;
	*errmsg           = '\0';
	*secondary_errmsg = '\0';

	interface_opts = capture_opts->default_options;
	/* ������*/
	if (!capture_loop_open_input(capture_opts, &global_ld, (char*)errmsg, sizeof(errmsg),
		(char*)secondary_errmsg, sizeof(secondary_errmsg))) 
	{
		error_log.dbfw_error_no = NPC_ERROR_OPEN_DEVICE-NPC_ERRNO_START;
		NPC_NEW_LOG(ERROR_LEVEL, error_log, "open device error\n");
		DBFW_ERROR_PRINT(&npc_errlog_file,&error_log);
		ret = NPC_ERROR_OPEN_DEVICE-NPC_ERRNO_START;
		goto error;
	}

	NPC_PRINT("[Info]: open device ok\n");

	NPC_NEW_LOG(INFO_LEVEL, info_log, "open device ok\n");
	DBFW_INFO_PRINT(&npc_log_file,&info_log);

	for (u_int i = 0; i < capture_opts->ifaces->len; i++) 
	{
		pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
		interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
		/* init the input filter from the network interface (capture pipe will do nothing) */
		/*
		* When remote capturing WinPCap crashes when the capture filter
		* is NULL. This might be a bug in WPCap. Therefore we provide an emtpy
		* string.
		*/
		switch (capture_loop_init_filter(pcap_opts->pcap_h, 
										interface_opts.name,
										interface_opts.cfilter?interface_opts.cfilter:"")) 
		{

		case INITFILTER_NO_ERROR:
			break;

		case INITFILTER_BAD_FILTER:
			cfilter_error = TRUE;
			error_index = i;
			g_snprintf((char*)errmsg, sizeof(errmsg), "%s", pcap_geterr(pcap_opts->pcap_h));
			error_log.dbfw_error_no = NPC_ERROR_COMPILE_FILTER-NPC_ERRNO_START;
			NPC_NEW_LOG(ERROR_LEVEL, error_log, "compile filter error\n");
			DBFW_ERROR_PRINT(&npc_errlog_file,&error_log);
			ret = NPC_ERROR_COMPILE_FILTER-NPC_ERRNO_START;
			goto error;

		case INITFILTER_OTHER_ERROR:
			g_snprintf((char*)errmsg, sizeof(errmsg), "Can't install filter (%s).",
				pcap_geterr(pcap_opts->pcap_h));
			g_snprintf((char*)secondary_errmsg, sizeof(secondary_errmsg), "%s", please_report);
			error_log.dbfw_error_no = NPC_ERROR_SET_FILTER-NPC_ERRNO_START;
			NPC_NEW_LOG(ERROR_LEVEL, error_log, "install filter error\n" );
			DBFW_ERROR_PRINT(&npc_errlog_file,&error_log);
			ret = NPC_ERROR_SET_FILTER-NPC_ERRNO_START;
			goto error;
		}
	}
	return 0;

error:
	if (cfilter_error)
		report_cfilter_error(capture_opts, error_index, (char*)errmsg);
	else
		report_capture_error((char*)errmsg, (char*)secondary_errmsg);
	return ret;
}

/*********************************
**
**	�˺�����ץ��ѭ��
**
*********************************/
gboolean capture_loop_start(capture_options *capture_opts, struct pcap_stat *stats)
{
	int					inpkts;
	pcap_options		*pcap_opts;
	interface_options	interface_opts;
	u_char				errmsg[MSG_MAX_LENGTH+1];
	guint				i;

	__OPTS = capture_opts;
	/* init the loop data */
	global_ld.go                  = TRUE;

	pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, 0);


	NPC_NEW_LOG(INFO_LEVEL, info_log, "start capturing packets.")
	DBFW_INFO_PRINT(&npc_log_file, &info_log);

	global_ld.start_time=time(NULL);/*���¿�ʼʱ��*/
	/*����ѭ������ʼץ��*/
	while (global_ld.go) 
	{
		/* dispatch incoming packets */
		inpkts = capture_loop_dispatch(&global_ld, (char*)errmsg, sizeof(errmsg), pcap_opts);
	}
	//if(global_ld.error_no<0)
	//{
	//	goto error;
	//}

	NPC_NEW_LOG(INFO_LEVEL, info_log, "stop capturing packets.")
	DBFW_INFO_PRINT(&npc_log_file, &info_log);


	/* did we have a pcap (input) error? */
	for (i = 0; i < capture_opts->ifaces->len; i++) 
	{
		pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
		if (pcap_opts->pcap_err)
		{
			/* On Linux, if an interface goes down while you're capturing on it,
			you'll get a "recvfrom: Network is down" or
			"The interface went down" error (ENETDOWN).
			(At least you will if g_strerror() doesn't show a local translation
			of the error.)

			These should *not* be reported to the Wireshark developers. */
			char *cap_err_str;

			cap_err_str = pcap_geterr(pcap_opts->pcap_h);
			if (strcmp(cap_err_str, "recvfrom: Network is down") == 0 ||
				strcmp(cap_err_str, "The interface went down") == 0 ||
				strcmp(cap_err_str, "read: Device not configured") == 0 ||
				strcmp(cap_err_str, "read: I/O error") == 0 ||
				strcmp(cap_err_str, "read error: PacketReceivePacket failed") == 0) 
            {
					report_capture_error("The network adapter on which the capture was being done "
						"is no longer running; the capture has stopped.",
						"");
                    //             NPC_NEW_LOG(ERROR_LEVEL, error_log,"%s", "test errorlog.");
                    //             DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
                     NPC_NEW_LOG(ERROR_LEVEL, error_log, "The network adapter on which the capture was being done is no longer running.")
                     DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
			} 
			else 
			{
				g_snprintf((char*)errmsg, sizeof(errmsg), "Error while capturing packets: %s",
					cap_err_str);
				report_capture_error((char*)errmsg, please_report);
                NPC_NEW_LOG(ERROR_LEVEL, error_log, "Error while capturing packets: %s",cap_err_str);
                DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
			}
			break;
		} 
	}

	NPC_PRINT("[Info]: after capture loop, drop statistics ...\n");

	/* get packet drop statistics from pcap */
	for (i = 0; i < capture_opts->ifaces->len; i++)
	{
		guint32 received;
		guint32 dropped;

		pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
		interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
		received = pcap_opts->received;
		dropped = pcap_opts->dropped;
		if (pcap_opts->pcap_h != NULL) {
			/* Get the capture statistics, so we know how many packets were dropped. */
			if (pcap_stats(pcap_opts->pcap_h, stats) >= 0) 
			{
				/* Let the parent process know. */
				dropped += stats->ps_drop;
			} else 
			{
				g_snprintf((char*)errmsg, sizeof(errmsg),
					"Can't get packet-drop statistics: %s",
					pcap_geterr(pcap_opts->pcap_h));
				report_capture_error((char*)errmsg, please_report);
			}
		}
//#ifdef DEBUG
//		report_packet_drops(received, dropped, interface_opts.name);
//		NPC_PRINT("[Info]: received packets:%d\t dropped packets:%d\n",received, dropped);
//#endif
		NPC_NEW_LOG(INFO_LEVEL, info_log, "received packets:%d, dropped packets:%d.", received, dropped);
		DBFW_INFO_PRINT(&npc_log_file, &info_log);

	}

	/* close the input file (pcap or capture pipe) */
	capture_loop_close_input(&global_ld);
	NPC_NEW_LOG(INFO_LEVEL, info_log, "close device ok");
	DBFW_INFO_PRINT(&npc_log_file, &info_log);
	return TRUE;

error:

	/* close the input file (pcap or cap_pipe) */
	capture_loop_close_input(&global_ld);

	NPC_PRINT("[Error]: errno=%d\n", global_ld.error_no);
	return FALSE;
}

void Npc_DropStatistic()
{

	pcap_options		*pcap_opts;
	struct pcap_stat	stats;
	interface_options	interface_opts;
	NPC_PRINT("[Info]: Npc_DropStatistic : drop statistics ...\n");

	for (int i = 0; i < __OPTS->ifaces->len; i++)
	{
		guint32 received;
		guint32 dropped;

		pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
		interface_opts = g_array_index(__OPTS->ifaces, interface_options, i);
		received = pcap_opts->received;
		dropped = pcap_opts->dropped;
		if (pcap_opts->pcap_h != NULL) {
			/* Get the capture statistics, so we know how many packets were dropped. */
			if (pcap_stats(pcap_opts->pcap_h, &stats) >= 0) 
			{
				/* Let the parent process know. */
				dropped += stats.ps_drop;
			}/* else 
			{
				g_snprintf((char*)errmsg, sizeof(errmsg),
					"Can't get packet-drop statistics: %s",
					pcap_geterr(pcap_opts->pcap_h));
				report_capture_error((char*)errmsg, please_report);
			}*/
		}
		report_packet_drops(received, dropped, interface_opts.name);
		g_print("[Info]: received packets:%d\t dropped packets:%d\n",received, dropped);
	}

#if defined DROP_STABLE_STEP && defined DROP_STABLE_INDEX
	double drop_packet_ratio;
	if(__TOTAL_PACKET_COUNT==0)
	{ 
		drop_packet_ratio = 0;
	}
	else
	{
		drop_packet_ratio = ((double)__DROP_PACKET_COUNT)/__TOTAL_PACKET_COUNT;
	}
	printf("[Info]: stable drop:%llu/%llu=%.2f [STEP:%d, INDEX:%d]\n", 
			__DROP_PACKET_COUNT, 
			__TOTAL_PACKET_COUNT, 
			drop_packet_ratio, 
			NPC_DROP_STABLE_STEP,
			DROP_STABLE_INDEX);
#else
	#ifdef DROP_RANDOM
		double drop_packet_ratio;
		if(__TOTAL_PACKET_COUNT==0)
		{ 
			drop_packet_ratio = 0;
		}
		else
		{
			drop_packet_ratio = ((double)__DROP_PACKET_COUNT)/__TOTAL_PACKET_COUNT;
		}
		printf("[Info]: random drop:%llu/%llu=%.2f [RANDOM:%d\%]\n", __DROP_PACKET_COUNT, __TOTAL_PACKET_COUNT, drop_packet_ratio, NPC_DROP_RANDOM);
	#endif
#endif
}

/**************************************************** 
**
**	֪ͨ����̴߳���NPP.
**	1.�ڲ������������һ��
**	2.�����ź�����ֵ
**	����ֵ:
**		0: ok
**		<0: error, return errno
**
*****************************************************/
int Npc_NotifyToCreateNpp(u_int client_ip, 
						  u_short client_port, 
						  const u_char *client_mac,
						  u_int server_ip, 
						  u_short server_port,
						  const u_char *server_mac,
						  u_short session_id)
{
    /* 
        ֧��NPP���̳�
        ****��Ҫ˵��(2015-07-25 �ǳ����ز������޵�BUG��׷��2��ŷ���)��
        �������Ƿ��ǻ���һ�������NPP������ǣ������ٽ��������뵽global_ld.npp_args��ȥ����NPP��
        ԭ���ǻ�����������⣺
            ����NPP�����ڰ�����С��NPP�ܿ촦����ϣ������½��뵽����״̬
            Ȼ��Npc_CreateNppThread�̺߳����ű����У���ʱ�Ự��״̬���Ѿ�����USED������SUSPEND״̬�ˣ���ɸ��߳�����ִ��CreateProcess����
        ��������SGA������Ӧ�Ự��SessBuf_SessionData_Ora��SessBuf_SessionData_Ext����
    */
    if((__NPC_SGA_SESSBUF->session_array->session_type[session_id]==DBFW_SESSION_TYPE_NPCPOOL) && 
       (__NPC_SGA_SESSBUF->session_array->npppid[session_id]>0)
      )
    {
        /* 
            �ǹ���Ľ��̣����ҽ���PID���� 
        */
        //printf("Npc_NotifyToCreateNpp is DBFW_SESSION_TYPE_NPCPOOL npppid = %d\n",__NPC_SGA_SESSBUF->session_array->npppid[session_id]);
        SessBuf_SessionData_Ora* sessdata = Npp_BindSessionDataFromSga_Ora(__NPC_SGA_SESSBUF,session_id);
        memset((char *)sessdata,0x00,(int)DBFW_SESSION_SIZE);
        /* �ͻ�����Ϣ */
        sessdata->client_ip = client_ip;
        sessdata->client_port = client_port;
        Npc_Ip2Str(client_ip, sessdata->client_ip_str);
        Npc_FormatMacAddress_Clear(client_mac, sessdata->client_mac);
        /* ��������Ϣ */
        sessdata->server_ip = server_ip;
        sessdata->server_port = server_port;
        Npc_Ip2Str(server_ip, sessdata->server_ip_str);
        Npc_FormatMacAddress_Clear(server_mac, sessdata->server_mac);
        /* �ͷ�SessBuf_SessionData_Ext���� */
        SessBuf_SessionData_Ext* sessdata_ext = Npp_BindSessionDataExtFromSga(__NPC_SGA_SESSBUF,session_id);
        memset((char *)sessdata_ext,0x00,(int)DBFW_SESSION_EXT_SIZE);
        /* ���������ﷵ�أ���������䴴��NPP�Ĳ����ͷ��źŴ���NPP�� */
        return 0;
    }
	global_ld.npp_args[global_ld.npp_arg_idx].client_ip = client_ip;
	global_ld.npp_args[global_ld.npp_arg_idx].client_port = client_port;
	memcpy(global_ld.npp_args[global_ld.npp_arg_idx].client_mac, client_mac, 6);

	global_ld.npp_args[global_ld.npp_arg_idx].server_ip = server_ip;
	global_ld.npp_args[global_ld.npp_arg_idx].server_port = server_port;
	memcpy(global_ld.npp_args[global_ld.npp_arg_idx].server_mac, server_mac, 6);

	global_ld.npp_args[global_ld.npp_arg_idx].session_id = session_id;

	//NPC_PRINT("[Info]: notify to create npp, npp_arg_idx=%d\n", global_ld.npp_arg_idx);

    //printf(">>>>npp_arg_idx = %d , sessionid=%d, client_ip=%u, client_port=%d, session_used=%d\n",global_ld.npp_arg_idx,session_id,client_ip,client_port,__NPC_SGA_SESSBUF->session_array->sessions_used[session_id]);
	if(++global_ld.npp_arg_idx==NPC_MAX_NPP_ARG)
	{
		global_ld.npp_arg_idx = 0;
	}    
	if(Dbfw_UnlockSem(global_ld.sem_id_for_create_npp)==-1)
	{
		NPC_PRINT("[Error]: unlock sem for create_npp error:%s\n", strerror(errno));
        NPC_NEW_LOG(ERROR_LEVEL, error_log,"unlock sem for create_npp error:%s", strerror(errno));
        DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
		return NPC_ERROR_UNLOCKSEM_FOR_CREATENPPTHREAD-NPC_ERRNO_START;
	}
	return 0;
}
/**************************************************** 
**
**	ץ���Ļص�����,�ص������쳣�˳�ʱ,NPC�����˳�.
**
*****************************************************/
void capture_loop_write_packet_cb(u_char *pcap_opts_p, 
							 const struct pcap_pkthdr *phdr,
							 const u_char *pd)
{
	pcap_options *pcap_opts = (pcap_options *) (void *) pcap_opts_p;

	u_int64		src_key, dst_key,key;		/* ����Դip,port��key��Ŀ��ip,port��key */
	u_int64		src_key_no_port, dst_key_no_port,key_no_port,src_key_port,dst_key_port;		/* ����Դip,port��key��Ŀ��ip,port��key */
	int			find_src_key, find_dst_key;	/*�Ƿ���db_hashmap���ҵ�src_key, dst_key */
	int			find_src_key_no_port, find_dst_key_no_port,find_src_key_port,find_dst_key_port;	/*�Ƿ���db_hashmap���ҵ�src_key, dst_key */
	u_int64		client_key=0;				/*������src_key��dst_key*/
	u_int64		server_key=0;				/*������src_key��dst_key*/
	u_int       key_dbtype_bucket = 0;
	u_int       dbserver_key_idx = 0;
	int			search_client_key =0;		/*�Ƿ���session_hashmap����ҹ�client_key(�����ҵ�)*/
	u_int		src_ip, dst_ip=0;
	u_short		src_port=0, dst_port=0;

	u_int64		client_ip_value;		/*��������npp�ṩ�Ľӿ�*/
	u_short		client_port;

	CapBuf_Header *new_header = NULL;
    u_char        *last_header_for_currentsession = NULL;
	u_short		cur_session_id=NPC_HASHMAP_NOT_FIND_KEY;
	u_short		new_session_id;
    u_short		tmp_session_id_forkey=NPC_HASHMAP_NOT_FIND_KEY;
    int  		tmp_session_id;
	int			sem_id = 0;
	int			ret;

	int			parse_ret;
	int			packet_type;
	int			create_npp=0;
    int         sem_value = 0;
    u_char      *cap_header_tmp = NULL;
	int			i = 0;
    u_int64     current_timestamp_for_createnpp = 0;
    u_int64     timeout_for_createnpp = 5;      /* ���5�� */
    u_int64     timestamp_for_createcpp = 0;
    u_char      is_syn_and_ack = 0;     /* ��SYN+ACK ����NPPģʽ */
    u_short     npp_dialect = 0;        /* ��ǰ���ݿ�ķ��� */
    u_char      usepool_flag = 0;        /* ��ǰ���ݿ�ķ��� */
    u_char      is_dynaport = 0;
//#ifdef DEBUG
//	int			switch_buf=0;
//	CapBuf_Header *last_header;
//	u_char		ip_str_1[16];
//	u_char		ip_str_2[16];
//#endif

#ifdef DROP_RANDOM
	int	rand_value;
#endif

	if (!global_ld.go)
		return;

//#ifdef DEBUG
//	++__COUNT;
//#endif

#if defined DROP_STABLE_STEP && defined DROP_STABLE_INDEX
	__TOTAL_PACKET_INDEX = (__TOTAL_PACKET_COUNT%NPC_DROP_STABLE_STEP);
	if(__TOTAL_PACKET_INDEX==NPC_DROP_STABLE_INDEX)
	{
		//printf("[Stable Drop]: __TOTAL_PACKET_INDEX=%llu, __TOTAL_PACKET_COUNT=%llu\n", __TOTAL_PACKET_INDEX, __TOTAL_PACKET_COUNT);
		__TOTAL_PACKET_COUNT++;
		__DROP_PACKET_COUNT++;
		return;
	}
	__TOTAL_PACKET_COUNT ++;
#else 
#ifdef DROP_RANDOM
	rand_value = rand()%100;
	if(rand_value < NPC_DROP_RANDOM)
	{
		__DROP_PACKET_COUNT++;
		__TOTAL_PACKET_COUNT++;
		return;
	}
	__TOTAL_PACKET_COUNT++;
#endif
#endif    
/* 2014-06-23 ����License��� */
    if(global_ld.license_result>0)
    {
        //printf("License OK\n");
#ifndef TEST_NPC_CAPTUER
        __TOTAL_PACKET_COUNT++;
	/*����ԴIP��ԴPort*/
	parse_ret = Npc_ParseSourceAndDestIpPort(pd, &src_ip, &src_port, &dst_ip, &dst_port);
	if(parse_ret == -1)
	{/* ����TCP�� */
        //printf("not tcp packet\n");
		return;
	}
    is_syn_and_ack = 0;
#ifdef NPC_USE_SYNANDACK_START
    if(parse_ret==1)
    {
        //printf("is SYN+ACK\n");
        is_syn_and_ack = 1;
    }
#endif    
    //printf("src_ip=%d\n",);
    //���ԣ�ֱ�ӷ���
    //return;
	/***********************/
	/* 2015-03-17 ע�͵�һ�¶�̬�˿ڴ����߼������±߲����µĴ���ʽ */
	/* ��̬�˿���� */
	//src_key = src_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
	//src_key = (src_key<<16)|src_port;
	//dst_key = dst_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
	//dst_key = (dst_key<<16)|dst_port;
	//find_src_key = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), src_key);
	//find_dst_key = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), dst_key);
	//if(find_src_key==NPC_HASHMAP_NOT_FIND_KEY && find_dst_key == NPC_HASHMAP_NOT_FIND_KEY)
	//{
	//	/* ˵���Ƕ�̬�˿� */
	//	if(parse_ret == 1)/*�Ǵ������ӵİ�*/
	//	{
	//		/*��δָ��filterʱ,��Ȼ�Ǵ������ӵİ�,���п��ܲ��������ݿ�ͨ�ŵİ�*/
	//		/*���Ի�Ҫ���Ŀ�ĵ�ַ�Ƿ���db_hashmap��*/
	//		ret = Npc_DynaPortFind(__NPC_SGA_SESSBUF,dst_ip,dst_port);
	//		if(ret==NPC_HASHMAP_NOT_FIND_KEY)
	//		{
	//			return ;
	//		}
	//		/* 
	//			2014-06-13 �޸��˿��ظ����������SYN�������ƶ�ε����
	//			���NPP�Ƿ��Ѿ��������ˣ��������ֱ�ӷ��أ����ٴ���
	//			���Ƿ��ִ���һ�������NPP���ڶ�ʧ��FIN�����û���������˳�����ʱ�������޷������µ���ͬsrc_key��NPP��
	//			���������߼���Ҫȥ������Ϊ��Npc_SetSessionWithClient����������
	//		*/
	////         src_key = src_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
	////         src_key = (src_key<<16)|src_port;
	////         NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
	////         //cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), src_key);
	////         cur_session_id = Npc_FindSessionWithClient(src_key);
	////         NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
	////         if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
	////         {
	////             /* �ҵ��˸�src_key,Ŀǰ��Ϊ�Ѿ�������NPP�ˣ������ظ�����,��Ҫ�ȼ��һ���Ƿ��session�Ĳ�λ�����ź������� */
	////             if(global_ld.session_withclients[cur_session_id]._sem_id>=0 && Dbfw_GetSemValue(global_ld.session_withclients[cur_session_id]._sem_id)>=0)
	////             {
	////                 /* ��sessionȷʵ���ڣ������ؽ� */
	////                 return ;
	////             }            
	////         }
	//		create_npp = 1;
	//		client_key = src_ip;
	//		client_key = (client_key<<16)|src_port;
	//		server_key = dst_ip;
	//		server_key = (server_key<<16)|dst_port;
	//		packet_type = REQUEST_PACKET;
	//		
	//	}
	//	else/*���Ǵ������ӵİ�*/
	//	{
	//		search_client_key=0;

	//		src_key = src_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
	//		src_key = (src_key<<16)|src_port;
	//		dst_key = dst_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
	//		dst_key = (dst_key<<16)|dst_port;

	//		find_src_key = Npc_DynaPortFind(__NPC_SGA_SESSBUF,src_ip,src_port);
	//		find_dst_key = Npc_DynaPortFind(__NPC_SGA_SESSBUF,dst_ip,dst_port);
	//		if(find_src_key==1 && find_dst_key==NPC_HASHMAP_NOT_FIND_KEY)
	//		{/*����һ����Ӧ��*/
	//			client_key = dst_key;
	//			server_key = src_key;
	//			packet_type = RESPONSE_PACKET;
	//		}
	//		else if(find_dst_key==1 && find_src_key==NPC_HASHMAP_NOT_FIND_KEY)
	//		{/*����һ�������*/
	//			client_key = src_key;
	//			server_key = dst_key;
	//			packet_type = REQUEST_PACKET;
	//		}
	//		else if(find_src_key==1 && find_dst_key==1)/*DB_LINK�������,Դ��ַ��Ŀ�ĵ�ַ����db_hashmap��*/
	//		{
	//			if(parse_ret == 1)/*�����ߵ�����*/
	//			{/*���Ǵ������ӵİ�*/
	//				client_key = src_key;
	//				server_key = dst_key;
	//				packet_type = REQUEST_PACKET;
	//			}
	//			else/*�ⲻ�Ǵ������ӵİ�*/
	//			{
	//				/*����session_hashmapʱ, ����*/
	//				NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
	//				//cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), src_key);
	//				cur_session_id = Npc_FindSessionWithClient(src_key);
	//				NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);

	//				if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
	//				{/*Դ��ַ��session_hashmap��,���������*/
	//					client_key = src_key;
	//					server_key = dst_key;
	//					packet_type = REQUEST_PACKET;
	//					search_client_key = 1;
	//				}
	//				else
	//				{
	//					NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
	//					//cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), dst_key);
	//					cur_session_id = Npc_FindSessionWithClient(dst_key);
	//					NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);

	//					if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
	//					{/*Ŀ�ĵ�ַ��session_hashmap��,������Ӧ��*/
	//						client_key = dst_key;
	//						server_key = src_key;
	//						packet_type = RESPONSE_PACKET;
	//						search_client_key = 1;
	//					}
	//					else/*ûץ���������ӵİ�,�޷�Ϊ����Ự����NPP.������������ĸ��ʼ�С*/
	//					{
	//						NPC_PRINT("[Error]: in DB_LINK, src_key and dst_key are neither found in session_hashmap, because not capture connection packet for this session.\n");
	//						return;
	//					}
	//				}
	//			}
	//		}
	//		else/*Դ��ַ��Ŀ�ĵ�ַ������db_hashmap��,�޷����������.��db_hashmap�ǿ�ʱ,���ִ����.*/
	//		{
	////#ifdef DEBUG
	////			Npc_Ip2Str(src_ip, ip_str_1);
	////			Npc_Ip2Str(dst_ip, ip_str_2);
	////			/*�ĳɼ���־*/
	////			//NPC_PRINT("[Error]: src_addr:%s:%d and dst_addr:%s:%d are neither found in db_hashmap, this packet couldn't be processed\n", 
	////			//		ip_str_1, src_port, ip_str_2, dst_port);
	////#endif
	//			return;
	//		}
	//		/*�жϿͻ��˵�ַ�Ƿ���session_hashmap��*/
	//		if(search_client_key==1)/*��session_hashmap����ҹ�client_key,�����ܹ��ҵ� */
	//		{
	//			create_npp = 0;
	//			/*cur_session_id�Ѿ���ֵ��*/
	//		}
	//		/*search_client_key=0��ʾ�������:(1)û���ҹ�,(2)�ҹ�,����û�ҵ�.��(2)������Ѿ�return*/
	//		else/*û���ҹ�*/
	//		{
	//			/*����session_hashmapʱ, ����*/
	//			NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
	//			//cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), client_key);
	//			cur_session_id = Npc_FindSessionWithClient(client_key);
	//			NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
	//			
	//			if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
	//			{/*�ҵ���,���ô���NPP*/
	//				create_npp = 0;
	//			}
	//			else
	//			{/*û�ҵ�˵��:û�в�׽���ûỰ�Ĵ������ӵ�ͨ�Ű�,��ô�����������ͨ�Ű�*/
	//				//create_npp = 1;
	//				/* 2014-04-06 ���������ӻỰ��ƹ��ܣ�����NPP */
	//				//printf("not find client_key = %llu\n",client_key);
	//#ifdef HAVE_NOCONNECT_SESSION
	//				NPC_PRINT("[Info]: not find client ip = %u  port=%u\n",src_ip,src_port);
	//				/* 
	//					2014-10-16 ��ɽ�ֳ������ִ��ںܶ�SQLServer��ͻ��˷��͵�TCP segment of a reassembled PDU 
	//					���ĳߴ��С������Ϊ0�ֽڻ�1�ֽڣ����������һ��<70�ֽ�
	//					�������ſͻ��˷��ظ��������İ�������Ҳ��С<70�ֽ�
	//					������������ӣ������������NPP����Ҫ����
	//				*/
	//				if(find_src_key==1 && find_dst_key==0)
	//				{
	//					/* ��DB->Client��Ӧ���,���ܴ����Ự��ֱ����һ��Client->DB������� */
	//					return;
	//				}
	//				else if(phdr->caplen>70)
	//				{
	//					create_npp = 1;	
	//				}
	//				else
	//				{
	//					return;
	//				}
	//#else
	//				return;
	//#endif
	//                			
	//			}
	//		}
	//		key_dbtype_bucket = server_key%DBFW_MAX_PROTECTED_DATABASE;
	//		if(global_ld.dbtype_bucket[key_dbtype_bucket].dbcount<DBFW_MAX_PROTECTED_DBADDRESS)
	//		{
	//			dbserver_key_idx = global_ld.dbtype_bucket[key_dbtype_bucket].dbcount;
	//			global_ld.dbtype_bucket[key_dbtype_bucket].dbserver_key[dbserver_key_idx] = server_key;
	//			global_ld.dbtype_bucket[key_dbtype_bucket].dialect[dbserver_key_idx] = 1;
	//			global_ld.dbtype_bucket[key_dbtype_bucket].dbcount++;
	//		}
	//	}
	//}
	//else

    /* ��̬�˿��µĴ���ʽ */
    is_dynaport = 0;
    npp_dialect = 0;
	src_key_no_port = src_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
	src_key_no_port = (src_key_no_port<<16);   /* �õ�����ip��keyȥ���ң��ҵ�˵���Ƕ�̬�˿� */
	dst_key_no_port = dst_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
	dst_key_no_port = (dst_key_no_port<<16);
	find_src_key_no_port = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), src_key_no_port);
	find_dst_key_no_port = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), dst_key_no_port);

	if(find_src_key_no_port == 1 || find_dst_key_no_port == 1)
	{
		src_key_port = src_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
		src_key_port = (src_key_port<<16)|src_port;   /* �õ�����ip��keyȥ���ң��ҵ�˵���Ƕ�̬�˿� */
		src_key_port = src_key_port|(1<<63);
		dst_key_port = dst_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
		dst_key_port = (dst_key_port<<16)|dst_port;
		dst_key_port = dst_key_port|(1<<63);
		find_src_key_port = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), src_key_port);
		find_dst_key_port = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), dst_key_port);

		src_key = src_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
		src_key = (src_key<<16)|src_port;   /* �õ�����ip��keyȥ���ң��ҵ�˵���Ƕ�̬�˿� */
		dst_key = dst_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
		dst_key = (dst_key<<16)|dst_port;
		find_src_key = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), src_key);
		find_dst_key = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), dst_key);
		/* �����Ƕ�̬�˿� ��Ϊһ��ip�»���ڶ�̬�˿ڵĿ��һ���Ƕ�̬�˿ڵĿ� */
		if(find_src_key == 1 || find_dst_key == 1)
		{
			/* ��̬��Ҳ���ҵ��������Ƕ�̬�е����ö˿ڣ�Ҳ������ͬip�ķǶ�̬�˿� */
			if(find_src_key_port == 1 || find_dst_key_port == 1)
			{
				/* ˵���Ƕ�̬�˿��е����ö˿� */
				return;
			}
			/* ��̬�˿� */
            is_dynaport = 0;
			goto static_port;
		}
		else
		{
			/* ȷ���Ƕ�̬�˿� */
			if(parse_ret == 1)
			{
#ifdef NPC_USE_SYNANDACK_START
                /* SYN+ACKӦ�𴴽�NPPģʽ */
                if(find_src_key_no_port == NPC_HASHMAP_NOT_FIND_KEY || src_port<1024 ||src_port == 3389)
                    return;
#else
                /* �ɰ汾��SYN����NPPģʽ */
                if(find_dst_key_no_port == NPC_HASHMAP_NOT_FIND_KEY || dst_port<1024 ||dst_port == 3389)
                    return;
#endif			
			}
			else if(find_dst_key_no_port == 1 && find_src_key_no_port == NPC_HASHMAP_NOT_FIND_KEY)
			{
				if(dst_port < 1024 || dst_port == 3389)
					return;
			}
			else if(find_src_key_no_port == 1 && find_dst_key_no_port == NPC_HASHMAP_NOT_FIND_KEY)
			{
				if(src_port < 1024 || dst_port == 3389)
					return;
			}
			else if(find_src_key_no_port == 1 && find_dst_key_no_port == 1)
			{
				if(src_port < 1024 || dst_port <1024 || src_port == 3389 || dst_port == 3389)
					return;
			}
		}
		search_client_key=0;
        is_dynaport = 1;
        /* ����Ƿ���������ͬ�ͻ���IP+PORT��SYN�� */
//         if(parse_ret == 1)
//         {
//             client_key = src_ip;
//             client_key = (client_key<<16)|src_port;
//             current_timestamp_for_createnpp = NPC_GetEpochTime();
//             if(client_key==global_ld.last_clientkey_for_createnpp && 
//                (global_ld.last_timestamp_for_createcpp+timeout_for_createnpp)>current_timestamp_for_createnpp
//               )
//             {
//                 /* ����һ�ε���ͬ */
//                 printf("same session for TCP Retransmission clientIp=%X, clientPort=%u for 3 sec\n",src_ip,src_port);                
//                 parse_ret = 0;
//             }
//             else
//             {
//                 printf("same session for TCP Retransmission clientIp=%X, clientPort=%u over 3 sec\n",src_ip,src_port);
//                 global_ld.last_clientkey_for_createnpp = client_key;
//                 global_ld.last_timestamp_for_createcpp = current_timestamp_for_createnpp;
//             }
//         }
        /* ������ */
		if(parse_ret == 1)
		{
			create_npp = 1;
#ifdef NPC_USE_SYNANDACK_START
            /* SYN+ACKӦ�𴴽�NPPģʽ */
            client_key = dst_ip;
            client_key =  (client_key<<16)|dst_port;
            packet_type = RESPONSE_PACKET;
#else
            /* �ɰ汾SYN����NPPģʽ */
            client_key = src_ip;
            client_key = (client_key<<16)|src_port;
            packet_type = REQUEST_PACKET;
#endif
// 			client_key = src_ip;
// 			client_key = (client_key<<16)|src_port;
//             packet_type = REQUEST_PACKET;
		}
		else
		{
			if(find_src_key_no_port == 1 && find_dst_key_no_port ==NPC_HASHMAP_NOT_FIND_KEY)
			{
				client_key = dst_key;
				packet_type = RESPONSE_PACKET;
			}
			else if(find_dst_key_no_port == 1 && find_src_key_no_port ==NPC_HASHMAP_NOT_FIND_KEY)
			{
				client_key = src_key;
				packet_type = REQUEST_PACKET;
			}
			else if(find_src_key_no_port == 1 && find_dst_key_no_port == 1)
			{
				if(parse_ret == 1)/*�����ߵ�����*/
				{/*���Ǵ������ӵİ�*/
#ifdef NPC_USE_SYNANDACK_START
                    /* SYN+ACKӦ�𴴽�NPPģʽ */
                    client_key = dst_key;
                    packet_type = RESPONSE_PACKET;
#else
                    /* �ɰ汾SYNӦ�𴴽�NPPģʽ */
					client_key = src_key;
					packet_type = REQUEST_PACKET;
#endif
				}
				else/*�ⲻ�Ǵ������ӵİ�*/
				{
					/*����session_hashmapʱ, ����*/
//#ifndef USE_BSLHASH_FORSESSION
					NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
					//cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), src_key);
					cur_session_id = Npc_FindSessionWithClient(src_key);
//#ifndef USE_BSLHASH_FORSESSION
					NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
					if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
					{/*Դ��ַ��session_hashmap��,���������*/
						client_key = src_key;
						packet_type = REQUEST_PACKET;
						search_client_key = 1;
					}
					else
					{
//#ifndef USE_BSLHASH_FORSESSION
						NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
						//cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), dst_key);
						cur_session_id = Npc_FindSessionWithClient(dst_key);
//#ifndef USE_BSLHASH_FORSESSION
						NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
						if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
						{/*Ŀ�ĵ�ַ��session_hashmap��,������Ӧ��*/
							client_key = dst_key;
							packet_type = RESPONSE_PACKET;
							search_client_key = 1;
						}
						else/*ûץ���������ӵİ�,�޷�Ϊ����Ự����NPP.������������ĸ��ʼ�С*/
						{
							NPC_PRINT("[Error]: in DB_LINK, src_key and dst_key are neither found in session_hashmap, because not capture connection packet for this session.\n");
							return;
						}
					}
				}
			}
			else
			{
				return;
			}
			/*�жϿͻ��˵�ַ�Ƿ���session_hashmap��*/
			if(search_client_key==1)/*��session_hashmap����ҹ�client_key,�����ܹ��ҵ� */
			{
				create_npp = 0;
				/*cur_session_id�Ѿ���ֵ��*/
			}
			/*search_client_key=0��ʾ�������:(1)û���ҹ�,(2)�ҹ�,����û�ҵ�.��(2)������Ѿ�return*/
			else/*û���ҹ�*/
			{
				/*����session_hashmapʱ, ����*/
//#ifndef USE_BSLHASH_FORSESSION
				NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
				//cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), client_key);
				cur_session_id = Npc_FindSessionWithClient(client_key);
//#ifndef USE_BSLHASH_FORSESSION
				NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
				if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
				{/*�ҵ���,���ô���NPP*/
					create_npp = 0;
				}
				else
				{  /*û�ҵ�˵��:û�в�׽���ûỰ�Ĵ������ӵ�ͨ�Ű�,��ô�����������ͨ�Ű�*/
					//create_npp = 1;
					/* 2014-04-06 ���������ӻỰ��ƹ��ܣ�����NPP */
					//printf("not find client_key = %llu\n",client_key);
#ifdef HAVE_NOCONNECT_SESSION
					NPC_PRINT("[Info]: not find client ip = %u  port=%u\n",src_ip,src_port);
					/* 
						2014-10-16 ��ɽ�ֳ������ִ��ںܶ�SQLServer��ͻ��˷��͵�TCP segment of a reassembled PDU 
						���ĳߴ��С������Ϊ0�ֽڻ�1�ֽڣ����������һ��<70�ֽ�
						�������ſͻ��˷��ظ��������İ�������Ҳ��С<70�ֽ�
						������������ӣ������������NPP����Ҫ����
					*/
					//if(find_src_key==1 && find_dst_key==0)
                    if(find_src_key==1 && find_dst_key==NPC_HASHMAP_NOT_FIND_KEY)
					{
						/* ��DB->Client��Ӧ���,���ܴ����Ự��ֱ����һ��Client->DB������� */
						return;
					}
					else if(phdr->caplen>70)
					{
                        //printf("create npp for caplen>70\n");
						create_npp = 1;	
					}
					else
					{
						return;
					}
#else
					   return;
#endif    			
				}
			}
		}
	}
	else
	{
static_port:
        is_dynaport = 0;    /* ���Ƕ�̬�˿� */
		if(parse_ret == 1)/*�Ǵ������ӵİ�*/
		{
			/*��δָ��filterʱ,��Ȼ�Ǵ������ӵİ�,���п��ܲ��������ݿ�ͨ�ŵİ�*/
			/*���Ի�Ҫ���Ŀ�ĵ�ַ�Ƿ���db_hashmap��*/
#ifdef NPC_USE_SYNANDACK_START
            /* SYN+ACK����NPPģʽ */
            dst_key = src_ip;/*С���ֽ���*/
            dst_key = (dst_key<<16)|src_port;

            ret = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), dst_key);
            if(ret==NPC_HASHMAP_NOT_FIND_KEY)
            {
                return ;
            }
            //printf("create_npp=1 for static_port");
            create_npp = 1;
            client_key = dst_ip;
            client_key = (client_key<<16)|dst_port;
            packet_type = RESPONSE_PACKET;
#else
            /* SYN����NPPģʽ */
			dst_key = dst_ip;/*С���ֽ���*/
			dst_key = (dst_key<<16)|dst_port;

			ret = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), dst_key);
			if(ret==NPC_HASHMAP_NOT_FIND_KEY)
			{
				return ;
			}
			/* 
				2014-06-13 �޸��˿��ظ����������SYN�������ƶ�ε����
				���NPP�Ƿ��Ѿ��������ˣ��������ֱ�ӷ��أ����ٴ���
				���Ƿ��ִ���һ�������NPP���ڶ�ʧ��FIN�����û���������˳�����ʱ�������޷������µ���ͬsrc_key��NPP��
				���������߼���Ҫȥ������Ϊ��Npc_SetSessionWithClient����������
			*/
	//         src_key = src_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
	//         src_key = (src_key<<16)|src_port;
	//         NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
	//         //cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), src_key);
	//         cur_session_id = Npc_FindSessionWithClient(src_key);
	//         NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
	//         if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
	//         {
	//             /* �ҵ��˸�src_key,Ŀǰ��Ϊ�Ѿ�������NPP�ˣ������ظ�����,��Ҫ�ȼ��һ���Ƿ��session�Ĳ�λ�����ź������� */
	//             if(global_ld.session_withclients[cur_session_id]._sem_id>=0 && Dbfw_GetSemValue(global_ld.session_withclients[cur_session_id]._sem_id)>=0)
	//             {
	//                 /* ��sessionȷʵ���ڣ������ؽ� */
	//                 return ;
	//             }            
	//         }
			create_npp = 1;
			client_key = src_ip;
			client_key = (client_key<<16)|src_port;
			packet_type = REQUEST_PACKET;
#endif			
		}
		else/*���Ǵ������ӵİ�*/
		{
			search_client_key=0;

			src_key = src_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
			src_key = (src_key<<16)|src_port;
			dst_key = dst_ip;/*С���ֽ���, �ڴ�����Ϊ:  [24][1][168][192]*/
			dst_key = (dst_key<<16)|dst_port;
			find_src_key = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), src_key);
			find_dst_key = Npc_HashmapFind(&(global_ld.db_hashmap[global_ld.db_hashmap_id]), dst_key);
			if(find_src_key==1 && find_dst_key==NPC_HASHMAP_NOT_FIND_KEY)
			{/*����һ����Ӧ��*/
				client_key = dst_key;
				packet_type = RESPONSE_PACKET;
			}
			else if(find_dst_key==1 && find_src_key==NPC_HASHMAP_NOT_FIND_KEY)
			{/*����һ�������*/
				client_key = src_key;
				packet_type = REQUEST_PACKET;
			}
			else if(find_src_key==1 && find_dst_key==1)/*DB_LINK�������,Դ��ַ��Ŀ�ĵ�ַ����db_hashmap��*/
			{
				if(parse_ret == 1)/*�����ߵ�����*/
				{/*���Ǵ������ӵİ�*/
#ifdef NPC_USE_SYNANDACK_START
                    /* SYN+ACK����NPPģʽ */
                    client_key = dst_key;
                    packet_type = RESPONSE_PACKET;
#else
                    /* SYN����NPPģʽ */
					client_key = src_key;
					packet_type = REQUEST_PACKET;
#endif
				}
				else/*�ⲻ�Ǵ������ӵİ�*/
				{
					/*����session_hashmapʱ, ����*/
//#ifndef USE_BSLHASH_FORSESSION
					NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
					//cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), src_key);
					cur_session_id = Npc_FindSessionWithClient(src_key);
//#ifndef USE_BSLHASH_FORSESSION
					NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
					if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
					{/*Դ��ַ��session_hashmap��,���������*/
						client_key = src_key;
						packet_type = REQUEST_PACKET;
						search_client_key = 1;
					}
					else
					{
//#ifndef USE_BSLHASH_FORSESSION
						NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
						//cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), dst_key);
						cur_session_id = Npc_FindSessionWithClient(dst_key);
//#ifndef USE_BSLHASH_FORSESSION
						NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
						if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
						{/*Ŀ�ĵ�ַ��session_hashmap��,������Ӧ��*/
							client_key = dst_key;
							packet_type = RESPONSE_PACKET;
							search_client_key = 1;
						}
						else/*ûץ���������ӵİ�,�޷�Ϊ����Ự����NPP.������������ĸ��ʼ�С*/
						{
							NPC_PRINT("[Error]: in DB_LINK, src_key and dst_key are neither found in session_hashmap, because not capture connection packet for this session.\n");
							return;
						}
					}
				}
			}
			else/*Դ��ַ��Ŀ�ĵ�ַ������db_hashmap��,�޷����������.��db_hashmap�ǿ�ʱ,���ִ����.*/
			{
	//#ifdef DEBUG
	//			Npc_Ip2Str(src_ip, ip_str_1);
	//			Npc_Ip2Str(dst_ip, ip_str_2);
	//			/*�ĳɼ���־*/
	//			//NPC_PRINT("[Error]: src_addr:%s:%d and dst_addr:%s:%d are neither found in db_hashmap, this packet couldn't be processed\n", 
	//			//		ip_str_1, src_port, ip_str_2, dst_port);
	//#endif
				return;
			}
			/*�жϿͻ��˵�ַ�Ƿ���session_hashmap��*/
			if(search_client_key==1)/*��session_hashmap����ҹ�client_key,�����ܹ��ҵ� */
			{
				create_npp = 0;
				/*cur_session_id�Ѿ���ֵ��*/
			}
			/*search_client_key=0��ʾ�������:(1)û���ҹ�,(2)�ҹ�,����û�ҵ�.��(2)������Ѿ�return*/
			else/*û���ҹ�*/
			{
				/*����session_hashmapʱ, ����*/
//#ifndef USE_BSLHASH_FORSESSION
				NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
				//cur_session_id=Npc_HashmapFind(&(global_ld.session_hashmap), client_key);
				cur_session_id = Npc_FindSessionWithClient(client_key);
//#ifndef USE_BSLHASH_FORSESSION
				NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
				if(cur_session_id!=NPC_HASHMAP_NOT_FIND_KEY)
				{/*�ҵ���,���ô���NPP*/
					create_npp = 0;
				}
				else
				{/*û�ҵ�˵��:û�в�׽���ûỰ�Ĵ������ӵ�ͨ�Ű�,��ô�����������ͨ�Ű�*/
					//create_npp = 1;
					/* 2014-04-06 ���������ӻỰ��ƹ��ܣ�����NPP */
					//printf("not find client_key = %llu\n",client_key);
	#ifdef HAVE_NOCONNECT_SESSION
					NPC_PRINT("[Info]: not find client ip = %u  port=%u\n",src_ip,src_port);
					/* 
						2014-10-16 ��ɽ�ֳ������ִ��ںܶ�SQLServer��ͻ��˷��͵�TCP segment of a reassembled PDU 
						���ĳߴ��С������Ϊ0�ֽڻ�1�ֽڣ����������һ��<70�ֽ�
						�������ſͻ��˷��ظ��������İ�������Ҳ��С<70�ֽ�
						������������ӣ������������NPP����Ҫ����
					*/
					//if(find_src_key==1 && find_dst_key==0)
                    if(find_src_key==1 && find_dst_key==NPC_HASHMAP_NOT_FIND_KEY)
					{
						/* ��DB->Client��Ӧ���,���ܴ����Ự��ֱ����һ��Client->DB������� */
						return;
					}
					else if(phdr->caplen>70)
					{
						create_npp = 1;	
					}
					else
					{
						return;
					}
	#else
					return;
	#endif
	                			
				}
			}
		}
	}
	
    /* ����Ƿ���������ͬ�ͻ���IP+PORT��SYN�� */
    if(parse_ret == 1)
    {
#ifdef NPC_USE_SYNANDACK_START
        /* SYN+ACK����NPPģʽ */
        client_key = dst_ip;
        client_key = (client_key<<16)|dst_port;
        current_timestamp_for_createnpp = NPC_GetEpochTime();
        tmp_session_id_forkey = Npc_FindSessionWithClient(client_key);
        if(tmp_session_id_forkey!=NPC_HASHMAP_NOT_FIND_KEY && global_ld.session_withclients[tmp_session_id_forkey].client_key==client_key)
        {
            /* �ҵ�����ͬ�ͻ���IP+PORT�ĻỰ�ˣ���Ҫ�����ж��Ƿ����ظ����������SYN+ACK���жϵķ�����ͨ��ʱ��� */            
            timestamp_for_createcpp = global_ld.session_withclients[tmp_session_id_forkey].timestamp_for_createcpp;
            //printf("same session for TCP Retransmission timestamp_for_createcpp = %ll\n",timestamp_for_createcpp);
            if(timestamp_for_createcpp>0)
            {
                if((timestamp_for_createcpp+timeout_for_createnpp)>current_timestamp_for_createnpp)
                {
                    /* ����һ�ε���ͬ */
                    //printf("same session for TCP Retransmission clientIp=%X, clientPort=%u for 3 sec\n",dst_ip,dst_port);                
                    parse_ret = 0;
                    create_npp = 0;
                    return;
                }
            }
        }
//         if(client_key==global_ld.last_clientkey_for_createnpp && 
//             (global_ld.last_timestamp_for_createcpp+timeout_for_createnpp)>current_timestamp_for_createnpp
//             )
//         {
//             /* ����һ�ε���ͬ */
//             //printf("same session for TCP Retransmission clientIp=%X, clientPort=%u for 3 sec\n",src_ip,src_port);                
//             parse_ret = 0;
//         }
//         else
//         {
//             global_ld.last_clientkey_for_createnpp = client_key;
//             global_ld.last_timestamp_for_createcpp = current_timestamp_for_createnpp;
//         }
#else
        client_key = src_ip;
        client_key = (client_key<<16)|src_port;
        current_timestamp_for_createnpp = NPC_GetEpochTime();
        tmp_session_id_forkey = Npc_FindSessionWithClient(client_key);
        if(tmp_session_id_forkey!=NPC_HASHMAP_NOT_FIND_KEY)
        {
            /* �ҵ�����ͬ�ͻ���IP+PORT�ĻỰ�ˣ���Ҫ�����ж��Ƿ����ظ����������SYN+ACK���жϵķ�����ͨ��ʱ��� */
            timestamp_for_createcpp = global_ld.session_withclients[tmp_session_id_forkey].timestamp_for_createcpp;
            if(timestamp_for_createcpp>0)
            {
                if((timestamp_for_createcpp+timeout_for_createnpp)>current_timestamp_for_createnpp)
                {
                    /* ����һ�ε���ͬ */
                    //printf("same session for TCP Retransmission clientIp=%X, clientPort=%u for 3 sec\n",src_ip,src_port);                
                    parse_ret = 0;
                    create_npp = 0;
                    return;
                }
            }
        }
//         if(client_key==global_ld.last_clientkey_for_createnpp && 
//             (global_ld.last_timestamp_for_createcpp+timeout_for_createnpp)>current_timestamp_for_createnpp
//             )
//         {
//             /* ����һ�ε���ͬ */
//             //printf("same session for TCP Retransmission clientIp=%X, clientPort=%u for 3 sec\n",src_ip,src_port);                
//             parse_ret = 0;
//         }
//         else
//         {
//             global_ld.last_clientkey_for_createnpp = client_key;
//             global_ld.last_timestamp_for_createcpp = current_timestamp_for_createnpp;
//         }
#endif
    }
    /* ������ */
	if(create_npp==1)
	{/*����NPP�Ĳ�������:*/

        //printf("create npp for client_key=%llu  client=%u:%d \n",client_key,cl);
        /**********************************
		**
		**	2013-08-29 ��ӷ����߼� 
        **  ����ڴ���ʣ�����Ƿ�<10%,����ﵽ������Ϊ�ڴ������㣬���ٴ���NPP����
		**
		**********************************/
        if(__OUT_OF_MEMORY_FLAG == 0x01)
        {
//             NPC_PRINT("[Error]: System's memory is not enough : total=%u(M)  used=%u(M)\n",s_system_source.system_total_memory,s_system_source.system_used_memory);
//             NPC_NEW_LOG(ERROR_LEVEL, error_log, "System's memory is not enough : total=%u(M)  used=%u(M)",s_system_source.system_total_memory,s_system_source.system_used_memory);
//             DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
            return;
        }
		/**********************************
		**
		**	1.�ж�npp���������Ƿ�ﵽ���ֵ 
		**
		**********************************/
// 		ret = Dbfw_Fixarray_AddNppCount(global_ld.sga_addr, global_ld.dbfw_max_session);
// 
// 		if(ret==-1)/* �Ի���������ʧ�� */
// 		{
// 			NPC_PRINT("[Error]: lock mutex error when add npp count\n");
// 			global_ld.error_no = NPC_ERROR_ADDNPPCOUNT_LOCK-NPC_ERRNO_START;
//             NPC_NEW_LOG(ERROR_LEVEL, error_log, "lock mutex error when add npp count");
//             DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
// 			goto finish;
// 		}
// 		else if(ret==0)/* NPP�������ﵽ�����ֵ */
// 		{
// 			NPC_PRINT("[Error]: npp's count reach to DBFW_MAX_SESSIONS when add npp count\n");
//             NPC_NEW_LOG(ERROR_LEVEL, error_log, "npp's count reach to DBFW_MAX_SESSIONS when add npp count");
//             DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
// 			return;
// 		}

		//NPC_PRINT("[Info]: NPP_COUNT after added:%d\n", ret);

		/**********************************
		**
		**	2.�ͷžɵ�session_id 
		**
		**********************************/
		//client_ip_value = ((client_key>>16)&0xFF) + ((client_key>>24)&0xFF)*255 + ((client_key>>32)&0xFF)*255*255 + ((client_key>>40)&0xFF)*255*255*255;
        client_ip_value = ((u_int)(client_key>>16));
		client_port = (client_key&0xFFFF);

        //printf("create npp for client_key=%llu  client=%u:%d \n",client_key,client_ip_value,client_port);

//         NPC_NEW_LOG(INFO_LEVEL, info_log, "client_ip_value(%u) = %s", client_ip_value,npc_ip2str(NPC_NTOH32((u_int)(client_ip_value))));
//         DBFW_INFO_PRINT(&npc_log_file, &info_log);

		/*Bind�ӿ��������Release�Ĺ���,���Բ�����Release�ӿ�*/
		//ret = Dbfw_ReleaseSessionForNPC(global_ld.sga_addr, client_ip_value, client_port);
		///* ret>=0: ���ͷŵ�session id */
		///* ret=65535: û����Ҫ���ͷŵ�session id */		
		//if(ret==-1)/* release failed */
		//{
		//	return;
		//}
		/**********************************
		**
		**	3.���µ�session_id 
		**
		**********************************/
		/* ���ret=65535, ��ʾ�����µ�session_id */
        /* �ȼ���Ƿ��ܹ�ʹ��NPP���̳� */
        if(packet_type==REQUEST_PACKET)
        {
            npp_dialect = Npc_GetDBDialectForServer(dst_ip, dst_port);
        }
        else
        {
            npp_dialect = Npc_GetDBDialectForServer(src_ip, src_port);
        }
        usepool_flag = 1;   /* ʹ�ý��̳ر�� */
        if(npp_dialect==DBFW_DBTYPE_MSSQL)
        {
            /* �ǵ�ǰ������MSSQL���͵�NPP */
            if(global_ld.npp_pool_type!=NPP_POOL_TYPE_MSSQL)
            {
                /* �����̳�����Ϊ�ǡ�MSSQL�͡� */
                usepool_flag = 0;
            }
        }
        else
        {
            /* ��ǰ�����ǡ�ͨ���͡�NPP */
            if(global_ld.npp_pool_type==NPP_POOL_TYPE_MSSQL)
            {
                /* �����̳�����Ϊ��MSSQL�͡� */
                usepool_flag = 0;
            }
        }
        //usepool_flag = 1;
		ret = Dbfw_BindSessionForNPC(global_ld.sga_addr, client_ip_value, client_port, 65535,usepool_flag);
		if(ret == -1)
		{
            /* ��NPP���̸�����һ */
            //Dbfw_Fixarray_SubNppCount((u_char*)global_ld.sga_addr);
            NPC_NEW_LOG(ERROR_LEVEL, error_log,"Dbfw_BindSessionForNPC() error: no free session can use.");
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
            NPC_PRINT("[Error]: Dbfw_BindSessionForNPC() error: no free session can use\n");
			return;
		}
		else if(ret == 65535)
		{/* û�п��õ�session_id */
            /* ��NPP���̸�����һ */
            //Dbfw_Fixarray_SubNppCount((u_char*)global_ld.sga_addr);
			NPC_NEW_LOG(ERROR_LEVEL, error_log,"Dbfw_BindSessionForNPC() error: no free session can use.");
			DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
			NPC_PRINT("[Error]: Dbfw_BindSessionForNPC() error: no free session can use\n");

			return;
		}
		cur_session_id = ret;
		#ifdef HAVE_LIBTIS
		#else
		global_ld.header_id[cur_session_id] = 1;
        global_ld.last_capbuf_header_idx[cur_session_id] = DBFW_NEXTHEADERIDX_UNKNOWN;  /* ��ʼֵ����ΪDBFW_NEXTHEADERIDX_UNKNOWN */
        #endif
        global_ld.semvalue_outofrange_flag[cur_session_id] = 0;

#ifdef HAVE_LIBTIS
        #ifdef TIS_HAVE_TCP_CHECK
		{
            /* ����ļ���߼��ǲ���ȷ�ģ���Ϊ֮ǰ�����λ�Ѿ���ʹ�ù��ˣ���������µļ��϶���ƥ�䲻�ϵ� */
// 			Tis_Tcp_Info mytcp,slottcp;
// 			mytcp.src_ip = src_ip;
// 			mytcp.src_port = src_port;
// 			mytcp.dst_ip = dst_ip;
// 			mytcp.dst_port = dst_port;
// 			memset(&slottcp,0,sizeof(Tis_Tcp_Info));
// 			if(Tis_Slot_Check_Tcp(global_ld.tis,cur_session_id,&mytcp,&slottcp) == TIS_ERROR_TCP_NOT_EXPECT)
// 			{
// 				NPC_NEW_LOG(ERROR_LEVEL, error_log,
// 					"Tis_Slot_Check_Tcp() error: not expect packet. slot_id=%d,current tcp: src_ip=%08x src_port=%d dst_ip=%08x dst_port=%d,but slot tcp: src_ip=%08x src_port=%d dst_ip=%08x dst_port=%d",
// 					cur_session_id,src_ip,src_port,dst_ip,dst_port,
// 					slottcp.src_ip,slottcp.src_port,slottcp.dst_ip,slottcp.dst_port);
// 				DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);				
// 			}
		}
        #endif
        Tis_Slot_Close(global_ld.tis,cur_session_id);
        #ifdef TIS_HAVE_TCP_CHECK
		ret = Tis_Slot_Open_With_Tcp(global_ld.tis,cur_session_id,src_ip,src_port,dst_ip,dst_port);
		#else
        ret = Tis_Slot_Open(global_ld.tis,cur_session_id);
        #endif
        if(ret < 0)
        {
            NPC_NEW_LOG(ERROR_LEVEL, error_log,"Tis_Slot_Open() error: slot_id=%d ret=%d",
					cur_session_id,ret);
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
            printf("Tis_Slot_Open() error: slot_id=%d ret=%d",
					cur_session_id,ret);
            Dbfw_FreeSession(global_ld.sga_addr,cur_session_id);
            /* ��NPP���̸�����һ */
            Dbfw_Fixarray_SubNppCount((u_char*)global_ld.sga_addr);
            return;
        }
#endif

		/**********************************
		**
		**	4.���client ip+port => {session_id, sem_id} 
		**	  ��session_hashmap��,����
		**	  
		**********************************/
		sem_id = global_ld.sems->semid[cur_session_id];

		//NPC_PRINT("[Info]: session_id: %d, sem_id:%d\n", cur_session_id, sem_id);
//#ifndef USE_BSLHASH_FORSESSION
		NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
		//ret = Npc_HashmapInsert(&(global_ld.session_hashmap), client_key, cur_session_id, sem_id);
        ret = Npc_SetSessionWithClient(client_key, cur_session_id, npp_dialect, is_dynaport, sem_id);
//#ifndef USE_BSLHASH_FORSESSION
		NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//#endif
		if(ret==-2)
		{ /* ������ù��� */
			global_ld.error_no = NPC_ERROR_HASHPOOL_ALLUSED-NPC_ERRNO_START;
            NPC_NEW_LOG(ERROR_LEVEL, error_log,"The buffer pool for session_hashmap have not slot.");
            DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
			goto finish;
		}
        /**********************************
		**
        **  2014-03-23���
		**	4.2.����Capbuf������Buffer��CapBuf_Header�������и�sessionid��ͷ���ݣ�������ʷ���������ݱ��µ�sessionʹ��
		**
		**********************************/
        #ifndef HAVE_LIBTIS
//         Tis_Slot_Close(global_ld.tis,cur_session_id);
// 		if(Tis_Slot_Open(global_ld.tis,cur_session_id) < 0)
// 		{
// 			NPC_NEW_LOG(ERROR_LEVEL, error_log,"Tis_Slot_Open() error: no free slot can use.");
// 			DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
// 			printf("[Error]: Tis_Slot_Open() error: no free slot can use\n");
// 			return;
// 		}
//         #else
        /* ��һ��buffer�� */
        cap_header_tmp = (u_char*)global_ld.header_addr[0];
        for(i=0;i<DBFW_CAPBUF_MAX_HEADER_COUNT;i++)
        {
            if(((CapBuf_Header*)cap_header_tmp)->session_id==cur_session_id)
            {
                //printf("clear buffer[0] data for session %d  datasize=%d\n",((CapBuf_Header*)cap_header_tmp)->session_id,((CapBuf_Header*)cap_header_tmp)->data_size);
                ((CapBuf_Header*)cap_header_tmp)->session_id = 65535;
                ((CapBuf_Header*)cap_header_tmp)->next_header_idx = DBFW_NEXTHEADERIDX_UNKNOWN;
            }
//             else if(((CapBuf_Header*)cap_header_tmp)->session_id<65535 && ((CapBuf_Header*)cap_header_tmp)->session_id>0)
//             {
//                 printf("buffer data session %d\n",((CapBuf_Header*)cap_header_tmp)->session_id);
//             }
            cap_header_tmp += DBFW_CAPBUF_HEADER_SIZE;
        }
        /* �ڶ���buffer�� */
        cap_header_tmp = (u_char*)global_ld.header_addr[1];
        for(i=0;i<DBFW_CAPBUF_MAX_HEADER_COUNT;i++)
        {
            if(((CapBuf_Header*)cap_header_tmp)->session_id==cur_session_id)
            {
                //printf("clear buffer[1] data for session %d  datasize=%d\n",((CapBuf_Header*)cap_header_tmp)->session_id,((CapBuf_Header*)cap_header_tmp)->data_size);
                ((CapBuf_Header*)cap_header_tmp)->session_id = 65535;
                ((CapBuf_Header*)cap_header_tmp)->next_header_idx = DBFW_NEXTHEADERIDX_UNKNOWN;
            }
//             else if(((CapBuf_Header*)cap_header_tmp)->session_id<65535 && ((CapBuf_Header*)cap_header_tmp)->session_id>0)
//             {
//                 printf("buffer data session %d\n",((CapBuf_Header*)cap_header_tmp)->session_id);
//             }
            cap_header_tmp += DBFW_CAPBUF_HEADER_SIZE;
        }
        #endif
		/**********************************
		**
		**	5.֪ͨ����̴߳���NPP 
		**
		**********************************/
		/*�������������Ӧ�����ֱ���ȡ�ͻ��˺ͷ�������ַ*/

//		NPC_PRINT("[Info]: normal create npp, cur_session_id:%u\n", cur_session_id);

		if(packet_type==REQUEST_PACKET)
		{
			ret = Npc_NotifyToCreateNpp(src_ip, src_port, pd+6, dst_ip, dst_port, pd, cur_session_id);
		}
		else
		{
			ret = Npc_NotifyToCreateNpp(dst_ip, dst_port, pd, src_ip, src_port, pd+6, cur_session_id);
		}
		if(ret<0)
		{
			global_ld.error_no = ret;
			goto finish;
		}
	}

	/*************************************
	**
	**	д��¼��capbuf��
	**
	*************************************/

    /*  
        2013-01-16 ��ӷ����߼� 
        ����ź����Ƿ񳬹�������ֵ��������������������
    */
    sem_value = Dbfw_GetSemValue(global_ld.sems->semid[cur_session_id]);
    if(sem_value>NPC_MAX_SEMVALUE)
    {
        //printf("[Info]: sem_value = %d\n",sem_value);
        /* ���������ߣ����ñ��Ϊ1 */
        global_ld.semvalue_outofrange_flag[cur_session_id] = 0x01;
    }
    else if(sem_value<NPC_NORMAL_SEMVALUE)
    {
        /* �ָ�����NPC_NORMAL_SEMVALUE���£����ñ��Ϊ0����ʼ�ɼ��ûỰ������ */
        global_ld.semvalue_outofrange_flag[cur_session_id] = 0x00;
    }
    //if(sem_value < NPC_MAX_SEMVALUE && phdr->caplen>0)
    if(global_ld.semvalue_outofrange_flag[cur_session_id]==0x00 && phdr->caplen>0)
    //if(phdr->caplen>0)
    {
	#ifdef HAVE_LIBTIS

	#else
	/*���p_header,p_body�Ƿ�ᳬ��buffer�߽� */
	if(global_ld.p_header>=global_ld.body_addr[global_ld.buffer_id] ||
		global_ld.p_body+phdr->caplen>=global_ld.tail_addr[global_ld.buffer_id])
	{
//#ifdef DEBUG
// 		if(global_ld.p_header>=global_ld.body_addr[global_ld.buffer_id])
// 		{
// 			printf("[Info]: header is full\n");
// 		}
// 		else
// 		{
// 			printf("[Info]: body is full\n");
//             /* ��Ҫ��header�к�����header��¼��������??? */
// 		}
//		/*��ַ��ȥcapbuf�׵�ַ*/
//		NPC_PRINT("\tp_header:%lu(id:%lu), body_addr[%d]:%lu\n", 
//			global_ld.p_header-global_ld.header_addr[0], 
//			((global_ld.p_header-global_ld.header_addr[0])%(32*1024*1024))/DBFW_CAPBUF_HEADER_SIZE,
//			global_ld.buffer_id, 
//			global_ld.body_addr[global_ld.buffer_id]-global_ld.header_addr[0]);
//		NPC_PRINT("\tp_body:%lu, caplen:%u, p_body+caplen:%lu, taild_addr[%d]:%lu\n", 
//			global_ld.p_body-global_ld.header_addr[0], 
//			phdr->caplen, 
//			global_ld.p_body+phdr->caplen-global_ld.header_addr[0],
//			global_ld.buffer_id, 
//			global_ld.tail_addr[global_ld.buffer_id]-global_ld.header_addr[0]);
//		last_header = (CapBuf_Header*)(global_ld.p_header-DBFW_CAPBUF_HEADER_SIZE);
//		NPC_PRINT("\tcur_header: session_id:%u, id:%llu, data_offset:%u, data_size:%u\n",
//			last_header->session_id,
//			last_header->id,
//			last_header->data_offset,
//			last_header->data_size);
//		switch_buf=1;
//
//#endif
		/*������һ��buffer*/
		global_ld.buffer_id=1-global_ld.buffer_id;
		global_ld.p_header = global_ld.header_addr[global_ld.buffer_id];
		global_ld.p_body = global_ld.body_addr[global_ld.buffer_id];        
        /* ������buffer����Ҫ��ʼ��global_ld.current_capbuf_header_idx:��ÿ��������ʼ�����±꿪ʼ */
        if(global_ld.buffer_id==0)
        {
            global_ld.current_capbuf_header_idx = 0;
        }
        else
        {
            global_ld.current_capbuf_header_idx = DBFW_CAPBUF_MAX_HEADER_COUNT;
        }
	}
	#endif

	#ifdef HAVE_LIBTIS
    __DROP_PACKET_COUNT++;
	ret = Tis_Content_Write(global_ld.tis,cur_session_id,(uint8_t*)pd, phdr->caplen);	
	if(ret < 0)
	{
		NPC_PRINT("Tis_Content_Write Error:%d slot_id:%d\n",ret,cur_session_id);
        return;
	}
	#else
	/*������header,��ǰ��p_header*/
	new_header=(CapBuf_Header*)global_ld.p_header;
	__sync_lock_test_and_set(&(new_header->session_id), cur_session_id);
	//new_header->session_id = cur_session_id;
	new_header->id = global_ld.header_id[cur_session_id]++;
    //printf("[%d]new_header->id=%d\n",cur_session_id,new_header->id);
	new_header->data_offset = global_ld.p_body-global_ld.header_addr[0];
    //new_header->data_offset = global_ld.p_body-global_ld.header_addr[global_ld.buffer_id];
	new_header->data_size = phdr->caplen;
    new_header->next_header_idx = DBFW_NEXTHEADERIDX_UNKNOWN;   /* ������һ����λ�±�ֵΪδ֪ */
    /* ���õ�ǰ�Ự��֮ǰ�����һ����λ����һ����λ:global_ld.current_capbuf_header_idx */    
#ifdef HAVE_HEADER_INDEX
    if(global_ld.last_capbuf_header_idx[cur_session_id]>=0 && global_ld.last_capbuf_header_idx[cur_session_id]!=DBFW_NEXTHEADERIDX_UNKNOWN)
    {
        /* ���ǳ�ʼ��ֵ��������� */
        if(global_ld.last_capbuf_header_idx[cur_session_id]<DBFW_CAPBUF_MAX_HEADER_COUNT)
        {
            /* �ǵ�һ��buffer�� */
            last_header_for_currentsession = global_ld.header_addr[0];
            last_header_for_currentsession += (global_ld.last_capbuf_header_idx[cur_session_id])*DBFW_CAPBUF_HEADER_SIZE;
        }
        else
        {
            /* �ǵڶ����� */
            last_header_for_currentsession = global_ld.header_addr[1];
            last_header_for_currentsession += (global_ld.last_capbuf_header_idx[cur_session_id]-DBFW_CAPBUF_MAX_HEADER_COUNT)*DBFW_CAPBUF_HEADER_SIZE;
        }
        /* ���ø�capbuf_header��next_header_idx,��Ҫͨ��ԭ�Ӳ������ȡ�Ự��ID */
        tmp_session_id = Dbfw_FetchAndAdd(&(((CapBuf_Header*)last_header_for_currentsession)->session_id),0);
        if(tmp_session_id==cur_session_id ||
           tmp_session_id==65535)
        {
            /* ��sessionidû�б����,�����Ѿ���Ӧ��NPP���Ϊ65535�� */
            ((CapBuf_Header*)last_header_for_currentsession)->next_header_idx = global_ld.current_capbuf_header_idx;
        }
        else
        {
            /* �ò�λ�Ѿ��������Ựʹ���ˣ������������� */
            //printf("this slot is used 1 by session=%d\n",tmp_session_id);
        }        
    }
    else
    {
        /* �����ǳ�ʼ���Ĳ�λ��Ҳ������ѭ��һ�ֺ�Ľ��,����ò�λ��sessionid��cur_session_idһ��������ѭ���Ľ��������ʹ�� */
        /* �϶��ǵ�һ��buffer�� */
//         last_header_for_currentsession = global_ld.header_addr[0];
//         tmp_session_id = Dbfw_FetchAndAdd(&(((CapBuf_Header*)last_header_for_currentsession)->session_id),0);
//         if(tmp_session_id==cur_session_id)
//         {
//             /* ��sessionidû�б���� */
//             ((CapBuf_Header*)last_header_for_currentsession)->next_header_idx = global_ld.current_capbuf_header_idx;
//         }
//         else
        {
            /* �ò�λ�Ѿ��������Ựʹ���ˣ������������� */
            //printf("this slot is used 2 by session=%d\n",tmp_session_id);
        }
    }
    global_ld.last_capbuf_header_idx[cur_session_id] = global_ld.current_capbuf_header_idx;
#endif
    /* ��ӡ������Ϣ */
//     printf("[last_header]:session_id=%d    id=%llu    next_header_idx=%d\n",
//         ((CapBuf_Header*)last_header_for_currentsession)->session_id,
//         ((CapBuf_Header*)last_header_for_currentsession)->id,
//         ((CapBuf_Header*)last_header_for_currentsession)->next_header_idx);
    //global_ld.last_capbuf_header_idx[cur_session_id]
//#ifdef DEBUG
//	if(switch_buf==1)
//	{
//		NPC_PRINT("\tnext_header: session_id:%u, id:%llu, data_offset:%u, data_size:%u\n",
//			new_header->session_id,
//			new_header->id,
//			new_header->data_offset,
//			new_header->data_size);
//		switch_buf = 0;
//	}
//#endif
	global_ld.p_header += DBFW_CAPBUF_HEADER_SIZE;
    /* �����µ�global_ld.current_capbuf_header_idxֵ */
    global_ld.current_capbuf_header_idx = global_ld.current_capbuf_header_idx + 1;
    if(global_ld.current_capbuf_header_idx>=((u_int)(DBFW_CAPBUF_MAX_HEADER_COUNT)*2))
    {
        /* �ﵽ��current_capbuf_header_idx�����ֵ������ */
//         if(global_ld.p_header>=global_ld.body_addr[global_ld.buffer_id])
//             printf("global_ld.current_capbuf_header_idx = %d  AND p_header is full\n",global_ld.current_capbuf_header_idx);
//         else
//             printf("global_ld.current_capbuf_header_idx = %d  BUT p_header not full\n",global_ld.current_capbuf_header_idx);
        global_ld.current_capbuf_header_idx = 0;
    }
    
	/*д����body,��ǰ��p_body*/
	memcpy(global_ld.p_body, pd, phdr->caplen);

#ifdef DUMP_PACKET
	Npc_Dump(__FOUT, global_ld.p_body,  phdr->caplen);
	//fwrite(global_ld.p_body, 1, phdr->caplen, __FOUT_SIMPLE);
	//fflush(__FOUT_SIMPLE);
#endif

	global_ld.p_body += phdr->caplen;
	#endif
	
	/*�����ź�����ֵ*/
	if(Dbfw_UnlockSem(global_ld.sems->semid[cur_session_id])==-1)
	{
//#ifdef DEBUG
//		NPC_PRINT("[Error]: NPP's problem. unlock sem error:%s for session_id:%d\n", strerror(errno), cur_session_id);
//#endif
// 		NPC_NEW_LOG(ERROR_LEVEL, error_log, "Unlock sem error for session %d : %s", cur_session_id,strerror(errno));
// 		DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);
//		//global_ld.error_no = NPC_ERROR_UNLOCKSEM-NPC_ERRNO_START;
//		//goto finish;
//		/*****************************************
//		**
//		**	���Խ�NPP���������ļ�������1
//		**
//		*****************************************/
//		ret = Dbfw_Fixarray_AddNppCount(global_ld.sga_addr, global_ld.dbfw_max_session);
//		if(ret==-1)/* �Ի���������ʧ�� */
//		{
//#ifdef DEBUG
//			NPC_PRINT("[Error]: lock mutex error when add npp count\n");
//#endif
//			global_ld.error_no = NPC_ERROR_ADDNPPCOUNT_LOCK-NPC_ERRNO_START;
//			goto finish;
//		}
//		else if(ret==0)/* NPP�������ﵽ�����ֵ */
//		{
//#ifdef DEBUG
//			NPC_PRINT("[Error]: npp's count reach to DBFW_MAX_SESSIONS when add npp count\n");
//#endif
//			return;
//		}
////#ifdef DEBUG
////		 NPC_PRINT("[Info]: NPP_COUNT after added:%d\n", ret);
////#endif
//
//		/****************************************************
//		**
//		**	����errno�ж�����������������������ź�����ֵʧ��
//		**	1.NPP�쳣��ֹ,�����ź�����ɾ��
//		**	2.NPP��������,�����ź����ﵽ���ֵ
//		**
//		****************************************************/
//		client_ip_value = ((client_key>>16)&0xFF) + ((client_key>>24)&0xFF)*255 + ((client_key>>32)&0xFF)*255*255 + ((client_key>>40)&0xFF)*255*255*255;
//		client_port = (client_key&0xFFFF);
//		if(errno==EINVAL)/*�ź�����ɾ����,˵��NPP�쳣��ֹ*/
//		{
//#ifdef DEBUG
//			NPC_PRINT("[Info]: NPP abort\n");
//#endif
//			/*����NPP�ṩ���ؽ�session�Ľӿ�*/
//			//new_session_id = ��ֵ, sem_id=��ֵ
//			new_session_id = cur_session_id;
//		}
//		else if(errno==ERANGE)/*�ź����ﵽ�����ֵ,˵��NPP����������*/
//		{
//#ifdef DEBUG
//			NPC_PRINT("[Info]: NPP is too busy for session:%u, sem_id:%d\n", cur_session_id, global_ld.sems->semid[cur_session_id]);
//#endif
//			/*����NPP�ṩ�Ĵ�����session_id�Ľӿ�(����NPP��Ӧһ��session)*/
//			//new_session_id = ��ֵ, sem_id=��ֵ
//			new_session_id = 65535;
//		}
//		
//		/***********************************************
//		**
//		**	��session:�ؽ�session_id��ʹ���µ�session_id
//		**
//		***********************************************/
//#ifdef DEBUG
//		NPC_PRINT("[Info]: rebind session before:cur_session_id=%u, new_session_id=%u\n", cur_session_id, new_session_id);
//#endif
//		ret = Dbfw_BindSessionForNPC(global_ld.sga_addr, client_ip_value, client_port, new_session_id);
//		if(ret == -1)
//		{
//			return;
//		}
//		else if(ret == 65535)
//		{/* û�п��õ�session_id */

//			NPC_NEW_LOG(ERROR_LEVEL, error_log,"Create NPP failed, no free session can use.");
//			DBFW_ERROR_PRINT(&npc_errlog_file, &error_log);

//#ifdef DEBUG
//			NPC_PRINT("[Error]: when create session:%u, Dbfw_BindSessionForNPC() error: no free session can use\n", new_session_id);
//#endif
//			return;
//		}
//		cur_session_id = ret;
//		global_ld.header_id[cur_session_id] = 1;
//
//#ifdef DEBUG
//		NPC_PRINT("[Info]: rebind session after:cur_session_id=%u\n", cur_session_id);
//#endif
//		/************************************************
//		**
//		**	����session_hashmap,����
//		**
//		************************************************/
//		sem_id = global_ld.sems->semid[cur_session_id];
//
//		NPC_LOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//		ret = Npc_HashmapInsert(&(global_ld.session_hashmap), client_key, cur_session_id, sem_id);
//		NPC_UNLOCK_MUTEX(&(global_ld.mutex_for_clear_session), ret);
//
//		if(ret==-2)
//		{ /* ������ù��� */
//			global_ld.error_no = NPC_ERROR_HASHPOOL_ALLUSED-NPC_ERRNO_START;
//			goto finish;
//		}
//
//		/************************************************
//		**
//		**	֪ͨCreateNppThread�̴߳���NPP����
//		**
//		*************************************************/
//		if(packet_type==REQUEST_PACKET)
//		{
//			ret = Npc_NotifyToCreateNpp(src_ip, src_port, pd+6, dst_ip, dst_port, pd, cur_session_id);
//		}
//		else
//		{
//			ret = Npc_NotifyToCreateNpp(dst_ip, dst_port, pd, src_ip, src_port, pd+6, cur_session_id);
//		}
//		if(ret<0)/*�����ź���sem_id_for_create_npp��ֵ����*/
//		{
//			global_ld.error_no = ret;
//			goto finish;
//		}
//		/****************************************
//		**
//		**	�޸ĸղ�д���header
//		**
//		****************************************/
//		new_header->session_id = cur_session_id;
//		new_header->id = global_ld.header_id[cur_session_id]++;
//		/***************************************
//		**
//		**	�����µ��ź�����ֵ
//		**
//		***************************************/
//		Dbfw_UnlockSem(global_ld.sems->semid[cur_session_id]);
	}
    }/* end if(phdr->caplen>0) */
#endif
//#ifdef DEBUG
//	NPC_PRINT("[Info]: **************************** packet over *************************\n\n");
//#endif 
    } /* END if(global_ld.license_result>0) */

	++global_ld.captured_packets_count;/*�������NPC�Ƿ��ڹ���*/
	++pcap_opts->received;
	global_ld.captured_bytes_count += phdr->caplen;

#ifdef DUMP_PACKET	
		//fprintf(__FOUT_SIMPLE, "%llu, %u, %u, %u\n", 
				//new_header->id, 
				//new_header->session_id, 
				//new_header->data_offset, 
				//new_header->data_size);
		//fflush(__FOUT_SIMPLE);
#endif

	return;

finish:
	global_ld.go = FALSE;

}

void report_cfilter_error(capture_options *capture_opts, guint i, const char *errmsg)
{
	interface_options interface_opts;


	if (i < capture_opts->ifaces->len) {

		/*
		* clopts_step_invalid_capfilter in test/suite-clopts.sh MUST match
		* the error message below.
		*/
		interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
		fprintf(stderr,
			"Invalid capture filter \"%s\" for interface %s!\n"
			"\n"
			"That string isn't a valid capture filter (%s).\n"
			"See the User's Guide for a description of the capture filter syntax.\n",
			interface_opts.cfilter, interface_opts.name, errmsg);

	}
}

void report_capture_error(const char *error_msg, const char *secondary_error_msg)
{
	fprintf(stderr, "%s\n", error_msg);
	if (secondary_error_msg[0] != '\0')
		fprintf(stderr, "%s\n", secondary_error_msg);
}

void report_packet_drops(guint32 received, guint32 drops, gchar *name)
{
	char tmp[22];

	g_snprintf(tmp, sizeof(tmp), "%u", drops);

	fprintf(stderr,
		"[Info]: Packets received/dropped on interface %s: %u/%u (%.1f%%)\n",
		name, received, drops,
		received ? 100.0 * received / (received + drops) : 0.0);
	/* stderr could be line buffered */
	fflush(stderr);
}

/****************************************
**	
**	RETURN
**		>=0: ����������ֵ
**		-1: fixarray��û���������
**
*****************************************/
int GetIntParamInFixarray(u_char* sga, u_short param_index)
{
	u_char value[PROCESS_PARAM_MAX_VALUES_LEN];
	int ret_value;

	memset((char*)value, 0, sizeof(value));
	Dbfw_Fixarray_GetValueAndValuelenInGlobal(sga, param_index, value, PROCESS_PARAM_MAX_VALUES_LEN);
	if(strlen((char*)value)==0)
	{
		return -1;
	}
	ret_value = strtol((char*)value, NULL, 10);

	return ret_value;
}


void Npc_FaultTrap(int signo, 
				   siginfo_t *siginfo, 
				   void *context)  /*�߳�(����)������*/
{  
	int i, num;  
	u_char **calls;  
	u_char log_file_path[PROCESS_PARAM_MAX_VALUES_LEN];
	u_char  log_file_name[128];
	FILE    *cdump_file=NULL;
	int granule_offset_for_capbuf = GetIntParamInFixarray((u_char*)__SGA,DBFW_GRANULES_OFFSET_FOR_CAPBUF);	
	u_char *capbuf_addr = (u_char*)__SGA+(granule_offset_for_capbuf*((u_int)(DBFW_SGA_GURANULE_SIZE)));

	memset(log_file_path, 0x00, sizeof(log_file_path));
	memset(log_file_name, 0x00, sizeof(log_file_name));
	/*�ͷ���Դ*/
	Npc_Clear(0);

	int log_file_path_len = Dbfw_Fixarray_GetValueAndValuelenInGlobal((u_char*)__SGA, S_LOG_HOME, log_file_path, PROCESS_PARAM_MAX_VALUES_LEN);
	if(log_file_path_len==0)
	{
//#ifdef DEBUG
//		NPC_PRINT("[Error]: in Npc_FaultTrap(): DBFW_LOG_HOME is null\n");
//#endif
		exit(0);
	}

	u_char value[PROCESS_PARAM_MAX_VALUES_LEN];
	memset((char*)value, 0, PROCESS_PARAM_MAX_VALUES_LEN);
	Dbfw_Fixarray_GetValueAndValuelenInGlobal((u_char*)__SGA, DBFW_INSTANCE_NAME, value, PROCESS_PARAM_MAX_VALUES_LEN);

	time_t cur_time;
	u_char time_str[32];
	time(&cur_time);
	strftime((char*)time_str, 32, "%Y%m%d%H%M%S", localtime(&cur_time));
	sprintf((char*)log_file_name, "core_%s_npc_%s_%d.log", value, time_str, getpid());
	strcat((char*)log_file_path, "/cdump/");
	/* ��� dbfw/log/cdump/npcĿ¼�Ƿ��Ѿ����� */
	if(access((char*)log_file_path, F_OK)==-1)
	{
//#ifdef DEBUG
//		NPC_PRINT("[Error]: in Npc_FaultTrap(): %s does not exist\n", log_file_path);
//#endif
		exit(0);
	}
	strcat((char*)log_file_path, (char*)log_file_name);


	cdump_file = fopen((char*)log_file_path, "w");
	if(cdump_file==NULL)
	{
//#ifdef DEBUG
//		NPC_PRINT("[Error]: in Npc_FaultTrap(): open file failed :%s\n", log_file_path);
//#endif
		exit(0);		
	}
	/* ����쳣�źŵĳ���ԭ�� */
	strftime((char*)time_str, 32, "%Y-%m-%d %H:%M:%S", localtime(&cur_time));
//	fprintf(cdump_file, "XSecure DBFirewall Enterprise Edition Release %s.%s.%s Build %s %s\n",DBFW_VERSION_MAX,DBFW_VERSION_MIN,DBFW_VERSION_PATCH,BUILD_DATE,BUILD_SVN);
	fprintf(cdump_file, "Release %s.%s.%s Build %s %s\n",DBFW_VERSION_MAX,DBFW_VERSION_MIN,DBFW_VERSION_PATCH,BUILD_DATE,BUILD_SVN);
	fprintf(cdump_file, "Process ID: %u    Time: %s\n",__PID, time_str);
	/* ���crash��ԭ�� */
	fprintf(cdump_file, "Crash Reason: ");
	switch (signo)
	{
	case SIGSEGV:      /* �ڴ���ʴ��� */
		fprintf(cdump_file, "memory segment error\n");        
		break;
	case SIGBUS:    /* ʹ�ô洢ӳ�亯���������� */
		fprintf(cdump_file, "memory bus error\n");
		break;
	case SIGFPE:    /* ��0���� */
		fprintf(cdump_file, "div zero error\n");
		break;
	case SIGABRT:    /* �쳣��ֹ */
		fprintf(cdump_file, "abort error\n");
		break;
	case SIGILL:    /* �Ƿ�Ӳ��ָ�� */
		fprintf(cdump_file, "error hardware code\n");
		break;
	case SIGQUIT:    /* ctrl+\ */
		fprintf(cdump_file, "ctrl+\\\n");
		break;
	case SIGSYS:    /* ��Чϵͳ���� */
		fprintf(cdump_file, "invalid system call\n");
		break;
	case SIGTRAP:    /* Ӳ������ */
		fprintf(cdump_file, "hardware error\n");
		break;
	default:
		fprintf(cdump_file, "unknown error %d\n",signo);
		break;
	}
	fprintf(cdump_file,"\n");

	/* ���siginfo�ĳ�Ա���� */
	fprintf(cdump_file,"signal number: %d\n", signo);/* �ĸ��ź��������crash, ��siginfo->si_signo��ֵ��ͬ*/
	fprintf(cdump_file,"signal code = %d \n", siginfo->si_code);/*�źŴ��룬��APUE��264ҳ*/
	fprintf(cdump_file,"fault address:0x%llx\n", (u_int64)siginfo->si_addr);/*����������ڴ��ַ,���ź���SIGSEGV��SIGILLʱ���д˵�ַ*/     
	fprintf(cdump_file,"errno:%d\n", siginfo->si_errno);/*<errno.h>�ж���Ĵ����*/
	fprintf(cdump_file,"\n");

	fprintf(cdump_file,"---------------- Begin of Stack Trace ---------------------\n");

	calls = Dbfw_Backtrace(&num);
	if(calls!=NULL)// ����޷�Ϊcalls�����ڴ棬�򷵻�NULL 
	{
		for (i = 0; i < num; i++)
		{
			fprintf(cdump_file, "%s\n", calls[i]);  
		}
		free(calls);/*calls���ڴ�ռ����ɿ⺯��malloc�����ģ�����Ҫ�ͷ�calls*/
	}

	fprintf(cdump_file, "---------------- End of Stack Trace -----------------\n\n");
	#ifdef HAVE_LIBTIS
	Tis_Report((Tis_Manager*)capbuf_addr,0,cdump_file);
	#endif
	fflush(cdump_file);
	fclose(cdump_file);
	exit(0);
}


