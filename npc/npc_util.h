/********************************************
*
*	npc_util.h
*	���ߺ���������:
*	������־
*	IP��ַ��MAC��ַת��
*	Hash�����
*	����NPP������
*
*********************************************/

#ifndef _NPC_UTIL_H_
#define _NPC_UTIL_H_

#include <stdio.h>
#include <time.h>
#include <string.h>
#include "dbfw_ipc.h"
#include "dbfw_limits.h"
#include "dbfwsga_session.h"

/*****************************************
*	����һ������־
*	log_level: ��־����, e.g. ERROR_LEVEL
*	log: ��־�ṹ��
*	format,... :��־��Ϣ
*****************************************/
extern time_t log_time;
#define NPC_NEW_LOG(log_level, log, format, ...)\
{\
    char msg_tmp[1024*10];\
    memset(msg_tmp,0x00,sizeof(msg_tmp));\
    if(log_level==ERROR_LEVEL)\
    {\
	    if(npc_errlog_file.level_enable[log_level]==1)\
	    {\
		    time(&log_time);\
		    strftime((char*)log.cur_time, 32, "%Y-%m-%d %H:%M:%S", localtime(&log_time));\
            sprintf((char*)msg_tmp, format, ## __VA_ARGS__);\
            memcpy((char*)log.msg,msg_tmp,sizeof(log.msg)-1);\
	    }\
    }\
    else\
    {\
        if(npc_log_file.level_enable[log_level]==1)\
        {\
            time(&log_time);\
            strftime((char*)log.cur_time, 32, "%Y-%m-%d %H:%M:%S", localtime(&log_time));\
            sprintf((char*)msg_tmp, format, ## __VA_ARGS__);\
            memcpy((char*)log.msg,msg_tmp,sizeof(log.msg)-1);\
        }\
    }\
}


#ifdef PRINT_INFO
	#define NPC_PRINT(format, ...)\
	{\
		printf(format, ## __VA_ARGS__); \
	}
#else
	#define NPC_PRINT(format, ...)\
	{\
	}
#endif 
/*********************************************
*	
*	��ʮ���Ƶ�IP��ַת�����ַ���
*
*********************************************/
void Npc_Ip2Str(u_int ip, u_char str[]);

/***********************************************
*
*	��6�ֽڵ�mac��ַת�����ַ���: AB-CD-EF-01-02-03
*
***********************************************/
void Npc_FormatMacAddress(const u_char *p_mac, u_char mac[]);

/***********************************************
*
*	��6�ֽڵ�mac��ַת�����ַ���: ABCDEF010203
*
***********************************************/
void Npc_FormatMacAddress_Clear(const u_char *p_mac, u_char mac[]);

#define NPC_HASHMAP_PRIME_FOR_SESSION         	5987	/*hash����ȡģ������,Ϊ client ip+port => session_id�ṩ */
#define NPC_HASHMAP_MAX_ELEMENTS_FOR_SESSION  	8320	/*session_hashmp�Ļ������ڵ���������, 
														  session�����8192��,������128������ڵ�,
														  ��Ϊ��session�Ͽ�ʱ,�ڵ㲻�ᱻ�������� 
														*/
#define NPC_HASHMAP_PRIME_FOR_DB         		1021	/*hash����ȡģ������,Ϊ db ip+port => 1 �ṩ */
#define NPC_HASHMAP_MAX_ELEMENTS_FOR_DB  		1024	/*db_hashmap�Ļ������ڵ������������ô�ֵ��ȷ��hashpool�Ĵ�С*/

#define NPC_HASHMAP_NOT_FIND_KEY        65535   /*��hash����û�ҵ�keyʱ���ش�ֵ, ��find()��delete()����ʹ��*/


#pragma pack(1)
/*************************************
**
**	Hashmap��ʹ�õĽڵ�
**	22���ֽ�
**************************************/
typedef struct Npc_HashNode
{
    u_int64				_key;			/* ��db_hashmap��,��db ip+port; ��session_hashmap��,��client ip+port */
    u_short				_value;			/* ��db_hashmap����1; ��session_hashmap��,��session_id(0-8191) */
	int					_sem_id;		/* ��db_hashmap��û��ʹ��;��session_hashmap��,��session_id��Ӧ���ź���id */
    struct Npc_HashNode* _next;
}Npc_HashNode;

/**************************************************************
**
**	ÿ��hashmap��һ���Լ���hashpool
**	db_hashmapռ�õĴ�С: 1021*8+1024*22=8168+22528=30696
**	session_hashmapռ�õĴ�С: 5987*8+8320*22=47896+183040=230936
**
**************************************************************/
typedef struct Npc_HashPool
{
	void			*_pool;				/*������׵�ַ��ָ��*/
	Npc_HashNode	*_header;			/*����ص����нڵ㹹��һ������,_header���ڷ�����ͷŽڵ�*/
	u_int			_size;				/*����صĴ�С,��λ���ֽ� */
	Npc_HashNode	**_buckets;			/*�ڵ��ָ������*/
	u_int			_num_bucket;		/*Ͱ������,������*/
	u_int			_num_element;		/*������������ɵĽڵ����� */
}Npc_HashPool;

/**************************************************************
**
**	��������Session��Client��Ϣ�Ĺ�ϵ
**  �����±����session_id
**
**************************************************************/
typedef struct Npc_SessionWithClient
{
    u_int64 client_key;     /* ��ʼֵΪ0 */
#ifdef USE_BSLHASH_FORSESSION
    u_short session_id;     /* 65535��ʾ��session������ */    
#endif
    int     _sem_id;        /* ��session���ź���ID */
    u_int64 timestamp_for_createcpp;    /* ���Ự����NPP��ʱ���(���ڽ���SYN+ACK�ļ��) */
    u_short dialect;        /* ���� */
    u_char  is_dynaport;    /* �Ƿ��Ƕ�̬�˿� 0-�� 1-�� */
}Npc_SessionWithClient;

/* 
    2014-10-15 ���ӱ������ݿ������IP�����ݿ����͵����ݽṹ 
    Ϊ�˼ӿ��ѯ�����ܣ�����IP+PORT������keyֵ%64��ֵΪ�±�����ơ�Ͱ�������ݽṹ
    ÿ����Ͱ�����ְ���DBFW_MAX_PROTECTED_DBADDRESS(1024)����ͬhashֵ��Ԫ��
    64:DBFW_MAX_PROTECTED_DATABASE
*/
typedef struct Npc_DBTypeWithIpAndPort_Bucket
{
    u_short dbcount;        /* Ͱ�а��������ݿ�ʵ������ */
    u_int64 dbserver_key[DBFW_MAX_PROTECTED_DBADDRESS];   /* IP��PORT������keyֵ */
    u_short dialect[DBFW_MAX_PROTECTED_DBADDRESS];        /* ���ݿ�����(����),�ο�dbfw_ac.h�еĺ궨�� */    
}Npc_DBTypeWithIpAndPort_Bucket;

#pragma pack()

/*********************
**	��ʼ��hashmap
**       ����ֵ
**               0: �ɹ�
**               -1:�����ڴ�ʧ��
**********************/
int Npc_HashmapInit(Npc_HashPool *hashpool);
/************************************************
**
**	����������,������֯��һ������
**	��buckets�������
**	RETURN
**		0:ok
**		-1:error
************************************************/
int Npc_HashmapReset(Npc_HashPool* hashpool);

/*************************************************
**	��hashmap�в���һ��Ԫ��
**	����ͬkey��Ԫ�ش��ڣ������valueֵ
**	ϵͳ���ź���id�ǷǸ���,������-1��ʾδʹ��sem_id�ֶ�
** 	����ֵ
**		-1 : ��������Ԫ��
**		>=0: �������Ѿ����ڵ�Ԫ��
**       -2 : ����ڵ�ʧ��,������ù���
**************************************************/
int Npc_HashmapInsert(Npc_HashPool *hashpool, u_int64 key, u_short value, int sem_id=-1);

/********************************************
**	���ҹؼ���Ϊkey��Ԫ��
**	����ֵ
**		>=0: �ҵ���value
**		NPC_HASHMAP_NOT_FIND_KEY: û���ҵ�,ֵ��65535
********************************************/
u_short Npc_HashmapFind(Npc_HashPool *hashpool, u_int64 key);

/********************************************
**	ɾ���ؼ���Ϊkey��Ԫ��, �ѽڵ�Żػ������
**	����ֵ:       
**		0: ɾ���ɹ�
**		65535: û���ҵ�
********************************************/
u_short Npc_HashmapDelete(Npc_HashPool *hashpool, u_int64 key);

/*******************************************
**	����hashmap��Ԫ�ص�����
********************************************/
int Npc_HashmapCount(Npc_HashPool *hashpool);

/**************************************************
**
**	����session_hashmap�ĺ���
**	����hash��,�����ȡ�ź�����ֵ�����ɾ���ڵ�
**	����ֵ:
**		0
**************************************************/
int Npc_HashmapClear(Npc_HashPool* hashpool);


/*******************************************
**       �ͷŸ�hashpool������ڴ�
*******************************************/
void Npc_HashmapDestroy(Npc_HashPool *hashpool);

/********************************************
*	����NPP�������ֵĺ���
*	buf: �����ִ���û�����
*	instance_name: DBFWʵ����
********************************************/
void Npc_ConstructNppName(u_char* buf, u_char* instance_name);

void Npc_Int2Str(u_int n, u_char* buf);

/* coredump������ */
void Npc_FaultTrap(int signo, 
					siginfo_t *siginfo, 
					void *context);

void Npc_Sched_CPU();

u_short Npc_DynaPortFind(Dbfw_Sga_SessionBuf *sga_session_buf, u_int ip, u_short port);

#endif

